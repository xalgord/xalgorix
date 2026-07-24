// Package agent — plan_tools.go registers the build_plan / update_plan tools.
//
// The structural planner (planner.go) auto-builds a plan from the seeded attack
// surface + recon once an endpoint inventory exists. These tools let the LLM
// replace or refine that plan with knowledge only it has — the live recon
// output the engine can't fully parse (e.g. JS-bundle-mined API routes, an auth
// flow it traced through the browser). The engine tracks the resulting plan and
// the finish gate + per-iteration nudge consult it, so an LLM-authored plan gets
// the same coverage enforcement as an auto-generated one.
//
// Why both tools exist:
//   - build_plan: replace the whole plan (used once after recon, or when the
//     model realizes the auto-plan missed a class/endpoint).
//   - update_plan: transition one task's status (pending→active→completed/
//     skipped) as the model works it, so the plan reflects progress without a
//     full rebuild.
//
// The tools are intentionally tolerant of malformed input — a bad task ID or
// status is reported back as a tool result (so the model self-corrects) rather
// than erroring out of the loop.
package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// planTaskInput is the LLM-supplied task shape for build_plan.
type planTaskInput struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Phase     int      `json:"phase"`
	VulnClass string   `json:"vuln_class"`
	Endpoint  string   `json:"endpoint"`
	DependsOn []string `json:"depends_on"`
	Notes     string   `json:"notes"`
}

// registerPlanTools adds build_plan and update_plan to the registry. The agent
// state is captured by closure so the tools mutate the live ScanState plan
// (shared across sub-agents via the ScanContext).
func (a *Agent) registerPlanTools(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name: "build_plan",
		Description: "Build or replace the structured scan plan as an ordered task graph. " +
			"Call this after recon once you know the real endpoint surface, OR when you realize the " +
			"current plan missed a vuln class / endpoint. Each task is coarse-grained (e.g. " +
			"'test /api/users for injection'), maps to a methodology phase (1-22), and may depend on " +
			"other task IDs. The engine tracks completion and will NOT let you finish until the plan " +
			"is complete (or the surface is exhausted). Pass tasks as a JSON array.",
		Parameters: []tools.Parameter{
			{Name: "tasks", Description: "JSON array of tasks: [{\"id\",\"title\",\"phase\",\"vuln_class\",\"endpoint\",\"depends_on\":[ids],\"notes\"}]. Use stable ids like 'test-sqli'. phase is 1-22.", Required: true},
		},
		Execute: a.buildPlanTool,
	})

	reg.Register(&tools.Tool{
		Name: "update_plan",
		Description: "Mark a planned task as active, completed, or skipped so the engine tracks " +
			"progress. Call this when you start a task and when it's done (covered, or ruled out " +
			"as not-applicable → skipped). The engine also auto-marks tasks done from coverage " +
			"evidence, so you only need this for tasks it can't infer (e.g. ruling a class " +
			"not-applicable).",
		Parameters: []tools.Parameter{
			{Name: "task_id", Description: "The task id from build_plan", Required: true},
			{Name: "status", Description: "One of: active, completed, skipped", Required: true},
			{Name: "notes", Description: "Optional rationale / finding reference", Required: false},
		},
		Execute: a.updatePlanTool,
	})
}

// buildPlanTool replaces the scan plan from a JSON task array.
func (a *Agent) buildPlanTool(args map[string]string) (tools.Result, error) {
	raw := strings.TrimSpace(args["tasks"])
	if raw == "" {
		return tools.Result{Error: "tasks is required (a JSON array of task objects)"}, nil
	}
	var inputs []planTaskInput
	if err := json.Unmarshal([]byte(raw), &inputs); err != nil {
		return tools.Result{Error: "invalid tasks JSON: " + err.Error() + " — expected an array like [{\"id\":\"test-sqli\",\"title\":\"...\",\"phase\":6,\"vuln_class\":\"sqli\",\"depends_on\":[\"recon\"]}]"}, nil
	}
	if len(inputs) == 0 {
		return tools.Result{Error: "tasks array is empty — pass at least one task"}, nil
	}

	plan := NewPlan()
	var warnings []string
	for _, in := range inputs {
		id := strings.TrimSpace(in.ID)
		if id == "" {
			warnings = append(warnings, "a task with no id was dropped")
			continue
		}
		t := &Task{
			ID:        id,
			Title:     strings.TrimSpace(in.Title),
			Phase:     clampPhase(in.Phase),
			VulnClass: strings.ToLower(strings.TrimSpace(in.VulnClass)),
			Endpoint:  strings.TrimSpace(in.Endpoint),
			Status:    TaskPending,
			DependsOn: trimIDList(in.DependsOn),
			Notes:     strings.TrimSpace(in.Notes),
			Origin:    "llm",
		}
		if t.Title == "" {
			t.Title = id
		}
		if !plan.add(t) {
			warnings = append(warnings, fmt.Sprintf("duplicate task id %q was dropped", id))
		}
	}
	if plan.IsEmpty() {
		return tools.Result{Error: "no valid tasks after parsing (every task needs a unique id)"}, nil
	}

	a.state.Plan = plan
	a.state.PlanBuilt = true
	// Ground the new plan in the discovered endpoints so coverage-gap detection
	// works against it immediately.
	a.state.DiscoveredEndpoints = extractEndpointsFromNotes(a.state)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Plan built: %d tasks.\n", len(plan.Tasks)))
	for _, t := range plan.Tasks {
		sb.WriteString(fmt.Sprintf("  • [%s] phase %d — %s\n", t.ID, t.Phase, t.Title))
	}
	if len(warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range warnings {
			sb.WriteString("  - " + w + "\n")
		}
	}
	pending, active, completed, skipped := plan.Counts()
	sb.WriteString(fmt.Sprintf("\nStatus: %d pending, %d active, %d completed, %d skipped. Work the tasks in dependency order; the engine tracks completion and gates finish on a complete plan.", pending, active, completed, skipped))
	return tools.Result{Output: sb.String()}, nil
}

// updatePlanTool transitions a task's status.
func (a *Agent) updatePlanTool(args map[string]string) (tools.Result, error) {
	id := strings.TrimSpace(args["task_id"])
	status := strings.ToLower(strings.TrimSpace(args["status"]))
	notes := strings.TrimSpace(args["notes"])
	if id == "" {
		return tools.Result{Error: "task_id is required"}, nil
	}
	plan := a.state.Plan
	if plan == nil || plan.IsEmpty() {
		return tools.Result{Error: "no plan exists yet — call build_plan first"}, nil
	}
	t := plan.Get(id)
	if t == nil {
		return tools.Result{Error: fmt.Sprintf("unknown task id %q — current task ids: %s", id, planIDList(plan))}, nil
	}
	var st TaskStatus
	switch status {
	case "active":
		st = TaskActive
	case "completed", "complete", "done":
		st = TaskCompleted
	case "skipped", "skip", "n/a", "na", "not-applicable":
		st = TaskSkipped
	default:
		return tools.Result{Error: "status must be one of: active, completed, skipped (got " + args["status"] + ")"}, nil
	}
	t.Status = st
	if notes != "" {
		if t.Notes != "" {
			t.Notes += " | " + notes
		} else {
			t.Notes = notes
		}
	}
	pending, active, completed, skipped := plan.Counts()
	return tools.Result{Output: fmt.Sprintf("Task %q → %s. Plan: %d pending, %d active, %d completed, %d skipped (%d%% complete).", id, st, pending, active, completed, skipped, plan.ProgressPct())}, nil
}

// clampPhase forces a phase into the 1-22 methodology range.
func clampPhase(p int) int {
	if p < 1 {
		return 1
	}
	if p > 22 {
		return 22
	}
	return p
}

// trimIDList cleans a dependency ID list (drops empties).
func trimIDList(ids []string) []string {
	var out []string
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// planIDList returns a comma-separated list of a plan's task ids for error
// messages.
func planIDList(p *Plan) string {
	if p == nil {
		return ""
	}
	ids := make([]string, 0, len(p.Tasks))
	for _, t := range p.Tasks {
		ids = append(ids, t.ID)
	}
	return strings.Join(ids, ", ")
}
