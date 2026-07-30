// Package agentsgraph provides multi-agent delegation tools with async spawning.
package agentsgraph

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

const maxConcurrentAgents = 3

// AgentRunner is a function that runs a sub-agent. This breaks the import cycle
// between agent and agentsgraph. The agent package injects this at registration time.
type AgentRunner func(name string, targets []string, task string) (string, error)

// subAgentState tracks an async sub-agent.
type subAgentState struct {
	ID          string
	Name        string
	Task        string
	Targets     []string
	Status      string // "running", "completed", "failed"
	StartedAt   time.Time
	CompletedAt time.Time
	Result      string
	Error       string

	// Partial results accumulated during execution
	partialMu      sync.Mutex
	partialResults []string
}

var (
	runner AgentRunner

	// Async sub-agent tracking
	agentsMu     sync.Mutex
	agentCounter int
	agents       = make(map[string]*subAgentState)

	// Semaphore to limit concurrent sub-agents
	agentSemaphore = make(chan struct{}, maxConcurrentAgents)

	// Reset signal — when true, running goroutines should exit early
	agentsStopped atomic.Bool
)

// Register adds multi-agent tools to the registry.
// The agentRunner function is injected to break the import cycle.
//
// NOTE: Only synchronous create_agent is registered. Async tools (spawn_agent,
// check_agent, wait_agent) are disabled — they cause zombie goroutines and
// semaphore leaks that prevent the watchdog from detecting stuck scans.
func Register(r *tools.Registry, agentRunner AgentRunner) {
	runner = agentRunner

	// Synchronous sub-agent — blocks until completion
	r.Register(&tools.Tool{
		Name:        "create_agent",
		Description: "Create and run a sub-agent synchronously. Blocks until the sub-agent completes and returns its results. Use for delegating focused tasks like 'scan this endpoint for SQLi' or 'fuzz this API for IDOR'.",
		Parameters: []tools.Parameter{
			{Name: "name", Description: "Name for the sub-agent (e.g. 'SQLi Scanner')", Required: true},
			{Name: "task", Description: "Task description for the sub-agent", Required: true},
			{Name: "target", Description: "Target URL/path for the sub-agent", Required: false},
		},
		Execute: createAgent,
	})

	// Async sub-agent tools are gated behind XALGORIX_ENABLE_ASYNC_AGENTS to prevent zombie goroutines & semaphore leaks
	if os.Getenv("XALGORIX_ENABLE_ASYNC_AGENTS") == "true" {
		r.Register(&tools.Tool{
			Name:        "spawn_agent",
			Description: "Spawn a sub-agent asynchronously and return an agent_id immediately. You can continue doing other work and use check_agent or wait_agent later to get results. Max 3 concurrent sub-agents allowed.",
			Parameters: []tools.Parameter{
				{Name: "name", Description: "Name for the sub-agent (e.g. 'Directory Brute-forcing')", Required: true},
				{Name: "task", Description: "Task description for the sub-agent", Required: true},
				{Name: "target", Description: "Target URL/path for the sub-agent", Required: false},
			},
			Execute: spawnAgent,
		})

		r.Register(&tools.Tool{
			Name:        "check_agent",
			Description: "Check the status and partial results of an asynchronously spawned sub-agent.",
			Parameters: []tools.Parameter{
				{Name: "agent_id", Description: "The ID returned by spawn_agent", Required: true},
			},
			Execute: checkAgent,
		})

		r.Register(&tools.Tool{
			Name:        "wait_agent",
			Description: "Block and wait until a spawned sub-agent completes or fails.",
			Parameters: []tools.Parameter{
				{Name: "agent_id", Description: "The ID returned by spawn_agent", Required: true},
				{Name: "timeout", Description: "Timeout in seconds to wait (default 600)", Required: false},
			},
			Execute: waitAgent,
		})
	}
}

func createAgent(args map[string]string) (tools.Result, error) {
	name := args["name"]
	task := args["task"]
	target := args["target"]

	if name == "" || task == "" {
		return tools.Result{}, fmt.Errorf("name and task are required")
	}

	targets := []string{}
	if target != "" {
		targets = append(targets, target)
	}

	if runner == nil {
		return tools.Result{}, fmt.Errorf("agent runner not initialized")
	}

	start := time.Now()
	summary, err := runner(name, targets, task)
	elapsed := time.Since(start)

	if err != nil {
		return tools.Result{
			Output: fmt.Sprintf("Sub-agent '%s' failed after %s: %s", name, elapsed.Round(time.Second), err.Error()),
		}, nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Sub-agent '%s' completed in %s\n", name, elapsed.Round(time.Second)))
	b.WriteString(summary)

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"agent_name": name,
			"elapsed":    elapsed.Seconds(),
		},
	}, nil
}

// spawnAgent launches a sub-agent asynchronously and returns immediately.
func spawnAgent(args map[string]string) (tools.Result, error) {
	name := args["name"]
	task := args["task"]
	target := args["target"]

	if name == "" || task == "" {
		return tools.Result{}, fmt.Errorf("name and task are required")
	}

	if runner == nil {
		return tools.Result{}, fmt.Errorf("agent runner not initialized")
	}

	targets := []string{}
	if target != "" {
		targets = append(targets, target)
	}

	// Check concurrent limit
	agentsMu.Lock()
	runningCount := 0
	for _, a := range agents {
		if a.Status == "running" {
			runningCount++
		}
	}
	agentsMu.Unlock()

	if runningCount >= maxConcurrentAgents {
		return tools.Result{
			Output: fmt.Sprintf("❌ Cannot spawn agent: %d/%d sub-agents already running. Wait for one to finish or use check_agent/wait_agent first.\nRunning agents:\n%s",
				runningCount, maxConcurrentAgents, listRunningAgents()),
		}, nil
	}

	// Create agent state
	agentsMu.Lock()
	agentCounter++
	agentID := fmt.Sprintf("sub_%d_%d", agentCounter, time.Now().Unix())
	state := &subAgentState{
		ID:        agentID,
		Name:      name,
		Task:      task,
		Targets:   targets,
		Status:    "running",
		StartedAt: time.Now(),
	}
	agents[agentID] = state
	agentsMu.Unlock()

	// Launch in background goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] spawnAgent goroutine panicked: %v\n%s", r, debug.Stack())
				agentsMu.Lock()
				state.Status = "failed"
				state.Error = fmt.Sprintf("panic: %v", r)
				state.CompletedAt = time.Now()
				agentsMu.Unlock()
			}
		}()

		// Check if reset was requested before acquiring slot
		if agentsStopped.Load() {
			agentsMu.Lock()
			state.Status = "failed"
			state.Error = "reset: parent scan session ended before agent could start"
			state.CompletedAt = time.Now()
			agentsMu.Unlock()
			return
		}

		// Acquire semaphore slot (blocks until available)
		select {
		case agentSemaphore <- struct{}{}:
			// Got slot
		case <-time.After(30 * time.Second):
			// Timeout — shouldn't happen normally
			agentsMu.Lock()
			state.Status = "failed"
			state.Error = "timeout: could not acquire agent slot within 30s"
			state.CompletedAt = time.Now()
			agentsMu.Unlock()
			return
		}
		defer func() { <-agentSemaphore }()

		// Check stopped flag again after acquiring semaphore
		if agentsStopped.Load() {
			completedAt := time.Now()
			agentsMu.Lock()
			state.Status = "failed"
			state.Error = "reset: parent scan session ended"
			state.CompletedAt = completedAt
			if s, ok := agents[agentID]; ok {
				s.Status = "failed"
				s.Error = "reset: parent scan session ended"
				s.CompletedAt = completedAt
			}
			agentsMu.Unlock()
			return
		}

		summary, err := runner(name, targets, task)

		agentsMu.Lock()
		defer agentsMu.Unlock()

		state.CompletedAt = time.Now()
		if err != nil {
			state.Status = "failed"
			state.Error = err.Error()
			state.Result = fmt.Sprintf("Sub-agent '%s' failed: %s", name, err.Error())
		} else {
			state.Status = "completed"
			state.Result = summary
		}
	}()

	return tools.Result{
		Output: fmt.Sprintf("✅ Sub-agent '%s' spawned with ID: %s\nTask: %s\nTarget: %s\n\nUse check_agent(agent_id=%s) to poll for results, or wait_agent(agent_id=%s) to block until done.",
			name, agentID, truncTask(task, 200), target, agentID, agentID),
		Metadata: map[string]any{
			"agent_id":   agentID,
			"agent_name": name,
			"spawned":    true,
		},
	}, nil
}

type agentSnapshot struct {
	ID             string
	Name           string
	Task           string
	Status         string
	StartedAt      time.Time
	CompletedAt    time.Time
	Result         string
	Error          string
	PartialResults []string
}

func snapshotAgent(agentID string) (agentSnapshot, bool) {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	state, exists := agents[agentID]
	if !exists {
		return agentSnapshot{}, false
	}

	snap := agentSnapshot{
		ID:          state.ID,
		Name:        state.Name,
		Task:        state.Task,
		Status:      state.Status,
		StartedAt:   state.StartedAt,
		CompletedAt: state.CompletedAt,
		Result:      state.Result,
		Error:       state.Error,
	}
	state.partialMu.Lock()
	snap.PartialResults = append([]string(nil), state.partialResults...)
	state.partialMu.Unlock()
	return snap, true
}

// checkAgent returns status and partial results of a spawned sub-agent.
func checkAgent(args map[string]string) (tools.Result, error) {
	agentID := args["agent_id"]
	if agentID == "" {
		return tools.Result{}, fmt.Errorf("agent_id is required")
	}

	state, exists := snapshotAgent(agentID)
	if !exists {
		return tools.Result{
			Output: fmt.Sprintf("❌ Agent '%s' not found.\n\nAvailable agents:\n%s", agentID, listAllAgents()),
		}, nil
	}

	var b strings.Builder
	elapsed := time.Since(state.StartedAt).Round(time.Second)

	switch state.Status {
	case "running":
		b.WriteString(fmt.Sprintf("🔄 Agent '%s' (%s) — RUNNING for %s\n", state.Name, state.ID, elapsed))
		b.WriteString(fmt.Sprintf("Task: %s\n", truncTask(state.Task, 150)))
		if len(state.PartialResults) > 0 {
			b.WriteString("\n--- Partial Results ---\n")
			start := 0
			if len(state.PartialResults) > 5 {
				start = len(state.PartialResults) - 5
			}
			for _, pr := range state.PartialResults[start:] {
				b.WriteString(pr + "\n")
			}
		} else {
			b.WriteString("\n(No partial results yet — agent is still working)\n")
		}

	case "completed":
		completedElapsed := state.CompletedAt.Sub(state.StartedAt).Round(time.Second)
		b.WriteString(fmt.Sprintf("✅ Agent '%s' (%s) — COMPLETED in %s\n", state.Name, state.ID, completedElapsed))
		b.WriteString("\n--- Results ---\n")
		result := state.Result
		if len(result) > 5000 {
			result = result[:5000] + "\n... [truncated]"
		}
		b.WriteString(result)

	case "failed":
		b.WriteString(fmt.Sprintf("❌ Agent '%s' (%s) — FAILED after %s\n", state.Name, state.ID, elapsed))
		b.WriteString(fmt.Sprintf("Error: %s\n", state.Error))
		if state.Result != "" {
			b.WriteString("\n--- Partial Results ---\n")
			b.WriteString(state.Result)
		}
	}

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"agent_id": agentID,
			"status":   state.Status,
			"elapsed":  elapsed.Seconds(),
		},
	}, nil
}

// waitAgent blocks until a sub-agent completes.
func waitAgent(args map[string]string) (tools.Result, error) {
	agentID := args["agent_id"]
	if agentID == "" {
		return tools.Result{}, fmt.Errorf("agent_id is required")
	}

	timeout := 600 // 10 minutes default
	if t := args["timeout"]; t != "" {
		_, _ = fmt.Sscanf(t, "%d", &timeout)
	}

	state, exists := snapshotAgent(agentID)
	if !exists {
		return tools.Result{
			Output: fmt.Sprintf("❌ Agent '%s' not found.\n\nAvailable agents:\n%s", agentID, listAllAgents()),
		}, nil
	}

	// If already done, return immediately
	if state.Status != "running" {
		return checkAgent(args)
	}

	// Poll until done or timeout
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	if timeout == 0 {
		deadline = time.Now().Add(24 * time.Hour) // "forever"
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		state, exists = snapshotAgent(agentID)
		if !exists {
			return tools.Result{
				Output: fmt.Sprintf("❌ Agent '%s' not found.\n\nAvailable agents:\n%s", agentID, listAllAgents()),
			}, nil
		}
		if state.Status != "running" {
			return checkAgent(args)
		}
		if time.Now().After(deadline) {
			elapsed := time.Since(state.StartedAt).Round(time.Second)
			return tools.Result{
				Output: fmt.Sprintf("⏰ Timeout waiting for agent '%s' (%s) after %s. Agent is still running.\nUse check_agent to poll later, or wait_agent with a longer timeout.",
					state.Name, state.ID, elapsed),
				Metadata: map[string]any{
					"agent_id": agentID,
					"status":   "timeout",
				},
			}, nil
		}
	}
	// unreachable — ticker.C never closes, but compiler requires a return
	return tools.Result{}, nil
}

// AddPartialResult adds a partial result to a running sub-agent (called from agent event handler).
func AddPartialResult(agentID string, result string) {
	agentsMu.Lock()
	state, exists := agents[agentID]
	if !exists {
		agentsMu.Unlock()
		return
	}
	// Hold agentsMu while acquiring partialMu to prevent CleanupCompleted from freeing state
	if state.Status != "running" {
		agentsMu.Unlock()
		return
	}
	state.partialMu.Lock()
	agentsMu.Unlock()

	state.partialResults = append(state.partialResults, result)
	if len(state.partialResults) > 50 {
		state.partialResults = state.partialResults[len(state.partialResults)-50:]
	}
	state.partialMu.Unlock()
}

// GetRunningCount returns the number of running sub-agents.
func GetRunningCount() int {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	count := 0
	for _, a := range agents {
		if a.Status == "running" {
			count++
		}
	}
	return count
}

// Reset clears ALL sub-agent state and signals running goroutines to exit.
// Call this between scan sessions to prevent memory leaks.
// Goroutines check agentsStopped flag and will exit early, releasing their
// semaphore slots via the defer statement.
func Reset() {
	// Signal all running goroutines to stop
	agentsStopped.Store(true)

	agentsMu.Lock()
	// Mark all running agents as failed so their state is correct
	for _, a := range agents {
		if a.Status == "running" {
			a.Status = "failed"
			a.Error = "reset: parent scan session ended"
			a.CompletedAt = time.Now()
		}
	}
	// Clear the entire map to free memory
	agents = make(map[string]*subAgentState)
	agentCounter = 0
	agentsMu.Unlock()

	// Reset the stopped flag so new agents can spawn
	agentsStopped.Store(false)
}

// CleanupCompleted removes finished/failed sub-agents from the map to free memory.
// Lighter alternative to Reset() — safe to call between subdomain scans.
func CleanupCompleted() {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	for id, a := range agents {
		if a.Status == "completed" || a.Status == "failed" {
			delete(agents, id)
		}
	}
}

// helpers

func listRunningAgents() string {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	var b strings.Builder
	for _, a := range agents {
		if a.Status == "running" {
			elapsed := time.Since(a.StartedAt).Round(time.Second)
			b.WriteString(fmt.Sprintf("  - %s (%s): %s — running for %s\n", a.Name, a.ID, truncTask(a.Task, 80), elapsed))
		}
	}
	if b.Len() == 0 {
		return "  (none)"
	}
	return b.String()
}

func listAllAgents() string {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	var b strings.Builder
	for _, a := range agents {
		elapsed := time.Since(a.StartedAt).Round(time.Second)
		b.WriteString(fmt.Sprintf("  - %s (%s): %s [%s] — %s\n", a.Name, a.ID, truncTask(a.Task, 80), a.Status, elapsed))
	}
	if b.Len() == 0 {
		return "  (none)"
	}
	return b.String()
}

func truncTask(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
