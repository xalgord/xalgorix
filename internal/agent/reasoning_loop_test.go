package agent

import (
	"strings"
	"testing"
)

// hookNoToolHandler must trigger a context compaction (ForceCompact) at the
// first consecutive threshold (6), not wait until the abort at 15. This is the
// reasoning-loop recovery path — without it the scan force-stops on the exact
// "llm_no_tool_calls" failure the reaper-search.biz scan hit.
func TestNoToolHandlerCompactsBeforeAbort(t *testing.T) {
	state := NewScanState()

	// Iterations 1-5: plain nudges, no compaction yet.
	for i := 0; i < ReasoningLoopCompactAt-1; i++ {
		res := hookNoToolHandler(state, map[string]string{"response": "let me think"})
		if res.ForceSkip {
			t.Fatalf("iter %d: ForceSkip before the abort threshold", i)
		}
		if res.ForceCompact {
			t.Fatalf("iter %d: ForceCompact fired before ReasoningLoopCompactAt (%d)", i, ReasoningLoopCompactAt)
		}
		if state.ReasoningLoopCompactions != 0 {
			t.Fatalf("iter %d: compaction counter incremented too early", i)
		}
	}

	// Iteration 6 (NoToolCount == ReasoningLoopCompactAt): first compaction.
	res := hookNoToolHandler(state, map[string]string{"response": "let me think"})
	if !res.ForceCompact {
		t.Fatalf("NoToolCount=%d: expected ForceCompact, got %+v", state.NoToolCount, res)
	}
	if state.ReasoningLoopCompactions != 1 {
		t.Fatalf("after first compact: ReasoningLoopCompactions=%d, want 1", state.ReasoningLoopCompactions)
	}
	if res.Nudge == "" {
		t.Fatal("ForceCompact result must carry a focused resume nudge")
	}
	if !strings.Contains(res.Nudge, "tool call") && !strings.Contains(res.Nudge, "terminal_execute") {
		t.Errorf("resume nudge should demand a tool call, got %q", res.Nudge)
	}
	if res.ForceSkip {
		t.Fatal("first compaction must NOT abort the scan")
	}

	// The abort at 15 only fires after the compaction cap is exhausted. Walk
	// the count up past the second compaction (at 10) and toward the abort.
	// NoToolCount is NOT reset by the compaction, so it keeps climbing.
	for i := state.NoToolCount; i < ReasoningLoopCompactAt2; i++ {
		hookNoToolHandler(state, map[string]string{"response": "thinking"})
	}
	res = hookNoToolHandler(state, map[string]string{"response": "thinking"})
	if state.ReasoningLoopCompactions > MaxReasoningCompactions {
		t.Fatalf("ReasoningLoopCompactions=%d exceeds MaxReasoningCompactions=%d", state.ReasoningLoopCompactions, MaxReasoningCompactions)
	}

	// Drive to the abort. After MaxReasoningCompactions, ForceCompact stops
	// firing and the count climbs to NoToolAbortAt, which ForceSkips.
	for state.NoToolCount < NoToolAbortAt {
		res = hookNoToolHandler(state, map[string]string{"response": "thinking"})
	}
	if !res.ForceSkip {
		t.Fatalf("NoToolCount=%d: expected ForceSkip (abort), got %+v", state.NoToolCount, res)
	}
}

// With the abort disabled (XALGORIX_NO_TOOL_ABORT_AT=0), the handler must NEVER
// ForceSkip on a no-tool loop, and must keep re-compacting on a cadence so the
// model keeps getting fresh context to fix itself — not just spin on nudges.
func TestNoToolHandler_AbortDisabledNeverGivesUp(t *testing.T) {
	state := NewScanState()
	state.NoToolAbortConfigured = true
	state.NoToolAbortLimit = 0 // disabled → never give up

	compactions := 0
	for i := 0; i < 100; i++ {
		res := hookNoToolHandler(state, map[string]string{"response": "thinking, no tool"})
		if res.ForceSkip {
			t.Fatalf("ForceSkip fired at NoToolCount=%d with abort disabled", state.NoToolCount)
		}
		if res.ForceCompact {
			compactions++
		}
	}
	// Recurring compaction (every ReasoningLoopCompactAt2) — not capped at the
	// default MaxReasoningCompactions=2 — so it keeps actively trying to recover.
	if compactions <= MaxReasoningCompactions {
		t.Errorf("expected recurring compactions with abort disabled, got %d (want > %d)", compactions, MaxReasoningCompactions)
	}
}

// The two consecutive compactions must be SPACED at ReasoningLoopCompactAt (6)
// and ReasoningLoopCompactAt2 (10) — NOT fired back-to-back at 6 and 7. The
// back-to-back bug consumed the whole compaction budget immediately, leaving
// the model un-helped from count 8 until the abort at 15 (observed on the
// pentest-ground.com scan: compactions at iters 79/80, then dead air to 88).
func TestNoToolHandlerCompactionsAreSpaced(t *testing.T) {
	state := NewScanState()

	compactedAt := []int{}
	for state.NoToolCount < NoToolAbortAt {
		res := hookNoToolHandler(state, map[string]string{"response": "let me think"})
		if res.ForceCompact {
			compactedAt = append(compactedAt, state.NoToolCount)
		}
		if res.ForceSkip {
			break
		}
	}

	if len(compactedAt) != 2 {
		t.Fatalf("expected exactly 2 compactions, got %d at counts %v", len(compactedAt), compactedAt)
	}
	if compactedAt[0] != ReasoningLoopCompactAt {
		t.Errorf("first compaction at count %d, want %d", compactedAt[0], ReasoningLoopCompactAt)
	}
	if compactedAt[1] != ReasoningLoopCompactAt2 {
		t.Errorf("second compaction at count %d, want %d (spaced, not back-to-back at %d)",
			compactedAt[1], ReasoningLoopCompactAt2, ReasoningLoopCompactAt+1)
	}
}

// The density path must catch a model that makes occasional tool calls —
// enough to reset the consecutive counter but not enough to make progress —
// which would otherwise run for hours. This is the exact 48-hour pattern:
// NoToolCount never reaches the consecutive threshold (6) so the consecutive
// recovery never fires, and without the density abort the scan runs forever.
func TestNoToolHandlerDensityRecovery(t *testing.T) {
	state := NewScanState()

	// Simulate the non-consecutive pattern: a tool call every 5 turns resets
	// NoToolCount to ≤4, so the consecutive compact (needs ≥6) never fires.
	// 4 of 5 turns are no-tool → ratio 0.8, which clears both the compact
	// (>0.6) and abort (>0.75) thresholds. Drive enough iterations that the
	// cumulative density crosses compact, then (after a compaction) abort.
	var sawCompact, sawAbort bool
	for i := 0; i < 200; i++ {
		// Reset the consecutive counter on a tool call (mimics OnHealthyResponse).
		if i%5 == 0 {
			state.NoToolCount = 0
			state.Iteration++
			continue
		}
		state.Iteration++
		res := hookNoToolHandler(state, map[string]string{"response": "thinking"})

		if res.ForceCompact {
			sawCompact = true
		}
		if res.ForceSkip {
			sawAbort = true
			break
		}
	}
	if !sawCompact {
		t.Fatalf("density path never compacted — TotalNoToolResponses=%d Iteration=%d (recovery should fire at ratio > %.2f)",
			state.TotalNoToolResponses, state.Iteration, ReasoningDensityCompactRatio)
	}
	if !sawAbort {
		t.Fatalf("density abort never fired for a non-consecutive reasoning loop — NoToolCount stayed ≤%d so the consecutive path never tripped, and the density abort was expected to catch it. TotalNoToolResponses=%d Iteration=%d",
			state.NoToolCount, state.TotalNoToolResponses, state.Iteration)
	}
	// The abort reason must classify as the reasoning loop, not the generic stall.
	reason, _ := classifyNoToolAbort(state)
	if reason != "llm_reasoning_loop" {
		t.Errorf("classifyNoToolAbort reason = %q, want llm_reasoning_loop", reason)
	}
}

// classifyNoToolAbort must report the density-based reasoning loop as a
// distinct reason from the consecutive stall, so operators can tell a
// "ran for hours making no progress" scan from a "flooded context" scan.
func TestClassifyNoToolAbortDensityReason(t *testing.T) {
	state := &ScanState{
		NoToolCount:          NoToolAbortAt,
		RefusalCount:         0,
		TotalNoToolResponses: 60,
		Iteration:            49, // 50 iters
	}
	reason, detail := classifyNoToolAbort(state)
	if reason != "llm_reasoning_loop" {
		t.Errorf("reason = %q, want llm_reasoning_loop", reason)
	}
	if !strings.Contains(strings.ToLower(detail), "reasoning loop") {
		t.Errorf("density detail should mention reasoning loop, got %q", detail)
	}
}

// A safety refusal must still take priority over both recovery paths.
func TestNoToolHandlerRefusalPriority(t *testing.T) {
	state := NewScanState()
	// Three refusals → RefusalCount climbs; the authorization nudge must fire,
	// not a compaction or abort.
	for i := 0; i < 3; i++ {
		res := hookNoToolHandler(state, map[string]string{"response": "I cannot fulfill this request"})
		if res.ForceSkip {
			t.Fatal("refusal should nudge, not abort, before the 15 threshold")
		}
		if res.ForceCompact {
			t.Fatal("refusal should not trigger compaction")
		}
		if !strings.Contains(res.Nudge, "AUTHORIZED") {
			t.Errorf("refusal nudge should re-assert authorization, got %q", res.Nudge)
		}
	}
	if state.RefusalCount != 3 {
		t.Errorf("RefusalCount=%d, want 3", state.RefusalCount)
	}
}
