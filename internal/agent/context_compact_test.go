package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
)

func msgsOfSize(totalBytes int) []llm.Message {
	// One big user message of the requested size (plus a system prompt).
	return []llm.Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: strings.Repeat("x", totalBytes)},
	}
}

// The auto-compaction trigger must be driven by the configurable token budget
// (XALGORIX_CONTEXT_COMPACT_TOKENS), not a hardcoded constant.
func TestShouldPruneBeforeLLM_TokenBudget(t *testing.T) {
	// 30000 tokens ≈ 120000 bytes threshold.
	a := &Agent{cfg: &config.Config{ContextCompactTokens: 30000}}

	a.messages = msgsOfSize(100000) // under 120000 → no prune
	if a.shouldPruneBeforeLLM() {
		t.Error("should NOT prune below the configured budget")
	}

	a.messages = msgsOfSize(200000) // over 120000 → prune
	if !a.shouldPruneBeforeLLM() {
		t.Error("should prune above the configured budget")
	}
}

// A budget of 0 disables proactive compaction entirely.
func TestShouldPruneBeforeLLM_Disabled(t *testing.T) {
	a := &Agent{cfg: &config.Config{ContextCompactTokens: 0}}
	a.messages = msgsOfSize(5_000_000)
	if a.shouldPruneBeforeLLM() {
		t.Error("budget 0 must disable auto-compaction")
	}
}

// With no config (tests/CLI) it falls back to the built-in default ceiling.
func TestShouldPruneBeforeLLM_DefaultFallback(t *testing.T) {
	a := &Agent{}
	if got := a.compactThresholdBytes(); got != pruneThresholdBytes {
		t.Fatalf("nil cfg threshold = %d, want default %d", got, pruneThresholdBytes)
	}
	a.messages = msgsOfSize(pruneThresholdBytes + 10000)
	if !a.shouldPruneBeforeLLM() {
		t.Error("should prune above the default ceiling when cfg is absent")
	}
}

// In AUTO mode (ContextCompactTokens < 0) the trigger is derived from the
// model's context window × ratio, NOT the old fixed budget. This is the
// behavior that keeps large-context models from compacting too early.
func TestShouldPruneBeforeLLM_AutoWindowRelative(t *testing.T) {
	// 1M-token window × 0.75 = 750K tokens ≈ 3,000,000 bytes threshold.
	a := &Agent{cfg: &config.Config{
		ContextCompactTokens: -1,
		LLMContextWindow:     1_000_000,
		ContextCompactRatio:  0.75,
	}}

	// A buffer that would have tripped the old 120K-token default must NOT
	// compact now — we're nowhere near 75% of a 1M window.
	a.messages = msgsOfSize(600_000) // ~150K tokens
	if a.shouldPruneBeforeLLM() {
		t.Error("must NOT compact well below 75% of the context window")
	}

	// Past ~75% of the window it should compact.
	a.messages = msgsOfSize(3_200_000)
	if !a.shouldPruneBeforeLLM() {
		t.Error("should compact once past the window-relative ceiling")
	}
}

// An out-of-range ratio falls back to the safe default (0.75).
func TestCompactThreshold_RatioClamp(t *testing.T) {
	a := &Agent{cfg: &config.Config{
		ContextCompactTokens: -1,
		LLMContextWindow:     100_000,
		ContextCompactRatio:  9, // nonsense → default 0.75
	}}
	want := int(float64(100_000)*0.75) * bytesPerTokenEstimate
	if got := a.compactThresholdBytes(); got != want {
		t.Fatalf("threshold = %d, want %d (ratio should clamp to default)", got, want)
	}
}
