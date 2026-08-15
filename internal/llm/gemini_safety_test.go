package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// newGeminiCapturingServer returns an httptest server that records the request
// body and replies with a minimal successful Gemini response so Chat returns on
// the first attempt (no retry/backoff).
func newGeminiCapturingServer(t *testing.T, gotBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`))
	}))
}

// TestGeminiRequestSendsSafetySettings proves that with the default
// XALGORIX_GEMINI_SAFETY posture (BLOCK_NONE), a native Gemini request carries a
// safetySettings array covering HARM_CATEGORY_DANGEROUS_CONTENT so Gemini's
// content filter cannot refuse legitimate authorized-security-testing output.
func TestGeminiRequestSendsSafetySettings(t *testing.T) {
	var gotBody []byte
	srv := newGeminiCapturingServer(t, &gotBody)
	defer srv.Close()

	cfg := &config.Config{
		LLM:                   "gemini-2.5-flash",
		APIBase:               srv.URL,
		APIKey:                "test",
		GeminiSafetyThreshold: "BLOCK_NONE",
	}
	c := NewClient(cfg)
	c.provider = "google"

	if _, err := c.Chat([]Message{{Role: "user", Content: "ping"}}); err != nil {
		t.Fatalf("Chat returned error: %v", err)
	}

	var req geminiRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("request body is not valid geminiRequest JSON: %v\nbody=%s", err, gotBody)
	}
	if len(req.SafetySettings) != len(geminiHarmCategories) {
		t.Fatalf("safetySettings has %d entries; want %d; body=%s", len(req.SafetySettings), len(geminiHarmCategories), gotBody)
	}
	got := make(map[string]string, len(req.SafetySettings))
	for _, s := range req.SafetySettings {
		got[s.Category] = s.Threshold
	}
	if got["HARM_CATEGORY_DANGEROUS_CONTENT"] != "BLOCK_NONE" {
		t.Errorf("dangerous-content threshold = %q; want BLOCK_NONE; body=%s", got["HARM_CATEGORY_DANGEROUS_CONTENT"], gotBody)
	}
	for _, cat := range geminiHarmCategories {
		if got[cat] != "BLOCK_NONE" {
			t.Errorf("category %s threshold = %q; want BLOCK_NONE", cat, got[cat])
		}
	}
}

// TestGeminiRequestOmitsSafetySettingsForDefault proves the opt-out path: when
// the operator sets XALGORIX_GEMINI_SAFETY=default (or leaves it empty), Xalgorix
// sends NO safetySettings and Gemini applies its own server-side defaults —
// preserving the pre-change behavior byte-for-byte.
func TestGeminiRequestOmitsSafetySettingsForDefault(t *testing.T) {
	for _, raw := range []string{"", "default", "DEFAULT", "unspecified"} {
		var gotBody []byte
		srv := newGeminiCapturingServer(t, &gotBody)

		cfg := &config.Config{
			LLM:                   "gemini-2.5-flash",
			APIBase:               srv.URL,
			APIKey:                "test",
			GeminiSafetyThreshold: raw,
		}
		c := NewClient(cfg)
		c.provider = "google"

		if _, err := c.Chat([]Message{{Role: "user", Content: "ping"}}); err != nil {
			srv.Close()
			t.Fatalf("Chat returned error for %q: %v", raw, err)
		}
		srv.Close()

		var req geminiRequest
		if err := json.Unmarshal(gotBody, &req); err != nil {
			t.Fatalf("request body is not valid geminiRequest JSON: %v\nbody=%s", err, gotBody)
		}
		if len(req.SafetySettings) != 0 {
			t.Errorf("XALGORIX_GEMINI_SAFETY=%q sent %d safetySettings; want 0 (server-side defaults)", raw, len(req.SafetySettings))
		}
	}
}

func TestNormalizeGeminiSafetyThreshold(t *testing.T) {
	cases := []struct {
		in       string
		want     string
		wantSend bool
	}{
		{"", "", false},
		{"default", "", false},
		{"UNSPECIFIED", "", false},
		{"block_none", "BLOCK_NONE", true},
		{"BLOCK_NONE", "BLOCK_NONE", true},
		{"none", "BLOCK_NONE", true},
		{"off", "OFF", true},
		{"block_only_high", "BLOCK_ONLY_HIGH", true},
		{"block_medium_and_above", "BLOCK_MEDIUM_AND_ABOVE", true},
		{"block_low_and_above", "BLOCK_LOW_AND_ABOVE", true},
		{"  BLOCK_NONE  ", "BLOCK_NONE", true},
		{"totally-bogus", "BLOCK_NONE", true}, // unknown falls back to BLOCK_NONE
	}
	for _, tc := range cases {
		gotThreshold, gotSend := normalizeGeminiSafetyThreshold(tc.in)
		if gotThreshold != tc.want || gotSend != tc.wantSend {
			t.Errorf("normalizeGeminiSafetyThreshold(%q) = (%q, %v); want (%q, %v)", tc.in, gotThreshold, gotSend, tc.want, tc.wantSend)
		}
	}
}

// TestGeminiBlockDetailSurfacesSafety proves that a safety-blocked Gemini
// response (empty candidate, finishReason SAFETY) produces a diagnosable detail
// string with an actionable remediation hint, instead of an opaque "no content"
// error.
func TestGeminiBlockDetailSurfacesSafety(t *testing.T) {
	resp := geminiResponse{
		Candidates:     []geminiCandidate{{FinishReason: "SAFETY"}},
		PromptFeedback: &geminiPromptFeedback{BlockReason: "SAFETY"},
	}
	detail := geminiBlockDetail(resp)
	if !strings.Contains(detail, "SAFETY") {
		t.Errorf("detail %q does not mention the SAFETY finish/block reason", detail)
	}
	if !strings.Contains(detail, "XALGORIX_GEMINI_SAFETY") {
		t.Errorf("detail %q does not surface the remediation env var", detail)
	}

	// A benign empty response (no finish/block reason) must not fabricate a hint.
	if got := geminiBlockDetail(geminiResponse{}); got != "" {
		t.Errorf("geminiBlockDetail(empty) = %q; want empty", got)
	}
}
