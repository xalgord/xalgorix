package websearch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestClampMaxResultsAndCVEIDNormalization(t *testing.T) {
	maxCases := map[string]int{
		"":    10,
		"abc": 10,
		"0":   1,
		"-9":  1,
		"1":   1,
		"25":  25,
		"200": 25,
		"12":  12,
	}
	for raw, want := range maxCases {
		if got := clampMaxResults(raw); got != want {
			t.Fatalf("clampMaxResults(%q) = %d, want %d", raw, got, want)
		}
	}

	cveCases := map[string]string{
		"2024-1234":    "CVE-2024-1234",
		" cve-2025-1 ": "CVE-2025-1",
		"":             "",
	}
	for raw, want := range cveCases {
		if got := normalizeCVEID(raw); got != want {
			t.Fatalf("normalizeCVEID(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestFormatResultsAndTruncateBody(t *testing.T) {
	formatted := formatResults("xalgorix", []searchResult{
		{Title: "One", URL: "https://one.test", Snippet: "first"},
		{Title: "Two", URL: "https://two.test"},
	})
	for _, want := range []string{"Search results for: xalgorix", "1. One", "URL: https://one.test", "first", "2. Two"} {
		if !strings.Contains(formatted.Output, want) {
			t.Fatalf("formatted output missing %q:\n%s", want, formatted.Output)
		}
	}

	empty := formatResults("nothing", nil)
	if !strings.Contains(empty.Output, "No results found for: nothing") {
		t.Fatalf("empty output = %q", empty.Output)
	}

	longBody := strings.Repeat("a", 600)
	truncated := truncateSearchBody(longBody)
	if len(truncated) >= len(longBody) || !strings.Contains(truncated, "[truncated]") {
		t.Fatalf("body was not truncated: len=%d", len(truncated))
	}
}

func TestSearchGeminiReturnsNon200AsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("Gemini request method = %s, want POST", r.Method)
		}
		http.Error(w, "bad key", http.StatusUnauthorized)
	}))
	defer server.Close()

	oldURL := geminiSearchURL
	geminiSearchURL = func(apiKey string) string {
		if apiKey != "test-key" {
			t.Fatalf("api key = %q, want test-key", apiKey)
		}
		return server.URL
	}
	defer func() { geminiSearchURL = oldURL }()

	cfg := config.Get()
	oldKey := cfg.GeminiAPIKey
	cfg.GeminiAPIKey = "test-key"
	defer func() { cfg.GeminiAPIKey = oldKey }()

	_, err := searchGemini("query", 3)
	if err == nil || !strings.Contains(err.Error(), "gemini search returned 401") {
		t.Fatalf("searchGemini non-200 error = %v", err)
	}
}

func TestSearchMiniMaxParsesResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("MiniMax request method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/messages" {
			t.Fatalf("MiniMax request path = %s, want /v1/messages", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "mm-key" {
			t.Fatalf("x-api-key = %q, want mm-key", r.Header.Get("x-api-key"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[
			{"type":"text","text":"Here is what I found"},
			{"type":"server_tool_use","input":{"query":"xalgorix"}},
			{"type":"web_search_tool_result","content":[
				{"type":"web_search_result","title":"One","url":"https://one.test","page_age":"1d","content":"first"},
				{"type":"web_search_result","title":"Two","url":"https://two.test","content":"second"},
				{"type":"web_search_result","title":"NoURL","url":"","content":"skipme"}
			]}
		]}`))
	}))
	defer server.Close()

	results, err := searchMiniMax("mm-key", server.URL, "MiniMax-M3", "xalgorix", 10)
	if err != nil {
		t.Fatalf("searchMiniMax error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results len = %d, want 2 (empty-URL result dropped): %+v", len(results), results)
	}
	if results[0].Title != "One" || results[0].URL != "https://one.test" || results[0].Snippet != "first" {
		t.Fatalf("unexpected first result: %+v", results[0])
	}
	if results[1].URL != "https://two.test" {
		t.Fatalf("unexpected second result: %+v", results[1])
	}

	// max clamps the number of returned results.
	capped, err := searchMiniMax("mm-key", server.URL, "MiniMax-M3", "xalgorix", 1)
	if err != nil {
		t.Fatalf("searchMiniMax (max=1) error = %v", err)
	}
	if len(capped) != 1 {
		t.Fatalf("capped len = %d, want 1", len(capped))
	}
}

func TestSearchMiniMaxNon200IsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad key", http.StatusUnauthorized)
	}))
	defer server.Close()

	if _, err := searchMiniMax("mm-key", server.URL, "MiniMax-M3", "q", 5); err == nil ||
		!strings.Contains(err.Error(), "minimax web_search returned 401") {
		t.Fatalf("searchMiniMax non-200 error = %v", err)
	}

	if _, err := searchMiniMax("", server.URL, "MiniMax-M3", "q", 5); err == nil {
		t.Fatalf("searchMiniMax with empty key should error")
	}
}

func TestSearchMiniMaxNoResultsIsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Model answered without searching — no web_search_tool_result block.
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"no search performed"}]}`))
	}))
	defer server.Close()

	if _, err := searchMiniMax("mm-key", server.URL, "MiniMax-M3", "q", 5); err == nil ||
		!strings.Contains(err.Error(), "no results") {
		t.Fatalf("searchMiniMax no-results error = %v", err)
	}
}

func TestIsMiniMaxProviderAndHelpers(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{"explicit provider", &config.Config{LLMProvider: "minimax"}, true},
		{"profile pointer", &config.Config{LLMProfile: "minimax:default"}, true},
		{"model string", &config.Config{LLM: "minimax/MiniMax-M3"}, true},
		{"api base", &config.Config{APIBase: "https://api.minimax.io/v1"}, true},
		{"other provider", &config.Config{LLMProvider: "openai", LLM: "openai/gpt-5.4"}, false},
	}
	for _, tc := range cases {
		if got := isMiniMaxProvider(tc.cfg); got != tc.want {
			t.Fatalf("%s: isMiniMaxProvider = %v, want %v", tc.name, got, tc.want)
		}
	}

	if base := minimaxAnthropicBase("https://api.minimaxi.com/v1"); base != "https://api.minimaxi.com/anthropic" {
		t.Fatalf("minimaxAnthropicBase(minimaxi.com) = %q", base)
	}
	if base := minimaxAnthropicBase(""); base != "https://api.minimax.io/anthropic" {
		t.Fatalf("minimaxAnthropicBase(default) = %q", base)
	}

	if m := minimaxModelName(&config.Config{LLM: "minimax/MiniMax-M3"}); m != "MiniMax-M3" {
		t.Fatalf("minimaxModelName(prefixed) = %q, want MiniMax-M3", m)
	}
	if m := minimaxModelName(&config.Config{LLM: ""}); m != "MiniMax-M3" {
		t.Fatalf("minimaxModelName(empty) = %q, want MiniMax-M3 default", m)
	}
}
