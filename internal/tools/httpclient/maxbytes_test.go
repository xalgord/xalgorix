package httpclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Serves a text body of the requested size.
func sizedServer(t *testing.T, n int) *httptest.Server {
	t.Helper()
	body := strings.Repeat("A", n)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
}

// countBodyAs counts the 'A' payload bytes returned in the tool output.
//
// It counts ONLY within the response-body section, not the whole output. The
// output also prints response headers, and the `Date` header's month
// abbreviation contains a capital 'A' in April ("Apr") and August ("Aug") — so
// counting 'A' across the entire output inflated the payload count by one for
// two months of the year, failing these tests every April and August.
func countBodyAs(out string) int {
	const marker = "--- Response Body (text) ---\n"
	if i := strings.Index(out, marker); i >= 0 {
		return strings.Count(out[i+len(marker):], "A")
	}
	return strings.Count(out, "A")
}

func TestMaxBytes_RaisesCapAboveDefault(t *testing.T) {
	const size = 200 * 1024 // 200KB, above the 50KB default
	srv := sizedServer(t, size)
	defer srv.Close()

	// Default cap → truncated at 50KB.
	res, err := execute(map[string]string{"url": srv.URL})
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	if !strings.Contains(res.Output, "[Body truncated at 50 KB") {
		t.Fatalf("default cap should truncate at 50KB: %s", tail(res.Output))
	}

	// Raised cap covering the whole body → NOT truncated, full body returned.
	res, err = execute(map[string]string{"url": srv.URL, "max_bytes": fmt.Sprintf("%d", size)})
	if err != nil {
		t.Fatalf("raised: %v", err)
	}
	if strings.Contains(res.Output, "Body truncated") {
		t.Fatalf("raised cap covering body must not truncate: %s", tail(res.Output))
	}
	if got := countBodyAs(res.Output); got != size {
		t.Fatalf("expected full %d body bytes, got %d", size, got)
	}
}

func TestMaxBytes_HardCeilingEnforced(t *testing.T) {
	// Body larger than the hard ceiling; request an absurd max_bytes far above
	// the 512KB hard cap. Output must be clamped to the hard ceiling.
	const size = 600 * 1024
	srv := sizedServer(t, size)
	defer srv.Close()

	res, err := execute(map[string]string{"url": srv.URL, "max_bytes": "100000000"})
	if err != nil {
		t.Fatalf("hard ceiling: %v", err)
	}
	if !strings.Contains(res.Output, "[Body truncated at 512 KB") {
		t.Fatalf("expected truncation at 512KB hard cap: %s", tail(res.Output))
	}
	if got := countBodyAs(res.Output); got != maxBodyBytesHard {
		t.Fatalf("body bytes = %d, want hard cap %d", got, maxBodyBytesHard)
	}
}

func TestMaxBytes_InvalidValueFallsBackToDefault(t *testing.T) {
	const size = 200 * 1024
	srv := sizedServer(t, size)
	defer srv.Close()

	res, err := execute(map[string]string{"url": srv.URL, "max_bytes": "not-a-number"})
	if err != nil {
		t.Fatalf("invalid max_bytes: %v", err)
	}
	if !strings.Contains(res.Output, "[Body truncated at 50 KB") {
		t.Fatalf("invalid max_bytes should fall back to 50KB default: %s", tail(res.Output))
	}
}

func tail(s string) string {
	if len(s) > 400 {
		return "..." + s[len(s)-400:]
	}
	return s
}
