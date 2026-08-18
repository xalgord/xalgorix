package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func jsonHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

func TestGzipMiddleware_CompressesJSONWhenAccepted(t *testing.T) {
	body := `{"events":[` + strings.Repeat(`{"k":"vvvvvvvvvv"},`, 200) + `null]}`
	h := gzipMiddleware(jsonHandler(body))

	req := httptest.NewRequest(http.MethodGet, "/api/scans/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if !strings.Contains(rr.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("Vary header missing Accept-Encoding: %q", rr.Header().Get("Vary"))
	}
	if rr.Header().Get("Content-Length") != "" {
		t.Fatalf("Content-Length must be dropped for compressed responses, got %q", rr.Header().Get("Content-Length"))
	}

	zr, err := gzip.NewReader(bytes.NewReader(rr.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzip body: %v", err)
	}
	if string(got) != body {
		t.Fatalf("decompressed body mismatch")
	}
	if rr.Body.Len() >= len(body) {
		t.Fatalf("compressed size %d not smaller than original %d", rr.Body.Len(), len(body))
	}
}

func TestGzipMiddleware_SkipsWhenClientDoesNotAccept(t *testing.T) {
	body := `{"ok":true}`
	h := gzipMiddleware(jsonHandler(body))

	req := httptest.NewRequest(http.MethodGet, "/api/scans/x", nil)
	// no Accept-Encoding header
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Header().Get("Content-Encoding") != "" {
		t.Fatalf("must not set Content-Encoding without client support")
	}
	if rr.Body.String() != body {
		t.Fatalf("body = %q, want %q", rr.Body.String(), body)
	}
}

func TestGzipMiddleware_SkipsWebSocketPath(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// The real /ws handler hijacks the connection; assert we handed it the
		// raw ResponseWriter, not our wrapper (which is not a Hijacker).
		if _, ok := w.(*gzipResponseWriter); ok {
			t.Fatalf("/ws must not be wrapped by gzipResponseWriter")
		}
	})
	h := gzipMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("inner handler was not invoked for /ws")
	}
}

func TestGzipMiddleware_SkipsNonCompressibleContentType(t *testing.T) {
	png := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(bytes.Repeat([]byte{0x89, 0x50, 0x4e, 0x47}, 100))
	})
	h := gzipMiddleware(png)

	req := httptest.NewRequest(http.MethodGet, "/logo.png", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Header().Get("Content-Encoding") == "gzip" {
		t.Fatal("image/png must not be gzip-compressed")
	}
}

func TestIsCompressibleContentType(t *testing.T) {
	cases := map[string]bool{
		"application/json":                true,
		"application/json; charset=utf-8": true,
		"text/html; charset=utf-8":        true,
		"text/plain":                      true,
		"image/svg+xml":                   true,
		"application/javascript":          true,
		"image/png":                       false,
		"application/zip":                 false,
		"font/woff2":                      false,
		"":                                false,
	}
	for ct, want := range cases {
		if got := isCompressibleContentType(ct); got != want {
			t.Errorf("isCompressibleContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}
