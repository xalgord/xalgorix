package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

// gzipWriterPool recycles gzip.Writer instances so the compression middleware
// does not allocate a fresh writer (and its ~64KB window) on every request.
var gzipWriterPool = sync.Pool{
	New: func() any { return gzip.NewWriter(io.Discard) },
}

// gzipMiddleware transparently compresses responses with gzip when the client
// advertises support via Accept-Encoding. The dashboard's JSON payloads —
// especially GET /api/scans/{id}, whose body embeds the full event log — are
// highly compressible (typically ~8-10x), so this cuts transfer time for large
// scans without any handler changes.
//
// The WebSocket endpoint (/ws) is never wrapped: it hijacks the raw connection
// and must not have its ResponseWriter replaced. Responses are only compressed
// when the Content-Type is text-like and the handler did not already set a
// Content-Encoding.
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" || !clientAcceptsGzip(r) {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipResponseWriter{ResponseWriter: w}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}

func clientAcceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]), "gzip") {
			return true
		}
	}
	return false
}

// gzipResponseWriter defers the compress/passthrough decision until the
// response headers are known, so it can honor the handler's Content-Type and
// avoid double-compressing already-encoded or binary payloads.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
	compress    bool
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	h := w.ResponseWriter.Header()
	// Only compress a normal body: skip informational/no-content/not-modified
	// responses, anything already encoded, and non-text content types.
	if status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified &&
		h.Get("Content-Encoding") == "" && isCompressibleContentType(h.Get("Content-Type")) {
		w.compress = true
		// Length changes after compression; let net/http stream it chunked.
		h.Del("Content-Length")
		h.Set("Content-Encoding", "gzip")
		addVaryAcceptEncoding(h)
		gz := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(w.ResponseWriter)
		w.gz = gz
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		// Handlers that Write without an explicit WriteHeader: pin the
		// Content-Type from the first chunk (mirroring net/http's own
		// sniffing) so the compress decision is stable, then default to 200.
		if w.ResponseWriter.Header().Get("Content-Type") == "" {
			w.ResponseWriter.Header().Set("Content-Type", http.DetectContentType(b))
		}
		w.WriteHeader(http.StatusOK)
	}
	if w.compress {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Flush supports streaming handlers (Server-Sent-Events style progress). It
// flushes the gzip buffer first so bytes actually reach the client.
func (w *gzipResponseWriter) Flush() {
	if w.compress && w.gz != nil {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *gzipResponseWriter) close() {
	if w.gz != nil {
		_ = w.gz.Close()
		gzipWriterPool.Put(w.gz)
		w.gz = nil
	}
}

func addVaryAcceptEncoding(h http.Header) {
	for _, v := range h.Values("Vary") {
		if strings.EqualFold(strings.TrimSpace(v), "Accept-Encoding") {
			return
		}
	}
	h.Add("Vary", "Accept-Encoding")
}

// isCompressibleContentType reports whether a Content-Type is worth gzipping.
// Text formats compress well; images/video/archives/fonts are already
// compressed and would only waste CPU (and can grow slightly).
func isCompressibleContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json",
		"application/javascript",
		"application/xml",
		"application/rss+xml",
		"application/atom+xml",
		"application/manifest+json",
		"application/wasm",
		"image/svg+xml":
		return true
	default:
		return false
	}
}
