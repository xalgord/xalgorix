package web

import (
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"
)

// StartDebugServerFromEnv starts a standalone pprof/debug HTTP server when
// XALGORIX_PPROF_ADDR is set (e.g. "127.0.0.1:6060"). It is DISABLED by
// default — profiling is opt-in.
//
// SECURITY: pprof exposes process internals (heap contents, goroutine stacks,
// command line). It is deliberately served on its OWN listener, separate from
// the authenticated dashboard mux, and should only ever be bound to a trusted
// interface. Prefer loopback (127.0.0.1) and reach it through an SSH tunnel:
//
//	ssh -L 6060:127.0.0.1:6060 user@host
//	go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30
//	go tool pprof http://127.0.0.1:6060/debug/pprof/heap
//
// A non-loopback bind logs a loud warning but is still honored (operators
// behind a firewall may want it); it never binds automatically.
func StartDebugServerFromEnv() {
	addr := strings.TrimSpace(os.Getenv("XALGORIX_PPROF_ADDR"))
	if addr == "" {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	if !isLoopbackAddr(addr) {
		log.Printf("[pprof] WARNING: XALGORIX_PPROF_ADDR=%q is not loopback — pprof exposes process "+
			"internals (heap/goroutines). Bind 127.0.0.1 and use an SSH tunnel instead.", addr)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("[pprof] debug server listening on %s (/debug/pprof/)", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[pprof] debug server stopped: %v", err)
		}
	}()
}

// isLoopbackAddr reports whether a "host:port" listen address targets the
// loopback interface (or an unspecified host, which is treated as local).
func isLoopbackAddr(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "", "127.0.0.1", "localhost", "::1":
		return true
	default:
		return strings.HasPrefix(host, "127.")
	}
}
