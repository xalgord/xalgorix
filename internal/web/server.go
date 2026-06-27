// Package web provides the Xalgorix web UI server.
package web

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	mathrand "math/rand/v2"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/providers"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/safe"
	"github.com/xalgord/xalgorix/v4/internal/sandbox"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
	"github.com/xalgord/xalgorix/v4/internal/tools/browser"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
	"golang.org/x/crypto/bcrypt"
)

// Version is set by main.go at startup — single source of truth.
var Version = "dev"

//go:embed static/*
var staticFiles embed.FS

// RateLimiter implements a simple in-memory rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		stopCh:   make(chan struct{}),
	}
	// Cleanup old entries every minute
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-rl.stopCh:
				return
			case <-ticker.C:
				rl.cleanup()
			}
		}
	}()
	return rl
}

// Stop signals the cleanup goroutine to exit. Safe to call multiple times.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.stopCh) })
}

// cleanup walks the request map and discards entries whose timestamps have
// all aged out of the active window. Done in two passes (collect → delete)
// to minimize lock contention with Allow() under high churn.
func (rl *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-rl.window)

	// Pass 1: collect IPs whose buckets are fully expired. RLock would be
	// ideal, but the underlying mutex is sync.Mutex; the read cost is small.
	rl.mu.Lock()
	var toDelete []string
	for ip, times := range rl.requests {
		stillValid := false
		for _, t := range times {
			if t.After(cutoff) {
				stillValid = true
				break
			}
		}
		if !stillValid {
			toDelete = append(toDelete, ip)
		}
	}
	rl.mu.Unlock()

	if len(toDelete) == 0 {
		return
	}

	// Pass 2: re-check each IP under lock — a request could have arrived
	// between passes and re-validated the bucket.
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for _, ip := range toDelete {
		times, ok := rl.requests[ip]
		if !ok {
			continue
		}
		stillValid := false
		for _, t := range times {
			if t.After(cutoff) {
				stillValid = true
				break
			}
		}
		if !stillValid {
			delete(rl.requests, ip)
		}
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Get or create the slice
	times := rl.requests[ip]
	var valid []time.Time
	for _, t := range times {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	rl.requests[ip] = append(valid, now)
	return true
}

func rateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for WebSocket, static files, and dashboard
			// polling reads. Auth still wraps this middleware, so protected
			// reads require a valid session before they reach this point.
			if r.URL.Path == "/ws" || isStaticWebAssetPath(r.URL.Path) ||
				isDashboardReadPath(r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Use RemoteAddr only — do not trust X-Forwarded-For as it can be
			// spoofed when running without a trusted reverse proxy. Strip the
			// port so each TCP connection from the same client shares a bucket.
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}

			if !rl.Allow(ip) {
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isStaticWebAssetPath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/api/") || path == "/ws" {
		return false
	}
	if strings.HasPrefix(path, "/static/") ||
		strings.HasPrefix(path, "/assets/") ||
		strings.HasPrefix(path, "/chunks/") {
		return true
	}
	switch filepath.Ext(path) {
	case ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2":
		return true
	default:
		return false
	}
}

func isDashboardReadPath(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	switch path {
	case "/api/auth/status",
		"/api/status",
		"/api/version",
		"/api/scans",
		"/api/instances",
		"/api/queue/status",
		"/api/findings/summary",
		"/api/legacy-import/status":
		return true
	default:
		return strings.HasPrefix(path, "/api/scans/") ||
			strings.HasPrefix(path, "/api/instances/")
	}
}

func setWebUICacheHeaders(w http.ResponseWriter) {
	// The embedded SPA uses stable asset names (/app.js, /style.css). Disable
	// browser caching so replacing the local binary takes effect on refresh.
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func canStartInstanceStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "saved", "stopped", "failed", "finished":
		return true
	default:
		return false
	}
}

// ─── Authentication ─────────────────────────────────────────────────────────

// logRecover is a deferred recovery helper used by best-effort cleanup
// blocks. The previous pattern was `defer func() { recover() }()` which
// silently swallowed panics — making cleanup bugs invisible in
// production. logRecover preserves the original behavior (don't crash
// the server during shutdown) while emitting a stack trace so the bug
// can be diagnosed.
//
// Usage: defer logRecover("scanSession.cleanup.scanctx")
func logRecover(label string) {
	if r := recover(); r != nil {
		log.Printf("[recover] %s: %v\n%s", label, r, debug.Stack())
	}
}

// authSessions stores valid session tokens (token → expiry)
var (
	authSessions      = make(map[string]time.Time)
	authSessionsMu    sync.RWMutex
	sessionReaperOnce sync.Once
)

const sessionCookieName = "xalgorix_session"
const sessionDuration = 24 * time.Hour
const sessionReaperInterval = 15 * time.Minute

// generateSessionToken creates a cryptographically random session token.
// 32 bytes of crypto/rand is already overwhelmingly sufficient entropy —
// hashing it wouldn't add security and only obscured the source.
// Returns an error if the system entropy source is unavailable instead of
// terminating the whole process — callers should surface a 500 to the user.
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand unavailable: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// loginAttempts tracks failed-login backoff per source IP. We replaced the
// unconditional time.Sleep(1s) on every failure because it held an HTTP
// connection open and let an attacker tie up worker goroutines with one IP.
// Instead, we reject further attempts from an IP that has racked up too many
// failures within a short window; legitimate users on a clean IP see no
// latency hit.
var (
	loginAttempts   = make(map[string]*loginAttempt)
	loginAttemptsMu sync.Mutex
)

type loginAttempt struct {
	failures  int
	firstFail time.Time
	lockUntil time.Time
}

const (
	loginAttemptWindow = 15 * time.Minute
	loginMaxFailures   = 10
	loginLockDuration  = 5 * time.Minute
)

// loginIsLocked returns (locked, retryAfterSeconds). It also garbage-collects
// stale entries opportunistically so the map cannot grow unbounded.
func loginIsLocked(ip string) (bool, int) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	now := time.Now()
	// Opportunistic GC — bounded work, runs only when this IP is queried.
	for k, v := range loginAttempts {
		if now.Sub(v.firstFail) > loginAttemptWindow && now.After(v.lockUntil) {
			delete(loginAttempts, k)
		}
	}
	a := loginAttempts[ip]
	if a == nil {
		return false, 0
	}
	if now.Before(a.lockUntil) {
		return true, int(a.lockUntil.Sub(now).Seconds()) + 1
	}
	return false, 0
}

// loginRecordFailure increments the failure counter for an IP. After
// loginMaxFailures within loginAttemptWindow, subsequent attempts are locked
// out for loginLockDuration.
func loginRecordFailure(ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	now := time.Now()
	a := loginAttempts[ip]
	if a == nil || now.Sub(a.firstFail) > loginAttemptWindow {
		loginAttempts[ip] = &loginAttempt{failures: 1, firstFail: now}
		return
	}
	a.failures++
	if a.failures >= loginMaxFailures {
		a.lockUntil = now.Add(loginLockDuration)
	}
}

// loginRecordSuccess clears any failure history on a successful login.
func loginRecordSuccess(ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	delete(loginAttempts, ip)
}

// clientIP extracts a comparable client identifier from the request. We
// intentionally do not trust X-Forwarded-For; if you put xalgorix behind a
// reverse proxy you should bind it to loopback and let the proxy enforce
// auth, or extend this helper to honor a configured trusted-proxy list.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isValidSession checks if a session token is valid and not expired
func isValidSession(token string) bool {
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	expiry, ok := authSessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(authSessions, token)
		return false
	}
	return true
}

// startSessionReaper sweeps expired session tokens on a fixed interval so the
// authSessions map cannot grow unbounded from abandoned cookies. Runs once
// per process.
func startSessionReaper() {
	sessionReaperOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(sessionReaperInterval)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				authSessionsMu.Lock()
				for tok, expiry := range authSessions {
					if now.After(expiry) {
						delete(authSessions, tok)
					}
				}
				authSessionsMu.Unlock()
			}
		}()
	})
}

// isCSRFSafe returns true when a state-changing request is verifiably
// originated from this site. We use Origin (and Referer as a fallback)
// because every modern browser sends one of them on POST/PUT/PATCH/DELETE.
// SameSite=Strict on the session cookie already blocks the most common CSRF
// vectors; this is defense in depth for the Sec-Fetch-Site and
// document-form-submit edge cases.
//
// Policy:
//   - Safe methods (GET/HEAD/OPTIONS) are always allowed.
//   - Sec-Fetch-Site: same-origin/none → allow; same-site/cross-site → deny.
//   - Else fall back to Origin/Referer host == r.Host.
//   - If none of the above are present AND the request carries our session
//     cookie, the request looks like a browser navigation without the
//     metadata we expected — refuse. Cookie-less non-browser clients
//     (curl, scripts) are still allowed; an attacker has no way to forge
//     a cookie on the victim, so allowing cookie-less requests is safe.
func isCSRFSafe(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}

	// Browser hint: only "same-origin"/"none" are safe.
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "":
		// fall through to Origin/Referer checks
	case "same-origin", "none":
		return true
	default:
		// "same-site" or "cross-site" — refuse.
		return false
	}

	// Compare Origin/Referer host with request Host.
	check := func(raw string) (bool, bool) {
		if raw == "" {
			return false, false
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return false, true
		}
		return u.Host == r.Host, true
	}

	if ok, present := check(r.Header.Get("Origin")); present {
		return ok
	}
	if ok, present := check(r.Header.Get("Referer")); present {
		return ok
	}

	// Neither Origin nor Referer nor Sec-Fetch-Site present.
	// If the client carries our session cookie this is suspicious (a real
	// browser strips none of these on cookie-bearing POSTs in 2026) —
	// refuse. Cookie-less requests are non-browser tooling, allow.
	if _, err := r.Cookie(sessionCookieName); err == nil {
		return false
	}
	return true
}

// authConfigured returns true when the server has dashboard credentials set
// (either plaintext password or bcrypt hash). When false, the authMiddleware
// short-circuits and serves all routes — used by the bind-time safety check
// to refuse external interfaces without auth.
func authConfigured(cfg *config.Config) bool {
	return cfg.Username != "" && (cfg.Password != "" || cfg.PasswordHash != "")
}

// authMiddleware protects routes when auth is configured
func authMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// CSRF: validate state-changing requests on /api/* regardless of
			// whether auth is configured. This blocks an attacker page from
			// triggering a scan via the cookie even when no password is set
			// for local-loopback deployments.
			if strings.HasPrefix(path, "/api/") && path != "/api/auth/login" {
				if !isCSRFSafe(r) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "CSRF check failed: request origin does not match server host",
					})
					return
				}
			}

			// Skip auth if no credentials configured
			if !authConfigured(cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Public routes that don't need auth. The React SPA owns the
			// operator login screen, so its static assets must be reachable
			// before a session exists.
			if path == "/api/auth/login" || path == "/api/auth/status" ||
				isStaticWebAssetPath(path) || strings.HasPrefix(path, "/uploads/") {
				next.ServeHTTP(w, r)
				return
			}

			// Check for session cookie
			cookie, err := r.Cookie(sessionCookieName)
			if err == nil && isValidSession(cookie.Value) {
				next.ServeHTTP(w, r)
				return
			}

			// For API requests, return 401 JSON
			if strings.HasPrefix(path, "/api/") || path == "/ws" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "Authentication required",
				})
				return
			}

			// For page requests, serve the SPA shell. The client-side router
			// will show the React login page after /api/auth/status reports
			// that there is no active session.
			next.ServeHTTP(w, r)
		})
	}
}

// verifyPassword checks a presented password against the configured credential.
// Prefers a bcrypt hash (PasswordHash) when set; falls back to a constant-time
// plaintext comparison for backwards compatibility. The plaintext path logs a
// one-time deprecation warning so operators know to migrate.
var plaintextPasswordWarnOnce sync.Once

func (s *Server) verifyPassword(presented string) bool {
	if s.cfg.PasswordHash != "" {
		// bcrypt.CompareHashAndPassword is constant-time wrt password length
		// for matching hashes and is the recommended verification path.
		err := bcrypt.CompareHashAndPassword([]byte(s.cfg.PasswordHash), []byte(presented))
		return err == nil
	}
	if s.cfg.Password == "" {
		return false
	}
	plaintextPasswordWarnOnce.Do(func() {
		log.Printf("[auth] WARNING: XALGORIX_PASSWORD is set in plaintext. Migrate to XALGORIX_PASSWORD_HASH (bcrypt) — see README.")
	})
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.Password)) == 1
}

// handleLogin handles POST /api/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	ip := clientIP(r)

	// Per-IP lockout — replaces the old unconditional 1s sleep so we don't
	// occupy goroutines on attacker traffic.
	if locked, retryAfter := loginIsLocked(ip); locked {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Too many failed attempts. Try again in %ds.", retryAfter),
		})
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// Constant-time username comparison; bcrypt for password. We always
	// run the password compare even on a username miss so the work
	// performed is independent of which side is wrong (timing-equalized).
	userMatch := subtle.ConstantTimeCompare([]byte(creds.Username), []byte(s.cfg.Username)) == 1
	passMatch := s.verifyPassword(creds.Password)
	if !userMatch || !passMatch {
		loginRecordFailure(ip)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	loginRecordSuccess(ip)

	// Create session
	token, err := generateSessionToken()
	if err != nil {
		log.Printf("[auth] session token generation failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal error generating session"})
		return
	}
	authSessionsMu.Lock()
	authSessions[token] = time.Now().Add(sessionDuration)
	authSessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecureRequest(r),
	})

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// isSecureRequest returns true if the request is over TLS. Used to decide
// whether to set the Secure flag on cookies — required for HTTPS deploys,
// must be off for localhost HTTP development.
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Honor an X-Forwarded-Proto header only when running behind a trusted
	// proxy; we keep it simple here and trust nothing by default. Operators
	// behind a TLS-terminating proxy should set the cookie's Secure flag
	// elsewhere if they need it.
	return false
}

// handleLogout handles POST /api/auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		authSessionsMu.Lock()
		delete(authSessions, cookie.Value)
		authSessionsMu.Unlock()
	}

	// Match the attributes of the cookie we set on login so browsers
	// consistently replace/clear it. Without SameSite and Secure here,
	// some browsers treat the deletion cookie as a different cookie and
	// the original stays in the jar.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecureRequest(r),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}

// handleAuthStatus handles GET /api/auth/status
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	authEnabled := authConfigured(s.cfg)

	authenticated := false
	if authEnabled {
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil && isValidSession(cookie.Value) {
			authenticated = true
		}
	} else {
		authenticated = true // No auth configured = always authenticated
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"auth_enabled":  authEnabled,
		"authenticated": authenticated,
	})
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Reject cross-site WebSocket connections to prevent CSWSH attacks.
		// Allow if no Origin header (direct connection) or Origin matches Host.
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		// Parse origin and compare scheme+host with request Host
		if u, err := url.Parse(origin); err == nil {
			return u.Host == r.Host
		}
		return false
	},
	ReadBufferSize:  8192,
	WriteBufferSize: 32768,
}

const (
	// WebSocket keepalive settings
	wsPingInterval   = 30 * time.Second
	wsPongWait       = 60 * time.Second
	wsWriteWait      = 10 * time.Second
	wsMaxMessageSize = 8192 // max incoming message from client
	wsMaxClients     = 50
	wsSendBufSize    = 512 // buffered channel size per client
)

// wsClient wraps a WebSocket connection with a buffered send channel.
//
// Concurrency: instanceID is mutated by readPump (subscribe/unsubscribe)
// and read by broadcastToInstance / broadcastDashboard from other
// goroutines. ALL reads and writes MUST hold server.mu (RLock for reads,
// Lock for writes). The lock also guards iteration over server.clients,
// so an atomic.Pointer would be redundant and would split the invariant
// into two synchronization mechanisms.
type wsClient struct {
	conn       *websocket.Conn
	send       chan []byte
	server     *Server
	instanceID string // GUARDED BY server.mu — see struct doc.

	// authenticated is true when the WebSocket upgrade carried a valid
	// session cookie (or auth is disabled and the connection is from
	// loopback). Privileged scan-request fields like Model/APIKey/APIBase
	// are only honored for authenticated connections — otherwise a
	// client could pivot the LLM to an attacker-controlled endpoint.
	authenticated bool
	fromLoopback  bool
}

// writePump drains the send channel and writes to the WebSocket.
// Also handles periodic ping messages for keepalive.
func (c *wsClient) writePump() {
	ticker := time.NewTicker(wsPingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
		c.server.removeClient(c)
	}()

	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if !ok {
				// Server closed the channel — send close frame
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads messages from the WebSocket (scan requests).
// Also sets up pong handler for keepalive.
func (c *wsClient) readPump() {
	defer func() {
		c.server.removeClient(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(wsMaxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
		return nil
	})

	// Single decode path. The previous "fast path" tried to detect
	// subscribe/unsubscribe via byte prefix, but it was order-dependent on
	// JSON field layout and would fall through unexpectedly. The combined
	// struct below handles all three message shapes in one Unmarshal.
	type wsInbound struct {
		Subscribe   string `json:"subscribe,omitempty"`
		Unsubscribe bool   `json:"unsubscribe,omitempty"`
		ScanRequest
	}

	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		var in wsInbound
		if err := json.Unmarshal(msg, &in); err != nil {
			continue
		}

		// Subscribe / unsubscribe to per-instance broadcasts.
		if in.Subscribe != "" {
			c.server.mu.Lock()
			c.instanceID = in.Subscribe
			c.server.mu.Unlock()
			continue
		}
		if in.Unsubscribe {
			c.server.mu.Lock()
			c.instanceID = ""
			c.server.mu.Unlock()
			continue
		}

		// Scan request.
		if len(in.Targets) == 0 {
			continue
		}
		normalizeScanRequestActivity(&in.ScanRequest)

		// Only authenticated (or loopback-when-auth-off) clients may override
		// LLM provider settings — otherwise an attacker could repoint the
		// agent's brain to an endpoint that returns crafted tool calls.
		scanCfg := *c.server.cfg // shallow copy
		if c.authenticated {
			if in.Model != "" {
				scanCfg.LLM = in.Model
			}
			if in.APIKey != "" {
				scanCfg.APIKey = in.APIKey
			}
			if in.APIBase != "" {
				scanCfg.APIBase = in.APIBase
			}
		} else if in.Model != "" || in.APIKey != "" || in.APIBase != "" {
			log.Printf("[ws] dropping LLM-provider overrides from unauthenticated client %s", c.conn.RemoteAddr())
		}

		go c.server.runMultiScan(in.ScanRequest, &scanCfg)
	}
}

// ScanRequest is the JSON body for starting a scan.
type ScanRequest struct {
	Targets        []string `json:"targets"`
	Instruction    string   `json:"instruction"`
	ScanMode       string   `json:"scan_mode"`       // "single" or "wildcard"
	Model          string   `json:"model"`           // e.g. "minimax/MiniMax-M2.5"
	APIKey         string   `json:"api_key"`         // provider API key
	APIBase        string   `json:"api_base"`        // provider API base URL
	DiscordWebhook string   `json:"discord_webhook"` // Discord webhook URL
	SeverityFilter []string `json:"severity_filter"` // e.g. ["critical", "high"]
	Name           string   `json:"name"`            // user-defined scan name
	SaveOnly       bool     `json:"save_only"`       // if true, save scan config without starting
	Phases         []int    `json:"phases"`          // selected methodology phases (empty = all)
	ReconMode      string   `json:"recon_mode"`      // active or passive reconnaissance
	ScanIntensity  string   `json:"scan_intensity"`  // active or passive testing/scanning
	CompanyName    string   `json:"company_name"`    // report branding: company name
	LogoPath       string   `json:"logo_path"`       // report branding: logo file path
	// ProviderProfile is the optional "<provider>:<profileId>" key
	// (e.g. "openai:default") that selects an Auth_Profile from
	// Profile_Store for this scan. When set on a request from an
	// Authenticated_Operator, resolveScanCredentials maps it to a
	// (baseURL, auth_method, credentials) tuple at scan start. When
	// empty, the existing legacy / catalog-default resolver path is
	// used. Ad-hoc Model/APIKey/APIBase fields still take precedence
	// per Requirement 11.4.
	// Validates: Requirements 11.1, 11.2, 11.5.
	ProviderProfile string `json:"provider_profile,omitempty"`
	// Internal fields — `json:"-"` makes them un-settable from the wire.
	// Critical: a client must not be able to set InstanceID to spoof
	// broadcasts to another scan, or set IsResume to bypass the resume
	// codepath's safety checks.
	InstanceID           string   `json:"-"` // parent instance ID, threaded server-side
	IsResume             bool     `json:"-"` // true when auto-resuming after restart
	ResumeQueueStatePath string   `json:"-"`
	ResumeActiveTarget   string   `json:"-"`
	ResumeScanDir        string   `json:"-"`
	ResumeScanID         string   `json:"-"`
	ResumeSubScanTarget  string   `json:"-"`
	ResumeSubScanDir     string   `json:"-"`
	ResumeSubScanID      string   `json:"-"`
	ResumeSubdomains     []string `json:"-"`
	ResumeSubIndex       int      `json:"-"`
	ResumeDiscoveryDone  bool     `json:"-"`
	ResumeOriginalTarget int      `json:"-"`
}

// WSEvent is a WebSocket message sent to clients.
type WSEvent struct {
	Type           string            `json:"type"`
	Content        string            `json:"content,omitempty"`
	ToolName       string            `json:"tool_name,omitempty"`
	ToolArgs       map[string]string `json:"tool_args,omitempty"`
	Output         string            `json:"output,omitempty"`
	Error          string            `json:"error,omitempty"`
	AgentID        string            `json:"agent_id,omitempty"`
	InstanceID     string            `json:"instance_id,omitempty"`
	Timestamp      string            `json:"timestamp,omitempty"`
	Vulns          []VulnSummary     `json:"vulns,omitempty"`
	TargetIndex    int               `json:"target_index,omitempty"`
	TotalTargets   int               `json:"total_targets,omitempty"`
	Target         string            `json:"target,omitempty"`
	TotalTokens    int               `json:"total_tokens,omitempty"`
	SubTargetIndex int               `json:"sub_target_index,omitempty"` // subdomain index within a wildcard target
	SubTargetTotal int               `json:"sub_target_total,omitempty"` // total subdomains for current wildcard target
	ParentTarget   string            `json:"parent_target,omitempty"`    // parent domain for subdomain scans
	CurrentPhase   int               `json:"current_phase,omitempty"`    // inferred active methodology phase
}

// VulnSummary is a simplified vulnerability for the UI.
type VulnSummary struct {
	ID                 string  `json:"id"`
	Title              string  `json:"title"`
	Severity           string  `json:"severity"`
	Target             string  `json:"target,omitempty"`
	Endpoint           string  `json:"endpoint"`
	CVSS               float64 `json:"cvss"`
	CVSSVector         string  `json:"cvss_vector,omitempty"`
	Description        string  `json:"description,omitempty"`
	Impact             string  `json:"impact,omitempty"`
	Method             string  `json:"method,omitempty"`
	CVE                string  `json:"cve,omitempty"`
	CWE                string  `json:"cwe_id,omitempty"`
	OWASP              string  `json:"owasp,omitempty"`
	TechnicalAnalysis  string  `json:"technical_analysis,omitempty"`
	PoCDescription     string  `json:"poc_description,omitempty"`
	PoCScript          string  `json:"poc_script,omitempty"`
	Remediation        string  `json:"remediation,omitempty"`
	ExploitationProof  string  `json:"exploitation_proof,omitempty"`
	VerificationMethod string  `json:"verification_method,omitempty"`
	Verified           bool    `json:"verified"`
}

// SubScanSummary is a child target scanned as part of a wildcard parent scan.
type SubScanSummary struct {
	ID          string `json:"id"`
	Target      string `json:"target"`
	StartedAt   string `json:"started_at,omitempty"`
	FinishedAt  string `json:"finished_at,omitempty"`
	Status      string `json:"status"`
	VulnCount   int    `json:"vuln_count"`
	TotalTokens int    `json:"total_tokens"`
}

// ScanRecord is a persisted scan result.
type ScanRecord struct {
	ID                       string           `json:"id"`
	InstanceID               string           `json:"instance_id,omitempty"` // parent queue/instance id returned by /api/scan
	Name                     string           `json:"name,omitempty"`        // user-defined scan name
	Target                   string           `json:"target"`
	ParentTarget             string           `json:"parent_target,omitempty"` // parent domain for subdomain scans (wildcard mode)
	StartedAt                string           `json:"started_at"`
	FinishedAt               string           `json:"finished_at,omitempty"`
	Status                   string           `json:"status"`                               // saved, running, finished, stopped
	StopReason               string           `json:"stop_reason,omitempty"`                // why scan stopped (error, user, watchdog, etc.)
	ScanMode                 string           `json:"scan_mode,omitempty"`                  // single, wildcard, dast
	Instruction              string           `json:"instruction,omitempty"`                // custom scan instructions
	SeverityFilter           []string         `json:"severity_filter,omitempty"`            // severity filter for scan
	DiscordWebhook           string           `json:"discord_webhook,omitempty"`            // discord notification webhook
	DiscordWebhookConfigured bool             `json:"discord_webhook_configured,omitempty"` // true when a per-scan or global webhook is configured
	TelegramConfigured       bool             `json:"telegram_configured,omitempty"`        // true when global Telegram notifications are configured (token never exposed)
	ReconMode                string           `json:"recon_mode,omitempty"`                 // active or passive reconnaissance
	ScanIntensity            string           `json:"scan_intensity,omitempty"`             // active or passive testing/scanning
	Events                   []WSEvent        `json:"events"`
	Vulns                    []VulnSummary    `json:"vulns"`
	TotalTokens              int              `json:"total_tokens"`
	Iterations               int              `json:"iterations"`
	ToolCalls                int              `json:"tool_calls"`
	CompanyName              string           `json:"company_name,omitempty"` // report branding: company name
	LogoPath                 string           `json:"logo_path,omitempty"`    // report branding: logo path
	Phases                   []int            `json:"phases,omitempty"`       // selected methodology phases
	CurrentPhase             int              `json:"current_phase,omitempty"`
	SubScans                 []SubScanSummary `json:"sub_scans,omitempty"`
	SubScanTotal             int              `json:"sub_scan_total,omitempty"`
	SubScanCompleted         int              `json:"sub_scan_completed,omitempty"`
	SubScanRunning           int              `json:"sub_scan_running,omitempty"`
	SubScanRemaining         int              `json:"sub_scan_remaining,omitempty"`
}

// QueueState persists scan queue state for recovery after restart
type QueueState struct {
	InstanceID            string   `json:"instance_id,omitempty"`
	Targets               []string `json:"targets"`
	CurrentIdx            int      `json:"current_idx"`
	Instruction           string   `json:"instruction"`
	ScanMode              string   `json:"scan_mode"`
	StartedAt             string   `json:"started_at"`
	Active                bool     `json:"active"`
	Name                  string   `json:"name,omitempty"`
	SeverityFilter        []string `json:"severity_filter,omitempty"`
	Phases                []int    `json:"phases,omitempty"`
	ReconMode             string   `json:"recon_mode,omitempty"`
	ScanIntensity         string   `json:"scan_intensity,omitempty"`
	CompanyName           string   `json:"company_name,omitempty"`
	LogoPath              string   `json:"logo_path,omitempty"`
	DiscordWebhook        string   `json:"discord_webhook,omitempty"`
	Paused                bool     `json:"paused,omitempty"`
	ActiveTarget          string   `json:"active_target,omitempty"`
	ActiveScanDir         string   `json:"active_scan_dir,omitempty"`
	ActiveScanID          string   `json:"active_scan_id,omitempty"`
	WildcardActiveTarget  string   `json:"wildcard_active_target,omitempty"`
	WildcardActiveScanDir string   `json:"wildcard_active_scan_dir,omitempty"`
	WildcardActiveScanID  string   `json:"wildcard_active_scan_id,omitempty"`
	WildcardDiscoveryDone bool     `json:"wildcard_discovery_done,omitempty"`
	WildcardSubdomains    []string `json:"wildcard_subdomains,omitempty"`
	WildcardSubIndex      int      `json:"wildcard_sub_index,omitempty"`
}

// ScanInstance represents a running or completed scan instance.
type ScanInstance struct {
	ID                string        `json:"id"`
	Name              string        `json:"name,omitempty"` // user-defined scan name
	Targets           string        `json:"targets"`
	ParentTarget      string        `json:"parent_target,omitempty"` // parent domain for subdomain scans
	Status            string        `json:"status"`                  // saved, running, paused, finished, stopped
	StartedAt         string        `json:"started_at"`
	FinishedAt        string        `json:"finished_at,omitempty"`
	StopReason        string        `json:"stop_reason,omitempty"` // why stopped (user, error, watchdog)
	Iterations        int           `json:"iterations"`
	ToolCalls         int           `json:"tool_calls"`
	VulnCount         int           `json:"vuln_count"`
	TotalTokens       int           `json:"total_tokens"`
	ScanMode          string        `json:"scan_mode"`
	Instruction       string        `json:"instruction,omitempty"`     // custom scan instructions for restart
	SeverityFilter    []string      `json:"severity_filter,omitempty"` // severity filter for restart
	Phases            []int         `json:"phases,omitempty"`          // selected methodology phases (empty = all)
	ReconMode         string        `json:"recon_mode,omitempty"`      // active or passive reconnaissance
	ScanIntensity     string        `json:"scan_intensity,omitempty"`  // active or passive testing/scanning
	CompanyName       string        `json:"company_name,omitempty"`    // report branding: company name
	LogoPath          string        `json:"logo_path,omitempty"`       // report branding: logo path
	DiscordWebhook    string        `json:"-"`                         // discord webhook (not exposed to API)
	Vulns             []VulnSummary `json:"vulns,omitempty"`
	CurrentPhase      int           `json:"current_phase,omitempty"`
	agent             *agent.Agent
	cancel            context.CancelFunc
	scanDir           string
	sctx              *scanctx.ScanContext // per-instance session state (vulns, notes, terminal, browser)
	events            []WSEvent            // buffered events for replay
	chatCfg           *config.Config       // provider settings for post-scan chat (not exposed)
	chatMessages      []llm.Message        // lightweight post-scan chat history (not exposed)
	mu                sync.RWMutex
	lastSessionTokens int // tracks token count from current session for delta calculation
}

// maxConcurrentInstances removed — replaced by dynamic resource-aware
// admission via resources.CanAdmitScan(). See internal/resources/.

type queueProgress struct {
	ActiveTarget          string
	ActiveScanDir         string
	ActiveScanID          string
	WildcardActiveTarget  string
	WildcardActiveScanDir string
	WildcardActiveScanID  string
	WildcardDiscoveryDone bool
	WildcardSubdomains    []string
	WildcardSubIndex      int
}

// saveQueueState saves the current queue state to disk.
func (s *Server) saveQueueState(idx int, req ScanRequest, progress ...queueProgress) {
	normalizeScanRequestActivity(&req)
	state := QueueState{
		InstanceID:     req.InstanceID,
		Targets:        req.Targets,
		CurrentIdx:     idx,
		Instruction:    req.Instruction,
		ScanMode:       req.ScanMode,
		StartedAt:      time.Now().Format(time.RFC3339),
		Active:         true,
		Name:           req.Name,
		SeverityFilter: req.SeverityFilter,
		Phases:         req.Phases,
		ReconMode:      req.ReconMode,
		ScanIntensity:  req.ScanIntensity,
		CompanyName:    req.CompanyName,
		LogoPath:       req.LogoPath,
		DiscordWebhook: req.DiscordWebhook,
	}
	if len(progress) > 0 {
		p := progress[0]
		state.ActiveTarget = p.ActiveTarget
		state.ActiveScanDir = p.ActiveScanDir
		state.ActiveScanID = p.ActiveScanID
		state.WildcardActiveTarget = p.WildcardActiveTarget
		state.WildcardActiveScanDir = p.WildcardActiveScanDir
		state.WildcardActiveScanID = p.WildcardActiveScanID
		state.WildcardDiscoveryDone = p.WildcardDiscoveryDone
		state.WildcardSubdomains = append([]string(nil), p.WildcardSubdomains...)
		state.WildcardSubIndex = p.WildcardSubIndex
	} else if req.ResumeScanDir != "" || len(req.ResumeSubdomains) > 0 {
		state.ActiveTarget = req.ResumeActiveTarget
		state.ActiveScanDir = req.ResumeScanDir
		state.ActiveScanID = req.ResumeScanID
		state.WildcardActiveTarget = req.ResumeSubScanTarget
		state.WildcardActiveScanDir = req.ResumeSubScanDir
		state.WildcardActiveScanID = req.ResumeSubScanID
		state.WildcardDiscoveryDone = req.ResumeDiscoveryDone
		state.WildcardSubdomains = append([]string(nil), req.ResumeSubdomains...)
		state.WildcardSubIndex = req.ResumeSubIndex
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("Error: failed to marshal queue state: %v", err)
		return
	}
	path := s.queueStatePathForInstance(req.InstanceID)
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Printf("Error: failed to save queue state: %v", err)
	}
}

func (s *Server) queueStatePath() string {
	return filepath.Join(s.dataDir, "queue_state.json")
}

func (s *Server) queueStatePathForInstance(instanceID string) string {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		return s.queueStatePath()
	}
	return filepath.Join(s.dataDir, fmt.Sprintf("queue_state_%s.json", sanitizeQueueStateID(instanceID)))
}

func sanitizeQueueStateID(instanceID string) string {
	clean := sanitizeTarget(instanceID)
	if clean == "" {
		return "unknown"
	}
	return clean
}

type queueStateEntry struct {
	state   *QueueState
	path    string
	modTime time.Time
}

func (s *Server) queueStatePaths() []string {
	var paths []string
	legacy := s.queueStatePath()
	if _, err := os.Stat(legacy); err == nil {
		paths = append(paths, legacy)
	}
	matches, _ := filepath.Glob(filepath.Join(s.dataDir, "queue_state_*.json"))
	paths = append(paths, matches...)
	sort.Strings(paths)
	return compactStrings(paths)
}

func compactStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := values[:0]
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func queueStateInstanceIDFromPath(path string) string {
	base := filepath.Base(path)
	if base == "queue_state.json" {
		return ""
	}
	if !strings.HasPrefix(base, "queue_state_") || !strings.HasSuffix(base, ".json") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(base, "queue_state_"), ".json")
}

func (s *Server) loadQueueStateEntry(path string) (queueStateEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return queueStateEntry{}, err
	}
	var state QueueState
	if err := json.Unmarshal(data, &state); err != nil {
		return queueStateEntry{}, err
	}
	if state.InstanceID == "" {
		state.InstanceID = queueStateInstanceIDFromPath(path)
	}
	info, _ := os.Stat(path)
	modTime := time.Time{}
	if info != nil {
		modTime = info.ModTime()
	}
	return queueStateEntry{state: &state, path: path, modTime: modTime}, nil
}

// loadQueueState loads queue state from disk if exists
func (s *Server) loadQueueState() *QueueState {
	entries := s.validQueueStateEntries(false)
	if len(entries) == 0 {
		return nil
	}
	return entries[0].state
}

func (s *Server) validQueueStateEntries(clearInvalid bool) []queueStateEntry {
	paths := s.queueStatePaths()
	if len(paths) == 0 {
		return nil
	}
	var valid []queueStateEntry
	for _, path := range paths {
		entry, err := s.loadQueueStateEntry(path)
		if err != nil {
			if clearInvalid {
				log.Printf("[queue] Invalid queue state %s, clearing: %v", path, err)
				s.clearQueueStatePath(path)
			}
			continue
		}
		if reason := invalidQueueStateReason(entry.state); reason != "" {
			if clearInvalid && reason != "inactive" {
				log.Printf("[queue] Invalid queue state %s (%s), clearing.", path, reason)
				s.clearQueueStatePath(path)
			}
			continue
		}
		valid = append(valid, entry)
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if !valid[i].modTime.Equal(valid[j].modTime) {
			return valid[i].modTime.After(valid[j].modTime)
		}
		return valid[i].state.StartedAt > valid[j].state.StartedAt
	})
	return valid
}

func invalidQueueStateReason(state *QueueState) string {
	if state == nil || !state.Active {
		return "inactive"
	}
	if len(state.Targets) == 0 {
		return "empty"
	}
	if state.CurrentIdx < 0 {
		return "corrupt_index"
	}
	if state.CurrentIdx >= len(state.Targets) {
		return "completed"
	}
	return ""
}

func scanRequestFromQueueState(state *QueueState, sourcePath string) ScanRequest {
	if state == nil {
		return ScanRequest{}
	}
	currentIdx := clampInt(state.CurrentIdx, 0, len(state.Targets))
	return ScanRequest{
		Targets:              append([]string(nil), state.Targets[currentIdx:]...),
		Instruction:          state.Instruction,
		ScanMode:             state.ScanMode,
		IsResume:             true,
		ResumeQueueStatePath: sourcePath,
		Name:                 state.Name,
		SeverityFilter:       append([]string(nil), state.SeverityFilter...),
		Phases:               append([]int(nil), state.Phases...),
		ReconMode:            state.ReconMode,
		ScanIntensity:        state.ScanIntensity,
		CompanyName:          state.CompanyName,
		LogoPath:             state.LogoPath,
		DiscordWebhook:       state.DiscordWebhook,
		ResumeActiveTarget:   state.ActiveTarget,
		ResumeScanDir:        state.ActiveScanDir,
		ResumeScanID:         state.ActiveScanID,
		ResumeSubScanTarget:  state.WildcardActiveTarget,
		ResumeSubScanDir:     state.WildcardActiveScanDir,
		ResumeSubScanID:      state.WildcardActiveScanID,
		ResumeSubdomains:     append([]string(nil), state.WildcardSubdomains...),
		ResumeSubIndex:       state.WildcardSubIndex,
		ResumeDiscoveryDone:  state.WildcardDiscoveryDone,
		ResumeOriginalTarget: state.CurrentIdx,
	}
}

func autoResumeQueueEntries(entries []queueStateEntry) []queueStateEntry {
	out := entries[:0]
	for _, entry := range entries {
		if entry.state != nil && entry.state.Paused {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func splitInstanceTargets(targets string) []string {
	var out []string
	for _, part := range strings.Split(targets, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func fillResumeRequestDefaults(req *ScanRequest, defaults ScanRequest) {
	if req == nil {
		return
	}
	if len(req.Targets) == 0 {
		req.Targets = append([]string(nil), defaults.Targets...)
	}
	if req.Instruction == "" {
		req.Instruction = defaults.Instruction
	}
	if req.ScanMode == "" {
		req.ScanMode = defaults.ScanMode
	}
	if req.Name == "" {
		req.Name = defaults.Name
	}
	if len(req.SeverityFilter) == 0 {
		req.SeverityFilter = append([]string(nil), defaults.SeverityFilter...)
	}
	if len(req.Phases) == 0 {
		req.Phases = append([]int(nil), defaults.Phases...)
	}
	if req.ReconMode == "" {
		req.ReconMode = defaults.ReconMode
	}
	if req.ScanIntensity == "" {
		req.ScanIntensity = defaults.ScanIntensity
	}
	if req.CompanyName == "" {
		req.CompanyName = defaults.CompanyName
	}
	if req.LogoPath == "" {
		req.LogoPath = defaults.LogoPath
	}
	if req.DiscordWebhook == "" {
		req.DiscordWebhook = defaults.DiscordWebhook
	}
}

func (s *Server) scanRequestForPausedInstance(instanceID string, inst *ScanInstance) (ScanRequest, bool, string) {
	if inst == nil {
		return ScanRequest{}, false, "instance not found"
	}

	inst.mu.RLock()
	defaultReq := ScanRequest{
		Targets:        splitInstanceTargets(inst.Targets),
		Instruction:    inst.Instruction,
		ScanMode:       inst.ScanMode,
		SeverityFilter: append([]string(nil), inst.SeverityFilter...),
		DiscordWebhook: inst.DiscordWebhook,
		Name:           inst.Name,
		Phases:         append([]int(nil), inst.Phases...),
		ReconMode:      inst.ReconMode,
		ScanIntensity:  inst.ScanIntensity,
		CompanyName:    inst.CompanyName,
		LogoPath:       inst.LogoPath,
		IsResume:       true,
	}
	scanDir := inst.scanDir
	inst.mu.RUnlock()

	queuePath := s.queueStatePathForInstance(instanceID)
	if entry, err := s.loadQueueStateEntry(queuePath); err == nil {
		if reason := invalidQueueStateReason(entry.state); reason == "" {
			req := scanRequestFromQueueState(entry.state, entry.path)
			fillResumeRequestDefaults(&req, defaultReq)
			req.IsResume = true
			return req, true, ""
		}
	}

	if scanDir == "" {
		return ScanRequest{}, false, "no persisted scan state found"
	}
	if strings.EqualFold(defaultReq.ScanMode, "wildcard") {
		return ScanRequest{}, false, "wildcard resume requires saved queue state"
	}

	defaultReq.ResumeScanDir = scanDir
	defaultReq.ResumeScanID = filepath.Base(scanDir)
	if rec, ok := loadScanRecordFromDir(scanDir); ok && rec.Target != "" {
		defaultReq.ResumeActiveTarget = rec.Target
	} else if len(defaultReq.Targets) > 0 {
		defaultReq.ResumeActiveTarget = defaultReq.Targets[0]
	}
	return defaultReq, true, ""
}

func shouldPreserveQueueStateOnExit(status, stopReason string, panicRecovered bool) bool {
	if panicRecovered {
		return true
	}
	if status == "paused" || stopReason == "user_paused" {
		return true
	}
	return strings.HasPrefix(stopReason, "signal_")
}

func shouldAdvanceQueueAfterTarget(stopRequested bool, status string) bool {
	if stopRequested {
		return false
	}
	switch status {
	case "paused", "stopped":
		return false
	default:
		return true
	}
}

func isInterruptedInstanceStatus(status string) bool {
	return status == "paused" || status == "stopped"
}

func (s *Server) instanceRunStatus(instanceID string) (string, string) {
	if instanceID == "" {
		return "", ""
	}
	s.instancesMu.RLock()
	inst := s.instances[instanceID]
	s.instancesMu.RUnlock()
	if inst == nil {
		return "", ""
	}
	inst.mu.RLock()
	status := inst.Status
	stopReason := inst.StopReason
	inst.mu.RUnlock()
	return status, stopReason
}

func (s *Server) instanceInterrupted(instanceID string) bool {
	status, _ := s.instanceRunStatus(instanceID)
	return isInterruptedInstanceStatus(status)
}

func (s *Server) markQueueStatePaused(instanceID string) {
	entry, err := s.loadQueueStateEntry(s.queueStatePathForInstance(instanceID))
	if err != nil || entry.state == nil {
		return
	}
	entry.state.Paused = true
	data, err := json.MarshalIndent(entry.state, "", "  ")
	if err != nil {
		log.Printf("Error: failed to marshal paused queue state: %v", err)
		return
	}
	if err := os.WriteFile(entry.path, data, 0600); err != nil {
		log.Printf("Error: failed to mark queue state paused: %v", err)
	}
}

// clearQueueState removes queue state. With an instance ID it clears only that
// scan's resume file; with no ID it clears every resumable queue.
func (s *Server) clearQueueState(instanceIDs ...string) {
	if len(instanceIDs) > 0 {
		for _, instanceID := range instanceIDs {
			if strings.TrimSpace(instanceID) == "" {
				s.clearQueueStatePath(s.queueStatePath())
				continue
			}
			s.clearQueueStatePath(s.queueStatePathForInstance(instanceID))
		}
		return
	}
	for _, path := range s.queueStatePaths() {
		s.clearQueueStatePath(path)
	}
}

func (s *Server) clearQueueStatePath(path string) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to remove queue state file %s: %v", path, err)
	}
}

// dashboardRoutes lists every URL pattern the dashboard mux
// registers in NewServer.Start. It exists primarily as a test
// surface so that the test in internal/web asserting
// `/oauth/callback` is NOT mounted on the dashboard mux (R13.3)
// has a single source of truth to consult — without it, that
// invariant would have to be re-derived from the call sites in
// Start every time the route surface changes.
//
// The slice is updated in lockstep with the mux.HandleFunc /
// mux.Handle calls inside Server.Start; if a route is added or
// removed there, the slice should be updated to match.
//
// Validates: Requirement 13.3 ("never registers `/oauth/callback`
// on the dashboard mux"), Requirement 15.2 (existing routes
// preserved unchanged).
var dashboardRoutes = []string{
	// Static + WebSocket roots (registered as catch-all and "/ws").
	"/",
	"/ws",

	// Existing scan / status / report / settings surface (unchanged).
	"/api/scan",
	"/api/stop",
	"/api/restart",
	"/api/status",
	"/api/findings/summary",
	"/api/legacy-import/status",
	"/api/scans",
	"/api/scans/",
	"/api/data-dirs/",
	"/api/schedules",
	"/api/schedules/",
	"/api/upload-targets",
	"/api/upload-instructions",
	"/api/upload-logo",
	"/uploads/logos/",
	"/api/report/",
	"/api/settings/rate-limit",
	"/api/settings/agentmail",
	"/api/settings/llm",
	"/api/settings/llm/keys",
	"/api/settings/llm/test-route",
	"/api/settings/environment",
	"/api/queue/status",
	"/api/queue/resume",
	"/api/queue/clear",
	"/api/version",
	"/api/stop-notify",
	"/api/instances",
	"/api/instances/",
	"/api/chat",

	// Dashboard auth (login/logout/status). Distinct from the new
	// /api/auth/profiles namespace below.
	"/api/auth/login",
	"/api/auth/logout",
	"/api/auth/status",

	// Provider catalog (read-only) + auth profile routes.
	"/api/providers",
	"/api/auth/profiles",
	"/api/auth/profiles/api-key",
	"/api/auth/profiles/oauth/start",
	"/api/auth/profiles/oauth/complete",
	"/api/auth/profiles/",
}

// Server is the web UI server.
type Server struct {
	cfg                  *config.Config
	port                 int
	clients              map[*wsClient]bool
	mu                   sync.RWMutex
	currentAgents        map[string]*agent.Agent // scanID → agent (replaces singleton currentAgent)
	cancelScan           context.CancelFunc      // cancels the current scan session context
	running              atomic.Bool
	stopReq              atomic.Bool
	restartWhenIdle      atomic.Bool // SIGUSR1 sets this; a watcher restarts once scans drain
	httpServer           *http.Server // set in Start; used to trigger graceful restart from the API
	dataDir              string
	currentScanDir       string
	currentScanID        string
	discordWebhook       string
	discordMinSeverity   string // minimum severity to send to Discord ("info", "low", "medium", "high", "critical")
	telegramBotToken     string // XALGORIX_TELEGRAM_BOT_TOKEN (secret, never exposed via API)
	telegramChatID       string // XALGORIX_TELEGRAM_CHAT_ID (numeric ID or @channelusername)
	telegramMinSeverity string // minimum severity to send to Telegram ("info", "low", "medium", "high", "critical")
	rateLimiter          *RateLimiter
	settingsMu           sync.Mutex
	instances            map[string]*ScanInstance // concurrent scan instances
	instancesMu          sync.RWMutex
	queueResumeMu        sync.Mutex
	queueResumeLaunching map[string]bool
	postScanChatFn       func(*config.Config, []llm.Message) (string, error)
	schedulesMu          sync.RWMutex
	schedules            map[string]*ScanSchedule
	shutdownChan         chan struct{}
	// scanListCache memoizes the built GET /api/scans list for a few seconds
	// so paging/filtering/polling don't each re-walk the whole data dir.
	scanListCacheMu sync.Mutex
	scanListCache   []scanListItem
	scanListCacheAt time.Time
	// scanSummaryCache memoizes the per-file parsed (events-free) scan record
	// keyed by file path. Finished scans' scan.json files are immutable, so
	// after the first parse they are reused across walks without re-reading or
	// re-parsing. Entries are validated by (modtime, size) so a running scan
	// whose file changes is re-parsed. See findAllScanSummaries.
	scanSummaryCacheMu sync.Mutex
	scanSummaryCache   map[string]scanSummaryCacheEntry
	// admissionWake is a buffered (len=1) channel used by runMultiScan's
	// admission loop to wait fairly for a freed slot. A scan instance ending
	// signals this channel non-blockingly in its defer cleanup, waking
	// exactly one waiter per terminate. The 2-second ticker in the loop is
	// retained as a safety-net so we still re-check periodically if a wake
	// signal is missed for any reason. (R3.2, R3.6 / Property 5.)
	admissionWake chan struct{}

	// legacyImportCount is the number of scan records imported from the
	// pre-migration directory (~/xalgorix-data/) into the active dataDir
	// on the current server start. It is set once by importLegacyDataDir
	// and surfaced via /api/legacy-import/status so the WebUI can render
	// a one-time banner. Not persisted; resets to 0 each restart.
	// legacyImportDismissed flips to true when the WebUI dismisses the
	// banner; only valid for the current process lifetime.
	// Guarded by legacyImportMu so the short banner-status reads/writes
	// don't contend with the WebSocket-clients lock (s.mu).
	// (See findings-consistency-and-pagination spec, Property 6.)
	legacyImportMu        sync.RWMutex
	legacyImportCount     int
	legacyImportDismissed bool

	// catalog is the read-only LLM provider catalog backing the
	// GET /api/providers handler and the per-scan endpoint
	// resolver. v4.4.22 collapsed the runtime-editable JSON-backed
	// catalog into a compiled-in providers.Builtin() set;
	// providers.NewService() is unconditional and never fails. The
	// field is kept (rather than being read from a singleton) so
	// tests can swap a fixture catalog in without touching package
	// state.
	catalog *providers.Service

	// profiles is the runtime-editable credential profile store
	// backing /api/auth/profiles (Wave E task 5.2). Like catalog,
	// it is initialized in NewServer and may be nil if startup
	// failed. The catalog handlers in this task do not consult
	// profiles directly, but the field is declared here so task 5.2
	// can wire profile handlers without re-touching the Server
	// shape. Validates: Requirement 4.1.
	profiles *auth.Store

	// oauthRegistry is the OAuth driver registry consulted by
	// handleOAuthStart / handleOAuthComplete / handleProfileRefresh
	// (Wave E task 5.2). It is wired in NewServer immediately
	// after profiles via auth.RegisterDefaultDrivers so the four
	// built-in flow handlers (pkce, device_code, setup_token,
	// claude_cli_reuse) are available without further setup. A
	// nil value mirrors the catalog/profiles fields: the OAuth
	// handlers surface 503 so the rest of the dashboard keeps
	// serving traffic. Validates: Requirements 6.x, 7.x, 8.x, 9.x.
	oauthRegistry *auth.Registry

	// llmKeyStore is the multi-provider API key store backing the
	// /api/settings/llm/keys handlers. nil if construction failed at
	// startup, in which case handleProviderKeys returns 503.
	llmKeyStore *llm.KeyStore

	// llmRouter resolves a model name to a provider endpoint using the
	// catalog + llmKeyStore. Backs /api/settings/llm/test-route. nil
	// when llmKeyStore is nil.
	llmRouter *llm.Router
}

// NewServer creates a new web server.
func NewServer(cfg *config.Config, port int) *Server {
	// The active Data_Dir is owned by config.resolveDataDir (R6.1, R6.3) and
	// already canonicalized + created with mode 0o700 before we get here.
	// The Web_Server is a downstream consumer; it must NOT re-derive a data
	// root from $HOME or $CWD (Task 3.6 / R6.4 / R6.6) — doing so would
	// silently bypass XALGORIX_DATA_DIR and resurrect the legacy
	// ~/xalgorix-data location.
	dataDir := cfg.DataDir
	// Rate limit from config (defaults: 60 requests per minute)
	rl := NewRateLimiter(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindow)*time.Second)

	srv := &Server{
		cfg:                  cfg,
		port:                 port,
		clients:              make(map[*wsClient]bool),
		currentAgents:        make(map[string]*agent.Agent),
		dataDir:              dataDir,
		discordWebhook:       cfg.DiscordWebhook,
		discordMinSeverity:   strings.ToLower(strings.TrimSpace(cfg.DiscordMinSeverity)),
		telegramBotToken:     cfg.TelegramBotToken,
		telegramChatID:       cfg.TelegramChatID,
		telegramMinSeverity: strings.ToLower(strings.TrimSpace(cfg.TelegramMinSeverity)),
		rateLimiter:          rl,
		instances:            make(map[string]*ScanInstance),
		queueResumeLaunching: make(map[string]bool),
		// postScanChatFn is set BELOW, after srv has been
		// allocated, so the closure can capture *srv and read
		// srv.catalog / srv.profiles at call time. Those fields
		// are populated later in NewServer when the catalog and
		// profile stores load successfully; capturing the
		// pointer keeps the closure valid even when those
		// fields flip from nil to non-nil during construction.
		schedules:    make(map[string]*ScanSchedule),
		shutdownChan: make(chan struct{}),
		// Buffered to length 1 so a non-blocking send from a terminating
		// scan never blocks; the buffered slot guarantees a wake signal
		// is delivered to whichever waiter is currently parked in the
		// admission select.
		admissionWake: make(chan struct{}, 1),
	}

	// Wire postScanChatFn now that srv exists. The closure reads
	// srv.catalog / srv.profiles at call time so the catalog
	// branch engages once both stores load below — the values
	// captured here are pointers, not snapshots, so a successful
	// catalog load later in NewServer is observable on every
	// subsequent invocation of postScanChatFn.
	//
	// Decision order matches llm.compositeResolver.Resolve
	// exactly (catalog non-empty → catalogResolver; otherwise
	// legacy when XALGORIX_LLM matches Legacy_Provider_Shape;
	// otherwise *ConfigError surfaced to the caller). That is
	// the contract Requirement 11.2 / Requirement 2.x require
	// for /api/scan, and putting the same resolver behind every
	// LLM call site keeps the chat-summary path consistent with
	// the per-scan path. (Wave E task 5.4.)
	srv.postScanChatFn = func(cfg *config.Config, messages []llm.Message) (string, error) {
		opts := []llm.ResolverOption{}
		if srv.catalog != nil && srv.profiles != nil {
			opts = append(opts, llm.WithCatalog(srv.catalog, srv.profiles))
		}
		opts = append(opts, llm.WithLegacy(cfg))
		resolver := llm.NewCompositeResolver(opts...)
		client := llm.NewClient(cfg, llm.WithResolver(resolver))
		client.SetContext(context.Background())
		return client.Chat(messages)
	}

	// Import legacy data dir (pre-migration ~/xalgorix-data/) into the
	// active dataDir on first start. Idempotent (sentinel-gated) and
	// non-fatal — failures are logged and the server still starts. Must
	// run BEFORE rebuildInstancesFromDisk so imported scans appear in
	// the dashboard immediately.
	imported, ierr := srv.importLegacyDataDir()
	if ierr != nil {
		log.Printf("[legacy-import] error: %v (continuing)", ierr)
	}
	srv.legacyImportCount = imported
	srv.legacyImportDismissed = false

	// Provider catalog + auth profile store.
	//
	// As of v4.4.22 the catalog is compiled-in (providers.Builtin)
	// rather than file-backed. providers.NewService is constructed
	// unconditionally and never fails. The auth profile store is
	// still file-backed under ~/.xalgorix/data/auth-profiles.json;
	// a failure there is non-fatal — the dashboard still serves
	// traffic, and the profile handlers surface the missing
	// dependency as HTTP 503 so the operator can repair the file
	// without losing access to the rest of the UI.
	//
	// auth.NewStore defers file creation until the first write, so
	// the constructor is safe to invoke unconditionally on every
	// start.
	srv.catalog = providers.NewService()
	profilePath := filepath.Join(dataDir, "auth-profiles.json")
	if store, err := auth.NewStore(profilePath, srv.catalog); err != nil {
		log.Printf("[auth] failed to load profile store at %s: %v (profile handlers will return 503)", profilePath, err)
	} else {
		srv.profiles = store
		// Wire the OAuth driver registry now that both
		// catalog + profile store are live. Driver
		// constructors in internal/auth are unexported,
		// so RegisterDefaultDrivers is the single
		// exported seam through which production code
		// stands up the canonical four-driver registry.
		// nil clock → registry uses realClock for the
		// device-code poller.
		srv.oauthRegistry = auth.NewRegistry(store, http.DefaultClient, nil)
		auth.RegisterDefaultDrivers(srv.oauthRegistry, nil)
	}

	// Multi-provider key store + model router (LiteLLM-style). The key
	// store is file-backed under <dataDir>/llm_keys.json; a load failure
	// is non-fatal — the provider-key handlers surface 503 and the rest
	// of the dashboard keeps serving. The router shares the compiled-in
	// catalog and is only built when the key store is live.
	if ks, err := llm.NewKeyStore(dataDir); err != nil {
		log.Printf("[llm] failed to load key store: %v (provider-key handlers will return 503)", err)
	} else {
		srv.llmKeyStore = ks
		srv.llmRouter = llm.NewRouter(srv.catalog, ks)
	}

	// Rebuild instances map from disk so dashboard shows historical scans on startup
	srv.rebuildInstancesFromDisk()

	// Load schedules from disk
	srv.loadSchedulesFromDisk()

	return srv
}

func (s *Server) hasPendingOrRunningInstance() bool {
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		active := inst.Status == "pending" || inst.Status == "running"
		inst.mu.RUnlock()
		if active {
			return true
		}
	}
	return false
}

func (s *Server) hasQueueResumeLaunchingLocked() bool {
	return len(s.queueResumeLaunching) > 0
}

func (s *Server) markQueueResumeLaunchingLocked(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "legacy"
	}
	if s.queueResumeLaunching == nil {
		s.queueResumeLaunching = make(map[string]bool)
	}
	s.queueResumeLaunching[key] = true
}

func (s *Server) clearQueueResumeLaunching(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "legacy"
	}
	s.queueResumeMu.Lock()
	delete(s.queueResumeLaunching, key)
	s.queueResumeMu.Unlock()
}

func queueResumeEntryKey(entry queueStateEntry) string {
	if entry.state != nil && strings.TrimSpace(entry.state.InstanceID) != "" {
		return strings.TrimSpace(entry.state.InstanceID)
	}
	if entry.path != "" {
		return filepath.Clean(entry.path)
	}
	return "legacy"
}

// Start launches the web server.
func (s *Server) Start() error {
	s.initDataDir()

	// Start the background scheduler
	go s.startScheduler()

	// Start the scan-retention sweeper. It self-disables (returns
	// immediately) when XALGORIX_SCAN_RETENTION_DAYS is 0, so this is a
	// no-op for installs that want to keep scans forever.
	go s.startRetentionSweeper()

	// Reap expired session cookies in the background so the auth map cannot
	// grow unbounded from abandoned logins.
	if authConfigured(s.cfg) {
		startSessionReaper()
	}

	// Auto-start Caido proxy in background if available
	startCaidoProxy()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
	}

	mux := http.NewServeMux()
	// SPA handler: serve static files if they exist, otherwise serve index.html
	fileServer := http.FileServer(http.FS(staticFS))
	// fs.Sub on embed.FS returns an fs.FS that does implement ReadFileFS today,
	// but assert with comma-ok so a future runtime change can't crash the server.
	rfs, hasRfs := staticFS.(fs.ReadFileFS)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		setWebUICacheHeaders(w)
		// Try to serve the static file
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Check if it's a real static file. Vite serves assets from the
		// static root (/app.js, /style.css, /chunks/...), while older builds
		// may request /static/app.js. staticFS already points at that root.
		strippedPath := strings.TrimPrefix(path, "/")
		strippedPath = strings.TrimPrefix(strippedPath, "static/")
		if hasRfs {
			if f, err := rfs.ReadFile(strippedPath); err == nil && f != nil {
				// Rewrite URL to serve from staticFS root (which is already "static")
				r.URL.Path = "/" + strippedPath
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// Known static asset paths that didn't resolve to a real file are
		// genuine 404s. App routes may contain dots in path params (for
		// example scan ids derived from hostnames), so don't treat every
		// dotted path as a file.
		if isStaticWebAssetPath(path) {
			http.NotFound(w, r)
			return
		}
		// Not a static file — serve index.html (SPA catch-all)
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/stop", s.handleStop)
	mux.HandleFunc("/api/restart", s.handleRestart)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/findings/summary", s.handleFindingsSummary)
	mux.HandleFunc("/api/findings", s.handleFindingsList)
	mux.HandleFunc("/api/legacy-import/status", s.handleLegacyImportStatus)
	mux.HandleFunc("/api/scans", s.handleListScans)
	mux.HandleFunc("/api/scans/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/vulns/") && r.Method == http.MethodDelete {
			s.handleDeleteVuln(w, r)
			return
		}
		s.handleGetScan(w, r)
	})
	// DELETE /api/data-dirs/{name} — delete one top-level Scan_Folder under
	// Data_Dir. Distinct prefix from /api/scans/ (no collision, R5.3); inherits
	// authMiddleware + CSRF and stays subject to rate limiting as a mutating
	// route (intentionally NOT added to isDashboardReadPath). R5.1, R5.2.
	mux.HandleFunc("/api/data-dirs/", s.handleDeleteDataDir)
	mux.HandleFunc("/api/schedules", s.handleSchedules)
	mux.HandleFunc("/api/schedules/", s.handleScheduleDetail)
	mux.HandleFunc("/api/upload-targets", s.handleUploadTargets)
	mux.HandleFunc("/api/upload-instructions", s.handleUploadInstructions)
	mux.HandleFunc("/api/upload-logo", s.handleUploadLogo)
	// Serve uploaded logos
	logosDir := filepath.Join(s.dataDir, "logos")
	_ = os.MkdirAll(logosDir, 0700)
	mux.Handle("/uploads/logos/", http.StripPrefix("/uploads/logos/", http.FileServer(http.Dir(logosDir))))
	mux.HandleFunc("/api/report/", s.handleDownloadReport)
	mux.HandleFunc("/api/settings/rate-limit", s.handleRateLimit)
	mux.HandleFunc("/api/settings/agentmail", s.handleAgentMailSettings)
	mux.HandleFunc("/api/settings/llm", s.handleLLMSettings)
	mux.HandleFunc("/api/settings/llm/keys", s.handleProviderKeys)
	mux.HandleFunc("/api/settings/llm/test-route", s.handleTestRoute)
	mux.HandleFunc("/api/settings/environment", s.handleEnvironmentSettings)
	mux.HandleFunc("/api/queue/status", s.handleQueueStatus)
	mux.HandleFunc("/api/queue/resume", s.handleQueueResume)
	mux.HandleFunc("/api/queue/clear", s.handleQueueClear)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/stop-notify", s.handleStopNotify)
	mux.HandleFunc("/api/instances", s.handleInstances)
	mux.HandleFunc("/api/instances/", s.handleInstanceAction)

	mux.HandleFunc("/api/chat", s.handleChat)

	// Auth routes (these are public — authMiddleware skips them)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)

	// ── Provider catalog + auth profile routes (Wave E task 5.4) ──
	//
	// All these routes mount on the same mux as the rest of /api/*,
	// so they inherit:
	//   • authMw  — Authenticated_Operator gate (R12.4) plus the
	//               global isCSRFSafe check that wraps every
	//               state-changing /api/* request (R12.5).
	//   • rlMw    — the per-IP token-bucket rate limiter applied to
	//               every API route.
	//
	// We deliberately do NOT register `/oauth/callback` here — the
	// PKCE driver allocates its own ephemeral 127.0.0.1 listener
	// per flow start (R13.1, R13.3). Putting the callback on the
	// dashboard mux would expose it to CSRF and to any long-lived
	// network exposure the operator chooses; the per-flow listener
	// avoids both. The dashboardRoutes slice below is consulted in
	// tests to assert this invariant continues to hold.
	//
	// Multi-method routes are dispatched by HTTP method via small
	// adapters; each downstream handler still validates its own
	// method so an unexpected verb returns 405 even when called
	// through these adapters from a future entry point.
	mux.HandleFunc("/api/providers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleListProviders(w, r)
	})
	mux.HandleFunc("/api/auth/profiles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleListProfiles(w, r)
	})
	mux.HandleFunc("/api/auth/profiles/api-key", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleCreateAPIKeyProfile(w, r)
	})
	mux.HandleFunc("/api/auth/profiles/oauth/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleOAuthStart(w, r)
	})
	mux.HandleFunc("/api/auth/profiles/oauth/complete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleOAuthComplete(w, r)
	})
	// /api/auth/profiles/{key}/refresh (POST) and
	// /api/auth/profiles/{key} (DELETE) share the same trailing-slash
	// dispatcher because http.ServeMux funnels every sub-path of
	// "/api/auth/profiles/" through one handler. We branch on the
	// "/refresh" suffix first; everything else is treated as the
	// {key}-only DELETE path. Both /api/auth/profiles/api-key and
	// /api/auth/profiles/oauth/{start,complete} are registered as
	// exact-match patterns above so their longer-prefix dispatch
	// wins over this trailing-slash handler.
	mux.HandleFunc("/api/auth/profiles/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/refresh") {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.handleProfileRefresh(w, r)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleDeleteProfile(w, r)
	})

	// Wrap with auth middleware (outermost) then rate limiting
	authMw := authMiddleware(s.cfg)
	rlMiddleware := rateLimitMiddleware(s.rateLimiter)

	// Bind to a specific interface. Default is 127.0.0.1 (loopback) so a
	// fresh install isn't exposed to the network. Operators who want
	// external access set XALGORIX_BIND=0.0.0.0 explicitly — and in that
	// case auth MUST be configured or we refuse to start. This is a
	// deliberate safety choice: the dashboard can launch arbitrary scans
	// and a chat tool with the LLM, so an open port is a control plane.
	bindAddr := s.cfg.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	isLoopback := bindAddr == "127.0.0.1" || bindAddr == "::1" || bindAddr == "localhost"
	if !isLoopback && !authConfigured(s.cfg) {
		return fmt.Errorf(
			"refusing to bind to non-loopback address %q without auth: set XALGORIX_USERNAME and either XALGORIX_PASSWORD_HASH (bcrypt) or XALGORIX_PASSWORD in ~/.xalgorix.env, or set XALGORIX_BIND=127.0.0.1",
			bindAddr,
		)
	}
	addr := fmt.Sprintf("%s:%d", bindAddr, s.port)
	if isLoopback {
		log.Printf("Xalgorix Web UI → http://%s:%d (loopback only)", bindAddr, s.port)
	} else {
		log.Printf("Xalgorix Web UI → http://%s:%d (NETWORK-EXPOSED)", bindAddr, s.port)
	}
	log.Printf("Scan data → %s", s.dataDir)
	log.Printf("Rate limiting: %d requests/%ds per IP", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	if authConfigured(s.cfg) {
		authMode := "plaintext"
		if s.cfg.PasswordHash != "" {
			authMode = "bcrypt"
		}
		log.Printf("Authentication enabled (user: %s, password: %s)", s.cfg.Username, authMode)
	} else {
		log.Printf("Authentication disabled — listening on loopback only. Set XALGORIX_USERNAME and XALGORIX_PASSWORD_HASH in ~/.xalgorix.env to enable.")
	}

	// ── Auto-resume interrupted scan queue after short startup delay ──
	// Gate the resume on no scan having started in the meantime — without
	// this, a user request arriving in the first 5 seconds would race with
	// the auto-resume goroutine and both runMultiScan calls would stomp
	// on the same cancelScan field.
	go func() {
		time.Sleep(5 * time.Second) // let HTTP server fully initialize
		s.queueResumeMu.Lock()
		defer s.queueResumeMu.Unlock()
		if s.running.Load() || s.hasPendingOrRunningInstance() || s.hasQueueResumeLaunchingLocked() {
			log.Printf("[AUTO-RESUME] Skipping — a scan is already pending or running.")
			return
		}
		entries := autoResumeQueueEntries(s.validQueueStateEntries(true))
		if len(entries) == 0 {
			return
		}
		log.Printf("[AUTO-RESUME] Resuming %d interrupted scan queue(s)", len(entries))
		for _, entry := range entries {
			req := scanRequestFromQueueState(entry.state, entry.path)
			if len(req.Targets) == 0 {
				continue
			}
			instanceID := entry.state.InstanceID
			log.Printf("[AUTO-RESUME] Resuming interrupted scan queue %s: %d targets from index %d", instanceID, len(req.Targets), entry.state.CurrentIdx)
			scanCfg := *s.cfg
			resumeKey := queueResumeEntryKey(entry)
			s.markQueueResumeLaunchingLocked(resumeKey)
			go func(req ScanRequest, scanCfg config.Config, instanceID, resumeKey string) {
				defer s.clearQueueResumeLaunching(resumeKey)
				s.runMultiScan(req, &scanCfg, instanceID)
			}(req, scanCfg, instanceID, resumeKey)
		}
	}()

	// ── Graceful shutdown on SIGTERM/SIGINT ──
	httpServer := &http.Server{
		Addr: addr,
		// safe.HTTPMiddleware MUST be the outermost wrapper so it catches
		// panics from every layer below it (auth, rate-limit, mux,
		// individual handlers). On panic it increments PanicsRecovered,
		// emits a structured log line with stack trace, and returns 500.
		Handler: safe.HTTPMiddleware(authMw(rlMiddleware(mux))),
		// Bound the time spent reading request headers so a slow client
		// cannot hold a connection open indefinitely (Slowloris). The
		// dashboard serves interactive traffic, so keep this generous.
		ReadHeaderTimeout: 30 * time.Second,
	}
	// Expose the server so the /api/restart handler can trigger a graceful
	// restart-when-idle through the same path as the SIGUSR1 watcher.
	s.httpServer = httpServer

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		log.Printf("[SHUTDOWN] Received signal %s — saving state and shutting down gracefully", sig)

		// Stop the background scheduler
		close(s.shutdownChan)

		// Stop all running scans so they save queue state
		s.stopReq.Store(true)
		s.mu.Lock()
		if s.cancelScan != nil {
			s.cancelScan()
		}
		for _, agnt := range s.currentAgents {
			if agnt != nil {
				agnt.Stop()
			}
		}
		s.mu.Unlock()

		// Stop all instances
		s.instancesMu.RLock()
		for _, inst := range s.instances {
			inst.mu.Lock()
			if inst.Status == "running" {
				inst.Status = "stopped"
				inst.StopReason = "signal_" + sig.String()
				inst.FinishedAt = time.Now().Format(time.RFC3339)
				if inst.agent != nil {
					inst.agent.Stop()
				}
			}
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()

		terminal.KillAllProcesses()

		// Send Discord notification. Use sig.String() explicitly so we get
		// "terminated"/"interrupt" rather than a numeric fallback for any
		// os.Signal implementation that doesn't satisfy fmt.Stringer.
		if s.discordWebhook != "" {
			s.sendDiscord(0xff6b6b, "🔄 Xalgorix Restarting", fmt.Sprintf("Service received %s signal. Saving state and restarting.\nInterrupted scans will auto-resume.", sig.String()))
		}
		if s.telegramConfigured() {
			s.sendTelegram(0xff6b6b, "🔄 Xalgorix Restarting", fmt.Sprintf("Service received %s signal. Saving state and restarting.\nInterrupted scans will auto-resume.", sig.String()))
		}

		// Give scans a moment to save their queue state
		time.Sleep(2 * time.Second)

		// Graceful HTTP shutdown (5s deadline for in-flight requests)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("[SHUTDOWN] HTTP shutdown error: %v", err)
		}

		s.rateLimiter.Stop()
		log.Printf("[SHUTDOWN] Graceful shutdown complete")
	}()

	// ── Graceful restart-when-idle on SIGUSR1 ──
	// `xalgorix --restart-when-idle` sends SIGUSR1 to this process. We do not
	// restart immediately: a watcher waits until no scan instance is active
	// and no tool process is leased, then restarts cleanly (so in-flight
	// engagements are never interrupted).
	go func() {
		usrCh := make(chan os.Signal, 1)
		signal.Notify(usrCh, syscall.SIGUSR1)
		for range usrCh {
			if !s.scheduleGracefulRestart() {
				log.Printf("[RESTART] Graceful restart already pending — ignoring duplicate SIGUSR1")
			}
		}
	}()

	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil // graceful shutdown
	}
	return err
}

// scheduleGracefulRestart marks the server for a restart-when-idle and starts
// the watcher that performs the restart once no scan/instance is active. It is
// the shared entry point for both the SIGUSR1 signal and the POST /api/restart
// endpoint. Returns false if a restart was already pending (idempotent), so
// duplicate requests don't spawn multiple watchers.
func (s *Server) scheduleGracefulRestart() bool {
	if s.restartWhenIdle.Swap(true) {
		return false
	}
	log.Printf("[RESTART] Graceful restart requested — will restart once all scans finish")
	if s.discordWebhook != "" {
		s.sendDiscord(0x4dabf7, "🕓 Xalgorix Restart Scheduled",
			"A restart was requested. Xalgorix will restart automatically once all running scans finish and no tools are active.")
	}
	if s.telegramConfigured() {
		s.sendTelegram(0x4dabf7, "🕓 Xalgorix Restart Scheduled",
			"A restart was requested. Xalgorix will restart automatically once all running scans finish and no tools are active.")
	}
	go s.restartWhenIdleWatcher(s.httpServer)
	return true
}

// scannerIdle reports whether it is safe to restart: no scan instance is// active (running/pending/paused/queued/starting) and no terminal tool is
// currently leased. Completed/stopped/failed instances are historical and
// do not block a restart.
func (s *Server) scannerIdle() bool {
	s.instancesMu.RLock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		st := strings.ToLower(strings.TrimSpace(inst.Status))
		inst.mu.RUnlock()
		switch st {
		case "running", "pending", "paused", "queued", "starting":
			s.instancesMu.RUnlock()
			return false
		}
	}
	s.instancesMu.RUnlock()
	if s.running.Load() {
		return false
	}
	if resources.Capacity().ActiveToolLeases > 0 {
		return false
	}
	return true
}

// restartWhenIdleWatcher polls scanner state after a SIGUSR1 request and
// triggers a restart once the scanner has been idle for a few consecutive
// checks (debounced so a brief gap between queued targets does not trigger an
// early restart).
func (s *Server) restartWhenIdleWatcher(httpServer *http.Server) {
	const interval = 5 * time.Second
	const idleChecksNeeded = 3 // ~15s of sustained idle before restarting
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	idleStreak := 0
	for range ticker.C {
		if !s.restartWhenIdle.Load() {
			return // request was cleared elsewhere
		}
		if s.scannerIdle() {
			idleStreak++
			if idleStreak >= idleChecksNeeded {
				s.restartNow(httpServer)
				return
			}
		} else {
			idleStreak = 0
		}
	}
}

// restartNow performs the actual restart. Under systemd (Restart=always) a
// clean exit is enough — systemd re-runs ExecStart, reloading the env file.
// Outside systemd (background mode) we re-exec the binary in place so the
// service comes back without an external supervisor. Either path also picks
// up a newly-installed binary on disk.
func (s *Server) restartNow(httpServer *http.Server) {
	log.Printf("[RESTART] Scanner idle — restarting now")
	if s.discordWebhook != "" {
		s.sendDiscord(0x4dabf7, "🔄 Xalgorix Restarting", "Scanner is idle. Restarting now; interrupted work (if any) auto-resumes.")
	}
	if s.telegramConfigured() {
		s.sendTelegram(0x4dabf7, "🔄 Xalgorix Restarting", "Scanner is idle. Restarting now; interrupted work (if any) auto-resumes.")
	}

	// Belt-and-suspenders: reap any stray tool processes before we go.
	terminal.KillAllProcesses()

	// Release the listening socket so the restarted process can rebind.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if httpServer != nil {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("[RESTART] HTTP shutdown error: %v", err)
		}
	}

	// systemd-managed: INVOCATION_ID is set by systemd for service units.
	// A clean exit triggers Restart=always with a freshly-loaded env file.
	if os.Getenv("INVOCATION_ID") != "" {
		log.Printf("[RESTART] Exiting for systemd to restart (fresh environment)")
		os.Exit(0)
	}

	// Background mode: re-exec in place.
	exe, err := os.Executable()
	if err != nil || strings.TrimSpace(exe) == "" {
		exe = os.Args[0]
	}
	log.Printf("[RESTART] Re-executing %s", exe)
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Printf("[RESTART] re-exec failed: %v — exiting for supervisor restart", err)
		os.Exit(0)
	}
}

// initDataDir is a thin wrapper around cfg.DataDir (Task 3.6 / R6.4, R6.6):
// the directory is already canonicalized and created with mode 0o700 by
// config.resolveDataDir at startup, so the MkdirAll below is belt-and-
// suspenders — it covers the narrow window where a test or operator
// removes the directory between config load and Server.Start. The
// function's real job is the per-startup cleanup of stale scan dirs and
// the surfacing of any interrupted scan queues for auto-resume.
func (s *Server) initDataDir() {
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		log.Printf("Error: failed to create data directory %s: %v", s.dataDir, err)
	}

	// Cleanup scans older than 30 days
	entries, _ := os.ReadDir(s.dataDir)
	cutoff := time.Now().AddDate(0, 0, -30)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Explicitly skip folder names starting with '_' or named 'logos'
		if strings.HasPrefix(e.Name(), "_") || e.Name() == "logos" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.RemoveAll(filepath.Join(s.dataDir, e.Name()))
			log.Printf("Cleaned up old scan: %s", e.Name())
		}
	}

	// Check for interrupted queues — will auto-resume after server starts
	if entries := s.validQueueStateEntries(true); len(entries) > 0 {
		remaining := 0
		for _, entry := range entries {
			remaining += len(entry.state.Targets) - entry.state.CurrentIdx
		}
		log.Printf("Found %d interrupted scan queue(s): %d targets remaining (will auto-resume in 5s)", len(entries), remaining)
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Enforce max client limit
	s.mu.RLock()
	numClients := len(s.clients)
	s.mu.RUnlock()
	if numClients >= wsMaxClients {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}

	// Capture authentication state at upgrade time. authMiddleware has
	// already validated the cookie for us when auth is configured —
	// reaching this handler proves the cookie was valid. When auth is
	// off, only loopback clients get the "authenticated" capability so
	// the agent's brain can't be repointed from off-box.
	ip := clientIP(r)
	loopback := ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
	authed := false
	if authConfigured(s.cfg) {
		// authMiddleware accepted this request, so the session is valid.
		authed = true
	} else {
		authed = loopback
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	client := &wsClient{
		conn:          conn,
		send:          make(chan []byte, wsSendBufSize),
		server:        s,
		authenticated: authed,
		fromLoopback:  loopback,
	}

	s.mu.Lock()
	s.clients[client] = true
	s.mu.Unlock()

	// Start write pump in a goroutine
	go client.writePump()
	// Read pump runs in this goroutine (blocks until disconnect)
	client.readPump()
}

// removeClient safely removes a client from the server's client set.
func (s *Server) removeClient(c *wsClient) {
	s.mu.Lock()
	if _, ok := s.clients[c]; ok {
		delete(s.clients, c)
		close(c.send)
	}
	s.mu.Unlock()
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "targets required", http.StatusBadRequest)
		return
	}
	normalizeScanRequestActivity(&req)

	// Reject up front when every requested target is a local/internal IP or
	// the dashboard's own listener. runMultiScan filters these out anyway,
	// but without this check a fully-blocked request produces a "started"
	// instance with zero effective targets that the operator must then
	// clean up. Surface a 400 instead. Mixed requests (at least one allowed
	// target) proceed and the blocked entries are filtered downstream.
	if !req.SaveOnly {
		allBlocked := true
		for _, t := range req.Targets {
			if strings.TrimSpace(t) == "" {
				continue
			}
			if !s.isBlockedTarget(t) {
				allBlocked = false
				break
			}
		}
		if allBlocked {
			http.Error(w, "all targets are local/internal addresses or the dashboard's own listener; refusing to self-scan", http.StatusBadRequest)
			return
		}
	}

	// R11.6 precondition check: if the request names a
	// provider_profile, fail fast with HTTP 400 BEFORE spawning a
	// scan goroutine. Other resolver errors are intentionally NOT
	// surfaced here — they're either transient (file lock contention
	// during a concurrent profile edit) or downstream concerns the
	// LLM client's own resolver will report when it actually runs
	// the request. This guard exists solely so a misspelled profile
	// id never produces a "started" instance the operator then has
	// to clean up.
	if _, err := s.resolveScanCredentials(r.Context(), req, s.cfg); err != nil {
		if errors.Is(err, errUnknownProviderProfile) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Non-sentinel resolver error (typically a transient
		// flock contention or a profile race-deleted between
		// the dashboard's profile-list fetch and the scan
		// submission). M8: log so the error is visible at
		// triage time rather than being silently swallowed; the
		// LLM client's own resolver will surface a follow-up
		// envelope at first chat call.
		log.Printf("scan: precondition resolveScanCredentials returned non-sentinel error: %v", err)
		// fall through — surface the error only when it is the
		// canonical R11.6 sentinel.
	}

	// Apply LLM provider settings from web UI securely using a copy
	scanCfg := *s.cfg // shallow copy
	if req.Model != "" {
		scanCfg.LLM = req.Model
	}
	if req.APIKey != "" {
		scanCfg.APIKey = req.APIKey
	}
	if req.APIBase != "" {
		scanCfg.APIBase = req.APIBase
	}

	// Save-only mode: create a persistent scan config without starting execution
	if req.SaveOnly {
		instanceID := randomSlug()
		now := time.Now().Format(time.RFC3339Nano)
		inst := &ScanInstance{
			ID:             instanceID,
			Name:           req.Name,
			Targets:        strings.Join(req.Targets, ", "),
			Status:         "saved",
			StartedAt:      now,
			ScanMode:       req.ScanMode,
			Instruction:    req.Instruction,
			SeverityFilter: req.SeverityFilter,
			Phases:         req.Phases,
			ReconMode:      req.ReconMode,
			ScanIntensity:  req.ScanIntensity,
			CurrentPhase:   firstSelectedPhase(req.Phases),
			CompanyName:    req.CompanyName,
			LogoPath:       req.LogoPath,
			DiscordWebhook: req.DiscordWebhook,
		}
		chatCfg := scanCfg
		inst.chatCfg = &chatCfg
		s.instancesMu.Lock()
		s.instances[instanceID] = inst
		s.instancesMu.Unlock()

		// Persist to disk so saved targets survive server restarts
		targetStr := strings.Join(req.Targets, ", ")
		savedDir := filepath.Join(s.dataDir, "_saved", instanceID)
		if err := os.MkdirAll(savedDir, 0700); err != nil {
			log.Printf("[ERROR] failed to create saved-target dir %s: %v", savedDir, err)
		} else {
			rec := &ScanRecord{
				ID:                       instanceID,
				Name:                     req.Name,
				Target:                   targetStr,
				Status:                   "saved",
				StartedAt:                now,
				ScanMode:                 req.ScanMode,
				Instruction:              req.Instruction,
				SeverityFilter:           req.SeverityFilter,
				Phases:                   req.Phases,
				ReconMode:                req.ReconMode,
				ScanIntensity:            req.ScanIntensity,
				CurrentPhase:             firstSelectedPhase(req.Phases),
			CompanyName:              req.CompanyName,
			LogoPath:                 req.LogoPath,
			DiscordWebhook:           req.DiscordWebhook,
			DiscordWebhookConfigured: req.DiscordWebhook != "" || s.discordWebhook != "",
			TelegramConfigured:       s.telegramConfigured(),
		}
			s.saveScanRecordTo(rec, savedDir)
		}

		s.broadcastDashboard(WSEvent{
			Type:    "instance_started",
			Content: instanceID,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved", "instance_id": instanceID})
		return
	}

	// Clear global stop flag so the new scan isn't immediately aborted
	// (fixes starvation bug where scans stay "pending" after Stop All)
	s.stopReq.Store(false)

	instanceID := randomSlug()
	req.Name = strings.TrimSpace(req.Name) // propagate name to running scans too
	go s.runMultiScan(req, &scanCfg, instanceID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "started", "instance_id": instanceID})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.stopReq.Store(true)

	// Cancel the current scan session context (interrupts LLM calls, tool execution)
	s.mu.Lock()
	cancel := s.cancelScan
	// Stop all tracked agents (safe for multi-instance)
	var agents []*agent.Agent
	for _, a := range s.currentAgents {
		agents = append(agents, a)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, agnt := range agents {
		if agnt != nil {
			agnt.Stop()
		}
	}

	// Stop ALL running instances (use write lock since we're modifying instance state)
	s.instancesMu.Lock()
	for _, inst := range s.instances {
		inst.mu.Lock()
		if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
			inst.Status = "stopped"
			inst.StopReason = "user_stopped"
			inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
			if inst.cancel != nil {
				inst.cancel()
			}
			if inst.agent != nil {
				inst.agent.Stop()
			}
		}
		inst.mu.Unlock()
	}
	s.instancesMu.Unlock()

	// Kill all spawned processes as a safety net
	terminal.KillAllProcesses()

	s.broadcast(WSEvent{Type: "stopped", Content: "All instances stopped by user"})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// handleRestart schedules a graceful restart of the backend. The restart is
// never immediate while work is in flight: it waits until no scan instance is
// active and no tool process is leased, then restarts cleanly (in-flight scans
// auto-resume afterwards). This is the HTTP equivalent of
// `xalgorix --restart-when-idle` (SIGUSR1) and shares the same watcher.
//
// POST /api/restart  → { "status": "scheduled"|"already_pending", "idle": bool }
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	idle := s.scannerIdle()
	scheduled := s.scheduleGracefulRestart()

	status := "scheduled"
	if !scheduled {
		status = "already_pending"
	}
	log.Printf("[RESTART] /api/restart requested (idle=%v, status=%s)", idle, status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"idle":   idle,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	scanID := s.currentScanID
	s.mu.RUnlock()

	// Count running instances
	s.instancesMu.RLock()
	runningCount := 0
	runningInstanceID := ""
	currentPhase := 0
	for _, inst := range s.instances {
		inst.mu.RLock()
		if inst.Status == "running" {
			runningCount++
			if runningInstanceID == "" {
				runningInstanceID = inst.ID
				currentPhase = inst.CurrentPhase
			}
		}
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Aggregate vulns across all active instances via their per-session context
	totalVulns := 0
	s.instancesMu.RLock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		if inst.sctx != nil {
			totalVulns += len(reporting.GetVulnerabilitiesForContext(inst.sctx.ID))
		}
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Take a single atomic snapshot of safe counters so the values are
	// internally consistent (Task 11.4 / R9.5).
	counters := safe.Snapshot()
	allowList := sandbox.Default().Roots()
	readDeny := sandbox.Default().ReadDenyRoots()

	// vulns_persisted: total count from on-disk corpus across every scan
	// record. Stable across teardown — survives reporting.CleanupContext.
	// Additive change; the existing `vulns` field keeps its in-memory
	// semantics for backward compatibility. See Task 3.3 in
	// .kiro/specs/findings-consistency-and-pagination/tasks.md.
	persistedVulns := s.totalPersistedVulnCount()

	_ = json.NewEncoder(w).Encode(map[string]any{
		"running":            s.running.Load() || runningCount > 0,
		"scan_id":            scanID,
		"instance_id":        runningInstanceID,
		"current_phase":      currentPhase,
		"vulns":              totalVulns,
		"vulns_persisted":    persistedVulns,
		"running_instances":  runningCount,
		"panics_recovered":   counters.PanicsRecovered,
		"path_rejections":    counters.PathRejections,
		"watchdog_kills":     counters.WatchdogKills,
		"admission_refusals": counters.AdmissionRefusals,
		"llm_inflight_cap":   resources.LLMInFlightCap(),
		"data_dir":           s.cfg.DataDir,
		"allow_list":         allowList,
		// read_deny is the deny-list applied to Filesystem_Tool reads.
		// Reads outside allow_list succeed by default; only paths under
		// these roots are rejected. Set XALGORIX_READ_DENY_LIST
		// (colon-separated) to extend the defaults.
		"read_deny": readDeny,
	})
}

// handleFindingsSummary returns a stable on-disk severity tally across
// every scan record under cfg.DataDir. Used by the WebUI Findings and
// Overview totals widgets to surface a counter that does NOT collapse
// when reporting.CleanupContext wipes in-memory stores during teardown.
//
// Counts are deduplicated by (target, endpoint, title, severity) — the
// same key the WebUI's dedupFindings helper uses. Without this, a
// vulnerability that recurs across N rescans of the same target would
// inflate the totals strip relative to the deduped row count rendered
// below it on /findings.
//
// Response shape:
//
//	{
//	  "totals": {"critical": N, "high": N, "medium": N, "low": N, "info": N},
//	  "as_of": "<RFC3339>",
//	  "etag": "<hex sha256>"
//	}
//
// Honors If-None-Match: returns 304 Not Modified when the etag matches.
// The etag is derived from the marshaled totals plus the seconds-truncated
// as_of timestamp, so it is stable for short polling windows but rotates
// at least once per second when totals change.
//
// See Task 3.2 in .kiro/specs/findings-consistency-and-pagination/tasks.md
// and Property 2 (counter monotonicity) in design.md.
func (s *Server) handleFindingsSummary(w http.ResponseWriter, r *http.Request) {
	totals := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	// Wrap the iteration in safe.Recover so a corrupt scan record cannot
	// kill the handler. (defer + named recover keeps response writing in
	// scope even when the walk panics.)
	func() {
		defer safe.Recover("findings-summary", "")
		seen := make(map[string]struct{})
		for _, entry := range s.findAllScanSummaries() {
			for _, v := range entry.rec.Vulns {
				key := dedupFindingKey(entry.rec.Target, v)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				bucket := normalizeSeverityBucket(v.Severity)
				totals[bucket]++
			}
		}
	}()

	asOf := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)

	// etag: sha256 over (marshaled totals || as_of). Truncating as_of to
	// seconds keeps the etag stable for sub-second polling windows.
	totalsJSON, _ := json.Marshal(totals)
	hash := sha256.New()
	hash.Write(totalsJSON)
	hash.Write([]byte(asOf))
	etag := hex.EncodeToString(hash.Sum(nil))

	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"totals": totals,
		"as_of":  asOf,
		"etag":   etag,
	})
}

// flatFinding is a single vulnerability flattened across scans and augmented
// with its owning scan's identity. The embedded VulnSummary inlines its JSON
// fields, so the wire shape matches the WebUI's FlatFinding type exactly.
type flatFinding struct {
	VulnSummary
	ScanID        string `json:"scan_id"`
	ScanTarget    string `json:"scan_target"`
	ScanStartedAt string `json:"scan_started_at"`
}

// severityRankValue mirrors the WebUI's severityRank so server-side ordering
// matches the client (critical > high > medium > low > info).
func severityRankValue(severity string) int {
	switch normalizeSeverityBucket(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// handleFindingsList returns every finding flattened across all scans, deduped
// by (target, endpoint, title, severity) and sorted by severity desc then
// scan_started_at desc. This replaces the previous WebUI behavior of fetching
// every scan record individually (an N+1 of full-record requests, each
// carrying the scan's entire event log) just to build the findings table.
// One server-side walk returns only the vuln fields the table needs.
func (s *Server) handleFindingsList(w http.ResponseWriter, r *http.Request) {
	deduped := make(map[string]flatFinding)

	func() {
		defer safe.Recover("findings-list", "")
		for _, entry := range s.findAllScanSummaries() {
			rec := entry.rec
			for _, v := range rec.Vulns {
				key := dedupFindingKey(rec.Target, v)
				candidate := flatFinding{
					VulnSummary:   v,
					ScanID:        rec.ID,
					ScanTarget:    rec.Target,
					ScanStartedAt: rec.StartedAt,
				}
				if existing, ok := deduped[key]; ok && existing.ScanStartedAt >= candidate.ScanStartedAt {
					continue
				}
				deduped[key] = candidate
			}
		}
	}()

	findings := make([]flatFinding, 0, len(deduped))
	for _, f := range deduped {
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := severityRankValue(findings[i].Severity), severityRankValue(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].ScanStartedAt > findings[j].ScanStartedAt
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(findings)
}

// handleLegacyImportStatus exposes the in-memory legacy import counter
// surfaced once to the WebUI on the run that did the import. The count
// originates from importLegacyDataDir at startup; this endpoint just
// reads the cached value so the WebUI can render a one-time dismissible
// banner on first load.
//
// Response shape:
//
//	{"count": N, "dismissed": false}
//
// Methods:
//   - GET  → return the current state.
//   - POST → flip dismissed=true for the remainder of the process and
//     return the updated state. Restart re-shows the banner once.
//
// The dismissed flag is in-memory only; restart re-shows. When count==0
// the WebUI suppresses the banner outright (so dismissal of a zero
// state is a harmless no-op).
//
// See Task 5.2 in .kiro/specs/findings-consistency-and-pagination/tasks.md
// and Property 6 (legacy-import idempotence) in design.md.
func (s *Server) handleLegacyImportStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.legacyImportMu.RLock()
		count := s.legacyImportCount
		dismissed := s.legacyImportDismissed
		s.legacyImportMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":     count,
			"dismissed": dismissed,
		})
	case http.MethodPost:
		s.legacyImportMu.Lock()
		s.legacyImportDismissed = true
		count := s.legacyImportCount
		dismissed := s.legacyImportDismissed
		s.legacyImportMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":     count,
			"dismissed": dismissed,
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInstances returns all scan instances (running + recent)
func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.instancesMu.RLock()
	instances := make([]*ScanInstance, 0, len(s.instances))
	for _, inst := range s.instances {
		inst.mu.RLock()
		instances = append(instances, &ScanInstance{
			ID:             inst.ID,
			Name:           inst.Name,
			Targets:        inst.Targets,
			Status:         inst.Status,
			StartedAt:      inst.StartedAt,
			FinishedAt:     inst.FinishedAt,
			Iterations:     inst.Iterations,
			ToolCalls:      inst.ToolCalls,
			VulnCount:      inst.VulnCount,
			TotalTokens:    inst.TotalTokens,
			ScanMode:       inst.ScanMode,
			Instruction:    inst.Instruction,
			SeverityFilter: append([]string(nil), inst.SeverityFilter...),
			Phases:         inst.Phases,
			ReconMode:      inst.ReconMode,
			ScanIntensity:  inst.ScanIntensity,
			CompanyName:    inst.CompanyName,
			LogoPath:       inst.LogoPath,
			CurrentPhase:   inst.CurrentPhase,
		})
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Sort: running first, then by start time descending
	sort.Slice(instances, func(i, j int) bool {
		if instances[i].Status == "running" && instances[j].Status != "running" {
			return true
		}
		if instances[i].Status != "running" && instances[j].Status == "running" {
			return false
		}
		return instances[i].StartedAt > instances[j].StartedAt
	})

	// Distinct scan modes across ALL instances, computed before filtering so
	// the UI's mode dropdown always offers the full set of options.
	modeSet := make(map[string]struct{})
	for _, inst := range instances {
		if inst.ScanMode != "" {
			modeSet[inst.ScanMode] = struct{}{}
		}
	}
	modes := make([]string, 0, len(modeSet))
	for m := range modeSet {
		modes = append(modes, m)
	}
	sort.Strings(modes)

	// Optional server-side filtering (no-ops when the params are absent).
	if q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q"))); q != "" {
		filtered := make([]*ScanInstance, 0, len(instances))
		for _, inst := range instances {
			if strings.Contains(strings.ToLower(inst.Name), q) ||
				strings.Contains(strings.ToLower(inst.Targets), q) ||
				strings.Contains(strings.ToLower(inst.ID), q) {
				filtered = append(filtered, inst)
			}
		}
		instances = filtered
	}
	if st := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status"))); st != "" && st != "all" {
		filtered := make([]*ScanInstance, 0, len(instances))
		for _, inst := range instances {
			if strings.ToLower(inst.Status) == st {
				filtered = append(filtered, inst)
			}
		}
		instances = filtered
	}
	if mode := strings.TrimSpace(r.URL.Query().Get("mode")); mode != "" && mode != "all" {
		filtered := make([]*ScanInstance, 0, len(instances))
		for _, inst := range instances {
			if inst.ScanMode == mode {
				filtered = append(filtered, inst)
			}
		}
		instances = filtered
	}

	// Pagination is opt-in: only slice when a page/size param is present, so
	// the default GET /api/instances response still returns every instance.
	total := len(instances)
	pageStr := r.URL.Query().Get("page")
	sizeStr := r.URL.Query().Get("size")
	page, size := 1, 0
	if pageStr != "" || sizeStr != "" {
		page, size = parsePageParams(pageStr, sizeStr)
		start := (page - 1) * size
		if start < 0 {
			start = 0
		}
		if start > total {
			start = total
		}
		end := start + size
		if end > total {
			end = total
		}
		instances = instances[start:end]
	}
	if instances == nil {
		instances = []*ScanInstance{}
	}

	// Include resource stats so the UI can explain why scans are pending
	stats := resources.GetStats()
	level, _ := resources.CurrentLevel()
	effectiveMax, reason := resources.EffectiveMaxInstances()
	capacity := resources.Capacity()
	response := map[string]any{
		"instances": instances,
		"total":     total,
		"page":      page,
		"size":      size,
		"modes":     modes,
		"resources": map[string]any{
			"cpu_cores":                stats.CPUCores,
			"cpu_load_1m":              stats.LoadAvg1m,
			"ram_total_mb":             stats.MemTotalMB,
			"ram_available_mb":         stats.MemAvailableMB,
			"disk_free_mb":             stats.DiskFreeMB,
			"process_rss_mb":           stats.ProcessRSSMB,
			"go_heap_alloc_mb":         stats.GoHeapAllocMB,
			"go_heap_sys_mb":           stats.GoHeapSysMB,
			"goroutines":               stats.Goroutines,
			"level":                    level.String(),
			"reason":                   reason,
			"max_instances":            effectiveMax,
			"manual_max_instances":     resources.MaxInstances(),
			"effective_max_instances":  effectiveMax,
			"active_tool_leases":       capacity.ActiveToolLeases,
			"active_heavy_tool_leases": capacity.ActiveHeavyToolLeases,
			"heavy_tool_slots":         capacity.HeavyToolSlots,
			"light_tool_slots":         capacity.LightToolSlots,
			"tool_mem_limit_mb":        capacity.ToolMemLimitMB,
			"scan_memory_budget_mb":    capacity.ScanMemoryBudgetMB,
			"heavy_tool_cpu_load":      capacity.HeavyToolCPULoad,
			"go_memory_limit_mb":       capacity.GoMemoryLimitMB,
		},
	}
	_ = json.NewEncoder(w).Encode(response)
}

// handleInstanceAction handles per-instance operations (stop, etc)
func (s *Server) handleInstanceAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Path: /api/instances/{id}/stop or /api/instances/{id}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/instances/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "instance ID required", http.StatusBadRequest)
		return
	}
	instanceID := parts[0]

	s.instancesMu.RLock()
	inst, ok := s.instances[instanceID]
	s.instancesMu.RUnlock()
	if !ok {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}

	// GET /api/instances/{id} — return instance details
	if r.Method == http.MethodGet && (len(parts) == 1 || parts[1] == "") {
		inst.mu.RLock()
		_ = json.NewEncoder(w).Encode(inst)
		inst.mu.RUnlock()
		return
	}

	// POST /api/instances/{id}/stop — stop specific instance
	if len(parts) >= 2 && parts[1] == "stop" && r.Method == http.MethodPost {
		inst.mu.Lock()
		// Queued scans are stoppable too, even before they acquire resources.
		if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
			inst.Status = "stopped"
			inst.StopReason = "user_stopped"
			inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
			if inst.cancel != nil {
				inst.cancel()
			}
			if inst.agent != nil {
				inst.agent.Stop()
			}
		}
		inst.mu.Unlock()

		// Broadcast stop to clients watching this instance
		s.broadcastToInstance(instanceID, WSEvent{Type: "stopped", Content: "Instance stopped by user"})
		// Broadcast update to dashboard clients
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped", "instance_id": instanceID})
		return
	}

	// POST /api/instances/{id}/restart — restart scan with same config
	if len(parts) >= 2 && parts[1] == "restart" && r.Method == http.MethodPost {
		// Avoid creating a duplicate scan against the same targets while this
		// instance is still active.
		inst.mu.RLock()
		currentStatus := inst.Status
		inst.mu.RUnlock()
		if currentStatus == "running" || currentStatus == "pending" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot restart: instance is still " + currentStatus,
			})
			return
		}

		inst.mu.RLock()
		targets := strings.Split(inst.Targets, ", ")
		instruction := inst.Instruction
		scanMode := inst.ScanMode
		severityFilter := inst.SeverityFilter
		discordWebhook := inst.DiscordWebhook
		phases := inst.Phases
		reconMode := inst.ReconMode
		scanIntensity := inst.ScanIntensity
		companyName := inst.CompanyName
		logoPath := inst.LogoPath
		instName := inst.Name
		inst.mu.RUnlock()

		// Clear global stop flag so the restarted scan isn't immediately aborted
		// by the queue wait loop checking stopReq.
		s.stopReq.Store(false)

		// Build a new ScanRequest from stored config
		req := ScanRequest{
			Targets:        targets,
			Instruction:    instruction,
			ScanMode:       scanMode,
			SeverityFilter: severityFilter,
			DiscordWebhook: discordWebhook,
			Name:           instName,
			Phases:         phases,
			ReconMode:      reconMode,
			ScanIntensity:  scanIntensity,
			CompanyName:    companyName,
			LogoPath:       logoPath,
		}

		scanCfg := *s.cfg // shallow copy
		go s.runMultiScan(req, &scanCfg)

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "restarted"})
		return
	}

	// POST /api/instances/{id}/start — start a saved scan, or start a new
	// run from an existing finished/stopped/failed scan's saved config.
	if len(parts) >= 2 && parts[1] == "start" && r.Method == http.MethodPost {
		inst.mu.RLock()
		currentStatus := strings.ToLower(strings.TrimSpace(inst.Status))
		inst.mu.RUnlock()
		if !canStartInstanceStatus(currentStatus) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot start: instance is " + currentStatus,
			})
			return
		}

		inst.mu.RLock()
		targets := strings.Split(inst.Targets, ", ")
		req := ScanRequest{
			Targets:        targets,
			Instruction:    inst.Instruction,
			ScanMode:       inst.ScanMode,
			SeverityFilter: inst.SeverityFilter,
			DiscordWebhook: inst.DiscordWebhook,
			Name:           inst.Name,
			Phases:         inst.Phases,
			ReconMode:      inst.ReconMode,
			ScanIntensity:  inst.ScanIntensity,
			CompanyName:    inst.CompanyName,
			LogoPath:       inst.LogoPath,
		}
		inst.mu.RUnlock()

		if currentStatus == "saved" {
			// Remove the saved placeholder — runMultiScan creates a new
			// pending/running instance. Finished scans are kept so their
			// reports remain available while the new run starts separately.
			s.instancesMu.Lock()
			delete(s.instances, instanceID)
			s.instancesMu.Unlock()

			savedDir := filepath.Join(s.dataDir, "_saved", instanceID)
			_ = os.RemoveAll(savedDir)
		}

		s.stopReq.Store(false)
		scanCfg := *s.cfg
		newID := randomSlug()
		go s.runMultiScan(req, &scanCfg, newID)

		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "started", "instance_id": newID})
		return
	}

	// POST /api/instances/{id}/pause — gracefully pause a running scan
	if len(parts) >= 2 && parts[1] == "pause" && r.Method == http.MethodPost {
		inst.mu.Lock()
		if inst.Status != "running" {
			inst.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot pause: instance is " + inst.Status,
			})
			return
		}
		inst.Status = "paused"
		inst.StopReason = "user_paused"
		if inst.cancel != nil {
			inst.cancel()
		}
		if inst.agent != nil {
			inst.agent.Stop()
		}
		inst.mu.Unlock()

		s.broadcastToInstance(instanceID, WSEvent{Type: "paused", Content: "Scan paused by user"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "paused", "instance_id": instanceID})
		return
	}

	// POST /api/instances/{id}/resume — resume a paused scan
	if len(parts) >= 2 && parts[1] == "resume" && r.Method == http.MethodPost {
		inst.mu.RLock()
		currentStatus := inst.Status
		inst.mu.RUnlock()
		if currentStatus != "paused" {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot resume: instance is " + currentStatus + ", expected paused",
			})
			return
		}

		req, ok, reason := s.scanRequestForPausedInstance(instanceID, inst)
		if !ok {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot resume: " + reason,
			})
			return
		}

		// Remove the paused instance — a new one will be created by runMultiScan
		s.instancesMu.Lock()
		delete(s.instances, instanceID)
		s.instancesMu.Unlock()

		s.stopReq.Store(false)
		scanCfg := *s.cfg
		newID := randomSlug()
		go s.runMultiScan(req, &scanCfg, newID)

		s.broadcastToInstance(instanceID, WSEvent{Type: "resumed", Content: "Scan resumed"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "resumed", "instance_id": newID})
		return
	}

	// GET /api/instances/{id}/events — return buffered event history
	if len(parts) >= 2 && parts[1] == "events" && r.Method == http.MethodGet {
		inst.mu.RLock()
		events := make([]WSEvent, len(inst.events))
		copy(events, inst.events)
		inst.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(events)
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}

// ────────────────────────────────────────────────────────
// scanSession — self-contained unit for a single scan run
// ────────────────────────────────────────────────────────

// scanSession isolates all per-scan state. Crashes in one session
// cannot corrupt server-level state or leak into subsequent scans.
type scanSession struct {
	id                string
	target            string
	parentTarget      string // parent domain for subdomain scans (wildcard mode)
	scanDir           string
	cfg               *config.Config
	agent             *agent.Agent
	events            chan agent.Event
	record            *ScanRecord
	recordTokenOffset int
	server            *Server
	instruction       string
	name              string
	userInstruction   string
	severityFilter    []string
	discordWebhook    string
	discoveryMode     bool
	genReport         bool
	resetState        bool
	instanceID        string               // parent instance ID for multi-instance tracking
	scanMode          string               // single, wildcard, dast — persisted so dashboard shows correct mode
	sctx              *scanctx.ScanContext // per-session isolated state
	companyName       string               // report branding: company name
	logoPath          string               // report branding: logo path
	phases            []int                // selected methodology phases
	reconMode         string               // active or passive reconnaissance
	scanIntensity     string               // active or passive testing/scanning

	// llmClient, when non-nil, is a pre-built llm.Client carrying
	// a per-scan endpoint resolver derived from the originating
	// ScanRequest.ProviderProfile (B1). executeScanSession threads
	// it into agent.NewAgent via agent.WithLLMClient so the scan's
	// outbound traffic actually uses the operator's chosen
	// credentials. nil falls back to the agent's default
	// llm.NewClient(cfg) construction, preserving the prior
	// behavior for tests and CLI paths that have not opted in.
	llmClient *llm.Client

	// Wildcard lifecycle flags
	skipNotesCleanup     bool   // when true, don't delete notes store on cleanup (discovery phase)
	parentReportingCtxID string // stable context ID for accumulating vulns across wildcard subdomain scans
}

// cleanup tears down all per-session resources. Every sub-operation
// has its own panic guard so cleanup NEVER panics upward.
func (sess *scanSession) cleanup() {
	// Deactivate and close the per-session ScanContext (if set).
	// Close() calls Terminal.KillAll() and Browser.Close() internally,
	// so no redundant calls are needed below.
	if sess.sctx != nil {
		func() {
			defer logRecover("cleanup.scanctx.close")
			scanctx.Deactivate(sess.sctx.ID)
			sess.sctx.Close()
		}()
	}

	// Clean up tool-level context stores to prevent unbounded memory growth.
	// Each tool package maintains a map[contextID]→store that must be cleared.
	if sess.sctx != nil {
		// Panic-safe persistence (Property 4 / spec
		// findings-consistency-and-pagination Wave C 4.2): persist
		// any in-memory vulns reported via report_vulnerability into
		// the on-disk scan record, and merge this child session's
		// vulns into the parent reporting context, BEFORE we delete
		// the in-memory reporting store via CleanupContext below.
		//
		// Each merge runs in its own safe.Recover boundary so a
		// panic in one branch does not skip the other. Both merges
		// are idempotent (mergeReportedVulnerabilitiesIntoRecord
		// dedups via appendVulnSummaryUnique keyed on
		// title|target|endpoint|method|CVE; MergeVulnsToContext
		// skips ID duplicates and semantic duplicates), so even when
		// the success path has already saved a partial record this
		// deferred call is a no-op for vulns it has already
		// persisted.
		func() {
			defer safe.Recover("cleanup.scanrecord.merge", sess.sctx.ID)
			if sess.record == nil {
				return
			}
			before := len(sess.record.Vulns)
			mergeReportedVulnerabilitiesIntoRecord(sess.record, reporting.GetVulnerabilitiesForContext(sess.sctx.ID))
			if added := len(sess.record.Vulns) - before; added > 0 {
				log.Printf("[cleanup] Persisted %d in-memory vulns into scan.json for session %s", added, sess.sctx.ID)
			}
			sess.server.saveScanRecordTo(sess.record, sess.scanDir)
		}()

		// Wildcard vuln accumulation: merge this session's vulns into
		// the parent reporting context BEFORE we delete this session's
		// reporting store.
		if sess.parentReportingCtxID != "" {
			func() {
				defer safe.Recover("cleanup.reporting.merge", sess.sctx.ID)
				merged := reporting.MergeVulnsToContext(sess.sctx.ID, sess.parentReportingCtxID)
				if merged > 0 {
					log.Printf("[wildcard] Merged %d vulns from session %s into parent context %s", merged, sess.sctx.ID, sess.parentReportingCtxID)
				}
			}()
		}

		func() {
			defer logRecover("cleanup.reporting.cleanup")
			reporting.CleanupContext(sess.sctx.ID)
		}()
		if !sess.skipNotesCleanup {
			func() {
				defer logRecover("cleanup.notes.cleanup")
				notes.CleanupContext(sess.sctx.ID)
			}()
		} else {
			log.Printf("[wildcard] Skipping notes cleanup for discovery session %s (notes preserved for subdomain collection)", sess.sctx.ID)
		}
		func() {
			defer logRecover("cleanup.terminal.cleanup")
			terminal.CleanupContext(sess.sctx.ID)
		}()
		func() {
			defer logRecover("cleanup.browser.cleanup")
			browser.CleanupContext(sess.sctx.ID)
		}()
	}

	// Fallback process kill if sctx was never initialized
	if sess.sctx == nil {
		func() {
			defer logRecover("cleanup.terminal.killAll")
			terminal.KillAllProcesses()
		}()
	}

	// Stop agent if still running
	if sess.agent != nil {
		func() {
			defer logRecover("cleanup.agent.stop")
			sess.agent.Stop()
		}()
	}

	// Clear sub-agent state to prevent memory/goroutine leaks across scans.
	// Only safe when this is the sole running scan — global reset would corrupt
	// concurrent sessions.
	sess.server.instancesMu.RLock()
	runningCount := 0
	for _, inst := range sess.server.instances {
		inst.mu.RLock()
		if inst.Status == "running" {
			runningCount++
		}
		inst.mu.RUnlock()
	}
	sess.server.instancesMu.RUnlock()
	if runningCount <= 1 {
		func() {
			defer logRecover("cleanup.agentsgraph.reset")
			agentsgraph.Reset()
		}()
	}

	// Clear terminal working directory to prevent stale workdir leaking to next session
	func() {
		defer logRecover("cleanup.terminal.setWorkDir")
		if sess.sctx != nil && sess.sctx.Terminal != nil {
			sess.sctx.Terminal.SetWorkDir("")
		} else {
			terminal.SetWorkDir("") // fallback if sctx not initialized
		}
	}()

	// Clear server references under lock
	sess.server.mu.Lock()
	delete(sess.server.currentAgents, sess.id)
	sess.server.mu.Unlock()
}

func (s *Server) scanRecordForSession(sess *scanSession) *ScanRecord {
	startedAt := time.Now().Format(time.RFC3339)
	rec := s.freshScanRecordForSession(sess, startedAt)
	sess.recordTokenOffset = 0

	if sess.resetState {
		return rec
	}

	existing, ok := loadScanRecordFromDir(sess.scanDir)
	if !ok || existing == nil {
		return rec
	}
	if existing.ID != "" && existing.ID != sess.id {
		log.Printf("[AUTO-RESUME] Ignoring scan record %s in %s while resuming %s", existing.ID, sess.scanDir, sess.id)
		return rec
	}

	rec = existing
	s.refreshResumedScanRecord(rec, sess, startedAt)
	sess.recordTokenOffset = rec.TotalTokens
	return rec
}

func (s *Server) freshScanRecordForSession(sess *scanSession, startedAt string) *ScanRecord {
	return &ScanRecord{
		ID:                       sess.id,
		InstanceID:               sess.instanceID,
		Name:                     sess.name,
		Target:                   sess.target,
		ParentTarget:             sess.parentTarget,
		ScanMode:                 sess.scanMode,
		Instruction:              sess.userInstruction,
		SeverityFilter:           append([]string(nil), sess.severityFilter...),
		DiscordWebhook:           sess.discordWebhook,
		DiscordWebhookConfigured: sess.discordWebhook != "" || s.discordWebhook != "",
		TelegramConfigured:       s.telegramConfigured(),
		ReconMode:                normalizeActivityMode(sess.reconMode),
		ScanIntensity:            normalizeActivityMode(sess.scanIntensity),
		StartedAt:                startedAt,
		Status:                   "running",
		Events:                   []WSEvent{},
		Vulns:                    []VulnSummary{},
		CompanyName:              sess.companyName,
		LogoPath:                 sess.logoPath,
		Phases:                   append([]int(nil), sess.phases...),
		CurrentPhase:             firstSelectedPhase(sess.phases),
	}
}

func (s *Server) refreshResumedScanRecord(rec *ScanRecord, sess *scanSession, fallbackStartedAt string) {
	if rec.ID == "" {
		rec.ID = sess.id
	}
	rec.InstanceID = sess.instanceID
	if sess.name != "" || rec.Name == "" {
		rec.Name = sess.name
	}
	rec.Target = sess.target
	rec.ParentTarget = sess.parentTarget
	rec.ScanMode = sess.scanMode
	if sess.userInstruction != "" || rec.Instruction == "" {
		rec.Instruction = sess.userInstruction
	}
	rec.SeverityFilter = append([]string(nil), sess.severityFilter...)
	rec.DiscordWebhook = sess.discordWebhook
	rec.DiscordWebhookConfigured = sess.discordWebhook != "" || s.discordWebhook != ""
	rec.TelegramConfigured = s.telegramConfigured()
	rec.ReconMode = normalizeActivityMode(sess.reconMode)
	rec.ScanIntensity = normalizeActivityMode(sess.scanIntensity)
	if rec.StartedAt == "" {
		rec.StartedAt = fallbackStartedAt
	}
	rec.Status = "running"
	rec.FinishedAt = ""
	rec.StopReason = ""
	if rec.Events == nil {
		rec.Events = []WSEvent{}
	}
	if rec.Vulns == nil {
		rec.Vulns = []VulnSummary{}
	}
	if sess.companyName != "" || rec.CompanyName == "" {
		rec.CompanyName = sess.companyName
	}
	if sess.logoPath != "" || rec.LogoPath == "" {
		rec.LogoPath = sess.logoPath
	}
	rec.Phases = append([]int(nil), sess.phases...)
	if rec.CurrentPhase == 0 || !phaseAllowed(sess.phases, rec.CurrentPhase) {
		rec.CurrentPhase = firstSelectedPhase(sess.phases)
	}
}

func mergeReportedVulnerabilitiesIntoRecord(rec *ScanRecord, reported []reporting.Vulnerability) {
	if rec == nil {
		return
	}
	existing := append([]VulnSummary(nil), rec.Vulns...)
	rec.Vulns = make([]VulnSummary, 0, len(existing)+len(reported))
	for _, vuln := range existing {
		appendVulnSummaryUnique(&rec.Vulns, vuln)
	}
	for _, vuln := range reported {
		appendVulnSummaryUnique(&rec.Vulns, vulnToSummary(vuln))
	}
}

// effectiveVulnCount returns the most stable counter source for an instance.
// Strategy: prefer in-memory while running (live), fall back to on-disk
// VulnCount once the scan is finished or torn down (stable across teardown).
//
// This consolidates the three triple-source assignments at the legacy
// VulnCount call sites (resume seeding and per-event status update),
// which previously caused visible counter drift as the scan moved between
// phases. See Property 2 (counter monotonicity) in
// .kiro/specs/findings-consistency-and-pagination/design.md.
//
// When sess is non-nil and the instance is actively running, the count
// comes from reporting.GetVulnerabilitiesForContext, preferring the
// parent reporting context when present (covers wildcard child sessions).
// In every other state — finished, stopped, errored, paused, torn down —
// the count comes from len(inst.Vulns), the on-disk-derived in-memory
// mirror that survives reporting.CleanupContext.
//
// The caller is responsible for holding inst.mu at the appropriate level
// (RLock to read inst.Status / inst.Vulns, Lock when assigning the
// returned value back into inst.VulnCount).
func (s *Server) effectiveVulnCount(inst *ScanInstance, sess *scanSession) int {
	if inst == nil {
		return 0
	}
	if sess != nil && inst.Status == "running" {
		ctxID := ""
		if sess.parentReportingCtxID != "" {
			ctxID = sess.parentReportingCtxID
		} else if sess.sctx != nil {
			ctxID = sess.sctx.ID
		}
		if ctxID != "" {
			return len(reporting.GetVulnerabilitiesForContext(ctxID))
		}
	}
	return len(inst.Vulns)
}

// totalPersistedVulnCount returns the total number of persisted (on-disk)
// vulnerabilities across every scan record under cfg.DataDir, deduplicated
// by (target, endpoint, title, severity). This is the stable on-disk
// corpus used by both /api/findings/summary and the vulns_persisted field
// on /api/status. The dedup matches the WebUI's dedupFindings helper so
// the totals strip and the row count never disagree. See Property 2
// (counter monotonicity) — the on-disk total is monotonic-non-decreasing
// across teardown because reporting.CleanupContext does not touch
// ScanRecord.Vulns.
func (s *Server) totalPersistedVulnCount() int {
	seen := make(map[string]struct{})
	for _, entry := range s.findAllScanSummaries() {
		for _, v := range entry.rec.Vulns {
			key := dedupFindingKey(entry.rec.Target, v)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
		}
	}
	return len(seen)
}

// dedupFindingKey computes the same lowercase (target, endpoint, title,
// severity) key the WebUI's dedupFindings helper uses, so the server
// counter sources and the WebUI row list are always in agreement.
//
// Severity is bucketed via normalizeSeverityBucket so "Informational",
// "info", and "" all collapse to "info" (mirrors the WebUI's
// normalizeSeverity).
func dedupFindingKey(target string, v VulnSummary) string {
	return strings.ToLower(strings.TrimSpace(target)) + "|" +
		strings.ToLower(strings.TrimSpace(v.Endpoint)) + "|" +
		strings.ToLower(strings.TrimSpace(v.Title)) + "|" +
		normalizeSeverityBucket(v.Severity)
}

// normalizeSeverityBucket folds free-form severity strings into one of
// the five canonical buckets. Mirrors the WebUI's normalizeSeverity so
// server-side dedup keys match client-side ones.
func normalizeSeverityBucket(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func (s *Server) seedResumeInstanceFromRecord(inst *ScanInstance, req ScanRequest) {
	if inst == nil || !req.IsResume || req.ResumeScanDir == "" {
		return
	}
	rec, ok := loadScanRecordFromDir(req.ResumeScanDir)
	if !ok || rec == nil {
		return
	}
	if rec.StartedAt != "" {
		inst.StartedAt = rec.StartedAt
	}
	if rec.Name != "" {
		inst.Name = rec.Name
	}
	if rec.Target != "" && strings.TrimSpace(inst.Targets) == "" {
		inst.Targets = rec.Target
	}
	if rec.ScanMode != "" {
		inst.ScanMode = rec.ScanMode
	}
	if rec.Instruction != "" {
		inst.Instruction = rec.Instruction
	}
	if len(rec.SeverityFilter) > 0 {
		inst.SeverityFilter = append([]string(nil), rec.SeverityFilter...)
	}
	if len(rec.Phases) > 0 {
		inst.Phases = append([]int(nil), rec.Phases...)
	}
	if rec.ReconMode != "" {
		inst.ReconMode = rec.ReconMode
	}
	if rec.ScanIntensity != "" {
		inst.ScanIntensity = rec.ScanIntensity
	}
	if rec.CompanyName != "" {
		inst.CompanyName = rec.CompanyName
	}
	if rec.LogoPath != "" {
		inst.LogoPath = rec.LogoPath
	}
	inst.Iterations = rec.Iterations
	inst.ToolCalls = rec.ToolCalls
	inst.TotalTokens = rec.TotalTokens
	inst.Vulns = append([]VulnSummary(nil), rec.Vulns...)
	// Resume path: scan is being seeded from on-disk record, no live session
	// exists yet, so effectiveVulnCount falls back to len(inst.Vulns).
	inst.VulnCount = s.effectiveVulnCount(inst, nil)
	if rec.CurrentPhase > 0 {
		inst.CurrentPhase = rec.CurrentPhase
	}
	events := rec.Events
	if len(events) > 500 {
		events = events[len(events)-500:]
	}
	inst.events = append([]WSEvent(nil), events...)
}

// executeScanSession runs a single scan in complete isolation.
// It NEVER panics upward — all panics are caught and logged.
func (s *Server) executeScanSession(sess *scanSession) {
	// IRONCLAD: This function NEVER panics upward.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] scanSession %s panicked: %v\n%s", sess.id, r, debug.Stack())
			if sess.instanceID != "" {
				s.broadcastToInstance(sess.instanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
			} else {
				s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
			}
		}
		// ALWAYS clean up, whether normal exit or panic
		sess.cleanup()
	}()

	// 0. Create and activate a per-session ScanContext for isolation.
	//    This must happen BEFORE any tool state is touched.
	sctx := scanctx.New(sess.id, sess.scanDir)
	scanctx.Activate(sctx)
	sess.sctx = sctx
	log.Printf("[scanctx] Activated context %s for target %s (dir=%s)", sctx.ID, sess.target, sess.scanDir)

	// Panic-safe persistence: register the child→parent reporting mapping so
	// reporting.PromoteToParent runs incrementally on every report_vulnerability
	// call. CleanupContext clears the mapping on session teardown.
	if sess.parentReportingCtxID != "" {
		reporting.SetParentContext(sctx.ID, sess.parentReportingCtxID)
	}

	// Propagate ScanContext to parent instance (if multi-instance mode)
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			inst.sctx = sctx
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// 1. Reset per-context state if requested (context-aware)
	if sess.resetState {
		func() {
			defer logRecover("session.resetContextState")
			reporting.ResetVulnerabilitiesForContext(sctx.ID)
			notes.ResetNotesForContext(sctx.ID)
		}()
	}

	// 1b. Configure notes disk persistence → saves notes.json in scan directory
	notes.SetPersistPathForContext(sctx.ID, sess.scanDir)
	if !sess.resetState {
		// Resume scenario: load previously saved notes from disk
		notes.LoadFromDiskForContext(sctx.ID)
	}

	// 2. Set working directory (context-aware)
	sctx.Terminal.SetWorkDir(sess.scanDir)
	sctx.Browser.SetSessionPath(sess.scanDir)

	// 3. Create agent with session's config AND ScanContext.
	// When the per-scan code path supplied a pre-resolved llm.Client
	// (B1: provider_profile-aware endpoint), thread it through
	// agent.WithLLMClient so the agent's outbound traffic actually
	// uses the operator's chosen credentials. A nil llmClient falls
	// back to the agent's default llm.NewClient(cfg) construction,
	// preserving the legacy behavior for tests / CLI / call sites
	// that have not opted in.
	events := make(chan agent.Event, 512)
	sess.events = events
	agentOpts := []any{sctx}
	if sess.llmClient != nil {
		agentOpts = append(agentOpts, agent.WithLLMClient(sess.llmClient))
	}
	agnt := agent.NewAgent(sess.cfg, "XalgorixAgent", events, scopeguard.Config{
		BindAddr: s.cfg.BindAddr,
		Port:     s.port,
	}, agentOpts...)
	agnt.SetPhaseRestrictions(sess.phases)
	agnt.SetActivityPolicy(sess.reconMode, sess.scanIntensity, []string{sess.target, sess.parentTarget})
	if sess.discoveryMode || isReconReportOnlyPhaseSelection(sess.phases) {
		agnt.SetDiscoveryMode(true)
	}
	sess.agent = agnt

	// Store agent ref on server for handleStop/handleChat (under lock)
	s.mu.Lock()
	s.currentScanDir = sess.scanDir
	s.currentScanID = sess.id
	s.currentAgents[sess.id] = agnt
	s.mu.Unlock()

	// Register agent with parent instance if applicable
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			inst.agent = agnt
			inst.scanDir = sess.scanDir
			inst.lastSessionTokens = 0 // reset token delta for this new session/phase
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// 4. Initialize scan record. Resume paths preserve previously persisted
	// events, vulnerabilities, counters, and sub-scan progress.
	sess.record = s.scanRecordForSession(sess)
	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 5. Event processing goroutine — drains events and broadcasts to WebSocket
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] Event processor panicked: %v — continuing\n%s", r, debug.Stack())
			}
		}() // never let panic escape event processor
		for evt := range events {
			s.processEvent(evt, sess)
		}
	}()

	// 6. Build instruction with severity filter
	instruction := sess.instruction
	if len(sess.severityFilter) > 0 {
		instruction = buildSeverityPrefix(sess.severityFilter) + "\n\n" + instruction
	}

	// 7. Run agent (blocks until finished or stopped)
	agnt.Run([]string{sess.target}, instruction)

	// 8. Close events channel and wait for event processor to drain
	close(events)
	<-done

	if status, stopReason := s.instanceRunStatus(sess.instanceID); isInterruptedInstanceStatus(status) {
		sess.record.Status = status
		sess.record.StopReason = stopReason
		sess.record.FinishedAt = time.Now().Format(time.RFC3339)
		// NOTE: in-memory→record merge and child→parent reporting merge
		// are deferred to sess.cleanup() (Wave C 4.2) so they survive an
		// agent panic. The deferred path is idempotent: merge dedups by
		// vuln summary key and MergeVulnsToContext skips ID/semantic
		// duplicates, so the success path merges exactly once.
		s.saveScanRecordTo(sess.record, sess.scanDir)
		return
	}

	// 9. Finalize record
	sess.record.Status = "finished"
	sess.record.FinishedAt = time.Now().Format(time.RFC3339)

	// NOTE: merges are deferred to sess.cleanup() (Wave C 4.2) under
	// safe.Recover boundaries to guarantee panic-safe persistence. Both
	// mergeReportedVulnerabilitiesIntoRecord and MergeVulnsToContext are
	// idempotent (each entry keyed by vuln id / summary tuple), so the
	// clean-finish path runs the merges exactly once via cleanup().

	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 10. Generate report if requested (always generate, even for clean scans)
	if sess.genReport {
		if p, err := s.generateReportAt(sess.record, sess.scanDir); err == nil {
			log.Printf("PDF report saved: %s", p)
			vulnCount := len(sess.record.Vulns)
			if vulnCount > 0 {
				desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found\n**Completed at:** %s",
					sess.target, vulnCount, time.Now().Format("15:04:05 MST"))
				s.sendDiscordWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", desc, p)
				if s.telegramConfigured() {
					s.sendTelegramWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", desc, p)
				}
			} else {
				desc := fmt.Sprintf("**Target:** %s\n**Result:** No vulnerabilities found (clean scan)\n**Completed at:** %s",
					sess.target, time.Now().Format("15:04:05 MST"))
				s.sendDiscordWithFile(0x2dd4bf, "✅ Scan Finished - Clean Report", desc, p)
				if s.telegramConfigured() {
					s.sendTelegramWithFile(0x2dd4bf, "✅ Scan Finished - Clean Report", desc, p)
				}
			}
			if sess.instanceID != "" {
				reportEvt := WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)}
				if phaseAllowed(sess.phases, 22) {
					reportEvt.CurrentPhase = 22
				}
				s.broadcastToInstance(sess.instanceID, reportEvt)
			} else {
				s.broadcast(WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)})
			}
		} else {
			log.Printf("Failed to generate PDF report: %v", err)
		}
	}
}

// processEvent handles a single agent event — forwards to WebSocket, updates scan record, sends Discord.
func (s *Server) processEvent(evt agent.Event, sess *scanSession) {
	wsEvt := WSEvent{
		Type:        evt.Type,
		Content:     evt.Content,
		ToolName:    evt.ToolName,
		ToolArgs:    evt.ToolArgs,
		AgentID:     evt.AgentID,
		Timestamp:   evt.Timestamp.Format(time.RFC3339),
		TotalTokens: evt.TotalTokens,
	}

	if evt.Type == "tool_result" {
		wsEvt.Output = evt.ToolResult.Output
		wsEvt.Error = evt.ToolResult.Error

		// Push vuln to UI in real-time when report_vulnerability succeeds
		if evt.ToolName == "report_vulnerability" && evt.ToolResult.Error == "" {
			vulnID, reported := metadataString(evt.ToolResult.Metadata, "vuln_id")
			if !reported {
				log.Printf("[VULN] report_vulnerability returned without a new vuln_id; not broadcasting stored vuln again")
			} else {
				vulns := reporting.GetVulnerabilitiesForContext(sess.sctx.ID)
				log.Printf("[VULN] report_vulnerability tool created %s, vulns in list: %d", vulnID, len(vulns))
				latest, found := findReportedVulnerabilityByID(vulns, vulnID)
				if !found {
					log.Printf("[VULN] report_vulnerability metadata referenced %s, but it was not found in context %s", vulnID, sess.sctx.ID)
				} else {
					vs := vulnToSummary(latest)
					log.Printf("[VULN] Latest vuln: %s %s (CVSS %.1f)", vs.Severity, vs.Title, vs.CVSS)

					// Severity filter is a DISPLAY/BROADCAST gate, NOT a
					// persistence gate. Every vuln the agent reports must be
					// persisted to the scan record (and thus the on-disk
					// scan.json + the PDF report) so the report reflects
					// everything found — not just the severities the operator
					// chose to surface live. Filtering here previously dropped
					// below-threshold vulns from the record entirely, causing
					// "report shows no findings but logs show critical" (#157
					// customer feedback).
					allowed := true
					if len(sess.severityFilter) > 0 {
						allowed = false
						for _, sev := range sess.severityFilter {
							if strings.EqualFold(sev, vs.Severity) {
								allowed = true
								break
							}
						}
						log.Printf("[VULN] Severity filter active: filter=%v, allowed=%v", sess.severityFilter, allowed)
					}

					// Always persist to the record (report + on-disk source of truth).
					if appendVulnSummaryUnique(&sess.record.Vulns, vs) {
						log.Printf("[VULN] Vuln persisted to record: %s %s", vs.Severity, vs.Title)
						// Broadcast + notify only when the severity filter allows it.
						if allowed {
							wsEvt.Vulns = []VulnSummary{vs}
							log.Printf("[VULN] Vuln broadcast real-time: %s %s", vs.Severity, vs.Title)

							// Discord: vulnerability found (respects XALGORIX_DISCORD_MIN_SEVERITY)
							sevColor := 0xef4444 // red for critical/high
							switch vs.Severity {
							case "medium":
								sevColor = 0xd97706
							case "low", "info":
								sevColor = 0x3b82f6
							}
							var details strings.Builder
							details.WriteString(fmt.Sprintf("**%s**\n\n", vs.Title))
							if vs.Description != "" {
								details.WriteString(fmt.Sprintf("📝 **Description:**\n%s\n\n", vs.Description))
							}
							if vs.Endpoint != "" {
								details.WriteString(fmt.Sprintf("🔗 **Endpoint:** `%s`\n", vs.Endpoint))
							}
							if vs.Method != "" {
								details.WriteString(fmt.Sprintf("📡 **Method:** `%s`\n", vs.Method))
							}
							if vs.CVE != "" {
								details.WriteString(fmt.Sprintf("🏷️ **CVE:** `%s`\n", vs.CVE))
							}
							details.WriteString(fmt.Sprintf("📊 **CVSS:** `%.1f` | **Severity:** `%s`\n\n", vs.CVSS, strings.ToUpper(vs.Severity)))
							if vs.Impact != "" {
								details.WriteString(fmt.Sprintf("💥 **Impact:**\n%s\n\n", vs.Impact))
							}
							if vs.TechnicalAnalysis != "" {
								details.WriteString(fmt.Sprintf("🔬 **Technical Analysis:**\n%s\n\n", vs.TechnicalAnalysis))
							}
							if vs.PoCDescription != "" {
								details.WriteString(fmt.Sprintf("🧪 **PoC:**\n%s\n", vs.PoCDescription))
							}
							if vs.PoCScript != "" {
								poc := vs.PoCScript
								if len(poc) > 800 {
									poc = poc[:800] + "\n... (truncated)"
								}
								details.WriteString(fmt.Sprintf("```\n%s\n```\n\n", poc))
							}
							if vs.Remediation != "" {
								details.WriteString(fmt.Sprintf("🛡️ **Remediation:**\n%s", vs.Remediation))
							}
						// Apply Discord minimum severity filter
						if severityMeetsThreshold(vs.Severity, s.discordMinSeverity) {
							s.sendDiscord(sevColor, fmt.Sprintf("🐛 %s Vulnerability Found", strings.ToUpper(vs.Severity)), details.String())
						} else {
							log.Printf("[DISCORD] Skipping %s vuln notification (min severity: %s)", vs.Severity, s.discordMinSeverity)
						}
						// Apply Telegram minimum severity filter (independent of Discord)
						if s.telegramConfigured() && severityMeetsThreshold(vs.Severity, s.telegramMinSeverity) {
							s.sendTelegram(sevColor, fmt.Sprintf("🐛 %s Vulnerability Found", strings.ToUpper(vs.Severity)), details.String())
						} else if s.telegramConfigured() {
							log.Printf("[TELEGRAM] Skipping %s vuln notification (min severity: %s)", vs.Severity, s.telegramMinSeverity)
						}
						}
					} else {
						log.Printf("[VULN] Skipping duplicate vuln already present in session record: %s %s", vs.ID, vs.Title)
					}
					if !allowed {
						log.Printf("[VULN] Vuln persisted but NOT broadcast (filtered out by severity: %s, filter: %v)", vs.Severity, sess.severityFilter)
					}
				}
			}
		}
	}

	if phase := inferCurrentPhase(wsEvt, sess.phases); phase > 0 {
		wsEvt.CurrentPhase = phase
		if sess.record != nil {
			sess.record.CurrentPhase = phase
		}
	}

	if evt.Type == "finished" {
		// Build set of vulns already broadcast in real-time to avoid duplicates
		seen := make(map[string]bool)
		for _, v := range sess.record.Vulns {
			seen[vulnSummaryKey(v)] = true
		}
		vulns := reporting.GetVulnerabilitiesForContext(sess.sctx.ID)
		log.Printf("[VULN] Finished event: total vulns in system: %d, already broadcast: %d", len(vulns), len(seen))
		for _, v := range vulns {
			vs := vulnToSummary(v)
			if seen[vulnSummaryKey(vs)] {
				log.Printf("[VULN] Finished: skipping already-broadcast vuln: %s %s", v.ID, v.Title)
				continue
			}
			allowed := true
			if len(sess.severityFilter) > 0 {
				allowed = false
				for _, sev := range sess.severityFilter {
					if strings.EqualFold(sev, vs.Severity) {
						allowed = true
						break
					}
				}
			}
			if allowed {
				wsEvt.Vulns = append(wsEvt.Vulns, vs)
				seen[vulnSummaryKey(vs)] = true
				log.Printf("[VULN] Finished: adding new vuln to final broadcast: %s %s", vs.Severity, vs.Title)
			} else {
				log.Printf("[VULN] Finished: filtered vuln (not added to broadcast): %s (filter: %v)", vs.Severity, sess.severityFilter)
			}
		}
		log.Printf("[VULN] Finished: total vulns in final broadcast: %d", len(wsEvt.Vulns))
	}

	// Track stats on per-session record
	if evt.Type == "thinking" {
		sess.record.Iterations++
	}
	if evt.Type == "tool_call" {
		sess.record.ToolCalls++
	}
	if evt.TotalTokens > 0 {
		sess.record.TotalTokens = sess.recordTokenOffset + evt.TotalTokens
	}

	// Update parent instance stats — ACCUMULATE across sessions (phases/subdomains),
	// don't overwrite. Each subdomain scan creates a fresh scanSession with zeroed
	// counters, so we increment the instance counters on each event.
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			if evt.Type == "thinking" {
				inst.Iterations++
			}
			if evt.Type == "tool_call" {
				inst.ToolCalls++
			}
			if evt.TotalTokens > 0 {
				// Tokens are cumulative within a session but reset between sessions,
				// so we track the delta
				inst.TotalTokens += evt.TotalTokens - inst.lastSessionTokens
				inst.lastSessionTokens = evt.TotalTokens
			}
			// Vulns: route through effectiveVulnCount so the counter source
			// is consistent across the scan lifecycle. While running, this
			// returns the in-memory count (parent context for wildcard child
			// sessions, session context otherwise); after teardown the
			// helper falls back to len(inst.Vulns). See Task 3.1 in
			// .kiro/specs/findings-consistency-and-pagination/tasks.md.
			inst.VulnCount = s.effectiveVulnCount(inst, sess)
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// Accumulate events for persistence (limit stored output size)
	savedEvt := wsEvt
	if len(savedEvt.Output) > 500 {
		savedEvt.Output = savedEvt.Output[:500] + "..."
	}
	sess.record.Events = append(sess.record.Events, savedEvt)

	// Periodically save scan record (every 10 events)
	if len(sess.record.Events)%10 == 0 {
		s.saveScanRecordTo(sess.record, sess.scanDir)
	}

	// Use instance-scoped broadcasting
	log.Printf("[VULN] Broadcasting: type=%s, instanceID=%s, vulns=%d", evt.Type, sess.instanceID, len(wsEvt.Vulns))
	if sess.instanceID != "" {
		s.broadcastToInstance(sess.instanceID, wsEvt)
	} else {
		s.broadcast(wsEvt)
	}
}

// buildSeverityPrefix creates the severity filter instruction prefix.
func buildSeverityPrefix(severityFilter []string) string {
	severityText := "CRITICAL INSTRUCTION: You MUST ONLY look for and report "
	severities := make([]string, len(severityFilter))
	copy(severities, severityFilter)
	severityText += strings.Join(severities, " and ") + " severity vulnerabilities. "
	severityText += "DO NOT report, investigate, or mention any LOW severity, INFORMATIONAL, or INFO findings. "
	severityText += "Ignore any potential LOW/INFO issues - they are out of scope for this engagement. "
	severityText += "Focus ONLY on: " + strings.Join(severities, ", ") + "."
	return severityText
}

func firstSelectedPhase(phases []int) int {
	if len(phases) == 0 {
		return 1
	}
	first := 0
	for _, phase := range phases {
		if phase < 1 || phase > 22 {
			continue
		}
		if first == 0 || phase < first {
			first = phase
		}
	}
	if first == 0 {
		return 1
	}
	return first
}

func phaseAllowed(phases []int, phase int) bool {
	if phase < 1 || phase > 22 {
		return false
	}
	if len(phases) == 0 {
		return true
	}
	for _, allowed := range phases {
		if allowed == phase {
			return true
		}
	}
	return false
}

func isReconReportOnlyPhaseSelection(phases []int) bool {
	if len(phases) == 0 {
		return false
	}
	for _, phase := range phases {
		if phase != 1 && phase != 22 {
			return false
		}
	}
	return true
}

var phaseMentionRe = regexp.MustCompile(`(?i)\bphase\s+([0-9]{1,2})\b`)

func inferCurrentPhase(evt WSEvent, allowed []int) int {
	if phase := parsePhaseMention(evt.Content); phaseAllowed(allowed, phase) {
		return phase
	}
	switch evt.Type {
	case "queue_started", "target_started", "scan_started":
		return firstSelectedPhase(allowed)
	case "queue_finished", "report_ready":
		if phaseAllowed(allowed, 22) {
			return 22
		}
	}

	if evt.Type != "tool_call" {
		return 0
	}
	args := strings.ToLower(strings.Join(mapValues(evt.ToolArgs), " "))

	switch {
	case strings.Contains(args, "sqlmap") || strings.Contains(args, "dalfox") ||
		strings.Contains(args, "union select") || strings.Contains(args, "<script") ||
		strings.Contains(args, "sleep("):
		if phaseAllowed(allowed, 6) {
			return 6
		}
	case strings.Contains(args, "ffuf") || strings.Contains(args, "gobuster") ||
		strings.Contains(args, "dirsearch") || strings.Contains(args, "feroxbuster"):
		if phaseAllowed(allowed, 3) {
			return 3
		}
	case strings.Contains(args, "ssrf") || strings.Contains(args, "169.254.169.254"):
		if phaseAllowed(allowed, 7) {
			return 7
		}
	case strings.Contains(args, "idor") || strings.Contains(args, "authorization") ||
		strings.Contains(args, "role=admin"):
		if phaseAllowed(allowed, 8) {
			return 8
		}
	case strings.Contains(args, "graphql") || strings.Contains(args, "/api/"):
		if phaseAllowed(allowed, 9) {
			return 9
		}
	case strings.Contains(args, "cors") || strings.Contains(args, "cookie"):
		if phaseAllowed(allowed, 4) {
			return 4
		}
	case strings.Contains(args, "login") || strings.Contains(args, "session") ||
		strings.Contains(args, "agentmail"):
		if phaseAllowed(allowed, 5) {
			return 5
		}
	case strings.Contains(args, "nmap") || strings.Contains(args, "naabu") ||
		strings.Contains(args, "masscan") || strings.Contains(args, "dig ") ||
		strings.Contains(args, "nslookup") || strings.Contains(args, "host ") ||
		strings.Contains(args, "whatweb") || strings.Contains(args, "wappalyzer") ||
		strings.Contains(args, "httpx") || strings.Contains(args, "wafw00f") ||
		strings.Contains(args, "subfinder") || strings.Contains(args, "amass") ||
		strings.Contains(args, "crt.sh"):
		if phaseAllowed(allowed, 1) {
			return 1
		}
	}

	return 0
}

func parsePhaseMention(text string) int {
	match := phaseMentionRe.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	var phase int
	if _, err := fmt.Sscanf(match[1], "%d", &phase); err != nil {
		return 0
	}
	if phase < 1 || phase > 22 {
		return 0
	}
	return phase
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ────────────────────────────────────────────────────────
// runMultiScan — orchestrates scanning across all targets
// ────────────────────────────────────────────────────────

// runMultiScan processes targets sequentially, one at a time.
// Each target is scanned in a fully isolated scanSession.
func (s *Server) runMultiScan(req ScanRequest, scanCfg *config.Config, instanceIDs ...string) {
	normalizeScanRequestActivity(&req)

	// Defensively flatten req.Targets in case the frontend or API sent them as a comma-separated mega string
	var cleanTargets []string
	for _, raw := range req.Targets {
		fields := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
		})
		for _, f := range fields {
			if f != "" {
				cleanTargets = append(cleanTargets, f)
			}
		}
	}

	// Filter out local/internal targets to prevent self-scanning
	var safeTargets []string
	for _, t := range cleanTargets {
		if s.isBlockedTarget(t) {
			log.Printf("[BLOCKLIST] Skipping blocked target: %s (local/internal IP or self-listener)", t)
		} else {
			safeTargets = append(safeTargets, t)
		}
	}
	if len(safeTargets) < len(cleanTargets) {
		log.Printf("[BLOCKLIST] Filtered %d blocked targets, %d remaining", len(cleanTargets)-len(safeTargets), len(safeTargets))
	}
	req.Targets = safeTargets

	// Create instance ID immediately
	var instanceID string
	if len(instanceIDs) > 0 && instanceIDs[0] != "" {
		instanceID = instanceIDs[0]
	} else {
		instanceID = randomSlug()
	}

	// Register instance as pending initially
	instance := &ScanInstance{
		ID:             instanceID,
		Name:           req.Name,
		Targets:        strings.Join(req.Targets, ", "),
		Status:         "pending",
		StartedAt:      time.Now().Format(time.RFC3339Nano),
		ScanMode:       req.ScanMode,
		Instruction:    req.Instruction,
		SeverityFilter: req.SeverityFilter,
		Phases:         req.Phases,
		ReconMode:      req.ReconMode,
		ScanIntensity:  req.ScanIntensity,
		CurrentPhase:   firstSelectedPhase(req.Phases),
		CompanyName:    req.CompanyName,
		LogoPath:       req.LogoPath,
		DiscordWebhook: req.DiscordWebhook,
	}
	s.seedResumeInstanceFromRecord(instance, req)
	chatCfg := *scanCfg
	instance.chatCfg = &chatCfg
	s.instancesMu.Lock()
	s.instances[instanceID] = instance
	s.instancesMu.Unlock()

	// Broadcast to dashboard
	s.broadcastDashboard(WSEvent{Type: "instance_started", Content: instanceID})

	// Register cleanup before the queue wait loop so pending instances that
	// are stopped early still release server-side references.
	ranScan := false
	panicRecovered := false
	defer func() {
		if r := recover(); r != nil {
			panicRecovered = true
			log.Printf("[CRITICAL] runMultiScan goroutine panicked: %v\n%s", r, debug.Stack())
			s.broadcastToInstance(instanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan goroutine crashed: %v — cleaning up", r)})
		}

		// Mark instance as finished (if still running)
		instance.mu.Lock()
		if instance.Status == "running" {
			if panicRecovered {
				instance.Status = "stopped"
				instance.StopReason = "panic_recovered"
			} else {
				instance.Status = "finished"
			}
		}
		instance.FinishedAt = time.Now().Format(time.RFC3339)
		instance.agent = nil
		instance.cancel = nil
		instance.sctx = nil
		instance.mu.Unlock()

		// Full post-scan cleanup only when the scan actually ran.
		// Pending→stopped instances skip queue/agent teardown since
		// they never acquired resources.
		if ranScan {
			// Only clear queue state when the scan really finished. Paused,
			// panicked, and signal-stopped scans keep it for resume.
			preserveQueue := false
			instance.mu.RLock()
			preserveQueue = shouldPreserveQueueStateOnExit(instance.Status, instance.StopReason, panicRecovered)
			instance.mu.RUnlock()
			if !preserveQueue {
				s.clearQueueState(instanceID)
			} else {
				log.Printf("[AUTO-RESUME] Preserving queue state after interrupted scan")
			}
		}

		// Always clean up server references (safe even if never set)
		s.mu.Lock()
		if s.currentScanID == instanceID {
			s.cancelScan = nil
			delete(s.currentAgents, instanceID)
		}
		s.mu.Unlock()

		instance.mu.RLock()
		finalStatus := instance.Status
		finalStopReason := instance.StopReason
		instance.mu.RUnlock()
		if finalStatus == "paused" {
			s.markQueueStatePaused(instanceID)
		}
		queueDoneEvt := WSEvent{Type: "queue_finished", Content: "Scan queue ended"}
		switch finalStatus {
		case "paused":
			queueDoneEvt = WSEvent{Type: "paused", Content: "Scan queue paused"}
		case "stopped":
			if strings.HasPrefix(finalStopReason, "signal_") || finalStopReason == "panic_recovered" {
				queueDoneEvt = WSEvent{Type: "stopped", Content: "Scan queue interrupted; resume state saved"}
			} else {
				queueDoneEvt = WSEvent{Type: "stopped", Content: "Scan queue stopped"}
			}
		default:
			if phaseAllowed(req.Phases, 22) {
				queueDoneEvt.CurrentPhase = 22
			}
		}
		s.broadcastToInstance(instanceID, queueDoneEvt)
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		time.Sleep(500 * time.Millisecond)

		// Only set running=false if no other instances are running
		s.instancesMu.RLock()
		stillRunning := false
		for _, inst := range s.instances {
			inst.mu.RLock()
			isRunning := inst.Status == "running" && inst.ID != instanceID
			inst.mu.RUnlock()
			if isRunning {
				stillRunning = true
				break
			}
		}
		s.instancesMu.RUnlock()
		if !stillRunning {
			s.running.Store(false)
		}
		// Wake exactly one admission waiter (if any) now that this
		// instance has finished and a slot is free. Non-blocking send:
		// the channel is buffered to len=1 so a single pending wake is
		// always queued; additional terminate signals while a wake is
		// already pending are intentionally collapsed (the recipient
		// will re-check via runningCount and either admit or wait
		// again on the safety-net ticker). This wake fires regardless
		// of whether the scan finished, errored, was stopped, or
		// panicked, because it lives in the unconditional defer.
		// (Task 11.2 / R3.2, R3.6 / Property 5.)
		select {
		case s.admissionWake <- struct{}{}:
		default:
		}
		log.Printf("[INFO] runMultiScan instance %s exited (ranScan=%v)", instanceID, ranScan)
	}()

	// Wait in queue until slot is available.
	// CRITICAL: The slot check + status transition MUST be atomic under a single
	// Lock to prevent a TOCTOU race where two goroutines both see runningCount=0
	// and start simultaneously, causing mutual process kills.
	//
	// Wakeup model (Task 11.2 / R3.2, R3.6): instead of busy-sleeping for 2s
	// between admission attempts, we park on a select that wakes when
	// (a) another instance terminates and signals s.admissionWake (fair
	// wakeup — exactly one waiter per terminate), (b) the 2s ticker fires
	// as a safety-net, or (c) the server is shutting down. The top of the
	// loop re-checks per-instance and global stop flags after every wake.
	admissionTicker := time.NewTicker(2 * time.Second)
	defer admissionTicker.Stop()
	for {
		// Check if THIS instance was stopped (via per-instance stop API)
		instance.mu.RLock()
		stopped := instance.Status == "stopped"
		instance.mu.RUnlock()
		if stopped {
			// Early return — defer is already registered and will clean up
			return
		}

		// Also check global stop (user clicked "stop all")
		if s.stopReq.Load() {
			instance.mu.Lock()
			if instance.Status == "pending" {
				instance.Status = "stopped"
				instance.StopReason = "user_stopped"
				instance.FinishedAt = time.Now().Format(time.RFC3339)
			}
			instance.mu.Unlock()
			// Early return — defer is already registered and will clean up
			return
		}

		// ATOMIC: Check resource availability AND transition to running under a single lock.
		// This eliminates the TOCTOU race window between resource check and status update.
		gotSlot := false
		s.instancesMu.Lock()
		runningCount := 0
		for _, inst := range s.instances {
			inst.mu.RLock()
			if inst.Status == "running" {
				runningCount++
			}
			inst.mu.RUnlock()
		}
		canAdmit, reason := resources.CanAdmitScan(runningCount)
		if canAdmit && instance.Status == "pending" {
			instance.Status = "running"
			instance.StartedAt = time.Now().Format(time.RFC3339)
			gotSlot = true
			log.Printf("[ADMIT] Scan %s started (running: %d) — %s", instanceID, runningCount+1, reason)
		}
		s.instancesMu.Unlock()

		if gotSlot {
			break
		}
		// Admission refused — record the event and emit a structured INFO log.
		// Each refusal observation is a distinct event; ticker cadence keeps
		// counter growth proportional to wait time, while admissionWake
		// signals collapse multiple near-simultaneous terminates into a
		// single fair wakeup for the next waiter.
		safe.IncAdmissionRefusal()
		ceiling, _ := resources.EffectiveMaxInstances()
		level, _ := resources.CurrentLevel()
		log.Printf("[admission] refused level=%s reason=%q ceiling=%d running=%d scan=%s",
			level.String(), reason, ceiling, runningCount, instanceID)

		// Park on the wake channel, the safety-net ticker, or shutdown.
		select {
		case <-s.admissionWake:
			// A peer instance freed a slot — re-check immediately.
		case <-admissionTicker.C:
			// Periodic safety-net wake; prevents indefinite waits if a
			// signal is ever missed (e.g. concurrent terminates collapse
			// onto a single buffered slot).
		case <-s.shutdownChan:
			// Server is shutting down. Mark this pending instance stopped
			// and exit; the defer will run the rest of cleanup.
			instance.mu.Lock()
			if instance.Status == "pending" {
				instance.Status = "stopped"
				instance.StopReason = "server_shutdown"
				instance.FinishedAt = time.Now().Format(time.RFC3339)
			}
			instance.mu.Unlock()
			return
		}
	}

	// Instance got a slot — mark that the scan ran for full cleanup
	ranScan = true

	s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})

	// ── PRE-SESSION CLEANUP ──
	// IMPORTANT: This runs AFTER the queue wait. Do not clear the queue file
	// before the refreshed state is written; resumed scans rely on it if the
	// process exits during admission/startup.
	req.InstanceID = instanceID // thread instance ID to all target handlers
	s.running.Store(true)
	s.stopReq.Store(false) // clear global stop so this scan isn't immediately aborted
	if req.DiscordWebhook != "" {
		s.discordWebhook = req.DiscordWebhook
	}

	if req.IsResume {
		log.Printf("[AUTO-RESUME] Skipping state reset — preserving vulns, notes, and recon files from previous session")
		// NOTE: Do NOT call terminal.KillAllProcesses() here — it kills ALL
		// processes globally, which would destroy a running instance's tools.
		// Per-context cleanup handles process termination on session boundaries.
	} else {
		// Fresh scan — only clean per-instance state, NOT global state.
		// Global resets (reporting.ResetVulnerabilities, notes.ResetNotes,
		// terminal.KillAllProcesses) would destroy another queued instance's
		// methodology workflow. Per-context resets happen in executeScanSession.
		func() {
			defer logRecover("multiScan.cleanTmpSubdomainFiles")
			cleanTmpSubdomainFiles()
		}()
	}
	totalTargets := len(req.Targets)

	// Save queue state for persistence
	s.saveQueueState(0, req)
	if req.ResumeQueueStatePath != "" && filepath.Clean(req.ResumeQueueStatePath) != filepath.Clean(s.queueStatePathForInstance(instanceID)) {
		s.clearQueueStatePath(req.ResumeQueueStatePath)
	}

	s.broadcastToInstance(instanceID, WSEvent{
		Type:         "queue_started",
		Content:      fmt.Sprintf("Starting scan queue: %d target(s)", totalTargets),
		TotalTargets: totalTargets,
		CurrentPhase: firstSelectedPhase(req.Phases),
	})

	// Discord: scan started
	s.sendDiscord(0x00ff88, "🚀 Scan Started", fmt.Sprintf("**Targets:** %s\n**Mode:** %s\n**Total:** %d target(s)", strings.Join(req.Targets, ", "), req.ScanMode, totalTargets))
	// Telegram: scan started
	if s.telegramConfigured() {
		s.sendTelegram(0x00ff88, "🚀 Scan Started", fmt.Sprintf("**Targets:** %s\n**Mode:** %s\n**Total:** %d target(s)", strings.Join(req.Targets, ", "), req.ScanMode, totalTargets))
	}

	interruptedQueue := false
	for i, target := range req.Targets {
		// Check both global stop and per-instance stop
		instance.mu.RLock()
		instStatus := instance.Status
		instance.mu.RUnlock()
		if s.stopReq.Load() || instStatus == "stopped" || instStatus == "paused" {
			interruptedQueue = true
			if instStatus == "paused" {
				s.broadcastToInstance(instanceID, WSEvent{Type: "paused", Content: "Scan queue paused"})
			} else {
				s.broadcastToInstance(instanceID, WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			}
			break
		}

		// Update queue state after each target
		s.saveQueueState(i, req)

		// No per-target timeout — let scans run indefinitely; user uses stop button
		ctx, cancel := context.WithCancel(context.Background())
		s.mu.Lock()
		s.cancelScan = cancel
		s.mu.Unlock()

		// Store cancel on the instance so per-instance stop can cancel the scan context
		instance.mu.Lock()
		instance.cancel = cancel
		instance.mu.Unlock()

		switch req.ScanMode {
		case "wildcard":
			// Each target gets full wildcard treatment: Phase 1 subdomain discovery + Phase 2 per-subdomain scan.
			// This applies whether the user provides 1 or 300+ root domains.
			s.runWildcardTarget(ctx, scanCfg, req, target, i, totalTargets)
		case "dast":
			s.runDASTTarget(ctx, scanCfg, req, target, i, totalTargets)
		default:
			s.runSingleTarget(ctx, scanCfg, req, target, i, totalTargets)
		}

		instance.mu.RLock()
		instStatusAfterTarget := instance.Status
		instance.mu.RUnlock()
		if shouldAdvanceQueueAfterTarget(s.stopReq.Load(), instStatusAfterTarget) {
			s.saveQueueState(i+1, req)
		} else {
			interruptedQueue = true
		}

		cancel() // always cancel context after target is done
	}

	if interruptedQueue {
		log.Printf("[INFO] runMultiScan queue interrupted before completion")
		return
	}

	// Discord: scan finished — use instance's accumulated vuln count
	// (don't read from inst.sctx.ID — it may point to a cleaned-up session context)
	vulnCount := 0
	s.instancesMu.RLock()
	if inst, ok := s.instances[instanceID]; ok {
		inst.mu.RLock()
		vulnCount = inst.VulnCount
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()
	if vulnCount > 0 {
		desc := fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** %d found\n**Completed at:** %s", totalTargets, vulnCount, time.Now().Format("15:04:05 MST"))
		s.sendDiscord(0x3b82f6, "✅ Scan Finished - Vulnerabilities Found", desc)
		if s.telegramConfigured() {
			s.sendTelegram(0x3b82f6, "✅ Scan Finished - Vulnerabilities Found", desc)
		}
	} else {
		s.sendDiscord(0x3b82f6, "✅ Scan Finished", fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** 0 found\n**Completed at:** %s", totalTargets, time.Now().Format("15:04:05 MST")))
		if s.telegramConfigured() {
			s.sendTelegram(0x3b82f6, "✅ Scan Finished", fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** 0 found\n**Completed at:** %s", totalTargets, time.Now().Format("15:04:05 MST")))
		}
	}

	log.Printf("[INFO] runMultiScan main body complete")
}

// ────────────────────────────────────────────────────────
// Mode-specific target handlers
// ────────────────────────────────────────────────────────

// makeScanDir creates a per-target scan directory with nested structure: target/date/randomslug
func (s *Server) makeScanDir(target string) string {
	dateDir := time.Now().Format("2006-01-02")
	scanDirName := fmt.Sprintf("%s_%s", sanitizeTarget(target), randomSlug())
	scanDir := filepath.Join(s.dataDir, target, dateDir, scanDirName)
	if err := os.MkdirAll(scanDir, 0700); err != nil {
		log.Printf("[ERROR] Failed to create scan directory %s: %v", scanDir, err)
	}
	return scanDir
}

func (s *Server) scanDirForResume(req ScanRequest, target string) (string, bool) {
	if !req.IsResume || req.ResumeScanDir == "" {
		return s.makeScanDir(target), false
	}
	if req.ResumeActiveTarget != "" && req.ResumeActiveTarget != target {
		return s.makeScanDir(target), false
	}
	return s.resumeScanDirOrNew(req.ResumeScanDir, target)
}

func (s *Server) scanDirForWildcardSubdomainResume(req ScanRequest, subdomain string, subIndex int) (string, bool) {
	if !req.IsResume || req.ResumeSubScanDir == "" {
		return s.makeScanDir(subdomain), false
	}
	if req.ResumeSubIndex != subIndex {
		return s.makeScanDir(subdomain), false
	}
	if req.ResumeSubScanTarget != "" && req.ResumeSubScanTarget != subdomain {
		return s.makeScanDir(subdomain), false
	}
	return s.resumeScanDirOrNew(req.ResumeSubScanDir, subdomain)
}

func (s *Server) resumeScanDirOrNew(scanDir, target string) (string, bool) {
	cleanDir := filepath.Clean(scanDir)
	dataDir := filepath.Clean(s.dataDir)
	rel, err := filepath.Rel(dataDir, cleanDir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		log.Printf("[AUTO-RESUME] Ignoring unsafe resume scan dir %q", scanDir)
		return s.makeScanDir(target), false
	}
	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		log.Printf("[AUTO-RESUME] Failed to reuse scan dir %s: %v", cleanDir, err)
		return s.makeScanDir(target), false
	}
	return cleanDir, true
}

func loadScanRecordFromDir(scanDir string) (*ScanRecord, bool) {
	if scanDir == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(scanDir, "scan.json"))
	if err != nil {
		return nil, false
	}
	var rec ScanRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false
	}
	return &rec, true
}

func subdomainTargetsFromRecord(rec *ScanRecord) []string {
	if rec == nil {
		return nil
	}
	seen := make(map[string]bool)
	targets := make([]string, 0, len(rec.SubScans))
	for _, child := range rec.SubScans {
		target := strings.TrimSpace(child.Target)
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, target)
	}
	return targets
}

// runSingleTarget handles a single-site mode scan for one target.
func (s *Server) runSingleTarget(_ context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	scanDir, resumed := s.scanDirForResume(req, target)
	s.saveQueueState(idx, req, queueProgress{
		ActiveTarget:  target,
		ActiveScanDir: scanDir,
		ActiveScanID:  filepath.Base(scanDir),
	})

	instruction := "This is a SINGLE TARGET scan. Do NOT enumerate subdomains or perform wildcard discovery. Only test the exact target URL provided. Focus on the main domain/IP only. " + req.Instruction
	if resumed {
		instruction += " This is an AUTO-RESUMED scan. Before doing new work, read existing notes and files in the current workspace, then continue from the last saved evidence instead of starting discovery from scratch."
	}

	// Inject phase filter if the user selected specific phases
	instruction += buildPhaseFilterInstruction(req.Phases)
	instruction += buildActivityPolicyInstruction(req.ReconMode, req.ScanIntensity)

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("Scanning target %d/%d: %s", idx+1, total, target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
		CurrentPhase: firstSelectedPhase(req.Phases),
	})

	sess := &scanSession{
		id:              filepath.Base(scanDir),
		target:          target,
		scanDir:         scanDir,
		cfg:             scanCfg,
		server:          s,
		instruction:     buildAutonomousInstruction(target, instruction),
		name:            req.Name,
		userInstruction: req.Instruction,
		severityFilter:  req.SeverityFilter,
		discordWebhook:  req.DiscordWebhook,
		discoveryMode:   false,
		genReport:       true,
		resetState:      !resumed,
		instanceID:      req.InstanceID,
		scanMode:        "single",
		companyName:     req.CompanyName,
		logoPath:        req.LogoPath,
		phases:          req.Phases,
		reconMode:       req.ReconMode,
		scanIntensity:   req.ScanIntensity,
		llmClient:       s.scanLLMClientForRequest(req, scanCfg),
	}
	s.executeScanSession(sess)
	if s.instanceInterrupted(req.InstanceID) {
		return
	}

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("Target %d/%d completed: %s", idx+1, total, target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// runDASTTarget handles a DAST mode scan for one target URL.
func (s *Server) runDASTTarget(_ context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	scanDir, resumed := s.scanDirForResume(req, target)
	s.saveQueueState(idx, req, queueProgress{
		ActiveTarget:  target,
		ActiveScanDir: scanDir,
		ActiveScanID:  filepath.Base(scanDir),
	})

	dastInstruction := buildDASTInstruction(target)
	if req.Instruction != "" {
		dastInstruction += "\n\n" + req.Instruction
	}
	if resumed {
		dastInstruction += "\n\n## AUTO-RESUME\nRead existing notes and files in the current workspace first, then continue from the last saved evidence instead of starting from scratch."
	}
	dastInstruction += buildPhaseFilterInstruction(req.Phases)
	dastInstruction += buildActivityPolicyInstruction(req.ReconMode, req.ScanIntensity)

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("[DAST] Scanning URL: %s", target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
		CurrentPhase: firstSelectedPhase(req.Phases),
	})

	sess := &scanSession{
		id:              filepath.Base(scanDir),
		target:          target,
		scanDir:         scanDir,
		cfg:             scanCfg,
		server:          s,
		instruction:     dastInstruction,
		name:            req.Name,
		userInstruction: req.Instruction,
		severityFilter:  req.SeverityFilter,
		discordWebhook:  req.DiscordWebhook,
		discoveryMode:   false,
		genReport:       true,
		resetState:      !resumed,
		instanceID:      req.InstanceID,
		scanMode:        "dast",
		companyName:     req.CompanyName,
		logoPath:        req.LogoPath,
		phases:          req.Phases,
		reconMode:       req.ReconMode,
		scanIntensity:   req.ScanIntensity,
		llmClient:       s.scanLLMClientForRequest(req, scanCfg),
	}
	s.executeScanSession(sess)
	if s.instanceInterrupted(req.InstanceID) {
		return
	}

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("[DAST] Completed: %s", target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// runWildcardTarget handles wildcard mode: Phase 1 subdomain discovery, then Phase 2 per-subdomain scanning.
func (s *Server) runWildcardTarget(_ context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	// ── Stable parent reporting context for vuln accumulation ──
	// All subdomain sessions merge their vulns into this context.
	// It persists across the entire wildcard scan and is cleaned up at the end.
	parentReportingCtxID := fmt.Sprintf("wc-%s-%s", req.InstanceID, sanitizeTarget(target))
	reporting.ResetVulnerabilitiesForContext(parentReportingCtxID) // start clean
	defer func() {
		// Final cleanup of the parent reporting context
		reporting.CleanupContext(parentReportingCtxID)
		log.Printf("[wildcard] Cleaned up parent reporting context: %s", parentReportingCtxID)
	}()

	// ── PHASE 1: Subdomain Discovery ──
	scanDir, resumed := s.scanDirForResume(req, target)
	subdomains := append([]string(nil), req.ResumeSubdomains...)
	resumeFromSubIndex := 0
	var parentRecord *ScanRecord
	if resumed && req.ResumeDiscoveryDone {
		resumeFromSubIndex = req.ResumeSubIndex
		if len(subdomains) == 0 {
			if rec, ok := loadScanRecordFromDir(scanDir); ok {
				parentRecord = rec
				subdomains = subdomainTargetsFromRecord(rec)
			}
		}
		if len(subdomains) == 0 {
			subdomains = s.collectSubdomains(scanDir, target, "")
		}
		log.Printf("[AUTO-RESUME] Resuming wildcard scan for %s at subdomain index %d/%d (scanDir=%s)", target, resumeFromSubIndex, len(subdomains), scanDir)
		s.broadcastToInstance(req.InstanceID, WSEvent{
			Type:           "target_started",
			Content:        fmt.Sprintf("[AUTO-RESUME] Resuming wildcard scan for %s at subdomain %d/%d", target, minInt(resumeFromSubIndex+1, len(subdomains)), len(subdomains)),
			Target:         target,
			AgentID:        filepath.Base(scanDir),
			TargetIndex:    idx + 1,
			TotalTargets:   total,
			SubTargetTotal: len(subdomains),
			ParentTarget:   target,
			CurrentPhase:   firstSelectedPhase(req.Phases),
		})
	} else {
		s.saveQueueState(idx, req, queueProgress{
			ActiveTarget:  target,
			ActiveScanDir: scanDir,
			ActiveScanID:  filepath.Base(scanDir),
		})

		discoveryRatePolicy := agent.EffectiveRequestRatePolicy(scanCfg, req.Instruction)
		discoveryInstruction := buildDiscoveryInstruction(target, req.ReconMode, discoveryRatePolicy)
		if req.Instruction != "" {
			discoveryInstruction += "\n\n" + req.Instruction
		}
		discoveryInstruction += buildActivityPolicyInstruction(req.ReconMode, req.ScanIntensity)

		s.broadcastToInstance(req.InstanceID, WSEvent{
			Type:         "target_started",
			Content:      fmt.Sprintf("[PHASE 1] Discovering subdomains for: %s", target),
			Target:       target,
			AgentID:      filepath.Base(scanDir),
			TargetIndex:  idx + 1,
			TotalTargets: total,
			CurrentPhase: 1,
		})

		// Save the discovery session's context ID so we can read notes after cleanup.
		// skipNotesCleanup=true prevents cleanup() from deleting the notes store,
		// keeping them available for collectSubdomains' Layer 3 (notes fallback).
		discoverySess := &scanSession{
			id:               filepath.Base(scanDir),
			target:           target,
			scanDir:          scanDir,
			cfg:              scanCfg,
			server:           s,
			instruction:      discoveryInstruction,
			name:             req.Name,
			userInstruction:  req.Instruction,
			severityFilter:   req.SeverityFilter,
			discordWebhook:   req.DiscordWebhook,
			discoveryMode:    true,
			genReport:        false,
			resetState:       true,
			instanceID:       req.InstanceID,
			scanMode:         "wildcard",
			skipNotesCleanup: true, // preserve notes for subdomain collection
			companyName:      req.CompanyName,
			logoPath:         req.LogoPath,
			phases:           req.Phases,
			reconMode:        req.ReconMode,
			scanIntensity:    req.ScanIntensity,
			llmClient:        s.scanLLMClientForRequest(req, scanCfg),
		}
		s.executeScanSession(discoverySess)
		if s.instanceInterrupted(req.InstanceID) {
			return
		}
		parentRecord = discoverySess.record

		// Capture the discovery session's context ID for notes lookup.
		// The sctx was set during executeScanSession and its notes were preserved.
		discoveryCtxID := ""
		if discoverySess.sctx != nil {
			discoveryCtxID = discoverySess.sctx.ID
		}

		// Read discovered subdomains — use discovery context ID for notes fallback
		subdomains = s.collectSubdomains(scanDir, target, discoveryCtxID)

		// Now clean up the discovery notes (deferred from skipNotesCleanup)
		if discoveryCtxID != "" {
			notes.CleanupContext(discoveryCtxID)
			log.Printf("[wildcard] Cleaned up discovery notes context: %s", discoveryCtxID)
		}
	}

	log.Printf("[INFO] Total subdomains found for %s: %d", target, len(subdomains))

	// Fallback: if discovery found 0 subdomains, scan the root domain itself
	if len(subdomains) == 0 {
		log.Printf("[INFO] No subdomains discovered for %s — falling back to root domain scan", target)
		subdomains = []string{target}
		s.broadcastToInstance(req.InstanceID, WSEvent{
			Type:         "target_completed",
			Content:      fmt.Sprintf("[PHASE 1] Discovery complete: found 0 subdomains. Falling back to root domain scan of %s.", target),
			Target:       target,
			TargetIndex:  idx + 1,
			TotalTargets: total,
		})
	} else {
		s.broadcastToInstance(req.InstanceID, WSEvent{
			Type:         "target_completed",
			Content:      fmt.Sprintf("[PHASE 1] Discovery complete: found %d subdomains. Now scanning each individually.", len(subdomains)),
			Target:       target,
			TargetIndex:  idx + 1,
			TotalTargets: total,
		})
	}
	pendingSubScans := make([]SubScanSummary, 0, len(subdomains))
	resumeFromSubIndex = clampInt(resumeFromSubIndex, 0, len(subdomains))
	for i, subdomain := range subdomains {
		status := "pending"
		if i < resumeFromSubIndex {
			status = "finished"
		}
		pendingSubScans = append(pendingSubScans, SubScanSummary{
			Target: subdomain,
			Status: status,
		})
	}
	if parentRecord == nil {
		parentRecord, _ = loadScanRecordFromDir(scanDir)
	}
	if parentRecord != nil {
		parentRecord.SubScans = pendingSubScans
		parentRecord.SubScanTotal = len(subdomains)
		parentRecord.SubScanCompleted = resumeFromSubIndex
		parentRecord.SubScanRunning = 0
		parentRecord.SubScanRemaining = len(subdomains) - resumeFromSubIndex
		parentRecord.Status = "running"
		s.saveScanRecordTo(parentRecord, scanDir)
	}
	s.saveQueueState(idx, req, queueProgress{
		ActiveTarget:          target,
		ActiveScanDir:         scanDir,
		ActiveScanID:          filepath.Base(scanDir),
		WildcardDiscoveryDone: true,
		WildcardSubdomains:    subdomains,
		WildcardSubIndex:      resumeFromSubIndex,
	})
	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:           "subdomains_discovered",
		Content:        fmt.Sprintf("Discovered %d subdomains for %s", len(subdomains), target),
		Target:         target,
		Output:         strings.Join(subdomains, "\n"),
		TargetIndex:    idx + 1,
		TotalTargets:   total,
		SubTargetTotal: len(subdomains),
		ParentTarget:   target,
		CurrentPhase:   firstSelectedPhase(req.Phases),
	})

	saveWildcardProgress := func(nextIndex, runningIndex int, activeSubTarget, activeSubScanDir string) {
		nextIndex = clampInt(nextIndex, 0, len(subdomains))
		if parentRecord == nil {
			parentRecord, _ = loadScanRecordFromDir(scanDir)
		}
		if parentRecord != nil {
			existing := make(map[string]SubScanSummary)
			for _, child := range parentRecord.SubScans {
				existing[child.Target] = child
			}
			children := make([]SubScanSummary, 0, len(subdomains))
			completed := 0
			running := 0
			for i, childTarget := range subdomains {
				child := existing[childTarget]
				child.Target = childTarget
				switch {
				case i == runningIndex:
					child.Status = "running"
					if activeSubScanDir != "" && childTarget == activeSubTarget {
						child.ID = filepath.Base(activeSubScanDir)
						if child.StartedAt == "" {
							child.StartedAt = time.Now().Format(time.RFC3339)
						}
					}
					running++
				case i < nextIndex:
					if child.Status == "" || child.Status == "pending" || child.Status == "running" {
						child.Status = "finished"
					}
					if child.FinishedAt == "" {
						child.FinishedAt = time.Now().Format(time.RFC3339)
					}
					completed++
				default:
					if child.Status == "" || child.Status == "running" {
						child.Status = "pending"
					}
				}
				children = append(children, child)
			}
			parentRecord.SubScans = children
			parentRecord.SubScanTotal = len(subdomains)
			parentRecord.SubScanCompleted = completed
			parentRecord.SubScanRunning = running
			parentRecord.SubScanRemaining = len(subdomains) - completed - running
			parentRecord.Status = "running"
			s.saveScanRecordTo(parentRecord, scanDir)
		}
		activeSubScanID := ""
		if activeSubScanDir != "" {
			activeSubScanID = filepath.Base(activeSubScanDir)
		}
		s.saveQueueState(idx, req, queueProgress{
			ActiveTarget:          target,
			ActiveScanDir:         scanDir,
			ActiveScanID:          filepath.Base(scanDir),
			WildcardActiveTarget:  activeSubTarget,
			WildcardActiveScanDir: activeSubScanDir,
			WildcardActiveScanID:  activeSubScanID,
			WildcardDiscoveryDone: true,
			WildcardSubdomains:    subdomains,
			WildcardSubIndex:      nextIndex,
		})
	}

	// ── PHASE 2: Scan each subdomain individually ──
	wildcardStopped := false
	for j := resumeFromSubIndex; j < len(subdomains); j++ {
		subdomain := subdomains[j]
		// Check both global stop and per-instance stop
		if s.stopReq.Load() || s.instanceInterrupted(req.InstanceID) {
			log.Printf("[INFO] Subdomain loop stopped by user at %d/%d for %s", j+1, len(subdomains), target)
			s.broadcastToInstance(req.InstanceID, WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			wildcardStopped = true
			break
		}

		// Note: No parent context timeout check here. Each subdomain scan has its own
		// agent-level timeout (2h). We let the stop button handle manual cancellation.

		// ── Memory & goroutine health check between subdomain scans ──
		logMemStats(fmt.Sprintf("Before subdomain %d/%d: %s", j+1, len(subdomains), subdomain))

		// Force GC between subdomain scans to free accumulated memory
		runtime.GC()
		debug.FreeOSMemory()

		subScanDir, subResumed := s.scanDirForWildcardSubdomainResume(req, subdomain, j)
		if subResumed {
			log.Printf("[AUTO-RESUME] Reusing interrupted subdomain scan dir for %s: %s", subdomain, subScanDir)
		}
		log.Printf("[INFO] Starting subdomain %d/%d: %s (parent: %s)", j+1, len(subdomains), subdomain, target)
		saveWildcardProgress(j, j, subdomain, subScanDir)

		// Each subdomain gets its own isolated session wrapped in a panic guard
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[PANIC] Subdomain %d/%d crashed (%s): %v — skipping to next\n%s", j+1, len(subdomains), subdomain, r, debug.Stack())
					s.broadcastToInstance(req.InstanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Subdomain %s crashed: %v — skipping", subdomain, r)})
				}
			}()

			scanInstruction := buildSubdomainScanInstruction(subdomain, target, req.Instruction)
			if subResumed {
				scanInstruction += "\n\n## AUTO-RESUME\nRead existing notes and files in the current workspace first, then continue this subdomain scan from the last saved evidence instead of starting from scratch."
			}
			scanInstruction += buildPhaseFilterInstruction(req.Phases)
			scanInstruction += buildActivityPolicyInstruction(req.ReconMode, req.ScanIntensity)

			s.broadcastToInstance(req.InstanceID, WSEvent{
				Type:           "target_started",
				Content:        fmt.Sprintf("[PHASE 2] Scanning subdomain %d/%d: %s", j+1, len(subdomains), subdomain),
				Target:         subdomain,
				AgentID:        filepath.Base(subScanDir),
				TargetIndex:    idx + 1,
				TotalTargets:   total,
				SubTargetIndex: j + 1,
				SubTargetTotal: len(subdomains),
				ParentTarget:   target,
				CurrentPhase:   firstSelectedPhase(req.Phases),
			})

			// Track vulns BEFORE this subdomain scan using the stable parent context
			vulnCountBefore := len(reporting.GetVulnerabilitiesForContext(parentReportingCtxID))

			subSess := &scanSession{
				id:                   filepath.Base(subScanDir),
				target:               subdomain,
				parentTarget:         target,
				scanDir:              subScanDir,
				cfg:                  scanCfg,
				server:               s,
				instruction:          scanInstruction,
				name:                 req.Name,
				userInstruction:      req.Instruction,
				severityFilter:       req.SeverityFilter,
				discordWebhook:       req.DiscordWebhook,
				discoveryMode:        false,
				genReport:            false,
				resetState:           false, // accumulate vulns across subdomains
				instanceID:           req.InstanceID,
				scanMode:             "wildcard",
				parentReportingCtxID: parentReportingCtxID, // merge vulns into parent on cleanup
				companyName:          req.CompanyName,
				logoPath:             req.LogoPath,
				phases:               req.Phases,
				reconMode:            req.ReconMode,
				scanIntensity:        req.ScanIntensity,
				llmClient:            s.scanLLMClientForRequest(req, scanCfg),
			}
			s.executeScanSession(subSess)
			if s.instanceInterrupted(req.InstanceID) {
				wildcardStopped = true
				return
			}

			// Generate PDF for this subdomain if NEW vulnerabilities found
			// Read from the stable parent context — guaranteed to have all accumulated vulns
			allVulns := reporting.GetVulnerabilitiesForContext(parentReportingCtxID)
			if vulnCountBefore <= len(allVulns) {
				newVulns := allVulns[vulnCountBefore:]
				if len(newVulns) > 0 {
					subScanRecord := ScanRecord{
						ID:                       filepath.Base(subScanDir),
						InstanceID:               req.InstanceID,
						Name:                     req.Name,
						Target:                   subdomain,
						ParentTarget:             target,
						ScanMode:                 "wildcard",
						Instruction:              req.Instruction,
						SeverityFilter:           append([]string(nil), req.SeverityFilter...),
						DiscordWebhook:           req.DiscordWebhook,
						DiscordWebhookConfigured: req.DiscordWebhook != "" || s.discordWebhook != "",
						TelegramConfigured:       s.telegramConfigured(),
						ReconMode:                req.ReconMode,
						ScanIntensity:            req.ScanIntensity,
						StartedAt:                time.Now().Format(time.RFC3339),
						Status:                   "finished",
						FinishedAt:               time.Now().Format(time.RFC3339),
						Vulns:                    []VulnSummary{},
						CompanyName:              req.CompanyName,
						LogoPath:                 req.LogoPath,
						Phases:                   append([]int(nil), req.Phases...),
						CurrentPhase:             22,
					}
					for _, v := range newVulns {
						subScanRecord.Vulns = append(subScanRecord.Vulns, vulnToSummary(v))
					}
				reportPath, err := s.generateReportAt(&subScanRecord, subScanDir)
				if err == nil {
					desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found", subdomain, len(newVulns))
					s.sendDiscordWithFile(0x3b82f6, "🔴 Vulnerability Found - Report Ready", desc, reportPath)
					if s.telegramConfigured() {
						s.sendTelegramWithFile(0x3b82f6, "🔴 Vulnerability Found - Report Ready", desc, reportPath)
					}
				}
				}
			}

			s.broadcastToInstance(req.InstanceID, WSEvent{
				Type:           "target_completed",
				Content:        fmt.Sprintf("[PHASE 2] Subdomain %d/%d completed: %s", j+1, len(subdomains), subdomain),
				Target:         subdomain,
				TargetIndex:    idx + 1,
				TotalTargets:   total,
				SubTargetIndex: j + 1,
				SubTargetTotal: len(subdomains),
				ParentTarget:   target,
			})
		}()
		if wildcardStopped {
			break
		}
		saveWildcardProgress(j+1, -1, "", "")

		// ── Cooldown between subdomain scans ──
		// Prevents LLM API rate-limiting and gives GC time to reclaim memory
		if j < len(subdomains)-1 && !s.stopReq.Load() && !s.instanceInterrupted(req.InstanceID) {
			log.Printf("[INFO] Cooldown: 10s pause before next subdomain (memory recovery + rate limit prevention)")
			time.Sleep(10 * time.Second)
		}
	}
	if parentRecord == nil {
		parentRecord, _ = loadScanRecordFromDir(scanDir)
	}
	if parentRecord != nil {
		if wildcardStopped || s.stopReq.Load() {
			if status, stopReason := s.instanceRunStatus(req.InstanceID); isInterruptedInstanceStatus(status) {
				parentRecord.Status = status
				parentRecord.StopReason = stopReason
			} else {
				parentRecord.Status = "stopped"
				parentRecord.StopReason = "user_stopped"
			}
		} else {
			saveWildcardProgress(len(subdomains), -1, "", "")
			parentRecord.Status = "finished"
		}
		parentRecord.FinishedAt = time.Now().Format(time.RFC3339)
		s.saveScanRecordTo(parentRecord, scanDir)
	}

	log.Printf("[INFO] Wildcard scan complete for %s: scanned %d subdomains", target, len(subdomains))
	logMemStats(fmt.Sprintf("Wildcard scan complete for %s", target))
	debug.FreeOSMemory()
	// Clean up processes before next target — use instance's terminal if available
	s.instancesMu.RLock()
	if inst, ok := s.instances[req.InstanceID]; ok {
		inst.mu.RLock()
		if inst.sctx != nil && inst.sctx.Terminal != nil {
			inst.sctx.Terminal.KillAll()
		} else {
			terminal.KillAllProcesses() // fallback
		}
		inst.mu.RUnlock()
	} else {
		terminal.KillAllProcesses() // fallback
	}
	s.instancesMu.RUnlock()
}

func commandRateForPolicy(policy scanctx.RequestRatePolicy) int {
	if !policy.Enabled() {
		if cfg := config.Get(); cfg != nil && cfg.RateLimitRPS > 0 {
			policy = scanctx.RequestRatePolicy{MaxRPS: cfg.RateLimitRPS}
		}
	}
	if rate := policy.CommandRPS(); rate > 0 {
		return rate
	}
	return 1
}

func commandDelayForPolicy(policy scanctx.RequestRatePolicy) string {
	if !policy.Enabled() {
		if cfg := config.Get(); cfg != nil && cfg.RateLimitRPS > 0 {
			policy = scanctx.RequestRatePolicy{MaxRPS: cfg.RateLimitRPS}
		}
	}
	delay := policy.Delay()
	if delay <= 0 {
		return "1s"
	}
	if delay%time.Second == 0 {
		return strconv.Itoa(int(delay/time.Second)) + "s"
	}
	return strconv.Itoa(int(delay/time.Millisecond)) + "ms"
}

// buildDiscoveryInstruction creates the Phase 1 subdomain enumeration instruction.
func buildDiscoveryInstruction(target, reconMode string, ratePolicy scanctx.RequestRatePolicy) string {
	if normalizeActivityMode(reconMode) == activityModePassive {
		return buildPassiveDiscoveryInstruction(target)
	}
	rate := commandRateForPolicy(ratePolicy)
	delay := commandDelayForPolicy(ratePolicy)

	instruction := `# PHASE 1: SUBDOMAIN ENUMERATION ONLY

## YOUR TASK: Find ALL subdomains of TARGET — NOTHING ELSE.

## STRICT RULES:
- You are ONLY allowed to enumerate subdomains in this phase.
- DO NOT run any vulnerability scanners (nuclei, sqlmap, ffuf, gobuster, nikto, etc.).
- DO NOT test for XSS, SQLi, SSRF, IDOR, or any other vulnerability.
- DO NOT analyze JavaScript files, test authentication, or probe endpoints.
- After collecting subdomains, you MUST call finish IMMEDIATELY.

## SAVE ALL FILES IN THE CURRENT DIRECTORY
Save all output files directly in the current working directory (not subdirectories).

## SUBDOMAIN ENUMERATION COMMANDS - RUN ALL:

## REQUEST RATE LIMIT
All target-touching commands must stay at or below RATE_LIMIT requests/sec. Use RATE_DELAY or slower when a tool needs an explicit delay.

# 1. subfinder (passive)
subfinder -d TARGET -recursive -silent -o ./passive_subfinder.txt
subfinder -d TARGET -all -recursive -silent -o ./passive_subfinder2.txt

# 2. Certificate Transparency (curl)
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > ./passive_crt.txt

# 3. findomain
findomain -t TARGET --unique-output ./passive_findomain.txt 2>/dev/null || true

# 4. assetfinder
assetfinder --subs-only TARGET | tee ./passive_assetfinder.txt 2>/dev/null || true

# 5. DNS Bufferover
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | sort -u > ./passive_dnsbufferover.txt
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.RDNS[]' 2>/dev/null | cut -d',' -f1 | sort -u >> ./passive_dnsbufferover.txt

# 6. Wayback Machine
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[].original' 2>/dev/null | cut -d'/' -f3 | sort -u > ./archive_subdomains.txt

# 7. Active enumeration
subfinder -d TARGET -all -recursive -rl RATE_LIMIT -t RATE_LIMIT -o ./active_subfinder.txt

# 8. MERGE ALL RESULTS
cat ./passive_*.txt ./active_*.txt ./archive_subdomains.txt 2>/dev/null | grep -v '*' | grep -v '@' | sort -u > ./all_subdomains.txt
echo "Total unique subdomains found:"
wc -l ./all_subdomains.txt

# 9. RESOLVE TO FIND LIVE HOSTS
cat ./all_subdomains.txt | dnsx -silent -a -resp -rl RATE_LIMIT -threads RATE_LIMIT -o ./live_resolved.txt 2>/dev/null || true
cat ./live_resolved.txt | cut -d' ' -f1 | grep -v '^$' | sort -u > ./live_subdomains.txt
echo "Live subdomains:"
wc -l ./live_subdomains.txt

## FINAL STEP (MANDATORY):
1. Call add_note with the complete list of live subdomains from ./live_subdomains.txt
2. Call finish IMMEDIATELY after. The system will handle vulnerability scanning of each subdomain separately.

DO NOT continue past this point. DO NOT scan for vulnerabilities. Call finish NOW.`

	// Replace TARGET placeholder with actual target
	instruction = strings.ReplaceAll(instruction, "TARGET", target)
	instruction = strings.ReplaceAll(instruction, "RATE_LIMIT", strconv.Itoa(rate))
	instruction = strings.ReplaceAll(instruction, "RATE_DELAY", delay)
	return instruction
}

func buildPassiveDiscoveryInstruction(target string) string {
	instruction := `# PHASE 1: PASSIVE SUBDOMAIN ENUMERATION ONLY

## YOUR TASK: Find subdomains of TARGET without direct target contact.

## STRICT PASSIVE RULES:
- Do NOT send HTTP requests, browser traffic, port scans, DNS brute force, crawlers, fingerprinting probes, or payloads to TARGET or discovered subdomains.
- Do NOT run dnsx, httpx, nmap, naabu, masscan, ffuf, gobuster, dirsearch, feroxbuster, katana, gospider, nuclei, sqlmap, dalfox, nikto, wpscan, whatweb, ping, dig, host, or nslookup against the target.
- Use passive sources only: web_search, certificate transparency, public archives, search engines, third-party intel datasets, existing notes, and already collected files.
- After collecting passive names, call finish IMMEDIATELY. The system will handle the selected scanning policy separately.

## SAVE ALL FILES IN THE CURRENT DIRECTORY
Save all output files directly in the current working directory.

## PASSIVE ENUMERATION COMMANDS:

# 1. Passive provider tools when available
subfinder -d TARGET -recursive -silent -o ./passive_subfinder.txt 2>/dev/null || true
subfinder -d TARGET -all -recursive -silent -o ./passive_subfinder2.txt 2>/dev/null || true
findomain -t TARGET --unique-output ./passive_findomain.txt 2>/dev/null || true
assetfinder --subs-only TARGET | tee ./passive_assetfinder.txt 2>/dev/null || true

# 2. Public third-party datasets
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > ./passive_crt.txt || true
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.FDNS_A[]?' 2>/dev/null | cut -d',' -f2 | sort -u > ./passive_dnsbufferover.txt || true
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.RDNS[]?' 2>/dev/null | cut -d',' -f1 | sort -u >> ./passive_dnsbufferover.txt || true
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[].original' 2>/dev/null | cut -d'/' -f3 | sort -u > ./archive_subdomains.txt || true

# 3. Merge passive names only. Do not resolve or probe them.
cat ./passive_*.txt ./archive_subdomains.txt 2>/dev/null | grep -v '*' | grep -v '@' | sort -u > ./all_subdomains.txt
echo "Total passive subdomains found:"
wc -l ./all_subdomains.txt

## FINAL STEP (MANDATORY):
1. Call add_note with the complete passive subdomain list from ./all_subdomains.txt.
2. Call finish IMMEDIATELY after.

DO NOT resolve hosts. DO NOT verify liveness. DO NOT scan for vulnerabilities. Call finish NOW.`

	instruction = strings.ReplaceAll(instruction, "TARGET", target)
	return instruction
}

// collectSubdomains reads discovered subdomains from all known file locations and agent notes.
// contextID is used for context-aware notes lookup; if empty, falls back to global notes.
func (s *Server) collectSubdomains(scanDir, target, contextID string) []string {
	seen := make(map[string]bool)
	var subdomains []string

	// Normalize target to root domain — strip www. prefix so "www.zooptos.com" → "zooptos.com"
	// This ensures api.zooptos.com matches when user entered www.zooptos.com
	rootTarget := strings.TrimPrefix(target, "www.")

	// ansiRegex strips ANSI escape codes (color, cursor, etc.) from tool output.
	// Tools like dnsx emit sequences like \x1b[35m that corrupt domain matching.
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

	// Helper: extract valid subdomains from a file (must be subdomains of the target)
	extractFromFile := func(path string) []string {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// Strip all ANSI escape codes before parsing
		clean := ansiRegex.ReplaceAllString(string(data), "")
		var found []string
		for _, line := range strings.Split(clean, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Total") || strings.HasPrefix(line, "wc") {
				continue
			}
			line = strings.TrimPrefix(line, "http://")
			line = strings.TrimPrefix(line, "https://")
			line = strings.TrimPrefix(line, "http[s]://")
			parts := strings.Fields(line)
			if len(parts) > 0 {
				domain := strings.TrimRight(parts[0], "/.,;:")
				domain = strings.ToLower(domain)
				// Accept: exact root domain OR any subdomain of root domain
				if strings.Contains(domain, ".") && (domain == rootTarget || strings.HasSuffix(domain, "."+rootTarget)) && !seen[domain] {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}
		return found
	}

	// stripMarkdown removes common markdown formatting from a token
	stripMarkdown := func(s string) string {
		s = strings.ReplaceAll(s, "**", "") // bold
		s = strings.ReplaceAll(s, "__", "") // bold alt
		s = strings.ReplaceAll(s, "`", "")  // code
		s = strings.ReplaceAll(s, "*", "")  // italic
		s = strings.TrimRight(s, "/.,;:()[]{}\"'")
		s = strings.TrimLeft(s, "/.,;:()[]{}\"'")
		return s
	}

	// isDomainMatch checks if a cleaned string is a valid subdomain of rootTarget
	isDomainMatch := func(domain string) bool {
		domain = strings.ToLower(domain)
		return strings.Contains(domain, ".") &&
			(domain == rootTarget || strings.HasSuffix(domain, "."+rootTarget)) &&
			!seen[domain]
	}

	// domainRegex matches potential domain names in free-form text
	domainRegex := regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+` + regexp.QuoteMeta(rootTarget) + `\b`)

	// Helper: extract subdomains from a text blob (e.g., agent notes)
	// Handles: plain lines, markdown lists (- , * , 1. ), bold (**...**), URLs, etc.
	extractFromText := func(text string) []string {
		// Strip ANSI escape codes from text blobs too (terminal captures may contain them)
		text = ansiRegex.ReplaceAllString(text, "")
		var found []string

		// Pass 1: line-by-line parsing (handles structured lists)
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Strip common list prefixes: "- ", "* ", "1. ", "2) ", etc.
			line = strings.TrimPrefix(line, "- ")
			line = strings.TrimPrefix(line, "* ")
			// Strip numbered list prefixes: "1. ", "2. ", "10. ", etc.
			if len(line) > 2 {
				dotIdx := strings.Index(line, ". ")
				if dotIdx > 0 && dotIdx <= 4 {
					prefix := line[:dotIdx]
					allDigits := true
					for _, c := range prefix {
						if c < '0' || c > '9' {
							allDigits = false
							break
						}
					}
					if allDigits {
						line = strings.TrimSpace(line[dotIdx+2:])
					}
				}
			}

			// Try each whitespace-delimited token in the line
			for _, token := range strings.Fields(line) {
				token = strings.TrimPrefix(token, "http://")
				token = strings.TrimPrefix(token, "https://")
				token = strings.TrimPrefix(token, "http[s]://")
				// Strip path component
				if idx := strings.Index(token, "/"); idx > 0 {
					token = token[:idx]
				}
				domain := strings.ToLower(stripMarkdown(token))
				if isDomainMatch(domain) {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}

		// Pass 2: regex fallback — catches domains embedded in any format
		if len(found) == 0 {
			lowerText := strings.ToLower(text)
			if strings.Contains(lowerText, rootTarget) {
				// Try regex extraction for subdomains
				matches := domainRegex.FindAllString(lowerText, -1)
				for _, m := range matches {
					m = strings.TrimRight(m, "/.,;:")
					if isDomainMatch(m) {
						seen[m] = true
						found = append(found, m)
					}
				}
				// Also check bare rootTarget (e.g., "bild.tv" itself)
				if !seen[rootTarget] {
					seen[rootTarget] = true
					found = append(found, rootTarget)
				}
			}
		}

		return found
	}

	subdomainFileNames := []string{
		"live_subdomains.txt", "live_subdomains_clean.txt", "live_resolved.txt",
		"all_subdomains.txt", "all_discovered_subdomains.txt", "subdomains.txt",
		"live_hosts.txt", "passive_subfinder.txt", "passive_subfinder2.txt",
		"active_subfinder.txt", "passive_crt.txt", "passive_findomain.txt",
		"passive_assetfinder.txt", "passive_dnsbufferover.txt", "archive_subdomains.txt",
		"resolved_subdomains.txt", "httpx_output.txt", "dnsx_output.txt",
	}

	// Layer 1: Check exact files in scan directory
	for _, name := range subdomainFileNames {
		path := filepath.Join(scanDir, name)
		if found := extractFromFile(path); len(found) > 0 {
			subdomains = append(subdomains, found...)
			if name == "live_subdomains.txt" || name == "live_resolved.txt" {
				break
			}
		}
	}

	// Layer 1.25: Check workspace and terminal workdir — agents run commands here,
	// so ./passive_subfinder.txt etc. land in these directories, NOT in scanDir.
	if len(subdomains) == 0 {
		checkDirs := []string{}
		if wd := terminal.GetWorkDir(); wd != "" && wd != scanDir {
			checkDirs = append(checkDirs, wd)
		}
		if s.cfg.Workspace != "" && s.cfg.Workspace != scanDir {
			checkDirs = append(checkDirs, s.cfg.Workspace)
		}
		for _, dir := range checkDirs {
			for _, name := range subdomainFileNames {
				path := filepath.Join(dir, name)
				if found := extractFromFile(path); len(found) > 0 {
					log.Printf("[INFO] Found %d subdomains from %s/%s (agent workdir)", len(found), dir, name)
					subdomains = append(subdomains, found...)
				}
			}
			if len(subdomains) > 0 {
				break
			}
		}
	}

	// Layer 1.5: Check /tmp — agents often save recon files here
	if len(subdomains) == 0 {
		for _, name := range subdomainFileNames {
			path := filepath.Join("/tmp", name)
			if found := extractFromFile(path); len(found) > 0 {
				log.Printf("[INFO] Found %d subdomains from /tmp/%s", len(found), name)
				subdomains = append(subdomains, found...)
			}
		}
	}

	// Layer 1.75: Check home directory — some agents write to ~/
	if len(subdomains) == 0 {
		if homeDir, err := os.UserHomeDir(); err == nil && homeDir != scanDir {
			for _, name := range subdomainFileNames {
				path := filepath.Join(homeDir, name)
				if found := extractFromFile(path); len(found) > 0 {
					log.Printf("[INFO] Found %d subdomains from %s/%s (home dir)", len(found), homeDir, name)
					subdomains = append(subdomains, found...)
				}
			}
		}
	}

	// Layer 2: Walk scan directory tree for any matching files
	if len(subdomains) == 0 {
		_ = filepath.WalkDir(scanDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			base := filepath.Base(path)
			for _, name := range subdomainFileNames {
				if base == name {
					if found := extractFromFile(path); len(found) > 0 {
						subdomains = append(subdomains, found...)
						return nil
					}
				}
			}
			return nil
		})
	}

	// Layer 3: Parse agent notes for subdomain data (context-aware)
	if len(subdomains) == 0 {
		var allNotes map[string]string
		if contextID != "" {
			allNotes = notes.GetAllNotesForContext(contextID)
		} else {
			allNotes = notes.GetAllNotes()
		}
		for key, value := range allNotes {
			lowerKey := strings.ToLower(key)
			if strings.Contains(lowerKey, "subdomain") || strings.Contains(lowerKey, "live") || strings.Contains(lowerKey, "discovered") || strings.Contains(lowerKey, "domain") {
				if found := extractFromText(value); len(found) > 0 {
					subdomains = append(subdomains, found...)
				}
			}
		}
		if len(subdomains) == 0 {
			for _, value := range allNotes {
				if found := extractFromText(value); len(found) > 0 {
					subdomains = append(subdomains, found...)
				}
			}
		}
	}

	if len(subdomains) == 0 {
		log.Printf("[WARN] No subdomains found after all fallback layers for target: %s (rootTarget: %s)", target, rootTarget)
	}

	// Shuffle so scan order is randomized — avoids predictable patterns
	mathrand.Shuffle(len(subdomains), func(i, j int) {
		subdomains[i], subdomains[j] = subdomains[j], subdomains[i]
	})

	return subdomains
}

// cleanTmpSubdomainFiles removes stale subdomain-related files from /tmp
// that could contaminate subsequent scans with targets from previous runs.
func cleanTmpSubdomainFiles() {
	subdomainFileNames := []string{
		"live_subdomains.txt", "live_subdomains_clean.txt", "live_resolved.txt",
		"all_subdomains.txt", "all_discovered_subdomains.txt", "subdomains.txt",
		"live_hosts.txt", "passive_subfinder.txt", "passive_subfinder2.txt",
		"active_subfinder.txt", "passive_crt.txt", "passive_findomain.txt",
		"passive_assetfinder.txt", "passive_dnsbufferover.txt", "archive_subdomains.txt",
		"resolved_subdomains.txt", "httpx_output.txt", "dnsx_output.txt",
	}

	// Remove known subdomain file names from /tmp
	for _, name := range subdomainFileNames {
		path := filepath.Join("/tmp", name)
		if err := os.Remove(path); err == nil {
			log.Printf("[CLEANUP] Removed stale /tmp file: %s", path)
		}
	}

	// Also remove any .txt files in /tmp that contain "subdomain" or "live" in the name
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		log.Printf("[CLEANUP] Failed to read /tmp for cleanup: %v", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".txt") && (strings.Contains(name, "subdomain") || strings.Contains(name, "live_") || strings.Contains(name, "passive_") || strings.Contains(name, "active_")) {
			path := filepath.Join("/tmp", name)
			if err := os.Remove(path); err == nil {
				log.Printf("[CLEANUP] Removed stale /tmp file: %s", path)
			}
		}
	}
}

// handleUploadTargets parses a text file with one target per line.
func (s *Server) handleUploadTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	} // 10MB max
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] Failed to read uploaded targets file: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"targets": targets,
		"count":   len(targets),
	})
}

// handleUploadInstructions reads a text file and returns its content.
func (s *Server) handleUploadInstructions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil {
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	} // 5MB max
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"content": string(data),
	})
}

// handleUploadLogo accepts an image file upload and saves it to the logos directory.
func (s *Server) handleUploadLogo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil { // 5MB max
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file extension. PDF reports can embed PNG/JPEG reliably; keep
	// uploads constrained to formats the report renderer can use.
	originalName := filepath.Base(header.Filename)
	ext := strings.ToLower(filepath.Ext(originalName))
	allowedExts := map[string]bool{".png": true, ".jpg": true, ".jpeg": true}
	if !allowedExts[ext] {
		http.Error(w, "unsupported image format: "+ext+" (allowed: png, jpg, jpeg)", http.StatusBadRequest)
		return
	}

	// Create logos directory
	logosDir := filepath.Join(s.dataDir, "logos")
	if err := os.MkdirAll(logosDir, 0700); err != nil {
		log.Printf("[ERROR] Failed to create logos directory: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Generate unique filename: timestamp_sanitizedname.ext
	nameOnly := strings.TrimSuffix(originalName, filepath.Ext(originalName))
	safeName := regexp.MustCompile(`[^a-zA-Z0-9._-]+`).ReplaceAllString(nameOnly, "_")
	safeName = strings.Trim(safeName, "._-")
	if safeName == "" {
		safeName = "logo"
	}
	fileName := fmt.Sprintf("%d_%s%s", time.Now().UnixMilli(), safeName, ext)
	dstPath := filepath.Join(logosDir, fileName)

	dst, err := os.Create(dstPath)
	if err != nil {
		log.Printf("[ERROR] Failed to create logo file: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("[ERROR] Failed to write logo file: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Return the serving path
	servingPath := "/uploads/logos/" + fileName
	log.Printf("Logo uploaded: %s → %s", header.Filename, servingPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"path":     servingPath,
		"filename": originalName,
	})
}

// randomSlug generates a short random hex string for scan IDs.
func randomSlug() string {
	b := make([]byte, 4)
	if _, err := cryptorand.Read(b); err != nil {
		log.Printf("Warning: crypto/rand failed, falling back to time-based slug: %v", err)
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// sanitizeTarget creates a safe directory name from a target URL/domain.
func sanitizeTarget(target string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	clean := re.ReplaceAllString(target, "_")
	clean = strings.TrimPrefix(clean, "https___")
	clean = strings.TrimPrefix(clean, "http___")
	clean = strings.Trim(clean, "_")
	if len(clean) > 60 {
		clean = clean[:60]
	}
	return clean
}

// importLegacyDataDir copies scan records from the pre-migration data
// directory ~/xalgorix-data/ into the active s.dataDir, idempotently
// and non-destructively. Each scan ID already present under dataDir is
// skipped. On completion (or no-op early return), a sentinel file
// .legacy-imported is written so subsequent starts skip the walk.
//
// Returns the number of scans imported.
//
// Validates: Property 6 (legacy-import idempotence) of the
// findings-consistency-and-pagination spec.
func (s *Server) importLegacyDataDir() (int, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, fmt.Errorf("home dir: %w", err)
	}
	legacyPath := filepath.Join(home, "xalgorix-data")
	sentinelPath := filepath.Join(s.dataDir, ".legacy-imported")

	// Early return: legacy IS the active dir — nothing to migrate.
	if filepath.Clean(legacyPath) == filepath.Clean(s.dataDir) {
		return 0, nil
	}
	// Early return: already imported once.
	if _, err := os.Stat(sentinelPath); err == nil {
		return 0, nil
	}
	// Early return: legacy dir doesn't exist or is empty.
	if info, err := os.Stat(legacyPath); err != nil || !info.IsDir() {
		// Still write the sentinel to skip future stat() calls.
		_ = os.MkdirAll(s.dataDir, 0o700)
		_ = os.WriteFile(sentinelPath, []byte("nothing-to-import\n"), 0o600)
		return 0, nil
	}

	existing := map[string]bool{}
	for _, entry := range s.findAllScans() {
		if entry.rec.ID != "" {
			existing[entry.rec.ID] = true
		}
	}

	imported := 0
	skipped := 0
	walkErr := filepath.WalkDir(legacyPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("[legacy-import] walk %s: %v", path, err)
			skipped++
			return nil // best effort; skip unreadable entries
		}
		if d.IsDir() || d.Name() != "scan.json" {
			return nil
		}
		// Read the scan.json to extract the id and target.
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			log.Printf("[legacy-import] skipped %s: read error: %v", path, readErr)
			skipped++
			return nil
		}
		var rec ScanRecord
		if jerr := json.Unmarshal(data, &rec); jerr != nil {
			log.Printf("[legacy-import] skipped %s: malformed json: %v", path, jerr)
			skipped++
			return nil
		}
		if rec.ID == "" {
			log.Printf("[legacy-import] skipped %s: missing scan id", path)
			skipped++
			return nil
		}
		if existing[rec.ID] {
			// Already present in active dataDir — not an error, no log spam.
			return nil
		}

		// Determine destination directory using the same date-stamped
		// shape as createScanDirFor: dataDir/<target>/<date>/<scan-id>/
		srcDir := filepath.Dir(path)
		target := sanitizeTarget(rec.Target)
		if target == "" {
			target = "unknown"
		}
		date := ""
		if t, perr := time.Parse(time.RFC3339, rec.StartedAt); perr == nil {
			date = t.Format("2006-01-02")
		} else if t, perr := time.Parse(time.RFC3339Nano, rec.StartedAt); perr == nil {
			date = t.Format("2006-01-02")
		} else {
			date = time.Now().Format("2006-01-02")
		}
		dstDir := filepath.Join(s.dataDir, target, date, rec.ID)

		if err := copyDirRecursive(srcDir, dstDir); err != nil {
			log.Printf("[legacy-import] copy %s -> %s: %v", srcDir, dstDir, err)
			skipped++
			return nil
		}
		imported++
		existing[rec.ID] = true
		return nil
	})
	if walkErr != nil {
		return imported, walkErr
	}

	// Write sentinel even on partial success — failed copies are logged
	// and the user can retry by removing the sentinel.
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		log.Printf("[legacy-import] mkdir dataDir: %v", err)
	}
	if err := os.WriteFile(sentinelPath, []byte(fmt.Sprintf("imported=%d skipped=%d at=%s\n", imported, skipped, time.Now().Format(time.RFC3339))), 0o600); err != nil {
		log.Printf("[legacy-import] write sentinel: %v", err)
	}
	if skipped > 0 {
		log.Printf("[legacy-import] imported %d scans, skipped %d (see log lines above) from %s", imported, skipped, legacyPath)
	} else {
		log.Printf("[legacy-import] imported %d scans from %s", imported, legacyPath)
	}
	return imported, nil
}

// copyDirRecursive copies src directory tree to dst, creating dst if
// needed. Existing files at dst are overwritten. Used by
// importLegacyDataDir for non-destructive copy semantics (legacy dir
// preserved untouched).
func copyDirRecursive(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

// saveScanRecordTo saves a scan record to a specific directory.
func (s *Server) saveScanRecordTo(rec *ScanRecord, scanDir string) {
	if scanDir == "" {
		return
	}

	// Check disk space before writing (50MB minimum)
	if avail := diskAvailable(scanDir); avail > 0 && avail < 50*1024*1024 {
		log.Printf("Warning: low disk space (%d MB available), scan record may fail to save", avail/1024/1024)
		s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Low disk space: %d MB remaining. Scan data may not be saved.", avail/1024/1024)})
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		log.Printf("Error: failed to marshal scan record: %v", err)
		return
	}
	if err := os.WriteFile(filepath.Join(scanDir, "scan.json"), data, 0600); err != nil {
		log.Printf("Error: failed to save scan record to %s: %v", scanDir, err)
		s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Failed to save scan data: %v", err)})
	}
}

// diskAvailable returns available bytes on the filesystem containing path, or 0 on error.
func diskAvailable(path string) uint64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}
	return stat.Bavail * uint64(stat.Bsize) //nolint:gosec // G115: filesystem block size is small and non-negative
}

// vulnToSummary converts a reporting.Vulnerability to a VulnSummary with all fields.
func vulnToSummary(v reporting.Vulnerability) VulnSummary {
	return VulnSummary{
		ID:                 v.ID,
		Title:              v.Title,
		Severity:           v.Severity,
		Target:             v.Target,
		Endpoint:           v.Endpoint,
		CVSS:               v.CVSS,
		CVSSVector:         v.CVSSVector,
		Description:        v.Description,
		Impact:             v.Impact,
		Method:             v.Method,
		CVE:                v.CVE,
		CWE:                v.CWE,
		OWASP:              v.OWASP,
		TechnicalAnalysis:  v.TechnicalAnalysis,
		PoCDescription:     v.PoCDescription,
		PoCScript:          v.PoCScript,
		Remediation:        v.Remediation,
		ExploitationProof:  v.ExploitationProof,
		VerificationMethod: v.VerificationMethod,
		Verified:           v.Verified,
	}
}

func metadataString(metadata map[string]any, key string) (string, bool) {
	if metadata == nil {
		return "", false
	}
	value, ok := metadata[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	text = strings.TrimSpace(text)
	return text, text != ""
}

func findReportedVulnerabilityByID(vulns []reporting.Vulnerability, id string) (reporting.Vulnerability, bool) {
	for _, vuln := range vulns {
		if vuln.ID == id {
			return vuln, true
		}
	}
	return reporting.Vulnerability{}, false
}

func appendVulnSummaryUnique(vulns *[]VulnSummary, vuln VulnSummary) bool {
	key := vulnSummaryKey(vuln)
	for _, existing := range *vulns {
		if vulnSummaryKey(existing) == key {
			return false
		}
	}
	*vulns = append(*vulns, vuln)
	return true
}

func vulnSummaryKey(v VulnSummary) string {
	return strings.Join([]string{
		normalizeSummaryPart(v.Title),
		normalizeSummaryPart(v.Target),
		normalizeSummaryPart(v.Endpoint),
		normalizeSummaryPart(v.Method),
		normalizeSummaryPart(v.CVE),
	}, "|")
}

func normalizeSummaryPart(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

// generateReportAt generates a PDF report, saving it to a specific directory.
func (s *Server) generateReportAt(scan *ScanRecord, scanDir string) (string, error) {
	// Temporarily set currentScanDir for the report generator,
	// then restore it. The report.go generateReport method reads s.currentScanDir.
	s.mu.Lock()
	prevDir := s.currentScanDir
	s.currentScanDir = scanDir
	s.mu.Unlock()

	reportPath, err := s.generateReport(scan)

	s.mu.Lock()
	s.currentScanDir = prevDir
	s.mu.Unlock()

	return reportPath, err
}

// scanEntry holds a discovered scan.json path and its parsed record.
type scanEntry struct {
	dir string     // directory containing scan.json
	rec ScanRecord // parsed record
}

// findAllScans recursively walks dataDir to find all scan.json files.
// Structure: dataDir/target/date/slug/scan.json
func (s *Server) findAllScans() []scanEntry {
	var results []scanEntry
	_ = filepath.WalkDir(s.dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() != "scan.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var rec ScanRecord
		if json.Unmarshal(data, &rec) != nil {
			return nil
		}
		results = append(results, scanEntry{dir: filepath.Dir(path), rec: rec})
		return nil
	})
	return results
}

// scanSummaryCacheEntry is one memoized, events-free scan record plus the file
// stat used to detect staleness.
type scanSummaryCacheEntry struct {
	modNano int64
	size    int64
	rec     ScanRecord
}

// scanRecordLite parses a scan.json while skipping the heavy events array.
// The embedded ScanRecord carries every field; the shadow Events field — a
// json.RawMessage at depth 0 — captures the "events" key so encoding/json
// routes it here instead of unmarshaling thousands of WSEvent structs into the
// embedded slice (encoding/json picks the shallowest field on a tag conflict).
// The captured bytes are discarded: list, findings, and summary views never
// read events, and skipping the per-event struct decode is the bulk of the
// parse-cost saving.
type scanRecordLite struct {
	ScanRecord
	Events json.RawMessage `json:"events"`
}

// findAllScanSummaries is the events-free, cached counterpart to findAllScans.
// It walks the data dir, parses each scan.json without decoding its event log,
// and memoizes the result per file keyed by (modtime, size). Subsequent walks
// only stat each file and re-parse the few that changed, so warm rebuilds are
// effectively free. Callers that need the event log (report generation,
// scan-detail) must use findAllScans instead.
func (s *Server) findAllScanSummaries() []scanEntry {
	var results []scanEntry

	s.scanSummaryCacheMu.Lock()
	defer s.scanSummaryCacheMu.Unlock()
	if s.scanSummaryCache == nil {
		s.scanSummaryCache = make(map[string]scanSummaryCacheEntry)
	}
	seen := make(map[string]struct{})

	_ = filepath.WalkDir(s.dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() != "scan.json" {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		seen[path] = struct{}{}
		modNano := info.ModTime().UnixNano()
		size := info.Size()
		if c, ok := s.scanSummaryCache[path]; ok && c.modNano == modNano && c.size == size {
			results = append(results, scanEntry{dir: filepath.Dir(path), rec: c.rec})
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var lite scanRecordLite
		if json.Unmarshal(data, &lite) != nil {
			return nil
		}
		rec := lite.ScanRecord
		rec.Events = nil
		s.scanSummaryCache[path] = scanSummaryCacheEntry{modNano: modNano, size: size, rec: rec}
		results = append(results, scanEntry{dir: filepath.Dir(path), rec: rec})
		return nil
	})

	// Drop cache entries for files that no longer exist so deleted scans
	// don't leak memory across the process lifetime.
	if len(s.scanSummaryCache) > len(seen) {
		for p := range s.scanSummaryCache {
			if _, ok := seen[p]; !ok {
				delete(s.scanSummaryCache, p)
			}
		}
	}

	return results
}

// findScanByID searches for a scan by its AgentID (the slug dir name).
func (s *Server) findScanByID(scanID string) (string, *ScanRecord) {
	// Sanitize: prevent path traversal via ../
	scanID = filepath.Base(scanID)
	if scanID == "" || scanID == "." || scanID == ".." {
		return "", nil
	}

	// First: prefer top-level scans. Multiple wildcard child records share the
	// same instance id; returning a child here makes the UI route land on one
	// subdomain instead of the parent wildcard scan.
	entries := s.findAllScans()
	for _, entry := range entries {
		if entry.rec.ParentTarget != "" {
			continue
		}
		if entry.rec.ID == scanID || entry.rec.InstanceID == scanID || filepath.Base(entry.dir) == scanID {
			return entry.dir, &entry.rec
		}
	}
	// Second: allow direct child lookup when the caller explicitly uses a child
	// scan id, for report generation and historical compatibility.
	for _, entry := range entries {
		if entry.rec.ID == scanID || entry.rec.InstanceID == scanID || filepath.Base(entry.dir) == scanID {
			return entry.dir, &entry.rec
		}
	}
	// Second: try legacy flat path as fallback (dataDir/scanID/scan.json)
	direct := filepath.Join(s.dataDir, scanID, "scan.json")
	if data, err := os.ReadFile(direct); err == nil {
		var rec ScanRecord
		if json.Unmarshal(data, &rec) == nil {
			return filepath.Join(s.dataDir, scanID), &rec
		}
	}
	return "", nil
}

var shortHexIDPattern = regexp.MustCompile(`^[a-f0-9]{8}$`)

func (s *Server) findRecentScanForShortAlias(scanID string) (string, *ScanRecord) {
	if !shortHexIDPattern.MatchString(scanID) {
		return "", nil
	}

	entries := s.findAllScans()
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].rec.StartedAt > entries[j].rec.StartedAt
	})

	for _, entry := range entries {
		if entry.rec.ParentTarget != "" {
			continue
		}
		startedAt, err := time.Parse(time.RFC3339Nano, entry.rec.StartedAt)
		if err != nil {
			continue
		}
		if time.Since(startedAt) > 24*time.Hour {
			continue
		}
		log.Printf("[web] Resolving short scan route %s to recent scan %s", scanID, entry.rec.ID)
		return entry.dir, &entry.rec
	}
	return "", nil
}

func (s *Server) markDiscordWebhookConfigured(rec *ScanRecord) {
	if rec == nil {
		return
	}
	rec.DiscordWebhookConfigured = rec.DiscordWebhookConfigured ||
		rec.DiscordWebhook != "" ||
		s.discordWebhook != ""
}

// markTelegramConfigured sets the TelegramConfigured flag on a scan
// record when global Telegram notifications are enabled. Telegram is
// global-only in v1 (no per-scan override), so the flag reflects the
// server-wide configuration rather than any per-scan field. The bot
// token itself is never written to the record (only the boolean).
func (s *Server) markTelegramConfigured(rec *ScanRecord) {
	if rec == nil {
		return
	}
	rec.TelegramConfigured = s.telegramConfigured()
}

func (s *Server) scanRecordFromInstance(inst *ScanInstance) *ScanRecord {
	if inst == nil {
		return nil
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()

	events := make([]WSEvent, len(inst.events))
	copy(events, inst.events)
	vulns := make([]VulnSummary, len(inst.Vulns))
	copy(vulns, inst.Vulns)
	phases := append([]int(nil), inst.Phases...)
	severityFilter := append([]string(nil), inst.SeverityFilter...)

	return &ScanRecord{
		ID:                       inst.ID,
		InstanceID:               inst.ID,
		Name:                     inst.Name,
		Target:                   inst.Targets,
		ParentTarget:             inst.ParentTarget,
		StartedAt:                inst.StartedAt,
		FinishedAt:               inst.FinishedAt,
		Status:                   inst.Status,
		StopReason:               inst.StopReason,
		ScanMode:                 inst.ScanMode,
		Instruction:              inst.Instruction,
		SeverityFilter:           severityFilter,
		DiscordWebhook:           inst.DiscordWebhook,
		DiscordWebhookConfigured: inst.DiscordWebhook != "",
		TelegramConfigured:       s.telegramConfigured(),
		ReconMode:                inst.ReconMode,
		ScanIntensity:            inst.ScanIntensity,
		Events:                   events,
		Vulns:                    vulns,
		TotalTokens:              inst.TotalTokens,
		Iterations:               inst.Iterations,
		ToolCalls:                inst.ToolCalls,
		CompanyName:              inst.CompanyName,
		LogoPath:                 inst.LogoPath,
		Phases:                   phases,
		CurrentPhase:             inst.CurrentPhase,
	}
}

func normalizeScanTarget(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimRight(target, "/")
	return target
}

func isFinishedSubScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed", "stopped", "failed":
		return true
	default:
		return false
	}
}

func isCompletedScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed":
		return true
	default:
		return false
	}
}

func isTerminalScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed", "stopped", "failed":
		return true
	default:
		return false
	}
}

func isUnresolvedSubScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "pending", "running":
		return true
	default:
		return false
	}
}

func terminalSubScanStatus(parentStatus string) string {
	if strings.EqualFold(strings.TrimSpace(parentStatus), "failed") {
		return "failed"
	}
	return "stopped"
}

func isChildOfScan(parent, child *ScanRecord) bool {
	if parent == nil || child == nil || child.ParentTarget == "" {
		return false
	}
	// Instance-aware matching: when the parent has an InstanceID (all
	// multi-instance scans do), the child must belong to the same
	// instance. Without this gate a new yahoo.com scan would absorb
	// every subdomain record from *previous* yahoo.com scans on disk,
	// instantly showing stale vulns and inflated subdomain counts.
	if parent.InstanceID != "" {
		return child.InstanceID == parent.InstanceID
	}
	// Legacy fallback for scans created before multi-instance mode:
	// match by target name only.
	return normalizeScanTarget(child.ParentTarget) == normalizeScanTarget(parent.Target)
}

func (s *Server) instanceForRecord(rec *ScanRecord) *ScanInstance {
	if rec == nil {
		return nil
	}
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	if rec.InstanceID != "" {
		if inst := s.instances[rec.InstanceID]; inst != nil {
			return inst
		}
	}
	return s.instances[rec.ID]
}

func (s *Server) applyInstanceSnapshot(rec *ScanRecord, includeEvents bool) {
	inst := s.instanceForRecord(rec)
	if inst == nil {
		return
	}
	snapshot := s.scanRecordFromInstance(inst)
	if snapshot == nil {
		return
	}
	if rec.InstanceID == "" {
		rec.InstanceID = snapshot.InstanceID
	}
	rec.Status = snapshot.Status
	rec.FinishedAt = snapshot.FinishedAt
	rec.StopReason = snapshot.StopReason
	if snapshot.Iterations > rec.Iterations {
		rec.Iterations = snapshot.Iterations
	}
	if snapshot.ToolCalls > rec.ToolCalls {
		rec.ToolCalls = snapshot.ToolCalls
	}
	if snapshot.TotalTokens > rec.TotalTokens {
		rec.TotalTokens = snapshot.TotalTokens
	}
	for _, vuln := range snapshot.Vulns {
		appendVulnSummaryUnique(&rec.Vulns, vuln)
	}
	if snapshot.CurrentPhase > 0 {
		rec.CurrentPhase = snapshot.CurrentPhase
	}
	if includeEvents && len(snapshot.Events) >= len(rec.Events) {
		rec.Events = snapshot.Events
	}
}

// attachWildcardSubScans resolves a wildcard parent scan's child sub-scans by
// walking the data dir. It is a thin wrapper around attachWildcardSubScansFrom
// for callers that do not already hold a walked entry slice.
func (s *Server) attachWildcardSubScans(rec *ScanRecord) {
	if rec == nil || rec.ParentTarget != "" {
		return
	}
	s.attachWildcardSubScansFrom(rec, s.findAllScans())
}

// attachWildcardSubScansFrom is the same as attachWildcardSubScans but reuses
// a pre-walked slice of scan entries instead of calling findAllScans() itself.
// This lets bulk callers (e.g. cachedScanList) walk the data dir ONCE and
// resolve children for every parent from the same slice, instead of triggering
// a full disk walk + parse per parent scan (previously O(parents × allScans)).
func (s *Server) attachWildcardSubScansFrom(rec *ScanRecord, entries []scanEntry) {
	if rec == nil || rec.ParentTarget != "" {
		return
	}

	children := make(map[string]*SubScanSummary)
	order := []string{}
	add := func(key string, summary SubScanSummary) *SubScanSummary {
		key = normalizeScanTarget(key)
		if key == "" {
			key = normalizeScanTarget(summary.Target)
		}
		if key == "" {
			return nil
		}
		if existing := children[key]; existing != nil {
			if summary.ID != "" {
				existing.ID = summary.ID
			}
			if summary.Target != "" {
				existing.Target = summary.Target
			}
			if summary.StartedAt != "" {
				existing.StartedAt = summary.StartedAt
			}
			if summary.FinishedAt != "" {
				existing.FinishedAt = summary.FinishedAt
			}
			if summary.Status != "" && (!isFinishedSubScanStatus(existing.Status) || !strings.EqualFold(summary.Status, "running")) {
				existing.Status = summary.Status
			}
			if summary.VulnCount > 0 {
				existing.VulnCount = summary.VulnCount
			}
			if summary.TotalTokens > 0 {
				existing.TotalTokens = summary.TotalTokens
			}
			return existing
		}
		if summary.Status == "" {
			summary.Status = "running"
		}
		children[key] = &summary
		order = append(order, key)
		return children[key]
	}

	total := 0
	if rec.SubScanTotal > total {
		total = rec.SubScanTotal
	}
	for _, child := range rec.SubScans {
		add(child.Target, child)
	}

	for _, entry := range entries {
		child := entry.rec
		if !isChildOfScan(rec, &child) {
			continue
		}
		for _, vuln := range child.Vulns {
			appendVulnSummaryUnique(&rec.Vulns, vuln)
		}
		add(child.Target, SubScanSummary{
			ID:          child.ID,
			Target:      child.Target,
			StartedAt:   child.StartedAt,
			FinishedAt:  child.FinishedAt,
			Status:      child.Status,
			VulnCount:   len(child.Vulns),
			TotalTokens: child.TotalTokens,
		})
	}

	for _, evt := range rec.Events {
		if evt.SubTargetTotal > total {
			total = evt.SubTargetTotal
		}
		if evt.ParentTarget == "" && evt.SubTargetTotal == 0 {
			continue
		}
		target := strings.TrimSpace(evt.Target)
		if target == "" {
			continue
		}
		status := ""
		startedAt := ""
		finishedAt := ""
		switch evt.Type {
		case "target_started":
			status = "running"
			startedAt = evt.Timestamp
		case "target_completed":
			status = "finished"
			finishedAt = evt.Timestamp
		case "subdomains_discovered":
			for _, line := range strings.Split(evt.Output, "\n") {
				target := strings.TrimSpace(line)
				if target == "" {
					continue
				}
				add(target, SubScanSummary{Target: target, Status: "pending"})
			}
			continue
		default:
			continue
		}
		summary := add(target, SubScanSummary{
			ID:         evt.AgentID,
			Target:     target,
			StartedAt:  startedAt,
			FinishedAt: finishedAt,
			Status:     status,
		})
		_ = summary
	}

	if total < len(children) {
		total = len(children)
	}
	if total == 0 {
		return
	}

	summaries := make([]SubScanSummary, 0, len(order))
	for _, key := range order {
		child := *children[key]
		summaries = append(summaries, child)
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].StartedAt == "" || summaries[j].StartedAt == "" {
			return summaries[i].Target < summaries[j].Target
		}
		return summaries[i].StartedAt < summaries[j].StartedAt
	})

	danglingActive := false
	if isTerminalScanStatus(rec.Status) {
		fallbackStatus := terminalSubScanStatus(rec.Status)
		finishedAt := rec.FinishedAt
		if finishedAt == "" {
			finishedAt = time.Now().Format(time.RFC3339)
		}
		for i := range summaries {
			if !isUnresolvedSubScanStatus(summaries[i].Status) {
				continue
			}
			danglingActive = true
			summaries[i].Status = fallbackStatus
			if summaries[i].FinishedAt == "" {
				summaries[i].FinishedAt = finishedAt
			}
		}
	}

	completed := 0
	running := 0
	for _, child := range summaries {
		if isFinishedSubScanStatus(child.Status) {
			completed++
		} else if strings.EqualFold(child.Status, "running") {
			running++
		}
	}
	remaining := total - completed - running
	if remaining < 0 {
		remaining = 0
	}
	if isCompletedScanStatus(rec.Status) && (danglingActive || running > 0 || remaining > 0) {
		rec.Status = "stopped"
		if rec.StopReason == "" {
			rec.StopReason = "incomplete_wildcard_subscans"
		}
		if rec.FinishedAt == "" {
			rec.FinishedAt = time.Now().Format(time.RFC3339)
		}
	}
	rec.SubScans = summaries
	rec.SubScanTotal = total
	rec.SubScanCompleted = completed
	rec.SubScanRunning = running
	rec.SubScanRemaining = remaining
}

func finalizeScanRecordForResponse(rec *ScanRecord) {
	if rec == nil {
		return
	}
	if isCompletedScanStatus(rec.Status) && phaseAllowed(rec.Phases, 22) {
		rec.CurrentPhase = 22
	}
}

// rebuildInstancesFromDisk populates s.instances from all saved scan.json files on disk.
// This ensures the dashboard shows historical scans immediately after server restart.
// Skips subdomain scans (those with ParentTarget set) — those are shown under their parent.
// Running scans from a previous server instance are marked as "stopped" since the agent process is gone.
func (s *Server) rebuildInstancesFromDisk() {
	for _, entry := range s.findAllScans() {
		// If scan was "running" from a previous server instance, it's no longer active.
		// Persist the correction so /api/scans and /api/instances agree after restart.
		if entry.rec.Status == "running" {
			stoppedAt := time.Now().Format(time.RFC3339)
			entry.rec.Status = "stopped"
			entry.rec.StopReason = "server_restart"
			entry.rec.FinishedAt = stoppedAt
			s.saveScanRecordTo(&entry.rec, entry.dir)
		}

		// Skip subdomain scans — they belong to their parent wildcard scan
		if entry.rec.ParentTarget != "" {
			continue
		}
		inst := &ScanInstance{
			ID:             entry.rec.ID,
			Name:           entry.rec.Name,
			Targets:        entry.rec.Target,
			ParentTarget:   entry.rec.ParentTarget,
			Status:         entry.rec.Status,
			StartedAt:      entry.rec.StartedAt,
			FinishedAt:     entry.rec.FinishedAt,
			StopReason:     entry.rec.StopReason,
			Iterations:     entry.rec.Iterations,
			ToolCalls:      entry.rec.ToolCalls,
			VulnCount:      len(entry.rec.Vulns),
			TotalTokens:    entry.rec.TotalTokens,
			ScanMode:       entry.rec.ScanMode,
			Instruction:    entry.rec.Instruction,
			SeverityFilter: entry.rec.SeverityFilter,
			Phases:         entry.rec.Phases,
			ReconMode:      entry.rec.ReconMode,
			ScanIntensity:  entry.rec.ScanIntensity,
			CompanyName:    entry.rec.CompanyName,
			LogoPath:       entry.rec.LogoPath,
			DiscordWebhook: entry.rec.DiscordWebhook,
			Vulns:          entry.rec.Vulns,
			CurrentPhase:   entry.rec.CurrentPhase,
			events:         append([]WSEvent(nil), entry.rec.Events...),
		}
		if inst.CurrentPhase == 0 {
			inst.CurrentPhase = firstSelectedPhase(inst.Phases)
		}
		inst.ReconMode = normalizeActivityMode(inst.ReconMode)
		inst.ScanIntensity = normalizeActivityMode(inst.ScanIntensity)
		chatCfg := *s.cfg
		inst.chatCfg = &chatCfg
		s.instances[entry.rec.ID] = inst
	}
	// Statuses may have been rewritten on disk above (running → stopped), so
	// drop any memoized scan list built before recovery.
	s.invalidateScanListCache()
}

// parsePageParams parses the `page` and `size` query parameters into a
// 1-indexed page number and a bounded page size. Invalid or missing values
// fall back to page 1 / size 50, and size is capped at 500 to protect the
// server from absurd page sizes.
func parsePageParams(pageStr, sizeStr string) (page, size int) {
	page, size = 1, 50
	if v, err := strconv.Atoi(strings.TrimSpace(pageStr)); err == nil && v >= 1 {
		page = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(sizeStr)); err == nil && v >= 1 {
		size = v
		if size > 500 {
			size = 500
		}
	}
	return page, size
}

// handleListScans returns a list of all saved scans (sorted newest first).
// scanListItem is the lightweight per-scan row returned by GET /api/scans.
type scanListItem struct {
	ID               string `json:"id"`
	Target           string `json:"target"`
	StartedAt        string `json:"started_at"`
	Status           string `json:"status"`
	ScanMode         string `json:"scan_mode,omitempty"`
	VulnCount        int    `json:"vuln_count"`
	TotalTokens      int    `json:"total_tokens"`
	SubScanTotal     int    `json:"sub_scan_total,omitempty"`
	SubScanCompleted int    `json:"sub_scan_completed,omitempty"`
	SubScanRunning   int    `json:"sub_scan_running,omitempty"`
	SubScanRemaining int    `json:"sub_scan_remaining,omitempty"`
}

// scanListCacheTTL bounds how long a built scan list is reused. Building the
// list walks the entire data dir and JSON-parses every scan.json, so without
// this cache each page/filter/poll request repeated that full-disk scan. The
// list view tolerates a few seconds of status lag (the instances page and the
// WebSocket feed are the live surfaces); deletes invalidate the cache for
// immediate effect.
const scanListCacheTTL = 5 * time.Second

// cachedScanList returns the sorted (newest-first) scan list, rebuilding it
// from disk at most once per scanListCacheTTL. The returned slice is shared
// read-only across callers — never mutate its elements; filtering/paginating
// must build new slices.
func (s *Server) cachedScanList() []scanListItem {
	s.scanListCacheMu.Lock()
	defer s.scanListCacheMu.Unlock()
	if s.scanListCache != nil && time.Since(s.scanListCacheAt) < scanListCacheTTL {
		return s.scanListCache
	}
	var scans []scanListItem
	// Walk the data dir ONCE (events-free + per-file cached) and reuse the
	// entry slice for child resolution. Previously each top-level scan
	// triggered its own findAllScans() walk via attachWildcardSubScans, making
	// list rebuilds O(parents × allScans) in full disk reads + JSON parses
	// (events included). Sharing one events-free walk makes it linear and skips
	// the per-event decode entirely.
	entries := s.findAllScanSummaries()
	for _, entry := range entries {
		if entry.rec.ParentTarget != "" {
			continue
		}
		rec := entry.rec
		// rec is a shallow copy of a cached, shared record. Detach the slices
		// that the snapshot/sub-scan logic appends to so we never mutate the
		// backing array held by scanSummaryCache (which other readers, e.g. the
		// findings handlers, access concurrently).
		rec.Vulns = append([]VulnSummary(nil), rec.Vulns...)
		s.applyInstanceSnapshot(&rec, false)
		// Only wildcard parents derive sub-scan progress from their own event
		// stream, so restore just that one record's events (cheap: one file)
		// rather than carrying events for every scan in the list.
		if strings.EqualFold(rec.ScanMode, "wildcard") {
			if full, ok := loadScanRecordFromDir(entry.dir); ok && full != nil {
				rec.Events = full.Events
			}
		}
		s.attachWildcardSubScansFrom(&rec, entries)
		scans = append(scans, scanListItem{
			ID:               rec.ID,
			Target:           rec.Target,
			StartedAt:        rec.StartedAt,
			Status:           rec.Status,
			ScanMode:         rec.ScanMode,
			VulnCount:        len(rec.Vulns),
			TotalTokens:      rec.TotalTokens,
			SubScanTotal:     rec.SubScanTotal,
			SubScanCompleted: rec.SubScanCompleted,
			SubScanRunning:   rec.SubScanRunning,
			SubScanRemaining: rec.SubScanRemaining,
		})
	}
	// Sort newest first.
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].StartedAt > scans[j].StartedAt
	})
	s.scanListCache = scans
	s.scanListCacheAt = time.Now()
	return scans
}

// invalidateScanListCache forces the next GET /api/scans to rebuild from disk.
// Called after mutations (e.g. scan deletion) so the change is reflected
// immediately rather than after the TTL.
func (s *Server) invalidateScanListCache() {
	s.scanListCacheMu.Lock()
	s.scanListCache = nil
	s.scanListCacheMu.Unlock()
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans := s.cachedScanList()

	// Optional server-side filtering. These are no-ops when the query params
	// are absent, so the default GET /api/scans response is unchanged. Build
	// new slices so the shared cache is never mutated.
	if q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q"))); q != "" {
		filtered := make([]scanListItem, 0, len(scans))
		for _, sc := range scans {
			if strings.Contains(strings.ToLower(sc.Target), q) ||
				strings.Contains(strings.ToLower(sc.ID), q) {
				filtered = append(filtered, sc)
			}
		}
		scans = filtered
	}
	if st := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status"))); st != "" && st != "all" {
		filtered := make([]scanListItem, 0, len(scans))
		for _, sc := range scans {
			if strings.ToLower(sc.Status) == st {
				filtered = append(filtered, sc)
			}
		}
		scans = filtered
	}

	w.Header().Set("Content-Type", "application/json")

	// Pagination is opt-in. Without a page/size query param we preserve the
	// historical bare-array response for backward compatibility (public API
	// consumers and existing callers). With it, we return a paginated
	// envelope { items, total, page, size }.
	pageStr := r.URL.Query().Get("page")
	sizeStr := r.URL.Query().Get("size")
	if pageStr == "" && sizeStr == "" {
		_ = json.NewEncoder(w).Encode(scans)
		return
	}
	page, size := parsePageParams(pageStr, sizeStr)
	total := len(scans)
	start := (page - 1) * size
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	items := scans[start:end]
	if items == nil {
		items = []scanListItem{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"items": items,
		"total": total,
		"page":  page,
		"size":  size,
	})
}

// handleDownloadReport serves the PDF report for a scan.
func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/api/report/")
	// Normalise: strip any path separators so a crafted /api/report/../etc/passwd
	// can never escape the scan-dir even if a future caller forgets.
	scanID = filepath.Base(scanID)
	if scanID == "" || scanID == "." || scanID == "/" {
		http.Error(w, "scan ID required", http.StatusBadRequest)
		return
	}

	scanDir, rec := s.findScanByID(scanID)
	if scanDir == "" || rec == nil {
		s.instancesMu.RLock()
		inst := s.instances[scanID]
		s.instancesMu.RUnlock()
		if inst != nil {
			rec = s.scanRecordFromInstance(inst)
			inst.mu.RLock()
			scanDir = inst.scanDir
			inst.mu.RUnlock()
		}
		if scanDir == "" || rec == nil {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
	}

	reportPath, err := s.generateReportAt(rec, scanDir)
	if err != nil {
		log.Printf("Report generation error: %v", err)
		fallbackPath := filepath.Join(scanDir, fmt.Sprintf("xalgorix_report_%s.pdf", scanID))
		if info, statErr := os.Stat(fallbackPath); statErr == nil && info.Mode().IsRegular() {
			reportPath = fallbackPath
		} else {
			http.Error(w, "failed to generate report: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Defense-in-depth: confirm the resolved target is a regular file before
	// handing it to http.ServeFile. ServeFile will happily render a directory
	// index if asked for a directory.
	info, err := os.Stat(reportPath)
	if err != nil {
		log.Printf("Report stat failed for %s: %v", reportPath, err)
		http.Error(w, "report not available", http.StatusNotFound)
		return
	}
	if !info.Mode().IsRegular() {
		log.Printf("Report path is not a regular file: %s (mode=%s)", reportPath, info.Mode())
		http.Error(w, "report not available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"xalgorix_report_%s.pdf\"", scanID))
	http.ServeFile(w, r, reportPath)
}

// handleRateLimit handles GET and POST for rate limit settings.
func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Return current rate limit settings
		_ = json.NewEncoder(w).Encode(map[string]int{
			"requests": s.cfg.RateLimitRequests,
			"window":   s.cfg.RateLimitWindow,
		})

	case "POST":
		// Update rate limit settings
		var req struct {
			Requests int `json:"requests"`
			Window   int `json:"window"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// Validate values
		if req.Requests < 1 {
			req.Requests = 1
		}
		if req.Requests > 1000 {
			req.Requests = 1000
		}
		if req.Window < 10 {
			req.Window = 10
		}
		if req.Window > 3600 {
			req.Window = 3600
		}

		if _, err := s.applyEnvironmentUpdates(map[string]string{
			"XALGORIX_RATE_LIMIT_REQUESTS": strconv.Itoa(req.Requests),
			"XALGORIX_RATE_LIMIT_WINDOW":   strconv.Itoa(req.Window),
		}); err != nil {
			log.Printf("Failed to save rate limit settings: %v", err)
			http.Error(w, "failed to save rate limit settings", http.StatusInternalServerError)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]int{
			"requests": s.cfg.RateLimitRequests,
			"window":   s.cfg.RateLimitWindow,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func maskAgentMailKey(apiKey string) string {
	if len(apiKey) > 8 {
		return "****" + apiKey[len(apiKey)-8:]
	}
	if apiKey != "" {
		return "****"
	}
	return ""
}

func isMaskedAgentMailKey(apiKey string) bool {
	apiKey = strings.TrimSpace(apiKey)
	return strings.HasPrefix(apiKey, "****") || strings.Contains(apiKey, "••••")
}

// handleAgentMailSettings handles GET and POST for AgentMail settings.
func (s *Server) handleAgentMailSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Return current AgentMail settings (without exposing the full API key)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"pod":       s.cfg.AgentMailPod,
			"apiKey":    maskAgentMailKey(s.cfg.AgentMailAPIKey),
			"hasApiKey": s.cfg.AgentMailAPIKey != "",
		})

	case "POST":
		// Update AgentMail settings
		var req struct {
			Pod    string `json:"pod"`
			APIKey string `json:"apiKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		preserveKey := strings.TrimSpace(req.APIKey) == "" || isMaskedAgentMailKey(req.APIKey)
		effectiveAPIKey := req.APIKey
		if preserveKey {
			effectiveAPIKey = s.cfg.AgentMailAPIKey
		}

		updates := map[string]string{"AGENTMAIL_POD": req.Pod}
		if !preserveKey {
			updates["AGENTMAIL_API_KEY"] = effectiveAPIKey
		}
		if _, err := s.applyEnvironmentUpdates(updates); err != nil {
			log.Printf("Failed to save AgentMail settings: %v", err)
			http.Error(w, "failed to save AgentMail settings", http.StatusInternalServerError)
			return
		}

		log.Printf("AgentMail settings updated: pod=%s", req.Pod)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"pod":       req.Pod,
			"apiKey":    maskAgentMailKey(effectiveAPIKey),
			"hasApiKey": effectiveAPIKey != "",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVersion returns the current Xalgorix version
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version": Version,
		"ai": map[string]any{
			"configured": s.cfg.APIKey != "" && s.cfg.LLM != "",
			"provider":   llmProviderLabel(s.cfg.LLM, s.cfg.APIBase),
			"model":      s.cfg.LLM,
			"gateway":    llmGatewayName(s.cfg.LLM, s.cfg.APIBase),
		},
	})
}

// handleStopNotify sends a stop notification to Discord if a scan was running
func (s *Server) handleStopNotify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Send Discord notification if webhook is configured
	if s.discordWebhook != "" {
		s.sendDiscord(0xff6b6b, "🛑 Xalgorix Stopped", "The Xalgorix service has been stopped by the user.")
	}
	if s.telegramConfigured() {
		s.sendTelegram(0xff6b6b, "🛑 Xalgorix Stopped", "The Xalgorix service has been stopped by the user.")
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "notified"})
}

// ChatRequest is the payload for sending a message to a running scan's
// agent via the chat endpoint.
type ChatRequest struct {
	Message    string `json:"message"`
	InstanceID string `json:"instance_id,omitempty"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	req.Message = strings.TrimSpace(req.Message)
	if req.Message == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "message is required"})
		return
	}

	response, err := s.routeChatMessage(strings.TrimSpace(req.InstanceID), req.Message)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"response": response,
	})
}

func (s *Server) routeChatMessage(instanceID, message string) (string, error) {
	if instanceID != "" {
		s.instancesMu.RLock()
		inst := s.instances[instanceID]
		s.instancesMu.RUnlock()
		if inst == nil {
			return "", fmt.Errorf("instance not found")
		}

		inst.mu.RLock()
		status := inst.Status
		agnt := inst.agent
		inst.mu.RUnlock()

		if agnt != nil && status == "running" {
			return agnt.SendMessage(message)
		}
		if status == "saved" || status == "pending" {
			return "", fmt.Errorf("scan is not active yet")
		}
		return s.postScanChat(inst, message)
	}

	// Fallback for the older single-scan UI path, where chat messages did not
	// include an instance_id and the currently running session was global.
	s.mu.RLock()
	targetID := s.currentScanID
	agnt := s.currentAgents[targetID]
	s.mu.RUnlock()
	if agnt != nil && s.running.Load() {
		return agnt.SendMessage(message)
	}

	if inst := s.latestChatInstance(); inst != nil {
		return s.postScanChat(inst, message)
	}

	return "", fmt.Errorf("no active or completed scan to chat with")
}

func (s *Server) latestChatInstance() *ScanInstance {
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()

	var best *ScanInstance
	var bestTime time.Time
	for _, inst := range s.instances {
		inst.mu.RLock()
		status := inst.Status
		finishedAt := inst.FinishedAt
		startedAt := inst.StartedAt
		inst.mu.RUnlock()

		switch status {
		case "finished", "stopped", "paused":
		default:
			continue
		}

		t := parseInstanceTime(finishedAt)
		if t.IsZero() {
			t = parseInstanceTime(startedAt)
		}
		if best == nil || t.After(bestTime) {
			best = inst
			bestTime = t
		}
	}
	return best
}

func parseInstanceTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func (s *Server) postScanChat(inst *ScanInstance, message string) (string, error) {
	inst.mu.Lock()
	if inst.chatCfg == nil {
		chatCfg := *s.cfg
		inst.chatCfg = &chatCfg
	}
	chatCfg := *inst.chatCfg
	if len(inst.chatMessages) == 0 {
		inst.chatMessages = []llm.Message{{
			Role:    "system",
			Content: buildPostScanChatPrompt(inst),
		}}
	}
	messages := append([]llm.Message(nil), inst.chatMessages...)
	messages = append(messages, llm.Message{Role: "user", Content: message})
	inst.mu.Unlock()

	response, err := s.postScanChatFn(&chatCfg, messages)
	if err != nil {
		return "", err
	}
	response = strings.TrimSpace(llm.CleanContent(response))
	if response == "" {
		response = "I do not have enough scan context to answer that."
	}

	inst.mu.Lock()
	inst.chatMessages = append(messages, llm.Message{Role: "assistant", Content: response})
	inst.chatMessages = trimPostScanChatHistory(inst.chatMessages)
	inst.mu.Unlock()

	return response, nil
}

func buildPostScanChatPrompt(inst *ScanInstance) string {
	var b strings.Builder
	if inst.Status == "paused" {
		b.WriteString("You are Xalgorix in paused-scan chat mode. The scan is paused, so answer follow-up questions using only the scan context captured so far. Do not claim that you are still scanning or that you can run tools in this chat. If the user asks for new testing, explain what the current results show and suggest resuming the scan.\n\n")
	} else {
		b.WriteString("You are Xalgorix in post-scan chat mode. The scan has already finished, so answer follow-up questions using only the completed scan context below. Do not claim that you are still scanning or that you can run tools in this chat. If the user asks for new testing, first summarize what the completed scan already found for that topic, then explain that additional live testing requires resuming, restarting, or starting a new scan.\n\n")
	}

	b.WriteString("## Scan\n")
	fmt.Fprintf(&b, "Instance ID: %s\n", inst.ID)
	fmt.Fprintf(&b, "Targets: %s\n", inst.Targets)
	fmt.Fprintf(&b, "Status: %s\n", inst.Status)
	if inst.ScanMode != "" {
		fmt.Fprintf(&b, "Mode: %s\n", inst.ScanMode)
	}
	if inst.StartedAt != "" {
		fmt.Fprintf(&b, "Started: %s\n", inst.StartedAt)
	}
	if inst.FinishedAt != "" {
		fmt.Fprintf(&b, "Finished: %s\n", inst.FinishedAt)
	}
	fmt.Fprintf(&b, "Iterations: %d\nTool calls: %d\nVulnerabilities: %d\nTotal tokens: %d\n", inst.Iterations, inst.ToolCalls, inst.VulnCount, inst.TotalTokens)
	if strings.TrimSpace(inst.Instruction) != "" {
		fmt.Fprintf(&b, "User instructions: %s\n", truncStr(inst.Instruction, 1200))
	}

	if len(inst.Vulns) > 0 {
		b.WriteString("\n## Vulnerabilities\n")
		for i, v := range inst.Vulns {
			if i >= 40 {
				fmt.Fprintf(&b, "- ... %d additional vulnerabilities omitted from prompt context\n", len(inst.Vulns)-i)
				break
			}
			fmt.Fprintf(&b, "- [%s] %s", strings.ToUpper(v.Severity), v.Title)
			if v.Endpoint != "" {
				fmt.Fprintf(&b, " at %s", v.Endpoint)
			}
			if v.CVSS > 0 {
				fmt.Fprintf(&b, " (CVSS %.1f)", v.CVSS)
			}
			if v.Description != "" {
				fmt.Fprintf(&b, " - %s", truncStr(v.Description, 500))
			}
			b.WriteByte('\n')
		}
	}

	if len(inst.events) > 0 {
		b.WriteString("\n## Recent Scan Events\n")
		start := 0
		if len(inst.events) > 80 {
			start = len(inst.events) - 80
		}
		for _, evt := range inst.events[start:] {
			line := summarizeChatEvent(evt)
			if line != "" {
				b.WriteString("- ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	}

	return b.String()
}

func summarizeChatEvent(evt WSEvent) string {
	switch evt.Type {
	case "thinking":
		return fmt.Sprintf("thinking: %s", truncStr(evt.Content, 160))
	case "message":
		return fmt.Sprintf("message: %s", truncStr(evt.Content, 300))
	case "error":
		return fmt.Sprintf("error: %s", truncStr(evt.Content, 300))
	case "tool_call":
		return fmt.Sprintf("tool_call: %s", evt.ToolName)
	case "tool_result":
		body := evt.Output
		if body == "" {
			body = evt.Error
		}
		if evt.ToolName != "" {
			return fmt.Sprintf("tool_result: %s: %s", evt.ToolName, truncStr(body, 300))
		}
		return fmt.Sprintf("tool_result: %s", truncStr(body, 300))
	case "finished":
		return fmt.Sprintf("finished: %s", truncStr(evt.Content, 300))
	case "target_started", "target_completed", "queue_started", "queue_finished", "report_ready":
		if evt.Target != "" {
			return fmt.Sprintf("%s: %s (%s)", evt.Type, truncStr(evt.Content, 220), evt.Target)
		}
		return fmt.Sprintf("%s: %s", evt.Type, truncStr(evt.Content, 220))
	default:
		return ""
	}
}

func trimPostScanChatHistory(messages []llm.Message) []llm.Message {
	const keepRecent = 40
	if len(messages) <= keepRecent+1 {
		return messages
	}
	trimmed := make([]llm.Message, 0, keepRecent+1)
	trimmed = append(trimmed, messages[0])
	trimmed = append(trimmed, messages[len(messages)-keepRecent:]...)
	return trimmed
}

func truncStr(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// handleQueueStatus returns the current queue state for recovery
func (s *Server) handleQueueStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	entries := s.validQueueStateEntries(true)
	if len(entries) > 0 {
		state := entries[0].state
		totalRemaining := 0
		for _, entry := range entries {
			totalRemaining += len(entry.state.Targets) - entry.state.CurrentIdx
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"available":                 true,
			"queue_count":               len(entries),
			"total_remaining":           totalRemaining,
			"instance_id":               state.InstanceID,
			"targets":                   state.Targets,
			"current_idx":               state.CurrentIdx,
			"remaining":                 len(state.Targets) - state.CurrentIdx,
			"instruction":               state.Instruction,
			"scan_mode":                 state.ScanMode,
			"started_at":                state.StartedAt,
			"paused":                    state.Paused,
			"name":                      state.Name,
			"severity_filter":           state.SeverityFilter,
			"phases":                    state.Phases,
			"recon_mode":                normalizeActivityMode(state.ReconMode),
			"scan_intensity":            normalizeActivityMode(state.ScanIntensity),
			"company_name":              state.CompanyName,
			"logo_path":                 state.LogoPath,
			"active_target":             state.ActiveTarget,
			"active_scan_id":            state.ActiveScanID,
			"wildcard_active_target":    state.WildcardActiveTarget,
			"wildcard_active_scan_id":   state.WildcardActiveScanID,
			"wildcard_sub_index":        state.WildcardSubIndex,
			"wildcard_subdomains_total": len(state.WildcardSubdomains),
		})
	} else {
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false})
	}
}

// handleQueueResume resumes an interrupted scan queue
func (s *Server) handleQueueResume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.queueResumeMu.Lock()
	defer s.queueResumeMu.Unlock()

	if s.running.Load() || s.hasPendingOrRunningInstance() || s.hasQueueResumeLaunchingLocked() {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "A scan is already pending or running"})
		return
	}

	entries := s.validQueueStateEntries(true)
	if len(entries) == 0 {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "No interrupted queue found"})
		return
	}

	totalRemaining := 0
	firstIdx := entries[0].state.CurrentIdx
	for _, entry := range entries {
		req := scanRequestFromQueueState(entry.state, entry.path)
		if len(req.Targets) == 0 {
			continue
		}
		totalRemaining += len(req.Targets)
		scanCfg := *s.cfg
		instanceID := entry.state.InstanceID
		resumeKey := queueResumeEntryKey(entry)
		s.markQueueResumeLaunchingLocked(resumeKey)
		go func(req ScanRequest, scanCfg config.Config, instanceID, resumeKey string) {
			defer s.clearQueueResumeLaunching(resumeKey)
			s.runMultiScan(req, &scanCfg, instanceID)
		}(req, scanCfg, instanceID, resumeKey)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "resumed",
		"resumed_queues": len(entries),
		"from_index":     firstIdx,
		"targets_left":   totalRemaining,
	})
}

// handleQueueClear clears an interrupted queue state
func (s *Server) handleQueueClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.clearQueueState()
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

// handleGetScan returns a specific scan's full data.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	// Extract scan ID from URL: /api/scans/{id}
	scanID := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	if scanID == "" || scanID == "latest" {
		// Find latest scan by StartedAt timestamp
		allScans := []scanEntry{}
		for _, entry := range s.findAllScans() {
			if entry.rec.ParentTarget != "" {
				continue
			}
			allScans = append(allScans, entry)
		}
		if len(allScans) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`null`))
			return
		}
		sort.Slice(allScans, func(i, j int) bool {
			return allScans[i].rec.StartedAt > allScans[j].rec.StartedAt
		})
		rec := allScans[0].rec
		s.applyInstanceSnapshot(&rec, true)
		s.attachWildcardSubScans(&rec)
		finalizeScanRecordForResponse(&rec)
		s.markDiscordWebhookConfigured(&rec)
		s.markTelegramConfigured(&rec)
		data, _ := json.Marshal(rec)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	// DELETE /api/scans/{id} — delete scan from disk and in-memory instances
	// Handle this BEFORE findScanByID because instance IDs (from runMultiScan)
	// may differ from scan record IDs (directory slugs). We need to clean up both.
	if r.Method == http.MethodDelete {
		// Try to find and delete from disk
		dir, rec := s.findScanByID(scanID)
		if dir != "" {
			_ = os.RemoveAll(dir)
		}
		if rec != nil {
			for _, entry := range s.findAllScans() {
				if entry.dir == dir {
					continue
				}
				if isChildOfScan(rec, &entry.rec) {
					_ = os.RemoveAll(entry.dir)
				}
			}
		}
		instanceIDs := []string{scanID}
		if rec != nil {
			instanceIDs = append(instanceIDs, rec.ID, rec.InstanceID)
		}
		seenInstanceIDs := make(map[string]bool, len(instanceIDs))
		s.instancesMu.Lock()
		for _, id := range instanceIDs {
			if id == "" || seenInstanceIDs[id] {
				continue
			}
			seenInstanceIDs[id] = true
			if inst := s.instances[id]; inst != nil && inst.cancel != nil {
				inst.cancel()
			}
			delete(s.instances, id)
		}
		s.instancesMu.Unlock()
		s.invalidateScanListCache()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"deleted"}`))
		return
	}

	if r.Method == http.MethodGet {
		s.instancesMu.RLock()
		inst := s.instances[scanID]
		s.instancesMu.RUnlock()
		if rec := s.scanRecordFromInstance(inst); rec != nil {
			if _, persisted := s.findScanByID(scanID); persisted != nil {
				s.applyInstanceSnapshot(persisted, true)
				s.attachWildcardSubScans(persisted)
				finalizeScanRecordForResponse(persisted)
				s.markDiscordWebhookConfigured(persisted)
				s.markTelegramConfigured(persisted)
				data, _ := json.Marshal(persisted)
				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
				return
			}
		s.attachWildcardSubScans(rec)
		finalizeScanRecordForResponse(rec)
		s.markDiscordWebhookConfigured(rec)
		s.markTelegramConfigured(rec)
		data, _ := json.Marshal(rec)
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
			return
		}
	}

	dir, rec := s.findScanByID(scanID)
	_ = dir
	if rec == nil {
		dir, rec = s.findRecentScanForShortAlias(scanID)
		_ = dir
	}
	if rec == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`null`))
		return
	}

	s.applyInstanceSnapshot(rec, true)
	s.attachWildcardSubScans(rec)
	finalizeScanRecordForResponse(rec)
	s.markDiscordWebhookConfigured(rec)
	s.markTelegramConfigured(rec)
	data, _ := json.Marshal(rec)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleDeleteVuln removes a single vulnerability from a scan record.
// DELETE /api/scans/{scanId}/vulns/{vulnId}
func (s *Server) handleDeleteVuln(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
		return
	}
	// Parse: /api/scans/{scanId}/vulns/{vulnId}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	parts := strings.SplitN(trimmed, "/vulns/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "invalid path: expected /api/scans/{id}/vulns/{id}", http.StatusBadRequest)
		return
	}
	scanID := parts[0]
	vulnID, err := url.PathUnescape(parts[1])
	if err != nil {
		http.Error(w, "invalid vuln id encoding", http.StatusBadRequest)
		return
	}

	dir, rec := s.findScanByID(scanID)
	if rec == nil {
		dir, rec = s.findRecentScanForShortAlias(scanID)
	}
	if rec == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"scan not found"}`))
		return
	}

	// Remove matching vulns
	filtered := make([]VulnSummary, 0, len(rec.Vulns))
	removed := 0
	for _, v := range rec.Vulns {
		if v.ID == vulnID {
			removed++
			continue
		}
		filtered = append(filtered, v)
	}
	if removed == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"vulnerability not found"}`))
		return
	}
	rec.Vulns = filtered

	// Persist to disk
	if dir != "" {
		s.saveScanRecordTo(rec, dir)
	}

	// Update in-memory instance if present
	s.instancesMu.Lock()
	if inst := s.instances[scanID]; inst != nil {
		inst.mu.Lock()
		inst.Vulns = filtered
		inst.VulnCount = len(filtered)
		inst.mu.Unlock()
	}
	s.instancesMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "deleted", "removed": removed, "remaining": len(filtered)})
}

// logMemStats logs current memory usage and goroutine count.
// Called between subdomain scans to track memory growth and detect leaks.
func logMemStats(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("[MEM] %s — HeapAlloc: %d MB, HeapInuse: %d MB, Sys: %d MB, NumGC: %d, Goroutines: %d",
		label,
		m.HeapAlloc/1024/1024,
		m.HeapInuse/1024/1024,
		m.Sys/1024/1024,
		m.NumGC,
		runtime.NumGoroutine(),
	)
}

func (s *Server) broadcast(evt WSEvent) {
	evt = withEventTimestamp(evt)
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		select {
		case client.send <- data:
			// queued successfully
		default:
			// client send buffer full — drop the client
			log.Printf("WebSocket client send buffer full, dropping client")
			go func(c *wsClient) {
				s.removeClient(c)
				c.conn.Close()
			}(client)
		}
	}
}

// broadcastToInstance sends an event to clients subscribed to a specific instance
// and to dashboard clients without an instance subscription.
// Buffers events into the instance for replay.
func (s *Server) broadcastToInstance(instanceID string, evt WSEvent) {
	evt = withEventTimestamp(evt)
	if evt.InstanceID == "" {
		evt.InstanceID = instanceID
	}
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	// Buffer event into instance for replay (cap at 500)
	s.instancesMu.RLock()
	if inst, ok := s.instances[instanceID]; ok {
		inst.mu.Lock()
		if len(inst.events) < 500 {
			inst.events = append(inst.events, evt)
		} else {
			// Keep last 400, drop oldest
			inst.events = append(inst.events[100:], evt)
		}
		// Also buffer vulns
		if len(evt.Vulns) > 0 {
			for _, vuln := range evt.Vulns {
				appendVulnSummaryUnique(&inst.Vulns, vuln)
			}
		}
		if evt.CurrentPhase > 0 {
			inst.CurrentPhase = evt.CurrentPhase
		}
		inst.mu.Unlock()
	}
	s.instancesMu.RUnlock()

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		if client.instanceID == "" || client.instanceID == instanceID {
			select {
			case client.send <- data:
			default:
				go func(c *wsClient) {
					s.removeClient(c)
					c.conn.Close()
				}(client)
			}
		}
	}
}

// broadcastDashboard sends an event only to dashboard clients (no instance subscription).
func (s *Server) broadcastDashboard(evt WSEvent) {
	evt = withEventTimestamp(evt)
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		if client.instanceID == "" {
			select {
			case client.send <- data:
			default:
				go func(c *wsClient) {
					s.removeClient(c)
					c.conn.Close()
				}(client)
			}
		}
	}
}

func withEventTimestamp(evt WSEvent) WSEvent {
	if strings.TrimSpace(evt.Timestamp) == "" {
		evt.Timestamp = time.Now().Format(time.RFC3339)
	}
	return evt
}

func llmProviderLabel(model, apiBase string) string {
	provider := llmProviderKey(model, apiBase)
	switch provider {
	case "vercel":
		return "Vercel AI Gateway"
	case "minimax":
		return "MiniMax"
	case "openai":
		return "OpenAI"
	case "anthropic":
		return "Anthropic"
	case "google", "gemini":
		return "Google Gemini"
	case "deepseek":
		return "DeepSeek"
	case "groq":
		return "Groq"
	case "ollama":
		return "Ollama"
	case "":
		return "Not configured"
	default:
		return strings.ToUpper(provider[:1]) + provider[1:]
	}
}

func llmGatewayName(model, apiBase string) string {
	if llmProviderKey(model, apiBase) == "vercel" {
		return "vercel"
	}
	return ""
}

func llmProviderKey(model, apiBase string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	apiBase = strings.ToLower(strings.TrimSpace(apiBase))
	if strings.Contains(apiBase, "vercel") || strings.HasPrefix(model, "vercel/") {
		return "vercel"
	}
	if idx := strings.Index(model, "/"); idx > 0 {
		return model[:idx]
	}
	switch {
	case strings.Contains(apiBase, "minimax"):
		return "minimax"
	case strings.Contains(apiBase, "anthropic"):
		return "anthropic"
	case strings.Contains(apiBase, "generativelanguage") || strings.Contains(apiBase, "googleapis"):
		return "google"
	case strings.Contains(apiBase, "deepseek"):
		return "deepseek"
	case strings.Contains(apiBase, "groq"):
		return "groq"
	case strings.Contains(apiBase, "openai"):
		return "openai"
	case strings.Contains(apiBase, "ollama") || strings.Contains(apiBase, "localhost:11434"):
		return "ollama"
	case model != "":
		return model
	default:
		return ""
	}
}

// sendDiscord sends a rich embed message to the configured Discord webhook.
func (s *Server) sendDiscord(color int, title, description string) {
	s.sendDiscordWithFile(color, title, description, "")
}

// sendDiscordWithFile sends a rich embed message with an optional file attachment to Discord.
func (s *Server) sendDiscordWithFile(color int, title, description, filePath string) {
	if s.discordWebhook == "" {
		return
	}

	// If no file, send simple embed
	if filePath == "" {
		s.sendSimpleEmbed(color, title, description)
		return
	}

	// Check if file exists
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read PDF for Discord: %v", err)
		// Send embed without file
		s.sendSimpleEmbed(color, title, description+" (PDF generation failed)")
		return
	}

	// Create multipart form data
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// Add payload JSON
	embedPayload := map[string]any{
		"username":   "Xalgorix",
		"avatar_url": "https://raw.githubusercontent.com/xalgord/xalgord/main/assets/logo.png",
		"embeds": []map[string]any{
			{
				"title":       title,
				"description": description,
				"color":       color,
				"timestamp":   time.Now().Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Xalgorix — Autonomous AI Pentesting Engine",
				},
			},
		},
	}
	embedJSON, err := json.Marshal(embedPayload)
	if err != nil {
		log.Printf("Error: failed to marshal Discord embed payload: %v", err)
		return
	}
	if err := writer.WriteField("payload_json", string(embedJSON)); err != nil {
		log.Printf("Error: failed to write Discord payload field: %v", err)
		return
	}

	// Add file
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		log.Printf("Error: failed to create form file for Discord: %v", err)
		return
	}
	if _, err := part.Write(fileData); err != nil {
		log.Printf("Error: failed to write file data for Discord: %v", err)
		return
	}
	_ = writer.Close()

	// Capture content type before goroutine to avoid fragile writer capture
	contentType := writer.FormDataContentType()

	// Send request
	go func() {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Post(s.discordWebhook, contentType, &b)
		if err != nil {
			log.Printf("Discord webhook file upload error: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			respBody, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				log.Printf("Warning: failed to read Discord error response: %v", readErr)
			}
			log.Printf("Discord webhook error: %d %s", resp.StatusCode, string(respBody))
		}
	}()
}

// sendSimpleEmbed sends a simple embed without file attachment
func (s *Server) sendSimpleEmbed(color int, title, description string) {
	payload := map[string]any{
		"username":   "Xalgorix",
		"avatar_url": "https://raw.githubusercontent.com/xalgord/xalgord/main/assets/logo.png",
		"embeds": []map[string]any{
			{
				"title":       title,
				"description": description,
				"color":       color,
				"timestamp":   time.Now().Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Xalgorix — Autonomous AI Pentesting Engine",
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	go func() {
		resp, err := http.Post(s.discordWebhook, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("Discord webhook error: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

// isBlockedTarget delegates to scopeguard.IsLocalOrListener, the
// authoritative classifier for Local_Or_Listener_Host shared by the
// web fetcher and the agent-side gate. Verdict for every target is
// identical to the pre-relocation in-package implementation; the
// shared package preserves the single-DNS-lookup-per-call contract
// (Requirement 3.8 / design.md → "DNS Lookup Semantics").
func (s *Server) isBlockedTarget(target string) bool {
	return scopeguard.IsLocalOrListener(scopeguard.Config{
		BindAddr: s.cfg.BindAddr,
		Port:     s.port,
	}, target)
}

// severityMeetsThreshold returns true if the vuln severity is at or above the minimum
// threshold. Empty threshold means "send everything".
// Severity hierarchy: info < low < medium < high < critical
func severityMeetsThreshold(severity, minSeverity string) bool {
	if minSeverity == "" {
		return true // no threshold = send all
	}
	order := map[string]int{
		"info":     0,
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	vulnLevel, ok1 := order[strings.ToLower(severity)]
	minLevel, ok2 := order[strings.ToLower(minSeverity)]
	if !ok1 || !ok2 {
		return true // unknown severity = send it
	}
	return vulnLevel >= minLevel
}

// telegramAPIBase is the fixed Telegram Bot API host. Pinned (not
// operator-configurable) so an attacker-influenced base URL cannot
// create an SSRF surface — the destination is always api.telegram.org
// over HTTPS, matching the security model described in issue #157.
// Declared as a var (not const) solely so tests can point it at a
// local httptest.Server stub; production code never reassigns it.
var telegramAPIBase = "https://api.telegram.org"

// telegramConfigured reports whether Telegram notifications are
// enabled (a bot token AND a chat ID are both set). Used by the
// status/scan endpoints to surface a telegram_configured boolean
// without exposing the token itself.
func (s *Server) telegramConfigured() bool {
	return s.telegramBotToken != "" && s.telegramChatID != ""
}

// telegramFormat builds an HTML-formatted message body from a
// (title, description) pair, mirroring the (color, title, description)
// shape Discord consumes. Telegram has no embed/color concept, so the
// color is ignored; we emit a bold title followed by the description.
// HTML parse_mode is used (rather than MarkdownV2) to avoid
// Markdown-escaping pitfalls noted in issue #157.
func telegramFormat(title, description string) string {
	title = strings.TrimSpace(title)
	description = strings.TrimSpace(description)
	if title == "" {
		return description
	}
	if description == "" {
		return "<b>" + htmlEscape(title) + "</b>"
	}
	return "<b>" + htmlEscape(title) + "</b>\n" + htmlEscape(description)
}

// htmlEscape escapes the four characters Telegram's HTML parse_mode
// treats specially (& < >), so operator/finding text cannot break out
// of the message body or inject markup.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// sendTelegram sends a text notification to the configured Telegram
// chat. It is the Telegram counterpart of sendDiscord. Fire-and-forget
// in a goroutine with a 30s timeout, identical to sendSimpleEmbed; a
// slow or blocked Telegram endpoint never stalls a scan. The color
// argument is accepted for signature symmetry with sendDiscord but is
// ignored (Telegram has no color concept).
//
// Early-returns when Telegram is not configured (no bot token or no
// chat ID) so an unconfigured instance makes zero outbound requests.
func (s *Server) sendTelegram(color int, title, description string) {
	s.sendTelegramWithFile(color, title, description, "")
}

// sendTelegramWithFile sends a text notification with an optional file
// attachment (the PDF report) to the configured Telegram chat. It is the
// Telegram counterpart of sendDiscordWithFile. When filePath is empty it
// sends a plain sendMessage; otherwise it sends a sendDocument
// (multipart/form-data) with the file attached and a caption.
//
// Telegram returns HTTP 200 with {"ok": false, ...} on logical errors
// (bad chat ID, bot not in channel, etc.), so in addition to non-2xx
// status codes we log when the response body indicates ok:false.
func (s *Server) sendTelegramWithFile(color int, title, description, filePath string) {
	if !s.telegramConfigured() {
		return
	}

	text := telegramFormat(title, description)

	if filePath == "" {
		// Plain text message via sendMessage.
		payload := url.Values{
			"chat_id":                  {s.telegramChatID},
			"text":                     {text},
			"parse_mode":               {"HTML"},
			"disable_web_page_preview": {"true"},
		}
		endpoint := telegramAPIBase + "/bot" + s.telegramBotToken + "/sendMessage"

		go func() {
			defer safe.Recover("telegram.sendMessage", "")
			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.PostForm(endpoint, payload)
			if err != nil {
				log.Printf("Telegram sendMessage error: %v", err)
				return
			}
			defer resp.Body.Close()
			s.logTelegramResponse(resp)
		}()
		return
	}

	// Message + file via sendDocument (multipart/form-data).
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read file for Telegram: %v", err)
		// Fall back to a plain text message noting the attachment failed.
		s.sendTelegram(color, title, description+" (report delivery failed)")
		return
	}

	var b bytes.Buffer
	writer := multipart.NewWriter(&b)
	if err := writer.WriteField("chat_id", s.telegramChatID); err != nil {
		log.Printf("Error: failed to write Telegram chat_id field: %v", err)
		return
	}
	if err := writer.WriteField("caption", text); err != nil {
		log.Printf("Error: failed to write Telegram caption field: %v", err)
		return
	}
	if err := writer.WriteField("parse_mode", "HTML"); err != nil {
		log.Printf("Error: failed to write Telegram parse_mode field: %v", err)
		return
	}
	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		log.Printf("Error: failed to create form file for Telegram: %v", err)
		return
	}
	if _, err := part.Write(fileData); err != nil {
		log.Printf("Error: failed to write file data for Telegram: %v", err)
		return
	}
	_ = writer.Close()
	contentType := writer.FormDataContentType()

	endpoint := telegramAPIBase + "/bot" + s.telegramBotToken + "/sendDocument"
	go func() {
		defer safe.Recover("telegram.sendDocument", "")
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Post(endpoint, contentType, &b)
		if err != nil {
			log.Printf("Telegram sendDocument error: %v", err)
			return
		}
		defer resp.Body.Close()
		s.logTelegramResponse(resp)
	}()
}

// logTelegramResponse logs non-2xx responses and logical ok:false
// bodies. Telegram returns 200 with {"ok": false, ...} on logical
// errors (e.g. bot lacks permission, chat not found), so a status-code
// check alone misses those. We read a bounded copy of the body and
// inspect the "ok" field; non-2xx is logged regardless.
func (s *Server) logTelegramResponse(resp *http.Response) {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10)) // 4 KiB cap
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Telegram API error: HTTP %d %s", resp.StatusCode, string(body))
		return
	}
	var parsed struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && !parsed.OK {
		desc := parsed.Description
		if desc == "" {
			desc = string(body)
		}
		log.Printf("Telegram API logical error: ok=false %s", desc)
	}
}

// startCaidoProxy launches Caido proxy in background if it's installed and not already running.
func startCaidoProxy() {
	cfg := config.Get()
	port := cfg.CaidoPort
	if port == 0 {
		port = 8080
	}

	// Check if something is already listening on the Caido port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
	if err == nil {
		_ = conn.Close()
		log.Printf("Caido proxy already running on port %d", port)
		return
	}

	// Check if caido binary exists
	caidoPath, err := exec.LookPath("caido")
	if err != nil {
		log.Printf("Caido not installed — proxy features will use direct HTTP (install from https://caido.io)")
		return
	}

	// Start Caido in background with --no-open (headless)
	cmd := exec.Command(caidoPath, "--no-open", "--listen", fmt.Sprintf("127.0.0.1:%d", port))
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		log.Printf("⚠️  Failed to start Caido proxy: %v", err)
		return
	}

	// Don't wait for the process — let it run in background
	go func() {
		_ = cmd.Wait() // Reap zombie process
	}()

	log.Printf("✅ Caido proxy started on port %d (PID: %d)", port, cmd.Process.Pid)
}

// scheduleIDPattern validates schedule IDs to prevent path traversal.
var scheduleIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// handleSchedules handles GET /api/schedules and POST /api/schedules
func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		s.schedulesMu.RLock()
		defer s.schedulesMu.RUnlock()
		list := make([]*ScanSchedule, 0, len(s.schedules))
		for _, sch := range s.schedules {
			list = append(list, sch)
		}
		// Sort by Name alphabetically
		sort.Slice(list, func(i, j int) bool {
			return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
		})
		_ = json.NewEncoder(w).Encode(list)
		return
	case http.MethodPost:
		var req ScanSchedule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.Targets) == 0 {
			http.Error(w, "targets are required", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			req.Name = "Scheduled Scan " + strings.Join(req.Targets, ", ")
		}
		if req.Interval == "" {
			req.Interval = "daily"
		}
		normalizeScheduleActivity(&req)
		req.ID = randomSlug()
		req.Enabled = true
		req.NextRun = calculateNextRun(req.Interval, time.Now())

		s.schedulesMu.Lock()
		s.schedules[req.ID] = &req
		diskCopy := req // snapshot under lock for race-free disk write
		s.schedulesMu.Unlock()

		if err := s.saveScheduleToDisk(&diskCopy); err != nil {
			log.Printf("[SCHEDULER] Error saving schedule to disk: %v", err)
			http.Error(w, "failed to save schedule: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(req)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// handleScheduleDetail handles GET /api/schedules/{id}, PUT /api/schedules/{id}, DELETE /api/schedules/{id}, and POST /api/schedules/{id}/trigger
func (s *Server) handleScheduleDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/api/schedules/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	id := parts[0]
	if !scheduleIDPattern.MatchString(id) {
		http.Error(w, "invalid schedule id", http.StatusBadRequest)
		return
	}

	s.schedulesMu.RLock()
	sch, exists := s.schedules[id]
	s.schedulesMu.RUnlock()

	if !exists {
		http.Error(w, "schedule not found", http.StatusNotFound)
		return
	}

	// Handle trigger action
	if len(parts) > 1 && parts[1] == "trigger" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Manually trigger the scan
		req := ScanRequest{
			Targets:        sch.Targets,
			Instruction:    sch.Instruction,
			ScanMode:       sch.ScanMode,
			SeverityFilter: sch.SeverityFilter,
			Phases:         sch.Phases,
			ReconMode:      sch.ReconMode,
			ScanIntensity:  sch.ScanIntensity,
			CompanyName:    sch.CompanyName,
			LogoPath:       sch.LogoPath,
			DiscordWebhook: sch.DiscordWebhook,
			Name:           sch.Name + " (Scheduled)",
			Model:          sch.Model,
		}

		scanCfg := *s.cfg
		if sch.Model != "" {
			scanCfg.LLM = sch.Model
		}
		instanceID := randomSlug()

		go s.runMultiScan(req, &scanCfg, instanceID)

		s.schedulesMu.Lock()
		sch.LastRun = time.Now()
		diskCopy := *sch // snapshot under lock for race-free disk write
		s.schedulesMu.Unlock()
		if err := s.saveScheduleToDisk(&diskCopy); err != nil {
			log.Printf("[SCHEDULER] Failed to persist schedule %s after manual trigger: %v", diskCopy.ID, err)
		}

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "triggered", "instance_id": instanceID})
		return
	}

	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(sch)
		return

	case http.MethodPut:
		var req ScanSchedule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.Targets) == 0 {
			http.Error(w, "targets are required", http.StatusBadRequest)
			return
		}
		normalizeScheduleActivity(&req)

		s.schedulesMu.Lock()
		oldEnabled := sch.Enabled
		oldInterval := sch.Interval

		sch.Name = req.Name
		sch.Interval = req.Interval
		sch.Enabled = req.Enabled
		sch.Targets = req.Targets
		sch.Instruction = req.Instruction
		sch.ScanMode = req.ScanMode
		sch.SeverityFilter = req.SeverityFilter
		sch.Phases = req.Phases
		sch.ReconMode = req.ReconMode
		sch.ScanIntensity = req.ScanIntensity
		sch.CompanyName = req.CompanyName
		sch.LogoPath = req.LogoPath
		sch.DiscordWebhook = req.DiscordWebhook
		sch.Model = req.Model

		// If interval changed, or enabled transitioned false -> true, recalculate NextRun
		if sch.Interval != oldInterval || (sch.Enabled && !oldEnabled) {
			sch.NextRun = calculateNextRun(sch.Interval, time.Now())
		}

		diskCopy := *sch // snapshot under lock for race-free disk write
		s.schedulesMu.Unlock()

		if err := s.saveScheduleToDisk(&diskCopy); err != nil {
			http.Error(w, "failed to save schedule: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(&diskCopy)
		return

	case http.MethodDelete:
		s.schedulesMu.Lock()
		delete(s.schedules, id)
		s.schedulesMu.Unlock()

		if err := s.deleteScheduleFromDisk(id); err != nil {
			http.Error(w, "failed to delete schedule: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
