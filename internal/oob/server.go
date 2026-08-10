// Package oob provides out-of-band (OAST) callback infrastructure for blind
// SSRF, RCE, XSS, XXE, and SQLi verification. A callback is concrete evidence
// that some system reached the unique URL; target attribution remains
// fail-closed until protocol and scanner-origin provenance are assessed.
//
// This is essential under Xalgorix's "no theoretical findings" policy: a blind
// class that cannot be reproduced by the verifier is dropped, so the agent
// needs a real callback oracle to prove impact.
//
// Design: a single in-process HTTP listener records every inbound request,
// correlated by a unique token embedded in the URL path (/{token}/...). The
// listener binds 0.0.0.0:<XALGORIX_OOB_PORT>; the operator exposes it publicly
// (directly or via reverse proxy) and sets XALGORIX_OOB_PUBLIC_URL to the
// address targets can reach. Without a public URL the feature is disabled and
// the tool tells the agent to fall back to in-band verification.
package oob

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// Interaction is a single recorded out-of-band callback.
type Interaction struct {
	Token          string            `json:"token"`
	Protocol       string            `json:"protocol"` // "http" / "https"
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Query          string            `json:"query"`
	RemoteAddr     string            `json:"remote_addr"`
	ScannerOrigin  bool              `json:"scanner_origin,omitempty"`
	OriginAssessed bool              `json:"origin_assessed,omitempty"`
	UserAgent      string            `json:"user_agent"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	Time           time.Time         `json:"time"`
}

// OriginCalibrationState describes whether remote callback provenance can be
// assessed. Anything except OriginCalibrationCalibrated must be treated as
// fail-closed for a remote, apparently non-scanner HTTP interaction.
type OriginCalibrationState string

const (
	OriginCalibrationNotStarted  OriginCalibrationState = "not_started"
	OriginCalibrationPending     OriginCalibrationState = "pending"
	OriginCalibrationCalibrated  OriginCalibrationState = "calibrated"
	OriginCalibrationUnavailable OriginCalibrationState = "unavailable"
)

var (
	mu           sync.Mutex
	interactions = map[string][]Interaction{} // token -> ordered interactions
	tokenOrder   []string                     // FIFO of registered tokens for eviction
	startErr     error
	startOnce    sync.Once

	scannerOriginMu         sync.RWMutex
	scannerOriginIPs        = map[string]struct{}{}
	scannerOriginState      = OriginCalibrationNotStarted
	scannerOriginRetryAfter time.Time
)

const (
	maxOOBBody                     = 8 * 1024
	maxHitsPerToken                = 100  // cap interactions kept per token
	maxTokens                      = 4096 // cap registered tokens; oldest evicted beyond this
	scannerOriginPollWindow        = 7 * time.Second
	scannerOriginRetryCooldown     = 30 * time.Second
	scannerOriginRequestTimeout    = 5 * time.Second
	scannerOriginPollCheckInterval = 200 * time.Millisecond
)

// selfHosted reports whether the operator configured a self-hosted callback
// listener (XALGORIX_OOB_PUBLIC_URL). When set it takes precedence over the
// zero-config interactsh backend.
func selfHosted() bool {
	return strings.TrimSpace(config.Get().OOBPublicURL) != ""
}

// Enabled reports whether OOB is usable: either a self-hosted listener is
// configured, or the interactsh backend is available (the default).
func Enabled() bool {
	return selfHosted() || interactshEnabled()
}

// rawGenerate mints a callback without triggering scanner-origin calibration.
func rawGenerate() (callbackURL, token string, err error) {
	if selfHosted() {
		return selfHostedGenerate()
	}
	if !interactshEnabled() {
		return "", "", fmt.Errorf("OOB is disabled (XALGORIX_OOB_DISABLE=true)")
	}
	return interactshGenerate()
}

func rawPoll(token string) []Interaction {
	if selfHosted() {
		return selfHostedPoll(token)
	}
	return interactshPoll(token)
}

func normalizedRemoteIP(remoteAddr string) string {
	raw := strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	return ""
}

func isDirectScannerOrigin(remoteAddr string) bool {
	ip := net.ParseIP(normalizedRemoteIP(remoteAddr))
	if ip == nil {
		return false
	}
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		var local net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			local = value.IP
		case *net.IPAddr:
			local = value.IP
		}
		if local != nil && local.Equal(ip) {
			return true
		}
	}
	return false
}

// ScannerOriginCalibrationState exposes whether remote callback origin
// assessments are currently trustworthy.
func ScannerOriginCalibrationState() OriginCalibrationState {
	scannerOriginMu.RLock()
	defer scannerOriginMu.RUnlock()
	return scannerOriginState
}

// ScannerOriginCalibrated reports whether external scanner egress calibration
// succeeded. Callers must fail closed when this is false.
func ScannerOriginCalibrated() bool {
	return ScannerOriginCalibrationState() == OriginCalibrationCalibrated
}

// IsScannerOrigin reports whether an OOB source address matches this scanner's
// calibrated public/NAT egress or one of its directly assigned interfaces.
func IsScannerOrigin(remoteAddr string) bool {
	if isDirectScannerOrigin(remoteAddr) {
		return true
	}
	ip := normalizedRemoteIP(remoteAddr)
	scannerOriginMu.RLock()
	_, known := scannerOriginIPs[ip]
	scannerOriginMu.RUnlock()
	return ip != "" && known
}

func assessScannerOrigin(remoteAddr string) (scannerOrigin, assessed bool) {
	if isDirectScannerOrigin(remoteAddr) {
		return true, true
	}
	ip := normalizedRemoteIP(remoteAddr)
	scannerOriginMu.RLock()
	_, known := scannerOriginIPs[ip]
	calibrated := scannerOriginState == OriginCalibrationCalibrated
	scannerOriginMu.RUnlock()
	if !calibrated {
		return false, false
	}
	return ip != "" && known, true
}

func calibrationHeaderMatches(headers map[string]string, nonce string) bool {
	for key, value := range headers {
		if strings.EqualFold(key, "X-Xalgorix-Origin-Calibration") && strings.TrimSpace(value) == nonce {
			return true
		}
	}
	return false
}

func finishScannerOriginCalibration(remoteAddr string) {
	ip := normalizedRemoteIP(remoteAddr)
	scannerOriginMu.Lock()
	defer scannerOriginMu.Unlock()
	if ip != "" {
		scannerOriginIPs[ip] = struct{}{}
		scannerOriginState = OriginCalibrationCalibrated
		scannerOriginRetryAfter = time.Time{}
		return
	}
	scannerOriginState = OriginCalibrationUnavailable
	scannerOriginRetryAfter = time.Now().Add(scannerOriginRetryCooldown)
}

// startScannerOriginCalibration starts a retryable background calibration. It
// never waits for the calibration request or polling window, so Generate can
// return the caller's independently minted token without calibration latency.
func startScannerOriginCalibration() {
	now := time.Now()
	scannerOriginMu.Lock()
	if scannerOriginState == OriginCalibrationCalibrated ||
		scannerOriginState == OriginCalibrationPending ||
		now.Before(scannerOriginRetryAfter) {
		scannerOriginMu.Unlock()
		return
	}
	scannerOriginState = OriginCalibrationPending
	scannerOriginMu.Unlock()
	go calibrateScannerOrigin()
}

// calibrateScannerOrigin makes one no-redirect request to a private OOB token
// and records the source IP observed by the callback service. A nonce header
// ensures old/shared-token interactions can never poison the calibration.
func calibrateScannerOrigin() {
	callbackURL, token, err := rawGenerate()
	if err != nil {
		finishScannerOriginCalibration("")
		return
	}
	nonceBytes := make([]byte, 12)
	if _, err := rand.Read(nonceBytes); err != nil {
		finishScannerOriginCalibration("")
		return
	}
	nonce := hex.EncodeToString(nonceBytes)
	req, err := http.NewRequest(http.MethodGet, callbackURL, nil)
	if err != nil {
		finishScannerOriginCalibration("")
		return
	}
	req.Header.Set("X-Xalgorix-Origin-Calibration", nonce)
	req.Header.Set("User-Agent", "xalgorix-origin-calibration/1")
	client := &http.Client{
		Timeout: scannerOriginRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if response, _ := client.Do(req); response != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
	}

	deadline := time.NewTimer(scannerOriginPollWindow)
	ticker := time.NewTicker(scannerOriginPollCheckInterval)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		for _, hit := range rawPoll(token) {
			protocol := strings.ToLower(strings.TrimSpace(hit.Protocol))
			if (protocol == "http" || protocol == "https") && calibrationHeaderMatches(hit.Headers, nonce) {
				finishScannerOriginCalibration(hit.RemoteAddr)
				return
			}
		}
		select {
		case <-deadline.C:
			finishScannerOriginCalibration("")
			return
		case <-ticker.C:
		}
	}
}

// Generate mints a callback URL + polling token using whichever backend is
// active: the self-hosted listener when configured, otherwise interactsh.
func Generate() (callbackURL, token string, err error) {
	startScannerOriginCalibration()
	return rawGenerate()
}

// Poll returns interactions for a token from whichever backend is active,
// filtered to the interaction protocols the operator allows via
// XALGORIX_OOB_INTERACTIONS (blank = all: dns, http, smtp). Each returned copy
// carries a fail-closed origin assessment.
func Poll(token string) []Interaction {
	// Polling an existing token is also an opportunity to recover from a
	// transient calibration failure once the retry cooldown has elapsed.
	startScannerOriginCalibration()
	filtered := applyProtocolFilter(rawPoll(token), parseAllowedProtocols(config.Get().OOBInteractions))
	hits := make([]Interaction, len(filtered))
	copy(hits, filtered)
	for index := range hits {
		hits[index].ScannerOrigin, hits[index].OriginAssessed = assessScannerOrigin(hits[index].RemoteAddr)
	}
	return hits
}

// parseAllowedProtocols turns an XALGORIX_OOB_INTERACTIONS value into the set of
// allowed protocol names. A nil result means "allow everything" (the default),
// so an unset/blank value preserves the historical behavior of retaining any
// DNS, HTTP or SMTP callback. "https" is folded into "http". A value
// that names no valid protocol also yields nil — an operator typo must never
// silently drop every callback (use XALGORIX_OOB_DISABLE to turn OOB off).
func parseAllowedProtocols(raw string) map[string]bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	set := map[string]bool{}
	for _, p := range strings.Split(raw, ",") {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "http", "https":
			set["http"] = true
		case "dns":
			set["dns"] = true
		case "smtp":
			set["smtp"] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// filterableProtocols are the only protocols XALGORIX_OOB_INTERACTIONS selects
// between. Anything else interactsh can report (ldap, smb, ftp, responder, or a
// protocol we don't recognize yet) is always kept: those are independent proof
// channels — LDAP is the primary one for JNDI/Log4Shell — that a DNS/HTTP/SMTP
// selector was never meant to suppress. An interaction with a blank protocol is
// kept for the same reason.
var filterableProtocols = map[string]bool{"dns": true, "http": true, "smtp": true}

// applyProtocolFilter drops interactions whose protocol the operator excluded.
// A nil allow-set is a pass-through (all protocols allowed), and protocols
// outside filterableProtocols are never dropped.
func applyProtocolFilter(in []Interaction, allow map[string]bool) []Interaction {
	if allow == nil {
		return in
	}
	out := make([]Interaction, 0, len(in))
	for _, it := range in {
		proto := strings.ToLower(strings.TrimSpace(it.Protocol))
		if proto == "https" {
			proto = "http"
		}
		if !filterableProtocols[proto] || allow[proto] {
			out = append(out, it)
		}
	}
	return out
}

// PublicBaseURL returns the operator-configured public callback base, trimmed
// of any trailing slash. Empty when OOB is disabled.
func PublicBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(config.Get().OOBPublicURL), "/")
}

// ensureStarted lazily starts the listener the first time OOB is used.
func ensureStarted() error {
	startOnce.Do(func() {
		port := config.Get().OOBPort
		if port <= 0 {
			startErr = fmt.Errorf("XALGORIX_OOB_PORT not set")
			return
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/", handle)
		srv := &http.Server{
			Addr:              fmt.Sprintf("0.0.0.0:%d", port),
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			startErr = fmt.Errorf("oob listen %s: %w", srv.Addr, err)
			return
		}
		go func() { _ = srv.Serve(ln) }()
	})
	return startErr
}

// selfHostedGenerate registers a fresh correlation token and returns the full
// callback URL the agent should plant in payloads, plus the bare token for
// polling. Returns an error when the self-hosted listener is not reachable.
func selfHostedGenerate() (callbackURL, token string, err error) {
	if !selfHosted() {
		return "", "", fmt.Errorf("OOB is not configured (set XALGORIX_OOB_PUBLIC_URL and XALGORIX_OOB_PORT)")
	}
	if err := ensureStarted(); err != nil {
		return "", "", err
	}
	token = randToken()
	mu.Lock()
	// Register the token so the handler only records callbacks for tokens we
	// actually minted (internet scan noise hitting random paths is ignored).
	interactions[token] = []Interaction{}
	tokenOrder = append(tokenOrder, token)
	// Evict the oldest tokens if we exceed the cap (long-lived server).
	for len(tokenOrder) > maxTokens {
		old := tokenOrder[0]
		tokenOrder = tokenOrder[1:]
		delete(interactions, old)
	}
	mu.Unlock()
	return PublicBaseURL() + "/" + token, token, nil
}

// selfHostedPoll returns interactions recorded by the self-hosted listener
// for a token since the beginning.
func selfHostedPoll(token string) []Interaction {
	token = strings.TrimSpace(token)
	mu.Lock()
	defer mu.Unlock()
	out := make([]Interaction, len(interactions[token]))
	copy(out, interactions[token])
	return out
}

func handle(w http.ResponseWriter, r *http.Request) {
	token := firstPathSegment(r.URL.Path)
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, maxOOBBody))
		body = string(b)
	}
	hdrs := map[string]string{}
	for k, v := range r.Header {
		hdrs[k] = strings.Join(v, ", ")
	}
	it := Interaction{
		Token:      token,
		Protocol:   proto,
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		RemoteAddr: r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Headers:    hdrs,
		Body:       body,
		Time:       time.Now(),
	}
	if token != "" {
		mu.Lock()
		// Only record callbacks for tokens we minted via Generate — ignore
		// unregistered paths (bots, scanners, favicon probes) so the store
		// can't be polluted or grown without bound by internet noise.
		if hits, ok := interactions[token]; ok && len(hits) < maxHitsPerToken {
			interactions[token] = append(hits, it)
		}
		mu.Unlock()
	}
	// Respond with a tiny, benign, unique marker so the agent can also detect
	// the callback in-band (e.g. an SSRF that reflects the response body).
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("xalgorix-oob-ok:" + token + "\n"))
}

func firstPathSegment(p string) string {
	p = strings.TrimLeft(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}

func randToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return "x" + hex.EncodeToString(b) // 17 chars, url/dns safe
}
