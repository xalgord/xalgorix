// Package web — HTTP handlers for the runtime-editable credential
// Profile_Store (/api/auth/profiles) and the OAuth start / complete
// / refresh surface mounted under /api/auth/profiles/...
//
// These handlers are thin adapters around *auth.Store and
// *auth.Registry: they decode JSON, dispatch to the right Store
// method or Driver method, mask credentials on the way out via
// maskProfile (masks.go), and translate the typed error sentinels
// from internal/auth into HTTP status codes. The validation policy
// itself lives inside internal/auth (Store.Put for profile shape,
// each driver for flow-specific errors); keeping the gates there
// means the same rules apply on every entry path including future
// internal CLI tools.
//
// Status-code mapping (Requirements 4.5–4.8, 5.1–5.4, 6.x, 7.x,
// 8.x, 9.x, 10.4, 12.3):
//
//   - Profile_Store
//
//   - auth.ErrUnknownProvider     → 400 (catalog miss on Put)
//
//   - auth.ErrProfileIDInvalid    → 400 (regex miss)
//
//   - auth.ErrProviderRequired    → 400 (empty provider)
//
//   - auth.ErrProfileTypeInvalid  → 400 (bad type)
//
//   - auth.ErrLockTimeout         → 503 (5s flock deadline hit)
//
//   - auth.ErrProfileNotFound     → 404 (Get/Delete miss)
//
//   - Driver path
//
//   - auth.ErrFlowTimeout         → 408 ("oauth flow timed out")
//
//   - auth.ErrReauthRequired      → 401 ("oauth refresh required")
//
//   - auth.ErrNotFound                    → 404 (Claude CLI credentials)
//
//   - auth.ErrCodexCredentialsNotFound    → 404 (Codex CLI credentials)
//
//   - providers.ErrUpstream{S,B}  → 502 with {statusCode, body}
//
//   - any other driver error      → 500
//
// Routes are NOT registered in this file — Wave E task 5.4 mounts
// them under authMw → rlMiddleware → CSRF in NewServer.Start. This
// task only builds the handler functions and the helpers they need.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// profilesReady gates every handler on the profiles + catalog +
// oauthRegistry fields having been initialized at startup. NewServer
// constructs all three together, so a nil profiles implies the
// whole subsystem is unavailable; handlers surface 503 with a
// single shape so the dashboard's error renderer has one envelope
// to consume.
//
// We separately check oauthRegistry because handleListProfiles /
// handleCreateAPIKeyProfile / handleDeleteProfile do not need the
// registry — only the flow handlers do. Callers that need the
// registry call profilesAndRegistryReady instead.
func (s *Server) profilesReady(w http.ResponseWriter) bool {
	if s.profiles == nil || s.catalog == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
			"error": "auth profile store not initialized",
		})
		return false
	}
	return true
}

// profilesAndRegistryReady extends profilesReady with a check on
// oauthRegistry — required by handleOAuthStart, handleOAuthComplete,
// and handleProfileRefresh.
func (s *Server) profilesAndRegistryReady(w http.ResponseWriter) bool {
	if !s.profilesReady(w) {
		return false
	}
	if s.oauthRegistry == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
			"error": "oauth driver registry not initialized",
		})
		return false
	}
	return true
}

// profileErrorStatus maps a *auth.Store / *auth.Driver error to the
// HTTP status code documented at the top of this file. Returns 0
// when err does not match any known sentinel so the caller falls
// back to 500.
//
// providers.ErrUpstream is intentionally NOT handled here — the
// caller branches on errors.As to extract the {statusCode, body}
// envelope, which needs a different response shape than the simple
// {error: msg} body the other sentinels produce.
func profileErrorStatus(err error) int {
	switch {
	case errors.Is(err, auth.ErrLockTimeout):
		return http.StatusServiceUnavailable
	case errors.Is(err, auth.ErrProfileNotFound):
		return http.StatusNotFound
	case errors.Is(err, auth.ErrCodexCredentialsNotFound):
		return http.StatusNotFound
	case errors.Is(err, auth.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, auth.ErrFlowTimeout):
		return http.StatusRequestTimeout
	case errors.Is(err, auth.ErrReauthRequired):
		return http.StatusUnauthorized
	case errors.Is(err, auth.ErrUnknownProvider),
		errors.Is(err, auth.ErrProfileIDInvalid),
		errors.Is(err, auth.ErrProviderRequired),
		errors.Is(err, auth.ErrProfileTypeInvalid):
		return http.StatusBadRequest
	}
	return 0
}

// writeProfileError writes err to w using the documented status-code
// mapping, falling back to 500 for unrecognized errors. The body
// shape matches writeCatalogError so the dashboard error renderer
// can consume both surfaces with a single shape.
//
// providers.ErrUpstream is unwrapped here so setup_token's 502
// envelope reaches the caller without each handler reimplementing
// the errors.As dance.
func writeProfileError(w http.ResponseWriter, err error) {
	var upstream providers.ErrUpstream
	if errors.As(err, &upstream) {
		writeJSONStatus(w, http.StatusBadGateway, map[string]any{
			"statusCode": upstream.StatusCode,
			"body":       upstream.Body,
		})
		return
	}
	if errors.Is(err, auth.ErrReauthRequired) {
		// The fixed message body matches the requirement
		// wording exactly so the dashboard can match on it.
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{
			"error": "oauth refresh required",
		})
		return
	}
	if errors.Is(err, auth.ErrFlowTimeout) {
		writeJSONStatus(w, http.StatusRequestTimeout, map[string]string{
			"error": "oauth flow timed out",
		})
		return
	}
	if errors.Is(err, auth.ErrNotFound) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error": "claude cli credentials not found",
		})
		return
	}
	if errors.Is(err, auth.ErrCodexCredentialsNotFound) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error": "codex cli credentials not found",
		})
		return
	}
	status := profileErrorStatus(err)
	if status == 0 {
		status = http.StatusInternalServerError
	}
	writeJSONStatus(w, status, map[string]string{"error": err.Error()})
}

// profileKeyFromPath extracts the "<provider>:<profileId>" key
// segment from URL paths of the form
//
//	/api/auth/profiles/{key}/refresh   (suffix == "/refresh")
//	/api/auth/profiles/{key}           (suffix == "")
//
// Returns "" when the path has no key (caller should reject 400).
// The function is deliberately strict: the key must not contain a
// '/' (apart from any trailing suffix), which guards against
// "/api/auth/profiles/foo/bar/refresh" silently matching a
// malformed multi-segment path as the key "foo".
func profileKeyFromPath(p, suffix string) string {
	const prefix = "/api/auth/profiles/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(p, prefix)
	if suffix != "" {
		if !strings.HasSuffix(rest, suffix) {
			return ""
		}
		rest = strings.TrimSuffix(rest, suffix)
	}
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return rest
}

// handleListProfiles serves GET /api/auth/profiles.
//
// The response body is a JSON array of auth.Profile values with
// every credential field passed through maskProfile so the operator
// can recognize the stored value without leaking the secret. The
// catalog-empty / store-uninitialized case maps to 503; an empty
// store returns "[]" not "null".
//
// Validates: Requirements 4.5, 4.6, 5.1, 5.2, 5.4, 12.3.
func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.profilesReady(w) {
		return
	}
	profiles, err := s.profiles.List(r.Context())
	if err != nil {
		writeProfileError(w, err)
		return
	}
	masked := make([]auth.Profile, 0, len(profiles))
	for _, p := range profiles {
		masked = append(masked, maskProfile(p))
	}
	writeJSONStatus(w, http.StatusOK, masked)
}

// handleCreateAPIKeyProfile serves POST /api/auth/profiles/api-key.
//
// Body shape (from the design):
//
//	{"provider": "openai", "profileId": "default",
//	 "apiKey": "sk-...", "apiBaseOverride": ""}
//
// Builds a Profile{Type: APIKey, ...} and persists via
// Store.Put. Returns 201 + masked profile on success. Validation
// errors from the Store map to 400; the catalog-miss case maps to
// 400 with the "unknown provider" envelope; flock timeouts map to
// 503.
//
// Validates: Requirements 4.5, 4.8, 5.1, 5.4.
func (s *Server) handleCreateAPIKeyProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.profilesReady(w) {
		return
	}
	limitJSONBody(w, r)
	var req struct {
		Provider        string `json:"provider"`
		ProfileID       string `json:"profileId"`
		APIKey          string `json:"apiKey"`
		APIBaseOverride string `json:"apiBaseOverride"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JSON: " + err.Error(),
		})
		return
	}
	if strings.TrimSpace(req.APIKey) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "apiKey is required",
		})
		return
	}
	p := auth.Profile{
		Provider:        req.Provider,
		ProfileID:       req.ProfileID,
		Type:            auth.APIKey,
		APIKey:          req.APIKey,
		APIBaseOverride: req.APIBaseOverride,
	}
	if err := s.profiles.Put(r.Context(), p); err != nil {
		writeProfileError(w, err)
		return
	}
	// Re-read so the response carries Store-stamped UpdatedAt.
	stored, ok, err := s.profiles.Get(r.Context(), p.Key())
	if err != nil {
		writeProfileError(w, err)
		return
	}
	if !ok {
		// Should not happen — Put just committed under flock —
		// but a defensive fallback prevents a 500 if a
		// concurrent delete races.
		stored = p
	}
	writeJSONStatus(w, http.StatusCreated, maskProfile(stored))
}

// handleDeleteProfile serves DELETE /api/auth/profiles/{key}.
//
// Returns 204 No Content on success. Missing key maps to
// auth.ErrProfileNotFound → 404; flock timeout → 503.
//
// On profile lookup, when the resolved Driver satisfies the
// optional auth.Revoker contract (PKCE / device_code today), the
// handler invokes Revoke under a 5-second context timeout BEFORE
// removing the on-disk profile. Failures are logged but never
// block the delete — the operator's intent is "remove this
// credential from xalgorix" and a flaky upstream must not strand a
// profile in the local store. The revoke attempt itself uses the
// stored refresh / access token and the catalog's
// RevocationEndpoint (or, when unset, the RFC 7009 sibling-path
// "<tokenEndpoint>/revoke"). H1.
//
// Validates: Requirements 4.7, 12.3; H1 (best-effort revoke on delete).
func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.profilesReady(w) {
		return
	}
	key := profileKeyFromPath(r.URL.Path, "")
	if key == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "missing profile key in URL path",
		})
		return
	}

	// Best-effort revoke (H1). Look up the profile first so we can
	// pass its tokens to the Revoker; if the lookup fails we fall
	// through to the Delete call below — the Delete itself will
	// return ErrProfileNotFound and produce a clean 404 for the
	// caller. Any error from the revoke path is logged with the
	// profile key for triage and dropped.
	if prof, ok, err := s.profiles.Get(r.Context(), key); err == nil && ok && prof.Type == auth.OAuth && s.oauthRegistry != nil {
		if entry, eok, eerr := s.catalog.Get(r.Context(), prof.Provider); eerr == nil && eok {
			if driver, dok := s.oauthRegistry.Get(entry.Flow); dok {
				if revoker, isRevoker := driver.(auth.Revoker); isRevoker {
					revokeCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
					if rerr := revoker.Revoke(revokeCtx, entry, prof); rerr != nil {
						log.Printf("auth: revoke %q best-effort failed: %v", key, rerr)
					}
					cancel()
				}
			}
		}
	}

	if _, err := s.profiles.Delete(r.Context(), key); err != nil {
		writeProfileError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleProfileRefresh serves POST /api/auth/profiles/{key}/refresh.
//
// The handler:
//
//  1. Extracts the key from the URL (strip "/api/auth/profiles/"
//     prefix, trim trailing "/refresh").
//  2. Looks up the stored Profile; absent → 404.
//  3. Looks up the matching Catalog_Entry by Profile.Provider;
//     absent → 400 ("provider config not found").
//  4. Looks up the Driver for entry.Flow; absent → 400 ("unknown
//     flow").
//  5. Calls driver.Refresh. The shared refreshWithSink helper
//     handles the Requirement 10.1–10.4 protocol; auth.ErrReauthRequired
//     surfaces as 401 with the canonical "oauth refresh required"
//     body.
//  6. Returns 200 + masked profile on success.
//
// Validates: Requirements 10.4, 12.3.
func (s *Server) handleProfileRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.profilesAndRegistryReady(w) {
		return
	}
	key := profileKeyFromPath(r.URL.Path, "/refresh")
	if key == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "missing profile key in URL path",
		})
		return
	}
	prof, ok, err := s.profiles.Get(r.Context(), key)
	if err != nil {
		writeProfileError(w, err)
		return
	}
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("profile %q not found", key),
		})
		return
	}
	entry, ok, err := s.catalog.Get(r.Context(), prof.Provider)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("provider %q is not in the catalog", prof.Provider),
		})
		return
	}
	driver, ok := s.oauthRegistry.Get(entry.Flow)
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unknown flow %q for provider %q", entry.Flow, prof.Provider),
		})
		return
	}
	refreshed, err := driver.Refresh(r.Context(), prof, entry)
	if err != nil {
		writeProfileError(w, err)
		return
	}
	writeJSONStatus(w, http.StatusOK, maskProfile(refreshed))
}

// handleOAuthStart serves POST /api/auth/profiles/oauth/start.
//
// Body shape: {"provider": "<id>", "preferPaste": false}. The
// handler:
//
//  1. Looks up the catalog entry by provider; absent → 400.
//  2. Looks up the Driver for entry.Flow; absent → 400.
//  3. Builds StartOptions{BindAddr: cfg.BindAddr, PreferPaste: req.PreferPaste}
//     so the PKCE driver can refuse non-loopback binds per R13.2.
//  4. Calls driver.Start.
//  5. Returns the polymorphic StartResult shape from the design:
//     {flowId, mode, authURL?, userCode?, verificationURI?, expiresAt?}.
//
// Validates: Requirements 6.1, 6.5, 7.1, 7.5, 8.1, 9.1, 13.1, 13.2.
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.profilesAndRegistryReady(w) {
		return
	}
	limitJSONBody(w, r)
	var req struct {
		Provider    string `json:"provider"`
		ProfileID   string `json:"profileId"`
		PreferPaste bool   `json:"preferPaste"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JSON: " + err.Error(),
		})
		return
	}
	if strings.TrimSpace(req.Provider) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "provider is required",
		})
		return
	}
	entry, ok, err := s.catalog.Get(r.Context(), req.Provider)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("provider %q is not in the catalog", req.Provider),
		})
		return
	}
	if strings.TrimSpace(entry.Flow) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("provider %q has no oauth flow configured", req.Provider),
		})
		return
	}
	driver, ok := s.oauthRegistry.Get(entry.Flow)
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unknown flow %q for provider %q", entry.Flow, req.Provider),
		})
		return
	}
	opts := auth.StartOptions{
		// cfg.BindAddr is the resolved XALGORIX_BIND value (default
		// "127.0.0.1"). The PKCE driver inspects this and refuses
		// non-loopback binds per R13.2 by returning Mode "paste".
		BindAddr:    s.cfg.BindAddr,
		PreferPaste: req.PreferPaste,
	}
	res, err := driver.Start(r.Context(), entry, opts)
	if err != nil {
		writeProfileError(w, err)
		return
	}
	// Build the response envelope explicitly rather than
	// JSON-encoding StartResult directly, because the design
	// pins specific lowercase JSON field names that don't match
	// the Go struct's tags. omitempty-style behavior is mimicked
	// by only setting fields that are non-zero for the chosen
	// mode.
	body := map[string]any{
		"flowId": res.FlowID,
		"mode":   res.Mode,
	}
	if res.Submode != "" {
		body["submode"] = res.Submode
	}
	if res.AuthURL != "" {
		body["authURL"] = res.AuthURL
	}
	if res.UserCode != "" {
		body["userCode"] = res.UserCode
	}
	if res.VerificationURI != "" {
		body["verificationURI"] = res.VerificationURI
	}
	if !res.ExpiresAt.IsZero() {
		body["expiresAt"] = res.ExpiresAt
	}
	writeJSONStatus(w, http.StatusOK, body)
}

// handleOAuthComplete serves POST /api/auth/profiles/oauth/complete.
//
// Body shape: {"provider", "flowId", "code"?, "state"?, "setupToken"?}.
// The handler routes the CompleteInput to driver.Complete on the
// driver matching entry.Flow:
//
//   - pkce paste-fallback: needs flowId + code (authorization code) + state
//   - setup_token: needs setupToken
//   - claude_cli_reuse: no input fields needed
//   - device_code: not supported (the device driver finalizes
//     internally; calling Complete returns an error)
//
// Status mapping:
//   - auth.ErrFlowTimeout                     → 408
//   - auth.ErrNotFound (Claude credentials)                 → 404
//   - auth.ErrCodexCredentialsNotFound (Codex credentials)  → 404
//   - providers.ErrUpstream                   → 502 envelope
//   - other errors                            → 500 / 400 per sentinel
//
// On success returns 200 + masked profile.
//
// Validates: Requirements 6.4, 6.5, 6.6, 7.4, 7.5, 8.1, 8.2, 9.1, 9.2.
func (s *Server) handleOAuthComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.profilesAndRegistryReady(w) {
		return
	}
	limitJSONBody(w, r)
	var req struct {
		Provider          string `json:"provider"`
		FlowID            string `json:"flowId"`
		AuthorizationCode string `json:"code"`
		State             string `json:"state"`
		SetupToken        string `json:"setupToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JSON: " + err.Error(),
		})
		return
	}

	// UX: the paste flow asks the operator to copy the value the browser
	// landed on after sign-in. That value may be the full redirect URL
	// (http://localhost:1455/auth/callback?code=...&state=...), a bare
	// "code=...&state=..." query fragment, or just the code. Normalize all
	// three so the operator never has to hand-split code from state. An
	// explicitly-provided state in the request still wins.
	if code, state, ok := parsePastedAuthCode(req.AuthorizationCode); ok {
		req.AuthorizationCode = code
		if strings.TrimSpace(req.State) == "" && state != "" {
			req.State = state
		}
	}
	if strings.TrimSpace(req.Provider) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "provider is required",
		})
		return
	}
	entry, ok, err := s.catalog.Get(r.Context(), req.Provider)
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("provider %q is not in the catalog", req.Provider),
		})
		return
	}
	driver, ok := s.oauthRegistry.Get(entry.Flow)
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unknown flow %q for provider %q", entry.Flow, req.Provider),
		})
		return
	}
	in := auth.CompleteInput{
		FlowID:            req.FlowID,
		AuthorizationCode: req.AuthorizationCode,
		State:             req.State,
		SetupToken:        req.SetupToken,
	}
	prof, err := driver.Complete(r.Context(), entry, in)
	if err != nil {
		writeProfileError(w, err)
		return
	}
	writeJSONStatus(w, http.StatusOK, maskProfile(prof))
}

// parsePastedAuthCode normalizes whatever the operator pasted into the
// paste-flow "code" field into a bare authorization code (and state when
// present). It accepts three shapes:
//
//   - a full redirect URL: http://localhost:1455/auth/callback?code=X&state=Y
//   - a bare query fragment: code=X&state=Y (with or without a leading '?')
//   - a bare code: X
//
// Returns (code, state, true) when it extracted a code, or ("","",false)
// when the input contained no recognizable code (the caller then leaves the
// original value untouched). Whitespace is trimmed throughout because
// copy-paste often drags a trailing newline along.
func parsePastedAuthCode(raw string) (code, state string, ok bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", "", false
	}

	// Full URL form. url.Parse accepts bare tokens too, so gate on a scheme
	// or a path+query marker before trusting it as a URL.
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil {
			q := u.Query()
			if c := strings.TrimSpace(q.Get("code")); c != "" {
				return c, strings.TrimSpace(q.Get("state")), true
			}
		}
	}

	// Query-fragment form: "code=...&state=..." possibly with a leading '?'.
	if strings.Contains(v, "code=") {
		frag := strings.TrimPrefix(v, "?")
		if q, err := url.ParseQuery(frag); err == nil {
			if c := strings.TrimSpace(q.Get("code")); c != "" {
				return c, strings.TrimSpace(q.Get("state")), true
			}
		}
	}

	// Bare code: return as-is (no state available). Only treat single-token
	// input as a code — anything with spaces is more likely an accidental
	// paste of unrelated text, so we decline rather than send garbage.
	if !strings.ContainsAny(v, " \t\r\n") {
		return v, "", true
	}
	return "", "", false
}

// Compile-time assertion that the handlers satisfy http.HandlerFunc.
// Wave E task 5.4 will register them via mux.HandleFunc; this guard
// catches signature drift before that wiring lands.
var (
	_ http.HandlerFunc = (*Server)(nil).handleListProfiles
	_ http.HandlerFunc = (*Server)(nil).handleCreateAPIKeyProfile
	_ http.HandlerFunc = (*Server)(nil).handleDeleteProfile
	_ http.HandlerFunc = (*Server)(nil).handleProfileRefresh
	_ http.HandlerFunc = (*Server)(nil).handleOAuthStart
	_ http.HandlerFunc = (*Server)(nil).handleOAuthComplete
)
