package httpclient

import (
	"fmt"
	"strings"
	"sync"
)

// Session authentication: operator-supplied credentials for the target so the
// agent can exercise post-authentication attack surface (IDOR/BOLA, privilege
// escalation, business logic). Stored per scan-context ID and applied
// automatically to http_request calls for headers the caller didn't set,
// so the agent's requests are authenticated by default while still allowing
// it to override (e.g. to test the SAME request unauthenticated for IDOR).

var (
	sessionAuthMu        sync.RWMutex
	sessionAuth          = map[string]map[string]string{} // contextID -> canonical header -> value
	sessionAuthSecondary = map[string]map[string]string{} // targeted retests only; never auto-applied
)

func setSessionAuthLocked(store map[string]map[string]string, contextID string, headers map[string]string) {
	if len(headers) == 0 {
		delete(store, contextID)
		return
	}
	cp := make(map[string]string, len(headers))
	for k, v := range headers {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		cp[k] = v
	}
	if len(cp) == 0 {
		delete(store, contextID)
		return
	}
	store[contextID] = cp
}

// SetSessionAuth registers authenticated-session headers for a scan context.
// Passing an empty map clears any existing auth for that context.
func SetSessionAuth(contextID string, headers map[string]string) {
	sessionAuthMu.Lock()
	defer sessionAuthMu.Unlock()
	setSessionAuthLocked(sessionAuth, contextID, headers)
}

// SetSessionAuthSecondary stores a second account for a targeted retest. It is
// selected only by the opaque auth_profile tool argument; credential values
// are never put into prompts, tool schemas, or pollable job state.
func SetSessionAuthSecondary(contextID string, headers map[string]string) {
	sessionAuthMu.Lock()
	defer sessionAuthMu.Unlock()
	setSessionAuthLocked(sessionAuthSecondary, contextID, headers)
}

func copySessionAuth(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	cp := make(map[string]string, len(src))
	for k, v := range src {
		cp[k] = v
	}
	return cp
}

// getSessionAuth returns a copy of the auth headers for a context (or nil).
func getSessionAuth(contextID string) map[string]string {
	sessionAuthMu.RLock()
	defer sessionAuthMu.RUnlock()
	return copySessionAuth(sessionAuth[contextID])
}

func getSessionAuthSecondary(contextID string) map[string]string {
	sessionAuthMu.RLock()
	defer sessionAuthMu.RUnlock()
	return copySessionAuth(sessionAuthSecondary[contextID])
}

func normalizeAuthProfile(profile string) string {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		return "primary"
	}
	return profile
}

func getSessionAuthProfile(contextID, profile string) (map[string]string, error) {
	switch normalizeAuthProfile(profile) {
	case "primary":
		return getSessionAuth(contextID), nil
	case "secondary":
		headers := getSessionAuthSecondary(contextID)
		if len(headers) == 0 {
			return nil, fmt.Errorf("secondary authentication profile is unavailable")
		}
		return headers, nil
	case "none":
		return nil, nil
	default:
		return nil, fmt.Errorf("auth_profile must be primary, secondary, or none")
	}
}

func protectedAuthHeaderNames(contextID string) map[string]struct{} {
	protected := map[string]struct{}{
		"authorization":       {},
		"proxy-authorization": {},
		"cookie":              {},
		"x-api-key":           {},
		"x-auth-token":        {},
	}
	sessionAuthMu.RLock()
	defer sessionAuthMu.RUnlock()
	for _, headers := range []map[string]string{sessionAuth[contextID], sessionAuthSecondary[contextID]} {
		for name := range headers {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				protected[name] = struct{}{}
			}
		}
	}
	return protected
}

// ParseAuthHeaders parses an operator auth string into HTTP headers. Accepts
// one "Header-Name: value" per line and/or ';'-separated entries. A bare
// "token"/"Bearer x" with no colon is treated as an Authorization value.
//
// Examples:
//
//	"Cookie: session=abc; Authorization: Bearer xyz"
//	"Cookie: a=1\nX-Api-Key: k"
func ParseAuthHeaders(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := map[string]string{}
	// Tokenize on newlines and ';', but treat a ';'-segment as a CONTINUATION
	// of the current header unless it starts a new "Header-Name:" pair. This
	// preserves multi-cookie values like `Cookie: a=1; b=2` (b=2 is not a new
	// header — it has no header-name-shaped prefix) while still splitting
	// `Cookie: a=1; Authorization: Bearer x` into two headers.
	var segments []string
	for _, line := range strings.Split(raw, "\n") {
		segments = append(segments, strings.Split(line, ";")...)
	}
	curName, curVal := "", ""
	flush := func() {
		if curName != "" && curVal != "" {
			// A repeated header name (rare) keeps the first occurrence.
			if _, ok := out[curName]; !ok {
				out[curName] = curVal
			}
		}
		curName, curVal = "", ""
	}
	for _, seg := range segments {
		s := strings.TrimSpace(seg)
		if s == "" {
			continue
		}
		if name, val, ok := splitHeaderSpec(s); ok {
			flush()
			curName, curVal = name, val
		} else if curName != "" {
			// Continuation of the current header value (e.g. another cookie).
			curVal = curVal + "; " + s
		} else if !strings.EqualFold(s, "Bearer") {
			// Leading bare token with no header name → Authorization value.
			flush()
			curName, curVal = "Authorization", s
		}
	}
	flush()
	if len(out) == 0 {
		return nil
	}
	return out
}

// splitHeaderSpec returns (name, value, true) when s begins with an
// HTTP-header-name-shaped token followed by ':'. Cookie pairs like "b=2" (which
// contain '=' rather than a header-name+':') return ok=false so they are kept
// as continuations of the preceding header instead of being mis-parsed.
func splitHeaderSpec(s string) (name, value string, ok bool) {
	idx := strings.IndexByte(s, ':')
	if idx <= 0 {
		return "", "", false
	}
	candidate := strings.TrimSpace(s[:idx])
	if candidate == "" || !isHeaderName(candidate) {
		return "", "", false
	}
	return candidate, strings.TrimSpace(s[idx+1:]), true
}

// isHeaderName reports whether tok is a valid RFC 7230 header field-name
// (token chars only). Notably '=' and space are excluded, so cookie pairs and
// values are never mistaken for a header name.
func isHeaderName(tok string) bool {
	for _, r := range tok {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}
