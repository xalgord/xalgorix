// Package auth — error sentinels for Profile_Store and the OAuth
// driver registry.
//
// This file holds the cross-handler sentinels that the HTTP layer
// (internal/web Wave E task 5.2) matches with errors.Is to pick the
// correct status code. Sentinels live here, separated from the
// types and store implementation, so a future task can add new
// driver-specific sentinels (ErrFlowTimeout, ErrReauthRequired,
// ErrNotFound) alongside these without disturbing the existing
// declarations.
package auth

import "errors"

// ErrUnknownProvider is returned from Store.Put when the supplied
// Profile.Provider does not correspond to a known Catalog_Entry.id.
// The HTTP layer maps this to 400 Bad Request with the message
// "unknown provider" per Requirement 4.8.
var ErrUnknownProvider = errors.New("unknown provider")

// ErrLockTimeout is returned from any Store mutation that fails to
// acquire the exclusive flock on auth-profiles.json within the 5s
// deadline. The HTTP layer maps this to 503 Service Unavailable so
// the caller can retry — a 5s wait already represents heavy
// contention from another xalgorix process or a stuck lock holder.
//
// Validates: Requirement 4.3.
var ErrLockTimeout = errors.New("auth-profiles flock timeout")

// ErrProfileNotFound is returned from Store.Get / Store.Delete when
// the requested key is absent. Get also signals this through its
// (Profile, false, nil) tuple for callers that prefer the boolean
// form; Delete returns the sentinel because it has no boolean to
// return.
var ErrProfileNotFound = errors.New("profile not found")

// ErrProfileIDInvalid is returned from Store.Put when the supplied
// Profile.ProfileID does not satisfy the canonical id regex shared
// with Catalog_Entry.id (Requirement 4.2). Mapped to HTTP 400.
var ErrProfileIDInvalid = errors.New("profileId must match ^[a-z0-9][a-z0-9_-]{0,63}$")

// ErrProviderRequired is returned from Store.Put when the supplied
// Profile.Provider is empty. Distinct from ErrUnknownProvider —
// "empty" is a request-shape error (HTTP 400), "unknown" is a
// catalog-lookup miss (HTTP 400 with a different message).
var ErrProviderRequired = errors.New("provider is required")

// ErrProfileTypeInvalid is returned from Store.Put when
// Profile.Type is neither APIKey nor OAuth.
var ErrProfileTypeInvalid = errors.New("profile type must be api_key or oauth")

// ErrReauthRequired is returned from Driver.Refresh when the
// upstream token endpoint refused the stored refresh_token with
// invalid_grant. The driver's refresh helper sets
// Profile.RequiresReauth=true and persists the profile before
// returning this sentinel; the HTTP layer maps it to 401 with the
// body "oauth refresh required" so the dashboard can surface a
// re-auth prompt to the operator.
//
// Validates: Requirement 10.4.
var ErrReauthRequired = errors.New("oauth refresh required")

// ErrNotFound is returned by the claude_cli_reuse driver when the
// documented Claude CLI credential file is absent or unreadable.
// The HTTP layer maps it to 404 with the body
// "claude cli credentials not found" per Requirement 9.2. The
// sentinel lives in the shared driver-error file rather than next
// to the Claude driver so other drivers (or HTTP-layer matchers)
// can errors.Is on it without importing driver-specific files.
//
// Validates: Requirement 9.2.
var ErrNotFound = errors.New("claude cli credentials not found")

// ErrCodexCredentialsNotFound is returned by the codex_cli_reuse driver when
// ~/.codex/auth.json is missing, unreadable, or does not contain a usable
// ChatGPT access token. It is distinct so the HTTP layer never reports a
// Claude-specific error for a Codex sign-in.
var ErrCodexCredentialsNotFound = errors.New("codex cli credentials not found")

// ErrInvalidGrant is the sentinel each driver's exchange callback
// returns from refreshWithSink when the upstream token endpoint
// responded with the OAuth 2.0 invalid_grant error. The shared
// helper translates this into:
//
//  1. Profile.RequiresReauth = true
//  2. Persist the marked profile via Store.Put
//  3. Return ErrReauthRequired to the caller
//
// per Requirement 10.4. Drivers do not return ErrInvalidGrant
// directly to their callers — refreshWithSink owns the translation
// so the response surface stays a single sentinel.
//
// Validates: Requirement 10.4.
var ErrInvalidGrant = errors.New("invalid_grant")

// ErrFlowTimeout is returned by an OAuth driver's Start / poller when
// the upstream flow exceeds its deadline:
//
//   - PKCE: the loopback listener did not receive a callback within
//     the 300s authorization window (Requirement 6.5).
//   - Device-code: the upstream-supplied expires_in elapsed before a
//     successful token response (Requirement 7.5).
//
// The HTTP layer (internal/web Wave E task 5.2) maps it to HTTP 408
// with the body "oauth flow timed out". Defined here, alongside the
// other driver-shared sentinels, so any handler can errors.Is on it
// without importing a per-driver file.
//
// Validates: Requirements 6.5, 7.5.
var ErrFlowTimeout = errors.New("oauth flow timed out")
