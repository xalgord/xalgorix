// Package auth — codex_cli_reuse OAuth driver.
//
// driver_codex.go implements the Driver contract for
// Catalog_Entry.flow == "codex_cli_reuse". Like claude_cli_reuse it
// performs NO browser/loopback handshake: it imports the credential the
// operator already obtained by running the official OpenAI Codex CLI
// (`codex login`) on the same host. This is the reliable path for both
// local and headless/remote (DigitalOcean) deployments — the operator
// signs in once with the well-tested CLI, and xalgorix reuses the result.
//
// The Codex CLI writes ~/.codex/auth.json with shape:
//
//	{
//	  "auth_mode": "chatgpt",
//	  "OPENAI_API_KEY": null,
//	  "tokens": {
//	    "id_token":      "<jwt>",
//	    "access_token":  "<jwt>",
//	    "refresh_token": "<opaque>",
//	    "account_id":    "<chatgpt account id>"
//	  },
//	  "last_refresh": "2026-05-28T18:23:50Z"
//	}
//
// Complete reads that file O_RDONLY (never mutates it), extracts the
// tokens + account_id, derives expiry from the access-token JWT, and
// persists an OAuth_Profile with AccountID set so the resolver can send
// the required chatgpt-account-id header.
//
// Validates: Requirements 9.1, 9.2, 9.3 (mirrors claude_cli_reuse).
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// codexCredentialPathFn resolves the on-disk path to the Codex CLI
// credential file. Production reads ~/.codex/auth.json; tests substitute
// a closure pointing at a fixture. Package-level (not a Driver field) so
// fixture tests can swap it without reaching through the registry.
var codexCredentialPathFn = codexCredentialPath

// codexCredentialPath returns the documented Codex CLI credential path.
// XALGORIX_CODEX_AUTH_FILE overrides it (useful when the dashboard runs
// as a different user than the one that ran `codex login`). Falls back to
// $HOME/.codex/auth.json. CODEX_HOME is also honored to match the CLI.
func codexCredentialPath() string {
	if v := strings.TrimSpace(os.Getenv("XALGORIX_CODEX_AUTH_FILE")); v != "" {
		return v
	}
	if codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME")); codexHome != "" {
		return filepath.Join(codexHome, "auth.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".codex", "auth.json")
}

// codexReuseDriver implements Driver for "codex_cli_reuse".
type codexReuseDriver struct {
	store *Store
	http  *http.Client
}

func newCodexReuseDriver(store *Store, httpClient *http.Client) *codexReuseDriver {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &codexReuseDriver{store: store, http: httpClient}
}

// Name returns the matching Catalog_Entry.flow value.
func (d *codexReuseDriver) Name() string { return "codex_cli_reuse" }

// Start returns a paste-mode StartResult with empty submode so the
// dashboard renders a confirm-and-import pane (no input field) — the
// credential file is already on disk and Complete reads it directly.
func (d *codexReuseDriver) Start(ctx context.Context, e providers.Entry, opts StartOptions) (StartResult, error) {
	if err := ctx.Err(); err != nil {
		return StartResult{}, err
	}
	id, err := randomFlowID()
	if err != nil {
		return StartResult{}, fmt.Errorf("auth: codex_cli_reuse start: %w", err)
	}
	return StartResult{FlowID: id, Mode: "paste", Submode: ""}, nil
}

// codexAuthFile is the tolerant decode shape for ~/.codex/auth.json.
type codexAuthFile struct {
	AuthMode string `json:"auth_mode"`
	Tokens   struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		AccountID    string `json:"account_id"`
	} `json:"tokens"`
	LastRefresh string `json:"last_refresh"`
}

// Complete imports ~/.codex/auth.json into Profile_Store. Read-only on
// the source file (O_RDONLY|O_NOFOLLOW); any open/read/parse failure that
// means "no usable credential" surfaces as ErrCodexCredentialsNotFound →
// HTTP 404.
func (d *codexReuseDriver) Complete(ctx context.Context, e providers.Entry, in CompleteInput) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}

	path := codexCredentialPathFn()
	if path == "" {
		return Profile{}, ErrCodexCredentialsNotFound
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Profile{}, ErrCodexCredentialsNotFound
	}
	defer func() { _ = f.Close() }()

	body, err := io.ReadAll(f)
	if err != nil {
		return Profile{}, ErrCodexCredentialsNotFound
	}

	var raw codexAuthFile
	if jerr := json.Unmarshal(body, &raw); jerr != nil {
		return Profile{}, fmt.Errorf("auth: codex credential parse: %w", jerr)
	}

	access := strings.TrimSpace(raw.Tokens.AccessToken)
	if access == "" {
		// No access token (e.g. an api-key-mode CLI login) — nothing to
		// import as an OAuth profile. Treat as "re-run codex login" → 404.
		return Profile{}, ErrCodexCredentialsNotFound
	}
	refresh := strings.TrimSpace(raw.Tokens.RefreshToken)

	// Account id: prefer the explicit field; fall back to the JWT claim.
	accountID := strings.TrimSpace(raw.Tokens.AccountID)
	if accountID == "" {
		accountID = extractChatGPTAccountID(access)
	}

	// Expiry comes from the access-token JWT `exp` claim; the CLI file
	// doesn't store an absolute expiry separately.
	expiresAt := jwtExpiry(access)

	scopes := append([]string(nil), e.Scopes...)

	prof := Profile{
		Provider:     e.ID,
		ProfileID:    "default",
		Type:         OAuth,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    expiresAt,
		Scopes:       scopes,
		TokenType:    "Bearer",
		AccountID:    accountID,
	}

	if err := d.store.Put(ctx, prof); err != nil {
		return Profile{}, err
	}
	stored, ok, err := d.store.Get(ctx, prof.Key())
	if err != nil {
		return Profile{}, err
	}
	if !ok {
		return Profile{}, fmt.Errorf("auth: codex credential persisted but missing on read-back")
	}
	return stored, nil
}

// Refresh rotates the access token via OpenAI's token endpoint using the
// refresh_token grant (the same one the Codex CLI uses), then re-extracts
// the account id from the new token. Falls back to ErrReauthRequired when
// no token endpoint or refresh token is available so the dashboard can
// prompt the operator to re-run `codex login`.
func (d *codexReuseDriver) Refresh(ctx context.Context, p Profile, e providers.Entry) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	if e.TokenEndpoint == "" || p.RefreshToken == "" {
		p.RequiresReauth = true
		_ = d.store.Put(ctx, p)
		return p, ErrReauthRequired
	}
	return refreshWithSink(ctx, d.store, p.Key(), func(current Profile) (Profile, error) {
		return d.exchangeRefresh(ctx, current, e)
	})
}

func (d *codexReuseDriver) exchangeRefresh(ctx context.Context, current Profile, e providers.Entry) (Profile, error) {
	if current.RefreshToken == "" {
		return Profile{}, ErrInvalidGrant
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", current.RefreshToken)
	if e.ClientID != "" {
		form.Set("client_id", e.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Profile{}, fmt.Errorf("auth: codex refresh: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := d.http.Do(req)
	if err != nil {
		return Profile{}, fmt.Errorf("auth: codex refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Profile{}, fmt.Errorf("auth: codex refresh: read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error == "invalid_grant" {
			return Profile{}, ErrInvalidGrant
		}
		return Profile{}, fmt.Errorf("auth: codex refresh: upstream %d: %s", resp.StatusCode, string(respBody))
	}

	var ok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(respBody, &ok); err != nil {
		return Profile{}, fmt.Errorf("auth: codex refresh: decode body: %w", err)
	}
	if ok.AccessToken == "" {
		return Profile{}, fmt.Errorf("auth: codex refresh: empty access_token in response")
	}

	next := current
	next.AccessToken = ok.AccessToken
	if ok.RefreshToken != "" {
		next.RefreshToken = ok.RefreshToken
	}
	if ok.ExpiresIn > 0 {
		next.ExpiresAt = time.Now().Add(time.Duration(ok.ExpiresIn) * time.Second).UTC()
	} else if exp := jwtExpiry(ok.AccessToken); !exp.IsZero() {
		next.ExpiresAt = exp
	}
	if ok.TokenType != "" {
		next.TokenType = ok.TokenType
	}
	if ok.Scope != "" {
		next.Scopes = strings.Fields(ok.Scope)
	}
	// Re-extract the account id from the rotated token; keep the old one
	// if the new token omits the claim.
	if id := extractChatGPTAccountID(ok.AccessToken); id != "" {
		next.AccountID = id
	}
	next.RequiresReauth = false
	return next, nil
}

// jwtExpiry returns the absolute expiry from a JWT's `exp` claim, or the
// zero Time when absent/unparseable.
func jwtExpiry(token string) time.Time {
	claims := decodeJWTClaims(token)
	if claims == nil {
		return time.Time{}
	}
	switch v := claims["exp"].(type) {
	case float64:
		if v > 0 {
			return time.Unix(int64(v), 0).UTC()
		}
	case json.Number:
		if n, err := v.Int64(); err == nil && n > 0 {
			return time.Unix(n, 0).UTC()
		}
	}
	return time.Time{}
}
