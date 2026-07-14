package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// writeCodexAuthFixture writes a ~/.codex/auth.json-shaped file and returns
// its path. accountID/exp are embedded so tests can assert extraction.
func writeCodexAuthFixture(t *testing.T, accountID string, exp time.Time) string {
	t.Helper()
	// Build an access token JWT carrying exp + the namespaced auth claim.
	claims := map[string]any{
		"exp": exp.Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID,
		},
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pj, _ := json.Marshal(claims)
	access := header + "." + base64.RawURLEncoding.EncodeToString(pj) + ".sig"

	file := map[string]any{
		"auth_mode":      "chatgpt",
		"OPENAI_API_KEY": nil,
		"tokens": map[string]any{
			"id_token":      "id." + access,
			"access_token":  access,
			"refresh_token": "rt_codex_123",
			"account_id":    accountID,
		},
		"last_refresh": time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(file, "", "  ")
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func newCodexReuseFixture(t *testing.T) (*codexReuseDriver, providers.Entry, *Store) {
	t.Helper()
	entry := codexEntry()
	entry.Flow = "codex_cli_reuse"
	cat := &pkceStubCatalog{id: "codex", entry: entry}
	store, err := NewStore(filepath.Join(t.TempDir(), "auth-profiles.json"), cat)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return newCodexReuseDriver(store, nil), entry, store
}

// TestCodexReuse_ImportsProfileWithAccountID is the happy path: Complete
// reads the CLI auth file and persists an OAuth profile carrying the
// tokens, expiry, and chatgpt account id.
func TestCodexReuse_ImportsProfileWithAccountID(t *testing.T) {
	d, entry, _ := newCodexReuseFixture(t)
	exp := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	path := writeCodexAuthFixture(t, "acct_reuse_77", exp)

	prev := codexCredentialPathFn
	codexCredentialPathFn = func() string { return path }
	t.Cleanup(func() { codexCredentialPathFn = prev })

	prof, err := d.Complete(context.Background(), entry, CompleteInput{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if prof.Provider != "codex" || prof.ProfileID != "default" {
		t.Errorf("profile key = %s, want codex:default", prof.Key())
	}
	if prof.Type != OAuth {
		t.Errorf("type = %v, want OAuth", prof.Type)
	}
	if prof.AccessToken == "" {
		t.Errorf("access token empty")
	}
	if prof.RefreshToken != "rt_codex_123" {
		t.Errorf("refresh token = %q", prof.RefreshToken)
	}
	if prof.AccountID != "acct_reuse_77" {
		t.Errorf("account id = %q, want acct_reuse_77", prof.AccountID)
	}
	if !prof.ExpiresAt.Equal(exp.UTC()) {
		t.Errorf("expiry = %v, want %v", prof.ExpiresAt, exp.UTC())
	}
}

// TestCodexReuse_AccountIDFromJWTFallback verifies the account id is read
// from the JWT claim when the explicit tokens.account_id field is absent.
func TestCodexReuse_AccountIDFromJWTFallback(t *testing.T) {
	d, entry, _ := newCodexReuseFixture(t)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	// Build a fixture then strip the explicit account_id field.
	path := writeCodexAuthFixture(t, "acct_jwt_only", exp)
	raw, _ := os.ReadFile(path)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["tokens"].(map[string]any)["account_id"] = ""
	b, _ := json.Marshal(m)
	_ = os.WriteFile(path, b, 0o600)

	prev := codexCredentialPathFn
	codexCredentialPathFn = func() string { return path }
	t.Cleanup(func() { codexCredentialPathFn = prev })

	prof, err := d.Complete(context.Background(), entry, CompleteInput{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if prof.AccountID != "acct_jwt_only" {
		t.Errorf("account id = %q, want acct_jwt_only (from JWT)", prof.AccountID)
	}
}

// TestCodexReuse_MissingFileIsNotFound maps a missing credential file to
// ErrCodexCredentialsNotFound (HTTP 404).
func TestCodexReuse_MissingFileIsNotFound(t *testing.T) {
	d, entry, _ := newCodexReuseFixture(t)
	prev := codexCredentialPathFn
	codexCredentialPathFn = func() string { return filepath.Join(t.TempDir(), "does-not-exist.json") }
	t.Cleanup(func() { codexCredentialPathFn = prev })

	_, err := d.Complete(context.Background(), entry, CompleteInput{})
	if !errors.Is(err, ErrCodexCredentialsNotFound) {
		t.Fatalf("err = %v, want ErrCodexCredentialsNotFound", err)
	}
}

// TestCodexReuse_NoAccessTokenIsNotFound treats an api-key-mode file (no
// access token) as not importable.
func TestCodexReuse_NoAccessTokenIsNotFound(t *testing.T) {
	d, entry, _ := newCodexReuseFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	_ = os.WriteFile(path, []byte(`{"auth_mode":"apikey","tokens":{"access_token":""}}`), 0o600)
	prev := codexCredentialPathFn
	codexCredentialPathFn = func() string { return path }
	t.Cleanup(func() { codexCredentialPathFn = prev })

	_, err := d.Complete(context.Background(), entry, CompleteInput{})
	if !errors.Is(err, ErrCodexCredentialsNotFound) {
		t.Fatalf("err = %v, want ErrCodexCredentialsNotFound", err)
	}
}
