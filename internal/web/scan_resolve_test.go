package web

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

func TestResolveScanCredentialsUsesActiveLLMProfile(t *testing.T) {
	ctx := context.Background()
	cat := providers.NewService()
	prof, err := auth.NewStore(filepath.Join(t.TempDir(), "auth-profiles.json"), cat)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if err := prof.Put(ctx, auth.Profile{
		Provider:  "google",
		ProfileID: "default",
		Type:      auth.APIKey,
		APIKey:    "google-key",
	}); err != nil {
		t.Fatalf("prof.Put: %v", err)
	}

	s := &Server{catalog: cat, profiles: prof}
	cfg := &config.Config{
		LLM:        "google/gemini-test-model",
		LLMProfile: "google:default",
	}

	ep, err := s.resolveScanCredentials(ctx, ScanRequest{}, cfg)
	if err != nil {
		t.Fatalf("resolveScanCredentials: %v", err)
	}
	if ep.APIKey != "google-key" {
		t.Fatalf("APIKey = %q, want google-key", ep.APIKey)
	}
	if ep.Model != "gemini-test-model" {
		t.Fatalf("Model = %q, want gemini-test-model", ep.Model)
	}
	wantURL := "https://generativelanguage.googleapis.com/v1beta/models/gemini-test-model:generateContent"
	if ep.URL != wantURL {
		t.Fatalf("URL = %q, want %q", ep.URL, wantURL)
	}
}

func TestResolveScanCredentialsUsesCredentialFreeProviderAndBareModel(t *testing.T) {
	s := &Server{catalog: providers.NewService()}
	cfg := &config.Config{
		LLMProvider: "ollama",
		LLM:         "deepseek-v4-pro:cloud",
		APIBase:     "http://host.docker.internal:11434/v1",
	}
	ep, err := s.resolveScanCredentials(context.Background(), ScanRequest{}, cfg)
	if err != nil {
		t.Fatalf("resolveScanCredentials: %v", err)
	}
	if ep.Model != "deepseek-v4-pro:cloud" {
		t.Fatalf("Model = %q, want deepseek-v4-pro:cloud", ep.Model)
	}
	if ep.URL != "http://host.docker.internal:11434/v1/chat/completions" {
		t.Fatalf("URL = %q", ep.URL)
	}
	if ep.APIKey != "" || ep.AccessToken != "" {
		t.Fatalf("credential-free endpoint contains credentials")
	}
}
