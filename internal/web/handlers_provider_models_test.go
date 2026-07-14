package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

func TestDiscoverProviderModelsOpenAICompatible(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("path = %q, want /v1/models", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("Authorization header was not applied")
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"model-b"},{"id":"model-a"}]}`))
	}))
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(context.Background())
	models, err := discoverProviderModels(req, providers.Entry{
		ID: "test", BaseURL: server.URL, HeaderStyle: "openai",
	}, "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"model-a", "model-b"}; !reflect.DeepEqual(models, want) {
		t.Fatalf("models = %v, want %v", models, want)
	}
}

func TestParseDiscoveredGeminiModelsFiltersNonGenerativeEntries(t *testing.T) {
	body := []byte(`{"models":[{"name":"models/gemini-chat","supportedGenerationMethods":["generateContent"]},{"name":"models/text-embedding","supportedGenerationMethods":["embedContent"]}]}`)
	models, err := parseDiscoveredModels("gemini", body)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"gemini-chat"}; !reflect.DeepEqual(models, want) {
		t.Fatalf("models = %v, want %v", models, want)
	}
}

func TestProviderModelsURLsIncludesOllamaNativeFallback(t *testing.T) {
	urls, err := providerModelsURLs(providers.Entry{
		ID: "ollama", BaseURL: "http://localhost:11434/v1", HeaderStyle: "openai",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"http://localhost:11434/v1/models",
		"http://localhost:11434/api/tags",
		"http://host.docker.internal:11434/v1/models",
		"http://host.docker.internal:11434/api/tags",
	}
	if !reflect.DeepEqual(urls, want) {
		t.Fatalf("URLs = %v, want %v", urls, want)
	}
}

func TestModelDiscoveryConfigIgnoresProfilesForCredentialFreeProvider(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/providers/ollama/models?profile=codex:default", nil)
	entry := providers.Entry{
		ID: "ollama", BaseURL: "http://localhost:11434/v1", HeaderStyle: "openai", AuthMethods: []string{"none"},
	}
	got, credential, accountID, err := (&Server{}).modelDiscoveryConfig(req, entry)
	if err != nil {
		t.Fatalf("modelDiscoveryConfig returned error: %v", err)
	}
	if credential != "" || accountID != "" || got.BaseURL != entry.BaseURL {
		t.Fatalf("config = (%q, %q), want (%q, empty credential)", got.BaseURL, credential, entry.BaseURL)
	}
}

func TestParseDiscoveredCodexModelsUsesSlug(t *testing.T) {
	body := []byte(`{"models":[{"slug":"gpt-5.5","display_name":"GPT-5.5"},{"slug":"gpt-5.4","display_name":"GPT-5.4"}]}`)
	models, err := parseDiscoveredModels("openai_responses", body)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gpt-5.4", "gpt-5.5"}
	if !reflect.DeepEqual(models, want) {
		t.Fatalf("models = %v, want %v", models, want)
	}
}

func TestProviderModelsURLsUsesCodexCatalogProtocol(t *testing.T) {
	urls, err := providerModelsURLs(providers.Entry{
		ID: "codex", BaseURL: "https://chatgpt.com/backend-api/codex", HeaderStyle: "openai_responses",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "https://chatgpt.com/backend-api/codex/models?client_version=" + codexModelsClientVersion
	if len(urls) != 1 || urls[0] != want {
		t.Fatalf("URLs = %v, want [%s]", urls, want)
	}
}
