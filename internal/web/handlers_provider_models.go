package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

const providerModelsResponseLimit = 4 << 20
const codexModelsClientVersion = "0.144.3"

type discoveredModelsResponse struct {
	Models []string `json:"models"`
	Source string   `json:"source"`
}

// handleDiscoverProviderModels queries the selected provider's documented
// model-list endpoint from the server. Credentials never cross the browser
// boundary. Requests use either a compiled-in catalog URL or an endpoint the
// operator already persisted as the active LLM base; arbitrary request URLs
// are never accepted by this handler.
func (s *Server) handleDiscoverProviderModels(w http.ResponseWriter, r *http.Request) {
	providerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/providers/"), "/models")
	if providerID == "" || strings.Contains(providerID, "/") || providerID == "custom" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "provider does not support automatic model discovery"})
		return
	}
	entry, ok, err := s.catalog.Get(r.Context(), providerID)
	if err != nil || !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	if strings.TrimSpace(entry.BaseURL) == "" {
		writeJSONStatus(w, http.StatusUnprocessableEntity, map[string]string{"error": "provider does not expose a compatible model-list endpoint"})
		return
	}

	entry, credential, accountID, err := s.modelDiscoveryConfig(r, entry)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	models, err := discoverProviderModels(r, entry, credential, accountID)
	if err != nil {
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSONStatus(w, http.StatusOK, discoveredModelsResponse{Models: models, Source: "remote"})
}

func (s *Server) modelDiscoveryConfig(r *http.Request, entry providers.Entry) (providers.Entry, string, string, error) {
	for _, method := range entry.AuthMethods {
		if method == "none" {
			if s.cfg != nil && strings.HasPrefix(s.cfg.LLM, entry.ID+"/") && strings.TrimSpace(s.cfg.APIBase) != "" {
				entry.BaseURL = strings.TrimSpace(s.cfg.APIBase)
			}
			return entry, "", "", nil
		}
	}
	key := strings.TrimSpace(r.URL.Query().Get("profile"))
	if key != "" {
		if s.profiles == nil {
			return entry, "", "", fmt.Errorf("credential profiles are unavailable")
		}
		profile, ok, err := s.profiles.Get(r.Context(), key)
		if err != nil {
			return entry, "", "", fmt.Errorf("load credential profile: %w", err)
		}
		if !ok || profile.Provider != entry.ID {
			return entry, "", "", fmt.Errorf("credential profile does not belong to provider %q", entry.ID)
		}
		if strings.TrimSpace(profile.APIBaseOverride) != "" {
			entry.BaseURL = strings.TrimSpace(profile.APIBaseOverride)
		}
		if profile.Type == auth.OAuth {
			return entry, strings.TrimSpace(profile.AccessToken), strings.TrimSpace(profile.AccountID), nil
		}
		return entry, strings.TrimSpace(profile.APIKey), "", nil
	}
	if s.cfg != nil && strings.HasPrefix(s.cfg.LLM, entry.ID+"/") {
		if strings.TrimSpace(s.cfg.APIBase) != "" {
			entry.BaseURL = strings.TrimSpace(s.cfg.APIBase)
		}
		return entry, strings.TrimSpace(s.cfg.APIKey), "", nil
	}
	return entry, "", "", fmt.Errorf("save or select credentials before scanning models")
}

func discoverProviderModels(r *http.Request, entry providers.Entry, credential, accountID string) ([]string, error) {
	endpoints, err := providerModelsURLs(entry)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, endpoint := range endpoints {
		models, err := requestProviderModels(r, entry, credential, accountID, endpoint)
		if err == nil {
			return models, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func requestProviderModels(r *http.Request, entry providers.Entry, credential, accountID, endpoint string) ([]string, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build model discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	switch entry.HeaderStyle {
	case "anthropic":
		if credential != "" {
			req.Header.Set("x-api-key", credential)
		}
		req.Header.Set("anthropic-version", "2023-06-01")
	case "gemini":
		if credential != "" {
			req.Header.Set("x-goog-api-key", credential)
		}
	case "openai", "openai_responses":
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		if accountID != "" {
			req.Header.Set("chatgpt-account-id", accountID)
		}
		if entry.HeaderStyle == "openai_responses" {
			req.Header.Set("version", codexModelsClientVersion)
		}
	default:
		return nil, fmt.Errorf("provider does not expose a compatible model-list endpoint")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("model discovery request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, providerModelsResponseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read model discovery response: %w", err)
	}
	if len(body) > providerModelsResponseLimit {
		return nil, fmt.Errorf("model discovery response exceeded 4 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider model discovery returned HTTP %d", resp.StatusCode)
	}
	return parseDiscoveredModels(entry.HeaderStyle, body)
}

func providerModelsURLs(entry providers.Entry) ([]string, error) {
	base := strings.TrimRight(strings.TrimSpace(entry.BaseURL), "/")
	for _, suffix := range []string{"/chat/completions", "/responses", "/messages", "/models"} {
		base = strings.TrimSuffix(base, suffix)
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("provider has no valid model discovery URL")
	}
	if entry.HeaderStyle == "anthropic" && !strings.HasSuffix(u.Path, "/v1") {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1"
	}
	if entry.HeaderStyle == "openai" && !strings.HasSuffix(u.Path, "/v1") && !strings.Contains(u.Path, "/v1/") {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1"
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/models"
	if entry.HeaderStyle == "openai_responses" {
		query := u.Query()
		query.Set("client_version", codexModelsClientVersion)
		u.RawQuery = query.Encode()
	}
	endpoints := []string{u.String()}
	if entry.ID == "ollama" {
		native := *u
		native.Path = strings.TrimSuffix(strings.TrimSuffix(native.Path, "/models"), "/v1") + "/api/tags"
		endpoints = append(endpoints, native.String())
	}
	if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" {
		hostEndpoint := *u
		hostEndpoint.Host = "host.docker.internal"
		if port := u.Port(); port != "" {
			hostEndpoint.Host += ":" + port
		}
		endpoints = append(endpoints, hostEndpoint.String())
		if entry.ID == "ollama" {
			native := hostEndpoint
			native.Path = strings.TrimSuffix(strings.TrimSuffix(native.Path, "/models"), "/v1") + "/api/tags"
			endpoints = append(endpoints, native.String())
		}
	}
	return endpoints, nil
}

func parseDiscoveredModels(headerStyle string, body []byte) ([]string, error) {
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			Name                       string   `json:"name"`
			Slug                       string   `json:"slug"`
			SupportedGenerationMethods []string `json:"supportedGenerationMethods"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode model discovery response: %w", err)
	}
	seen := make(map[string]struct{})
	models := make([]string, 0, len(payload.Data)+len(payload.Models))
	add := func(model string) {
		model = strings.TrimSpace(strings.TrimPrefix(model, "models/"))
		if model == "" {
			return
		}
		if _, ok := seen[model]; ok {
			return
		}
		seen[model] = struct{}{}
		models = append(models, model)
	}
	for _, model := range payload.Data {
		add(model.ID)
	}
	for _, model := range payload.Models {
		if headerStyle == "gemini" && len(model.SupportedGenerationMethods) > 0 {
			supported := false
			for _, method := range model.SupportedGenerationMethods {
				if method == "generateContent" {
					supported = true
					break
				}
			}
			if !supported {
				continue
			}
		}
		if model.Slug != "" {
			add(model.Slug)
		} else {
			add(model.Name)
		}
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("provider returned no generative models")
	}
	sort.Strings(models)
	return models, nil
}
