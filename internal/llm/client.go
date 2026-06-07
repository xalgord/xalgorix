// Package llm provides the LLM API client for Xalgorix.
package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/safe"
)

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// StreamChunk is a piece of streaming response.
type StreamChunk struct {
	Content string
	Done    bool
	Err     error
}

// Client is the LLM API client.
type Client struct {
	cfg        *config.Config
	httpClient *http.Client
	apiModel   string
	provider   string // "openai", "anthropic", "google", "gemini", "deepseek", etc.
	mu         sync.Mutex
	totalIn    int
	totalOut   int
	// ctx is read concurrently by chatWithRetry / ChatStream and written by
	// SetContext. Use atomic.Value to avoid a race; loadCtx() is the only
	// reader, storeCtx() is the only writer.
	ctx atomic.Value // context.Context
	// rateLimiter enforces cfg.RateLimitRPS / cfg.RateLimitBurst against
	// outbound LLM calls. Wait(ctx) blocks until a token is available
	// (or ctx is canceled), so the limiter cannot drop requests
	// (R3.5). nil when the configured RPS is non-positive.
	rateLimiter *rate.Limiter
	// resolver, when non-nil, is consulted by Wave D to obtain the
	// outbound Endpoint instead of resolveEndpoint(). Task 1.3 only
	// stores the resolver; doChat / ChatStream still go through the
	// existing path until Wave D (task 4.2) swaps the dispatch.
	//
	// Validates: Requirement 11.2.
	resolver Resolver
	// tempOverride stores a *float64 for per-role temperature overrides.
	// When set, effectiveTemperature() returns it instead of cfg.Temperature.
	// Use SetTemperature() to change at runtime (e.g. scanner→validator→reporter).
	tempOverride atomic.Value // *float64
}

// TokenUsage holds cumulative token counts.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// GetTokens returns cumulative token usage.
func (c *Client) GetTokens() (promptTokens, completionTokens, totalTokens int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalIn, c.totalOut, c.totalIn + c.totalOut
}

// NewClient creates a new LLM client. Optional opts (such as
// WithResolver) tune the client for catalog-aware resolution; the
// no-option form preserves the existing legacy resolveEndpoint
// behavior so existing callers compile unchanged.
func NewClient(cfg *config.Config, opts ...Option) *Client {
	apiModel := cfg.ResolveModel()
	provider := ""
	if idx := strings.Index(apiModel, "/"); idx >= 0 {
		provider = strings.ToLower(apiModel[:idx])
	}
	c := &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Minute},
		apiModel:   apiModel,
		provider:   provider,
	}
	c.ctx.Store(ctxHolder{ctx: context.Background()})
	// Construct the token-bucket rate limiter from cfg.RateLimitRPS /
	// cfg.RateLimitBurst (R3.5). Wait(ctx) is the only consumer, so
	// requests block instead of being dropped, and ctx cancellation is
	// honored. A non-positive RPS leaves rateLimiter nil so chatWithRetry
	// skips the wait (matching legacy behavior).
	if cfg != nil && cfg.RateLimitRPS > 0 {
		burst := cfg.RateLimitBurst
		if burst < 1 {
			burst = 1
		}
		c.rateLimiter = rate.NewLimiter(rate.Limit(cfg.RateLimitRPS), burst)
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// ctxHolder wraps context.Context so atomic.Value sees a concrete type even
// when callers pass a nil context.Context interface.
type ctxHolder struct{ ctx context.Context }

// SetContext sets the context for HTTP requests, enabling cancellation.
// Safe for concurrent use.
func (c *Client) SetContext(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.ctx.Store(ctxHolder{ctx: ctx})
}

// loadCtx returns the current request context, falling back to Background
// if SetContext has never been called.
func (c *Client) loadCtx() context.Context {
	if v := c.ctx.Load(); v != nil {
		if h, ok := v.(ctxHolder); ok && h.ctx != nil {
			return h.ctx
		}
	}
	return context.Background()
}

// chatRequest is the OpenAI-compatible chat completion request.
type chatRequest struct {
	Model         string         `json:"model"`
	Messages      []Message      `json:"messages"`
	Stream        bool           `json:"stream"`
	StreamOptions *streamOptions `json:"stream_options,omitempty"`
	Temperature   *float64       `json:"temperature,omitempty"`
	MaxTokens     int            `json:"max_tokens,omitempty"`
}

// streamOptions opts into usage stats for OpenAI-compatible streaming
// responses (OpenAI, Groq, DeepSeek, MiniMax, etc.). Without this the
// final `usage` field is omitted from the SSE stream.
type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// chatChoice represents a response choice.
type chatChoice struct {
	Delta   struct{ Content string } `json:"delta"`
	Message struct{ Content string } `json:"message"`
}

// chatResponse is the OpenAI-compatible response.
type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Usage   *TokenUsage  `json:"usage,omitempty"`
}

// ── Google Gemini types ──────────────────────────────────────────────────────

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiRequest struct {
	Contents          []geminiContent `json:"contents,omitempty"`
	SystemInstruction *geminiContent  `json:"system_instruction,omitempty"`
}

type geminiCandidate struct {
	Content struct {
		Parts []geminiPart `json:"parts"`
	} `json:"content"`
}

type geminiResponse struct {
	Candidates []geminiCandidate `json:"candidates"`
}

// geminiStreamResponse is the same structure but used for SSE streaming responses.
type geminiStreamResponse = geminiResponse

// ── Anthropic types ──────────────────────────────────────────────────────────

type anthropicRequest struct {
	Model     string    `json:"model"`
	Messages  []Message `json:"messages"`
	System    string    `json:"system,omitempty"`
	MaxTokens int       `json:"max_tokens"`
	Stream    bool      `json:"stream"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type anthropicMessage struct {
	ID         string                  `json:"id"`
	Type       string                  `json:"type"`
	Role       string                  `json:"role"`
	Content    []anthropicContentBlock `json:"content"`
	Model      string                  `json:"model"`
	StopReason string                  `json:"stop_reason,omitempty"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type anthropicResponse struct {
	Type    string           `json:"type"`
	Message anthropicMessage `json:"message,omitempty"`
	Delta   struct {
		Text string `json:"text"`
	} `json:"delta,omitempty"`
	Index int `json:"index,omitempty"`
	// Usage at the top level (message_delta events carry final output token count here).
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage,omitempty"`
}

// resolveRequestEndpoint returns the Endpoint to use for one
// outbound chat / stream request. When c.resolver is wired
// (Wave D / task 4.1) we delegate to it so the catalog +
// profile stack drives URL, model, headerStyle, and
// credentials. Otherwise we synthesize an Endpoint from the
// existing resolveEndpoint() + cfg path so callers that haven't
// adopted the resolver yet still produce byte-identical
// outbound requests.
//
// Validates: Requirements 2.2, 2.3, 11.2.
func (c *Client) resolveRequestEndpoint(ctx context.Context) (Endpoint, error) {
	if c.resolver != nil {
		return c.resolver.Resolve(ctx)
	}
	url, model := c.resolveEndpoint()
	hs := "openai"
	switch {
	case c.usesGeminiAPI(url):
		hs = "gemini"
	case c.usesAnthropicAPI(url):
		hs = "anthropic"
	}
	return Endpoint{
		URL:         url,
		Model:       model,
		HeaderStyle: hs,
		Auth:        AuthAPIKey,
		APIKey:      c.cfg.APIKey,
	}, nil
}

// unknownHeaderStyleOnce guards a single log line per process so a
// catalog file edited out-of-band with a corrupt headerStyle
// produces exactly one breadcrumb instead of spamming the log on
// every outbound request. M10.
var unknownHeaderStyleOnce sync.Once

// applyAuthHeaders writes the outbound auth headers for the
// resolved endpoint. The matrix is HeaderStyle × AuthMethod:
//
//   - anthropic: x-api-key (api_key) | Authorization: Bearer
//     (oauth_bearer); always emit anthropic-version: 2023-06-01.
//   - gemini:    x-goog-api-key (api_key) | Authorization:
//     Bearer (oauth_bearer).
//   - openai:    Authorization: Bearer for both auth modes
//     (the access token replaces the api key).
//
// Empty credentials skip the header entirely so downstream
// transports don't see "Authorization: Bearer ".
//
// Validates: Requirements 2.2, 2.3, 11.2.
func applyAuthHeaders(req *http.Request, ep Endpoint) {
	switch ep.HeaderStyle {
	case "anthropic":
		req.Header.Set("anthropic-version", "2023-06-01")
		switch ep.Auth {
		case AuthAPIKey:
			if ep.APIKey != "" {
				req.Header.Set("x-api-key", ep.APIKey)
			}
		case AuthOAuthBearer:
			if ep.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+ep.AccessToken)
			}
		}
	case "gemini":
		switch ep.Auth {
		case AuthAPIKey:
			if ep.APIKey != "" {
				req.Header.Set("x-goog-api-key", ep.APIKey)
			}
		case AuthOAuthBearer:
			if ep.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+ep.AccessToken)
			}
		}
	case "openai", "openai_responses", "":
		// "openai" / "openai_responses" / unspecified — apply the
		// OpenAI-compatible Bearer header for both auth modes.
		switch ep.Auth {
		case AuthAPIKey:
			if ep.APIKey != "" {
				req.Header.Set("Authorization", "Bearer "+ep.APIKey)
			}
		case AuthOAuthBearer:
			if ep.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+ep.AccessToken)
			}
		}
	default:
		// Unknown HeaderStyle — validateEntry rejects this on
		// catalog write, so reaching this branch means the
		// providers.json file was edited out-of-band. Log
		// exactly once via sync.Once so a triage reader sees
		// the breadcrumb without the log being spammed on
		// every outbound request, then fall through to the
		// OpenAI-compatible Bearer header so the request still
		// has a chance of succeeding (a catalog entry pointing
		// at an OpenAI-compatible base URL with a corrupt
		// headerStyle is the most common shape of this bug).
		// M10.
		unknownHeaderStyleOnce.Do(func() {
			log.Printf("[llm] applyAuthHeaders: unknown HeaderStyle %q (catalog corruption?); falling back to openai-style Bearer auth", ep.HeaderStyle)
		})
		switch ep.Auth {
		case AuthAPIKey:
			if ep.APIKey != "" {
				req.Header.Set("Authorization", "Bearer "+ep.APIKey)
			}
		case AuthOAuthBearer:
			if ep.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+ep.AccessToken)
			}
		}
	}
	if ep.VendorOverride != nil {
		ep.VendorOverride(req)
	}
}

// resolveEndpoint returns the full chat completions URL and clean model name.
// Handles provider prefixes like "minimax/", "openai/", "anthropic/", etc.
// Auto-appends /v1/chat/completions if the base doesn't already contain /v1.
// Also supports custom providers - just set XALGORIX_API_BASE to your endpoint.
//
// This is the legacy single-call resolver kept on the Client so
// the no-resolver fallback path in resolveRequestEndpoint can
// reuse it (Requirement 2.3 — preserved endpoint shape).
func (c *Client) resolveEndpoint() (string, string) {
	apiBase := c.cfg.APIBase
	model := c.apiModel

	// Extract provider prefix if present (e.g., "openai/gpt-5.4" -> provider="openai", model="gpt-5.4")
	provider := ""
	if idx := strings.Index(model, "/"); idx >= 0 {
		provider = strings.ToLower(model[:idx])
		model = model[idx+1:]
	}

	// Provider prefix in model name is the source of truth for API base.
	// However, if a non-empty API base was explicitly set (e.g., from web UI), use it.
	providerBases := map[string]string{
		"openai":    "https://api.openai.com/v1",
		"anthropic": "https://api.anthropic.com",
		"minimax":   "https://api.minimax.io/v1",
		"deepseek":  "https://api.deepseek.com/v1",
		"groq":      "https://api.groq.com/openai/v1",
		"ollama":    "http://localhost:11434/v1",
		// Google's chat endpoint is /v1beta/models/MODEL:generateContent — we
		// store the bare host here and append the version segment below.
		"google": "https://generativelanguage.googleapis.com",
		"gemini": "https://generativelanguage.googleapis.com",
	}

	if apiBase == "" {
		// No explicit API base set — use provider default
		if knownBase, ok := providerBases[provider]; ok {
			apiBase = knownBase
		} else {
			// Unknown/no provider — default to OpenAI
			apiBase = "https://api.openai.com/v1"
		}
	}

	apiBase = strings.TrimRight(apiBase, "/")

	// Build the URL based on provider
	url := apiBase
	if provider == "anthropic" || strings.Contains(strings.ToLower(apiBase), "anthropic") {
		// Anthropic uses /v1/messages
		if !strings.HasSuffix(strings.ToLower(url), "/messages") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/messages"
		}
	} else if isGeminiProvider(provider) || isGeminiAPIBase(apiBase) {
		// Google Gemini uses /v1beta/models/MODEL:generateContent.
		// Strip any trailing /v1 so we don't end up with /v1beta concatenated
		// onto a version segment the user supplied.
		url = strings.TrimSuffix(url, "/v1")
		url += "/v1beta/models/" + model + ":generateContent"
	} else {
		if !strings.HasSuffix(strings.ToLower(url), "/chat/completions") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/chat/completions"
		}
	}

	return url, model
}

func isGeminiProvider(provider string) bool {
	provider = strings.ToLower(provider)
	return provider == "google" || provider == "gemini"
}

func isGeminiAPIBase(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "generativelanguage.googleapis.com") ||
		strings.Contains(value, "generativelanguage")
}

func (c *Client) usesGeminiAPI(endpoint string) bool {
	return isGeminiProvider(c.provider) ||
		isGeminiAPIBase(c.cfg.APIBase) ||
		isGeminiAPIBase(endpoint)
}

func isAnthropicAPIBase(value string) bool {
	return strings.Contains(strings.ToLower(value), "anthropic")
}

func (c *Client) usesAnthropicAPI(endpoint string) bool {
	return c.provider == "anthropic" ||
		isAnthropicAPIBase(c.cfg.APIBase) ||
		isAnthropicAPIBase(endpoint)
}

func apiErrorHasStatus(errStr string, status int) bool {
	errStr = strings.ToLower(errStr)
	statusText := fmt.Sprintf("%d", status)
	return strings.Contains(errStr, "api returned "+statusText) ||
		strings.Contains(errStr, "http "+statusText)
}

func isContextWindowError(errStr string) bool {
	errStr = strings.ToLower(errStr)
	return strings.Contains(errStr, "400") &&
		(strings.Contains(errStr, "context window") ||
			strings.Contains(errStr, "maximum context length") ||
			strings.Contains(errStr, "too many tokens") ||
			strings.Contains(errStr, "token limit") ||
			strings.Contains(errStr, "invalid params"))
}

func isRateLimitError(errStr string) bool {
	errStr = strings.ToLower(errStr)
	return apiErrorHasStatus(errStr, http.StatusTooManyRequests) ||
		strings.Contains(errStr, "too many requests") ||
		strings.Contains(errStr, "rate limited") ||
		strings.Contains(errStr, "rate limit") ||
		strings.Contains(errStr, "rate_limit") ||
		strings.Contains(errStr, "ratelimit") ||
		strings.Contains(errStr, "resource_exhausted")
}

func isNonRetryableLLMError(errStr string) bool {
	errStr = strings.ToLower(errStr)
	if apiErrorHasStatus(errStr, http.StatusBadRequest) ||
		apiErrorHasStatus(errStr, http.StatusUnauthorized) ||
		apiErrorHasStatus(errStr, http.StatusForbidden) ||
		apiErrorHasStatus(errStr, http.StatusNotFound) {
		return true
	}
	return strings.Contains(errStr, "unauthenticated") ||
		strings.Contains(errStr, "access_token_type_unsupported") ||
		strings.Contains(errStr, "invalid authentication credentials") ||
		strings.Contains(errStr, "permission_denied") ||
		strings.Contains(errStr, "model not found") ||
		strings.Contains(errStr, "not found")
}

// Chat sends a non-streaming chat request and returns the full response.
func (c *Client) Chat(messages []Message) (string, error) {
	return c.chatWithRetry(messages)
}

// SetTemperature overrides the LLM temperature for subsequent calls.
// Pass nil to revert to the config default.
// This is goroutine-safe and takes effect on the next Chat/ChatStream call.
func (c *Client) SetTemperature(temp *float64) {
	if temp == nil {
		c.tempOverride.Store((*float64)(nil))
	} else {
		// Copy so caller can't mutate after setting
		v := *temp
		c.tempOverride.Store(&v)
	}
}

// effectiveTemperature returns the per-call override if set, otherwise
// falls back to the config default.
func (c *Client) effectiveTemperature() *float64 {
	if v, ok := c.tempOverride.Load().(*float64); ok && v != nil {
		return v
	}
	return c.cfg.Temperature
}

func (c *Client) chatWithRetry(messages []Message) (string, error) {
	maxRetries := c.cfg.LLMMaxRetries
	if maxRetries < 3 {
		maxRetries = 3
	}
	var lastErr error

	for attempt := range maxRetries {
		if attempt > 0 {
			// Smart backoff based on error type
			backoff := time.Duration(attempt*3) * time.Second
			if lastErr != nil {
				errStr := lastErr.Error()
				if isRateLimitError(errStr) {
					backoff = 30 * time.Second // rate limit: wait longer
				} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "timeout") || strings.Contains(errStr, "EOF") {
					backoff = time.Duration(attempt*10) * time.Second // network: longer backoff
				} else if strings.Contains(errStr, "500") || strings.Contains(errStr, "502") || strings.Contains(errStr, "503") {
					backoff = time.Duration(attempt*5) * time.Second // server error
				}
			}
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			log.Printf("[llm] Retry %d/%d after %s (last error: %v)", attempt+1, maxRetries, backoff, lastErr)
			time.Sleep(backoff)
		}

		// Check if context is canceled before retrying
		if ctx := c.loadCtx(); ctx.Err() != nil {
			return "", fmt.Errorf("LLM request canceled: %w", ctx.Err())
		}

		result, err := c.doChat(messages)
		if err == nil {
			return result, nil
		}
		lastErr = err

		// Non-retryable errors: context window overflow, malformed request, etc.
		// These will never succeed on retry — return immediately so the caller
		// can handle them (e.g. by pruning messages).
		errStr := err.Error()
		if isContextWindowError(errStr) {
			log.Printf("[llm] Non-retryable error (context overflow), returning immediately: %v", err)
			return "", fmt.Errorf("context window overflow: %w", err)
		}

		if isNonRetryableLLMError(errStr) {
			log.Printf("[llm] Non-retryable LLM error, returning immediately: %v", err)
			return "", fmt.Errorf("LLM request failed: %w", err)
		}

		// Track if last error was a rate limit for the post-loop wrapper
		if isRateLimitError(errStr) {
			lastErr = fmt.Errorf("rate limited: %w", err)
			continue
		}
	}

	// Preserve rate-limit marker if the final error was rate-limited
	if lastErr != nil && strings.Contains(lastErr.Error(), "rate limited:") {
		return "", fmt.Errorf("rate limited: LLM request failed after %d retries: %w", maxRetries, lastErr)
	}
	return "", fmt.Errorf("LLM request failed after %d retries: %w", maxRetries, lastErr)
}

// ChatStream sends a streaming chat request and returns a channel of chunks.
func (c *Client) ChatStream(messages []Message) <-chan StreamChunk {
	ch := make(chan StreamChunk, 64)

	// Spawn the streaming goroutine under safe.Go (R1.2 / R1.5) so a
	// panic in JSON parsing, transport, or scanner produces exactly one
	// recovery log line and increments PanicsRecovered. Without this
	// wrapper a panic here would crash the entire process.
	safe.Go("llm.stream", "", func() {
		defer close(ch)

		// Honor the LLM token-bucket rate limiter (R3.5) and the
		// in-flight cap (R3.3 / R3.4) for streaming calls too — both
		// limits are about outbound LLM volume, not request shape.
		// On ctx cancellation neither call consumes a slot (P3.4).
		streamCtx := c.loadCtx()
		if c.rateLimiter != nil {
			if err := c.rateLimiter.Wait(streamCtx); err != nil {
				ch <- StreamChunk{Err: fmt.Errorf("llm rate limit: %w", err)}
				return
			}
		}
		release, err := resources.AcquireLLMSlot(streamCtx)
		if err != nil {
			ch <- StreamChunk{Err: fmt.Errorf("llm slot: %w", err)}
			return
		}
		defer release()

		ep, err := c.resolveRequestEndpoint(streamCtx)
		if err != nil {
			ch <- StreamChunk{Err: err}
			return
		}
		// OpenAI Responses API (Codex / ChatGPT subscription) uses a
		// distinct streaming contract — delegate and stop here.
		if ep.HeaderStyle == headerStyleResponses {
			c.streamResponses(streamCtx, ep, messages, ch)
			return
		}
		endpoint, model := ep.URL, ep.Model
		isGoogle := ep.HeaderStyle == "gemini"
		isAnthropic := ep.HeaderStyle == "anthropic"

		var body []byte
		if isGoogle {
			endpoint = strings.TrimSuffix(endpoint, "generateContent") + "streamGenerateContent?alt=sse"
			var systemParts []geminiPart
			contents := make([]geminiContent, 0, len(messages))
			for _, m := range messages {
				if m.Role == "system" {
					systemParts = append(systemParts, geminiPart{Text: m.Content})
				} else {
					role := m.Role
					if role == "assistant" {
						role = "model"
					}
					contents = append(contents, geminiContent{Role: role, Parts: []geminiPart{{Text: m.Content}}})
				}
			}
			gemReq := geminiRequest{Contents: contents}
			if len(systemParts) > 0 {
				gemReq.SystemInstruction = &geminiContent{Role: "user", Parts: systemParts}
			}
			body, _ = json.Marshal(gemReq)
		} else if isAnthropic {
			var systemPrompt string
			anthropicMsgs := make([]Message, 0, len(messages))
			for _, m := range messages {
				if m.Role == "system" {
					systemPrompt = m.Content
				} else {
					anthropicMsgs = append(anthropicMsgs, m)
				}
			}
			maxTokens := 8192
			anReq := anthropicRequest{
				Model:     model,
				Messages:  anthropicMsgs,
				System:    systemPrompt,
				MaxTokens: maxTokens,
				Stream:    true,
			}
			body, _ = json.Marshal(anReq)
		} else {
			reqBody := chatRequest{
				Model:         model,
				Messages:      messages,
				Stream:        true,
				StreamOptions: &streamOptions{IncludeUsage: true},
				Temperature:   c.effectiveTemperature(),
			}
			body, _ = json.Marshal(reqBody)
		}

		req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			ch <- StreamChunk{Err: err}
			return
		}

		req.Header.Set("Content-Type", "application/json")
		applyAuthHeaders(req, ep)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			ch <- StreamChunk{Err: fmt.Errorf("request failed: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				ch <- StreamChunk{Err: fmt.Errorf("API returned %d (failed to read body: %w)", resp.StatusCode, readErr)}
				return
			}
			ch <- StreamChunk{Err: fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))}
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		if isAnthropic {
			// Anthropic SSE: each line is "event: TYPE" followed by "data: JSON"
			var currentEvent string
			var anResp anthropicResponse
			for scanner.Scan() {
				line := scanner.Text()
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if ev, ok := strings.CutPrefix(line, "event: "); ok {
					currentEvent = ev
					continue
				}
				data, ok := strings.CutPrefix(line, "data: ")
				if !ok {
					continue
				}
				data = strings.TrimSpace(data)

				if err := json.Unmarshal([]byte(data), &anResp); err != nil {
					continue
				}

				switch currentEvent {
				case "message_start":
					c.mu.Lock()
					c.totalIn += anResp.Message.Usage.InputTokens
					c.totalOut += anResp.Message.Usage.OutputTokens
					c.mu.Unlock()
				case "content_block_delta":
					if anResp.Delta.Text != "" {
						ch <- StreamChunk{Content: anResp.Delta.Text}
					}
				case "message_delta":
					// Final usage update — output_tokens arrives at the top level here.
					if anResp.Usage.OutputTokens > 0 {
						c.mu.Lock()
						c.totalOut += anResp.Usage.OutputTokens
						c.mu.Unlock()
					}
				case "message_stop":
					ch <- StreamChunk{Done: true}
					return
				}
			}
			ch <- StreamChunk{Done: true}
			return
		}

		// OpenAI/Google streaming: "data: JSON" lines
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				ch <- StreamChunk{Done: true}
				return
			}

			if isGoogle {
				var gemResp geminiStreamResponse
				if err := json.Unmarshal([]byte(data), &gemResp); err != nil {
					continue
				}
				if len(gemResp.Candidates) > 0 && len(gemResp.Candidates[0].Content.Parts) > 0 {
					content := gemResp.Candidates[0].Content.Parts[0].Text
					if content != "" {
						ch <- StreamChunk{Content: content}
					}
				}
			} else {
				var sseResp chatResponse
				if err := json.Unmarshal([]byte(data), &sseResp); err != nil {
					continue
				}
				if sseResp.Usage != nil {
					c.mu.Lock()
					c.totalIn += sseResp.Usage.PromptTokens
					c.totalOut += sseResp.Usage.CompletionTokens
					c.mu.Unlock()
				}
				if len(sseResp.Choices) > 0 {
					content := sseResp.Choices[0].Delta.Content
					if content != "" {
						ch <- StreamChunk{Content: content}
					}
				}
			}
		}

		ch <- StreamChunk{Done: true}
	})

	return ch
}

// doChat performs a single non-streaming API call.
func (c *Client) doChat(messages []Message) (out string, err error) {
	// Panic boundary (R1.5): any panic in the LLM client (JSON
	// marshaling, header construction, HTTP transport panic) is
	// converted into a typed error so the caller can decide whether to
	// retry. The recovered panic is logged exactly once and the
	// PanicsRecovered counter is incremented by safe.Recover.
	defer safe.Recover("llm.doChat", "", &err)

	// Honor the LLM token-bucket rate limiter (R3.5): block instead of
	// dropping, and propagate ctx cancellation (R3.4 / P3.4) without
	// consuming a token slot.
	reqCtx := c.loadCtx()
	if c.rateLimiter != nil {
		if err = c.rateLimiter.Wait(reqCtx); err != nil {
			return "", fmt.Errorf("llm rate limit: %w", err)
		}
	}

	// Reserve one in-flight LLM slot (R3.3 / R3.4). The slot is held
	// for the entire request, including body read, so a stalled
	// upstream cannot let more requests pile up than the cap allows.
	release, err := resources.AcquireLLMSlot(reqCtx)
	if err != nil {
		return "", fmt.Errorf("llm slot: %w", err)
	}
	defer release()

	ep, err := c.resolveRequestEndpoint(reqCtx)
	if err != nil {
		return "", err
	}
	endpoint, model := ep.URL, ep.Model
	log.Printf("[llm] Request → URL=%s model=%s apiModel=%s cfgLLM=%s cfgAPIBase=%s", endpoint, model, c.apiModel, c.cfg.LLM, c.cfg.APIBase)

	// OpenAI Responses API (Codex / ChatGPT subscription backend) has its
	// own request/response contract — delegate to the dedicated path.
	if ep.HeaderStyle == headerStyleResponses {
		return c.doResponses(reqCtx, ep, messages)
	}

	isGoogle := ep.HeaderStyle == "gemini"
	isAnthropic := ep.HeaderStyle == "anthropic"

	var body []byte
	if isGoogle {
		// Google Gemini: extract system messages, convert roles
		var systemParts []geminiPart
		contents := make([]geminiContent, 0, len(messages))
		for _, m := range messages {
			if m.Role == "system" {
				systemParts = append(systemParts, geminiPart{Text: m.Content})
			} else {
				role := m.Role
				if role == "assistant" {
					role = "model"
				}
				contents = append(contents, geminiContent{Role: role, Parts: []geminiPart{{Text: m.Content}}})
			}
		}
		gemReq := geminiRequest{Contents: contents}
		if len(systemParts) > 0 {
			gemReq.SystemInstruction = &geminiContent{Role: "user", Parts: systemParts}
		}
		body, err = json.Marshal(gemReq)
		if err != nil {
			return "", fmt.Errorf("failed to marshal Gemini request: %w", err)
		}
	} else if isAnthropic {
		// Anthropic: system as top-level field, max_tokens required
		var systemPrompt string
		anthropicMsgs := make([]Message, 0, len(messages))
		for _, m := range messages {
			if m.Role == "system" {
				systemPrompt = m.Content
			} else {
				anthropicMsgs = append(anthropicMsgs, m)
			}
		}
		// Default max_tokens; Anthropic requires this field
		maxTokens := 8192
		anReq := anthropicRequest{
			Model:     model,
			Messages:  anthropicMsgs,
			System:    systemPrompt,
			MaxTokens: maxTokens,
			Stream:    false,
		}
		body, err = json.Marshal(anReq)
		if err != nil {
			return "", fmt.Errorf("failed to marshal Anthropic request: %w", err)
		}
	} else {
		reqBody := chatRequest{Model: model, Messages: messages, Stream: false, Temperature: c.effectiveTemperature()}
		body, err = json.Marshal(reqBody)
		if err != nil {
			return "", fmt.Errorf("failed to marshal request: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	applyAuthHeaders(req, ep)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	if isGoogle {
		var gemResp geminiResponse
		if err := json.Unmarshal(respBody, &gemResp); err != nil {
			return "", fmt.Errorf("failed to parse Gemini response: %w", err)
		}
		if len(gemResp.Candidates) == 0 || len(gemResp.Candidates[0].Content.Parts) == 0 {
			return "", fmt.Errorf("no content in Gemini response")
		}
		return gemResp.Candidates[0].Content.Parts[0].Text, nil
	}

	if isAnthropic {
		var anMsg anthropicMessage
		if err := json.Unmarshal(respBody, &anMsg); err != nil {
			return "", fmt.Errorf("failed to parse Anthropic response: %w", err)
		}
		// Track token usage
		c.mu.Lock()
		c.totalIn += anMsg.Usage.InputTokens
		c.totalOut += anMsg.Usage.OutputTokens
		c.mu.Unlock()
		// Extract text from content blocks
		for _, block := range anMsg.Content {
			if block.Type == "text" && block.Text != "" {
				return block.Text, nil
			}
		}
		log.Printf("[llm] Anthropic response with no text content (stop_reason: %s, content_blocks: %d): %s", anMsg.StopReason, len(anMsg.Content), string(respBody))
		return "", fmt.Errorf("no text content in Anthropic response (stop_reason: %s, content_blocks: %d)", anMsg.StopReason, len(anMsg.Content))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	if chatResp.Usage != nil {
		c.mu.Lock()
		c.totalIn += chatResp.Usage.PromptTokens
		c.totalOut += chatResp.Usage.CompletionTokens
		c.mu.Unlock()
	}
	return chatResp.Choices[0].Message.Content, nil
}
