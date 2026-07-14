// Package providers declares the compiled-in catalog of LLM
// providers known to Xalgorix. v4.4.22 replaced the runtime-editable
// JSON-backed catalog with this read-only built-in list — there is
// no operator-editable catalog file, no openclaw importer, no
// migration sentinel. Operators pick a provider slug in the LLM
// Settings tab; "custom" handles arbitrary user-supplied endpoints.
//
// Entry shape is intentionally close to the v4.4.21 on-disk format
// so the LLM resolver, OAuth driver registry, and webui types can
// keep round-tripping the same struct without a wire-level change.
package providers

// Entry describes one compiled-in provider. The runtime catalog is
// the slice returned by Builtin(); there is no on-disk source of
// truth and no mutation surface.
//
// Field semantics:
//
//   - ID is the alphanumeric slug the rest of the system uses to
//     reference a provider (e.g. "openai", "anthropic"). Slugs are
//     stable across releases.
//
//   - DisplayName is the human label for the LLM tab dropdown.
//
//   - BaseURL is the canonical OpenAI/Anthropic/Gemini-compatible
//     endpoint root. Empty for entries the operator must fill via
//     the "custom" provider override.
//
//   - HeaderStyle picks the request-shape branch in the LLM client
//     ("openai" | "anthropic" | "gemini").
//
//   - AuthMethods enumerates the auth shapes the LLM tab should
//     surface. "api_key" is shown for any cloud provider; "oauth"
//     is shown when Flow is non-empty; "none" hides credential
//     entry entirely (used by local-runtime providers like Ollama).
//
//   - Models is retained for wire compatibility with older clients. Built-in
//     entries leave it empty: the dashboard discovers models from provider
//     APIs and falls back to manual entry when discovery is unavailable.
//
//   - Flow / ClientID / AuthorizationEndpoint / TokenEndpoint /
//     DeviceAuthorizationEndpoint / Scopes mirror the v4.4.21
//     OAuth shape. Empty fields surface the driver's "no endpoint
//     configured" error to the operator with no special handling
//     in the resolver.
//
//   - Notes documents per-provider caveats (beta status, required
//     env-var overrides, etc.) and is rendered as a "(beta)" hint
//     in the LLM tab.
type Entry struct {
	ID                          string   `json:"id"`
	DisplayName                 string   `json:"displayName"`
	BaseURL                     string   `json:"baseURL"`
	HeaderStyle                 string   `json:"headerStyle"`
	AuthMethods                 []string `json:"authMethods,omitempty"`
	Models                      []string `json:"models,omitempty"`
	Flow                        string   `json:"flow,omitempty"`
	ClientID                    string   `json:"clientID,omitempty"`
	AuthorizationEndpoint       string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint               string   `json:"tokenEndpoint,omitempty"`
	DeviceAuthorizationEndpoint string   `json:"deviceAuthorizationEndpoint,omitempty"`
	RevocationEndpoint          string   `json:"revocationEndpoint,omitempty"`
	Scopes                      []string `json:"scopes,omitempty"`
	Audience                    string   `json:"audience,omitempty"`
	Notes                       string   `json:"notes,omitempty"`
}
