# Xalgorix Testing Checklist

This checklist tracks the automated and manual gates for the CLI, web UI, LLM providers, scan orchestration, and agent tools.

## Automated baseline

- [ ] `go test ./...`
- [ ] `go test ./... -cover`
- [ ] `go test ./... -race`
- [ ] `go vet ./...`
- [ ] `node --check internal/web/static/assets/app-*.js`
- [ ] `go build ./cmd/xalgorix`
- [ ] `make test-ci`

## Config and LLM providers

- [ ] Env file loading covers LLM, API base, API key, retry, dashboard auth, rate limit, proxy, telemetry, browser, web search, and AgentMail settings.
- [ ] Secret values are masked in logs and settings responses.
- [ ] Gemini API bases use `generateContent` with `x-goog-api-key`, including unprefixed custom model names.
- [ ] Anthropic API bases use `/v1/messages`, `x-api-key`, and `anthropic-version`, including unprefixed custom model names.
- [ ] OpenAI-compatible providers use `/v1/chat/completions` and bearer auth for OpenAI, DeepSeek, Groq, MiniMax, Ollama-compatible, and custom providers.
- [ ] Non-retryable errors return immediately: `400`, `401`, `403`, `404`, invalid auth, permission denied, and missing model.
- [ ] True rate limits are classified only from `429`, explicit rate-limit text, or `RESOURCE_EXHAUSTED`.
- [ ] Live provider smoke tests are opt-in and skipped unless provider keys are present.

## Web API, security, and persistence

- [ ] Auth status, login, session cookie flags, logout, and expired sessions.
- [ ] CSRF rejection for cross-site unsafe API requests; same-origin and non-browser API clients still work.
- [ ] Rate limiting enforces API limits and bypasses WebSocket/static routes.
- [ ] `/api/scan` rejects invalid method, invalid JSON, and empty target lists without starting a scan.
- [ ] Upload endpoints parse target lists and instruction files.
- [ ] Queue state saves, loads, reports status, clears, and handles corrupt/missing state.
- [ ] Scan listing, latest scan lookup, scan deletion, and instance rebuild from persisted `scan.json`.
- [ ] Instance detail, stop, restart, and event replay APIs.
- [ ] WebSocket origin checks, subscribe/unsubscribe, replay, and unauthorized access.

## Agent and tools

- [ ] Agent parser handles valid XML, malformed XML, multiple calls, hidden thought stripping, stuck detection, and prune alignment.
- [ ] Terminal blocks destructive commands, encoded destructive commands, known noisy scanners, and common obfuscation.
- [ ] Terminal classifies heavy tools, applies timeout tiers, parses missing commands, and maps known install packages.
- [ ] File editor creates, views, replaces, inserts, lists, and returns precise validation errors.
- [ ] Browser actions cover launch, goto, snapshot, input, tabs, iframes, cookies, screenshots, sessions, and cleanup.
- [ ] Proxy tool covers request methods, headers, bodies, timeout, Caido unavailable, and request listing.
- [ ] Reporting rejects weak evidence, deduplicates findings, preserves strong evidence, and generates reports.
- [ ] Python tool covers validation, stdout, stderr, timeout, exit code, and missing interpreter.
- [ ] AgentMail, web search, CVE/exploit search, sub-agents, and skills cover configured, unconfigured, timeout, and failure paths.

## Frontend and end-to-end

- [ ] Dashboard loads in authenticated and unauthenticated modes.
- [ ] Model fields allow custom IDs while showing current suggestions.
- [ ] Gemini suggestions include current text models such as `gemini-3.1-pro-preview` and do not force deprecated models.
- [ ] DeepSeek suggestions include `deepseek-v4-pro` and `deepseek-v4-flash`.
- [ ] Start, stop, queue, resume, chat, report download, and instance detail flows work from the UI.
- [ ] Empty states, long target names, long logs, upload errors, WebSocket reconnect, and mobile layout render cleanly.
- [ ] Full e2e scans run only against local or explicitly authorized targets.
