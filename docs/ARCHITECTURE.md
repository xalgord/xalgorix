# Xalgorix Architecture

Xalgorix is a single Go binary that runs an autonomous, LLM-driven web/API
penetration test against an authorized target and produces an evidence-backed
report. This document describes the code as it is today; it is the source of
truth for how the packages fit together.

## High-level layers

```
Runtime            cmd/xalgorix        binary entrypoint + OS service wiring
   │  dispatches (web mode / scan mode)
   ▼
Web Platform       internal/web        local HTTP API + embedded React dashboard,
   │                                   scan orchestration, persistence, notifications
   ▼
Agent Core         internal/agent      the autonomous loop: reason → call tool →
   │                                   observe → repeat, under scope/phase guards
   ▼
Tooling            internal/tools      the tool registry + every capability the
   │                                   agent can invoke (shell, browser, http, …)
   ▼
Providers / LLM    internal/llm,       model routing, API-key store, provider
                   internal/providers  catalog, auth/credential drivers
```

Cross-cutting: `internal/scanctx` (per-scan isolation), `internal/reporting`
(findings store + PDF), `internal/storage` (atomic disk writes),
`internal/sandbox` + `internal/scopeguard` (safety), `internal/config`
(configuration).

## Runtime — `cmd/xalgorix`

- `main.go` — parses flags/config and dispatches: **web mode** starts the
  dashboard + API server (`internal/web`); **scan mode** (and CLI subcommands
  like `--start`, `--restart`) drive the engine directly. Holds the compiled-in
  `version` string. Default dashboard bind is `127.0.0.1:9137`.
- `exec_unix.go` / `exec_windows.go` — OS-specific process/service helpers
  (systemd integration on Linux with a background fallback, etc.).

## Web Platform — `internal/web`

The local server exposes a REST API + WebSocket telemetry and serves the React
dashboard, which is compiled from `webui/` and embedded into the binary via
`//go:embed static/*`. It also owns scan orchestration and persistence.

After the v4.5.44 decomposition this package is split into cohesive files
(behavior-preserving; `server.go` is now a thin core + routing hub):

| File | Responsibility |
| --- | --- |
| `server.go` | `Server` struct, `NewServer`/`Start`, lifecycle, small handlers |
| `handlers_router.go` | route table / mux wiring |
| `auth_session.go` | dashboard auth: sessions, login backoff, CSRF, middleware |
| `ws_hub.go` | WebSocket client pumps + event broadcast |
| `orchestrator.go` | scan orchestration: single / DAST / wildcard / multi + subdomain collection |
| `scan_session.go` | run one scan session + event processing + phase inference |
| `queue_state.go` | scan-queue persistence, resume, admission control |
| `scan_record.go` / `scan_query.go` / `scan_list.go` | scan-record assembly, lookup, listing/caching |
| `notify.go` | Discord + Telegram notifications (severity-gated) |
| `chat.go` | in-scan / post-scan chat with the agent |
| `schedules.go` / `scheduler.go` | scheduled scans |
| `uploads.go` | target/instruction/logo/context uploads |
| `report.go` | report delivery API |
| `settings_env.go`, `handlers_profiles.go` | settings, provider keys, credential profiles, OAuth |
| `retention.go`, `data_dirs.go`, `legacy_import.go` | data-dir management + retention |

Concurrency: the `Server` owns the running scan instances and several
independently-locked caches. Each scan runs in its own goroutine and its own
`scanctx` context so concurrent scans never cross-wire.

## Agent Core — `internal/agent`

The autonomous loop. It builds a system prompt encoding the 22-phase
methodology, sends the conversation to the configured LLM, executes the tool
calls the model requests, feeds results back, and repeats until the objective
is met or a budget (iterations / duration / tokens) is hit.

| File | Responsibility |
| --- | --- |
| `agent.go` | the loop, tool dispatch, watchdog, lifecycle (`Run`/`Stop`) |
| `agent_guard.go` | scope guard, phase-restriction guard, passive-recon guard, host/URL extraction |
| `agent_prompt.go` | system-prompt / closing-instruction / whitebox-guidance construction |
| `agent_messages.go` | tool-result formatting + conversation pruning/compaction |
| `agent_ratepolicy.go` | request-rate policy parsing (from the instruction) |
| `hooks.go` | loop hooks incl. stuck/loop detection (repeated identical calls) |
| `verifier.go` | the independent Verifier agent that re-tests candidate findings |

Guards keep the agent inside the authorized scope and the selected phases, and
throttle to the requested request-rate policy. These are the safety boundaries
that make an autonomous offensive agent safe to point at a target.

## Tooling — `internal/tools`

`registry.go` is the tool surface presented to the model. Each subpackage is one
capability:

- `terminal` — sandboxed shell execution (the workhorse for CLI security tools)
- `browser` + `pageagent` — headless browser automation (JS-heavy apps, auth flows)
- `httpclient` — direct HTTP requests
- `websearch`, `codesearch`, `fileedit`, `notes`, `python` — research / analysis helpers
- `reporting` — the `report_vulnerability` tool + findings store (see below)
- `agentmail`, `agentsgraph` — email/OOB interaction and sub-agent graphs
- `proxy`, `oob`, `finish`, `iolimit`, `skills` — proxying, out-of-band callbacks, termination, IO limits, methodology corpus

## Findings & verification — `internal/tools/reporting` + `internal/reporting`

Every reported vulnerability passes gates (valid method, mandatory
exploitation proof, false-positive and claim-consistency checks, dedup,
severity/CVSS normalization) and is handed to the independent Verifier. Each
finding carries exactly one verification tag:

- `verified` — the Verifier independently reproduced it.
- `exploit-proven` — the Verifier was inconclusive/absent, but the finding's
  own proof shows a concrete exploitation outcome (command output, extracted
  data, OOB callback, …). Proven, not a guess.
- `needs-manual-verification` — preserved but not yet concretely proven.

`internal/reporting` renders the branded PDF from the persisted findings.

## Knowledge — `internal/tools/skills`

The methodology corpus / skills content that guides the agent, embedded in the
binary.

## Providers, LLM & auth — `internal/llm`, `internal/providers`, `internal/auth`

- `internal/llm` — model **router** (resolves a model name to a provider
  endpoint), multi-provider **KeyStore**, and the chat client.
- `internal/providers` — the compiled-in provider catalog.
- `internal/auth` — credential profiles + OAuth drivers (PKCE, device-code,
  setup-token, CLI-reuse) for provider authentication.

The engine is model-agnostic: the LLM, API base, and key are configured at
runtime; there is no hard-coded provider.

## Scan modes

- **single** — one URL/host, full vulnerability testing.
- **dast** — deep crawl of a specific app: discovery → parameter mining → vuln testing.
- **wildcard** — subdomain enumeration (passive + active) → per-subdomain scan.

Multiple targets are processed through the scan queue with resume support.

## Data flow

```
target + instruction
   → web: create scan instance (own goroutine + scanctx)
   → agent loop: reason → tool call → observe (events stream over WebSocket live)
   → reporting: gated + verified findings persisted to the scan record
   → storage: atomic scan.json per scan dir
   → report.go / internal/reporting: branded PDF on demand
   → notify.go: Discord/Telegram lifecycle + finding notifications
```

## Persistence & isolation

- `internal/storage` — atomic file writes (never a torn `scan.json`).
- `internal/scanctx` — per-scan context keyed by ID; findings stores and the
  Verifier are scoped to it, so concurrent scans are fully isolated.
- Each scan record (metadata, events, findings) is a `scan.json` under its own
  scan directory in the data dir; finished records are immutable and cached.

## Configuration

Read from `~/.xalgorix.env` (and process env). Key variables:

| Variable | Purpose |
| --- | --- |
| `XALGORIX_LLM` | provider-native model ID |
| `XALGORIX_LLM_PROVIDER` | provider selected by the dashboard for catalog routing |
| `XALGORIX_API_KEY` / `XALGORIX_API_BASE` | LLM credentials / custom endpoint |
| `XALGORIX_BIND` | dashboard listen address, default `127.0.0.1` (set `0.0.0.0` to expose; port defaults to `9137`) |
| `XALGORIX_PASSWORD` / `XALGORIX_PASSWORD_HASH` | dashboard auth |
| `XALGORIX_DATA_DIR` | where scan records are stored |
| `XALGORIX_MAX_ITERATIONS` / `_MAX_DURATION` / `_MAX_TOKENS` / `_MAX_TOOL_CALLS` | per-scan budgets |
| `XALGORIX_RATE_LIMIT_REQUESTS` / `_RATE_LIMIT_WINDOW` / `_RATE_RPS` / `_RATE_BURST` | request throttling |
| `XALGORIX_PROXY_URL` / `_PROXY_FILE` / `_PROXY_ROTATION` | upstream proxying |
| `XALGORIX_OOB_*`, `XALGORIX_INTERACTSH_*` | out-of-band callback config |
| `XALGORIX_DISCORD_WEBHOOK` / `_DISCORD_MIN_SEVERITY` | Discord notifications |
| `XALGORIX_TELEGRAM_BOT_TOKEN` / `_CHAT_ID` / `_MIN_SEVERITY` | Telegram notifications |

Secrets (password hash, bot token, API keys) are never returned by any API
response — only a `*_configured` boolean is surfaced.
