# Changelog

## [Unreleased] — Provider model selector

### Added
- **Provider model selection across authentication methods.** Settings now renders one reusable model field for API-key, OAuth, and credential-free providers. Saved values retain the canonical `provider/model` routing prefix.
- **Live provider model discovery.** Providers with compatible OpenAI, Anthropic, Gemini, or Ollama model-list endpoints automatically load the models available to the selected credential. Discovery runs server-side and keeps credentials out of the browser. The built-in catalog no longer hardcodes model examples; providers without discovery support use explicit manual entry.
- **Novita AI provider.** The built-in catalog now includes Novita's OpenAI-compatible API endpoint and API-key authentication, with models loaded dynamically from Novita's API.

## [Unreleased] — Provider-specific CLI credential errors

### Fixed
- **Codex sign-in incorrectly reported missing Claude credentials.** Both CLI-reuse drivers previously returned the Claude-specific `auth.ErrNotFound` sentinel, so OAuth completion responded with `claude cli credentials not found` when the Codex credential was unavailable. Codex now returns a dedicated sentinel and the API responds with `codex cli credentials not found`. The sign-in modal also identifies the expected Codex credential path and read-only Docker mount.

## [Unreleased] — Per-scan live guidance

### Added
- **Operators can guide an agent while its scan is running.** The individual scan Events tab now includes a per-instance message composer with focused guidance suggestions, keyboard submission, delivery feedback, and responsive layout. Messages are routed to the exact running `instance_id`, queued for the agent's next iteration without interrupting its active work, and then surface in the same instance event stream. The WebUI client response type now also matches the existing `/api/chat` response contract.

## [Unreleased] — Markdown rendering in finding details

### Fixed
- **Finding text rendered raw Markdown in the dashboard.** The finding detail dialog showed `description`, `impact`, `technical_analysis`, and `remediation` as plain text, so the LLM-emitted Markdown (`##` headings, `**bold**`, fenced code, lists) appeared as literal characters. Added a small dependency-free Markdown renderer (`webui/src/components/markdown.tsx`) and use it for all non-code sections; the full description now renders as its own section. Code fields (PoC script, exploitation proof, suggested fix) stay verbatim in `<pre>`.

## [Unreleased] — Recognize command-injection RCE as proven

### Fixed
- **Genuine OS command-injection RCE was flagged "manual verification needed"** despite proof of root command execution. A critical `/uptime/{flag}` finding (CVSS 9+) whose proof showed `whoami`→`root`, `uname -a`→`… x86_64 GNU/Linux`, `uptime`→`load average …`, and full source-code disclosure was tagged `needs-manual-verification`. Cause: the concrete-impact detector (`HasConcreteImpact` and the reproduced-/concrete-impact indicator lists) only recognized command execution via `id`/`cat /etc/passwd`-style output (`uid=`, `gid=`, `root:`, `/etc/passwd`); it did not recognize `whoami`, `uname`, `uptime`, or Windows command output, so neither the independent Verifier's auto-confirm nor the `exploit-proven` classification fired. Added high-signal command-execution markers (`gnu/linux`, `load average`, `nt authority\`, `volume serial number`, `windows ip configuration`, `microsoft windows [version`) to both lists. Such findings are now `verified`/`exploit-proven` (Verified=true) instead of flagged for manual review. Regression: `TestHasConcreteImpact_RecognizesCommandExecutionOutput`.

## [Unreleased] — Phase-progress accuracy

### Fixed
- **Phase progress jumped to a late phase during reconnaissance** (e.g. showed "8. IDOR / BAC" at iteration 4 while still fingerprinting). `inferCurrentPhase` mapped ubiquitous HTTP tokens in tool arguments to methodology phases — `authorization` → 8, `cookie` → 4, `login`/`session` → 5, `/api/`/`graphql` → 9 — but those appear in ordinary requests on nearly every target (an authenticated scan sends an `Authorization` header from its first recon request), so the bar false-jumped immediately. Those keyword heuristics are removed; phases without a dedicated tool signal now advance only via the agent's explicit phase narration. Additionally, the reported phase is now **monotonic** (progress only moves forward) so it no longer bounces backward when the autonomous agent revisits recon between exploit attempts. Regression guard in `TestInferCurrentPhase_*`.

## [Unreleased] — "Exploit-proven" verification state

### Fixed
- **Proven findings were being flagged "manual verification needed."** When the independent Verifier returned an *inconclusive* verdict (ran out of turn/time budget, hit an LLM error, or the class needs state/timing/OOB it lacks), the finding was tagged `needs-manual-verification` regardless of the strength of its own proof — so a proven RCE whose exploitation proof shows `uid=0(root)`, or a SQLi that dumped rows, was presented as unverified. The verification dimension now has three states: `verified` (independently reproduced by the Verifier), **`exploit-proven`** (Verifier inconclusive/absent, but the finding's OWN proof contains a concrete exploitation outcome per `HasConcreteImpact` — command output, extracted data, OOB callback, SQL extraction, cloud-metadata), and `needs-manual-verification` (no concrete proof yet). `Verified` is now true for both `verified` and `exploit-proven`, so reports no longer stamp proven findings "UNVERIFIED — manual review required." Regression: `TestReportVuln_IndependentVerifierGate/inconclusive_with_concrete_first-party_proof_is_EXPLOIT-PROVEN`.

## [Unreleased] — Internal refactor: decompose web/agent god-files

### Changed
- **Behavior-preserving decomposition of the two largest files** into cohesive, single-purpose files within their existing packages. No logic changed (verified: top-level declaration sets identical vs the prior revision, and code content byte-identical except two removed stale orphan comments; build/vet/gofmt/golangci-lint clean, tests + `-race` green).
  - `internal/web/server.go` 8865 → 3187 LOC, split into `auth_session`, `ws_hub`, `queue_state`, `orchestrator`, `uploads`, `notify`, `scan_session`, `chat`, `schedules`, `scan_list`, `scan_query`, `scan_record`, `legacy_import`.
  - `internal/agent/agent.go` 4028 → 1422 LOC, split into `agent_prompt`, `agent_ratepolicy`, `agent_messages`, `agent_guard`.

## [Unreleased] — Report accuracy vs severity filter (customer feedback)

### Fixed
- **Report omitted findings the live severity filter hid.** When a scan was launched with a `severity_filter` (e.g. only show `critical` live), a vulnerability below that threshold was dropped from `sess.record.Vulns` entirely — so it never reached the on-disk `scan.json` or the PDF report. Customers saw "report shows no findings, but the logs show findings, even critical." The severity filter is now a **display/broadcast gate only**: every vuln the agent reports is always persisted to the scan record (and thus the report + `/api/findings`), and the filter only suppresses the real-time WebSocket broadcast and Discord/Telegram notification. `report_vulnerability` event handling in `internal/web/server.go` no longer wraps persistence in the `if allowed` block. Regression tests: `TestReportPersistsBelowFilterVulns`, `TestAppendVulnSummaryUniqueIsFilterAgnostic`.

## [Unreleased] — Telegram bot notifications (#157)

### Added
- **Telegram bot notifications** as a first-class notification channel alongside Discord. Operators configure a bot token + chat ID (`XALGORIX_TELEGRAM_BOT_TOKEN`, `XALGORIX_TELEGRAM_CHAT_ID`, `XALGORIX_TELEGRAM_MIN_SEVERITY`) and receive the same lifecycle and finding notifications Discord already receives: scan started, vulnerability found (severity-gated), scan finished, the completed PDF report delivered via `sendDocument`, and service restart/stop events. Telegram and Discord are independent and can be enabled together or separately.
  - New `sendTelegram` / `sendTelegramWithFile` helpers in `internal/web/server.go` mirror `sendDiscord` / `sendDiscordWithFile` (fire-and-forget goroutine, 30s timeout, `safe.Recover` boundary, early-return when unconfigured). Text messages use HTML parse_mode; the PDF report is attached as a `sendDocument` multipart upload. Telegram logical `ok:false` responses (HTTP 200 with an error body) are logged without crashing the scan.
  - The outbound host is pinned to `api.telegram.org` over HTTPS (not operator-configurable) so an attacker-influenced base URL cannot create an SSRF surface.
  - The bot token is `Sensitive: true` in the settings registry and never returned by any `/api/...` response; only a `telegram_configured` boolean is surfaced on scan records (mirrors the existing `discord_webhook_configured` redaction pattern verified in `server_test.go`).
  - Settings → Notifications tab now has a Telegram card (bot token, chat ID, minimum severity) and the Integrations page has a Telegram bot card.
  - v1 is global-only (no per-scan Telegram override); per-scan parity with Discord is tracked as a future follow-up.

## [Unreleased] — Loop-breaker for repeated identical tool calls

### Fixed
- **Endless loop on repeated identical tool calls (#158).** The agent could spin indefinitely, regenerating the same tool call (most commonly `terminal_execute`) with identical arguments and an identical failing result — observed reaching iteration 2106+ with no progress. Stuck detection in `internal/agent/hooks.go` only accumulated for `browser_action` and `web_search`; the default branch of `hookStuckTracker` reset all stuck counters for every other tool, so a loop on `terminal_execute` (or any non-browser/search tool) never tripped a nudge or force-skip and ran until `MaxIterations` (default 0 = unlimited) or process kill.
  - New `ScanState` fields track consecutive identical `(tool, args)` and consecutive byte-identical tool outputs; these counters are deliberately NOT reset by `OnHealthyResponse` (a "healthy" response re-issuing the same call is exactly the loop).
  - New thresholds `RepeatCallSoftNudge=3`, `RepeatCallHardSkip=5`, `RepeatResultHardSkip=4`.
  - `hashToolArgs()` (order-independent FNV-64a) and `resultFingerprint()` detect identical `(tool, args)` and identical output across iterations.
  - `hookStuckTracker`'s default branch now counts consecutive identical calls; `add_note`/`read_notes` are excluded so legitimate note-taking between identical test calls doesn't reset the counter.
  - New `hookResultRepeatTracker` on `OnToolResult` counts byte-identical outputs (ignores `add_note`/`read_notes`/`finish`).
  - `hookStuckNudge` force-skips + nudges ahead of the browser hard-limit on repeated identical call (soft/hard) and repeated identical output; counters reset after firing.

### Notes
- No change to `agent.go` (existing `ForceSkip`→skip / `Nudge`→user-message machinery already consumes the result) and no change to the `MaxIterations` default (legitimate wildcard scans run thousands of iterations).
- Known follow-up, not fixed here: the three block branches in `agent.go` (`shouldBlockForActivityPolicy` / `shouldBlockForPhaseRestriction` / `shouldBlockForOutOfScope`, ~L1547-1581) still do not increment any stuck counter.

## [Unreleased]

### Added
- **`POST /api/restart`** — schedules a graceful backend restart from the dashboard/API. The restart never interrupts active work: it waits until the scanner is idle (no running/pending/paused/queued/starting instances, no in-progress scan, no leased tool processes) before restarting, then in-flight scans auto-resume. Shares the same `scannerIdle` gate and restart-when-idle watcher as the existing `xalgorix --restart-when-idle` (SIGUSR1) path. Returns `{ "status": "scheduled"|"already_pending", "idle": <bool> }`. Inherits the existing auth + CSRF stack as a mutating route.

## [Unreleased] — Runtime-editable provider catalog and OAuth flows

### Added
- **Runtime-editable provider catalog** at `~/.xalgorix/data/providers.json`. The file ships empty: there are no baked-in defaults, no startup writes, and no auto-fetch. Operators populate it through the dashboard or the new HTTP API. Catalog reads/writes use atomic temp-rename with `0600` file mode and a parent dir `chmod 0700`; corrupt JSON is treated as empty for `List` and refuses every `Create`/`Update`/`Delete` until the file is fixed.
- **Four OAuth flows** for storing per-provider credentials, all coalesced through a single `Driver` registry and a `TokenSink` that serializes refreshes per `(provider, profileId)`:
  - `pkce`: loopback redirect on `127.0.0.1:<ephemeral>` with PKCE S256 plus a paste-fallback that activates automatically when `XALGORIX_BIND` resolves to a non-loopback address.
  - `device_code` (RFC 8628): polls the token endpoint at the server-supplied interval, honors `slow_down`, and surfaces `408` on `expires_in` timeout.
  - `setup_token`: posts an operator-supplied bearer to the configured `tokenEndpoint` and persists the resulting profile.
  - `claude_cli_reuse`: read-only import of the Claude CLI credential file; mtime + SHA-256 of the source file are unchanged after import.
- **Operator-triggered openclaw catalog import** via `POST /api/providers/import-openclaw`. HTTPS-only, skip-on-collision merge with a per-entry `outcomes` envelope. Upstream non-2xx responses bubble up as a `502` envelope and the on-disk catalog is left untouched.
- **Per-scan `provider_profile` field** on `ScanRequest`. The web layer's `resolveScanCredentials` resolves the routing precedence `provider_profile → catalog default → legacy env`, with explicit `api_key` overrides forcing API-key auth. Unknown profile keys fail fast with `400` before any scan goroutine spawns.
- **One-time legacy migration banner.** When `XALGORIX_LLM` (or `XALGORIX_API_KEY`) is set and both `providers.json` / `auth-profiles.json` are absent or empty, the dashboard offers a one-click migration that materializes a `legacy` catalog entry plus a `legacy:default` API-key profile and drops a `.legacy-providers-migrated` sentinel. The importer never modifies `~/.xalgorix.env`.
- **New HTTP routes** under the existing auth + CSRF stack:
  - `GET/POST /api/providers`, `PUT/DELETE /api/providers/{id}`, `POST /api/providers/import-openclaw`
  - `GET/POST /api/providers/migrate-legacy` and `GET /api/providers/migrate-legacy/status`
  - `GET /api/auth/profiles`, `POST /api/auth/profiles/api-key`, `POST /api/auth/profiles/oauth/start`, `POST /api/auth/profiles/oauth/complete`, `POST /api/auth/profiles/{key}/refresh`, `DELETE /api/auth/profiles/{key}`
  All credential strings (`apiKey`, `accessToken`, `refreshToken`) are masked via `maskAuthCredential` on every response while metadata (`expiresAt`, `scopes`, `tokenType`, `requiresReauth`, `apiBaseOverride`) round-trips unmasked.
- **Settings → Providers tab** in the dashboard composing the catalog editor, profile list with per-flow OAuth modal (loopback / device / paste shapes), openclaw import button, and the legacy migration banner.

### Changed
- The LLM client now resolves outbound endpoints through a composite resolver: when the catalog is non-empty it routes through `catalogResolver`; when the catalog is empty and `XALGORIX_LLM` matches the legacy provider shape it falls back to `legacyResolver`; otherwise requests fail with a config error. The header-application matrix lives in a single `(HeaderStyle × AuthMethod)` switch covering OpenAI / Anthropic (`anthropic-version: 2023-06-01`) / Gemini (`x-goog-api-key`) for both API-key and OAuth-bearer auth.

### Notes
- The env-file path keeps working unchanged for existing operators: setting `XALGORIX_LLM` and `XALGORIX_API_KEY` continues to drive scans without touching the catalog or profile store. Catalog and profile writes never modify `~/.xalgorix.env`.
- `/oauth/callback` is intentionally not registered on the dashboard mux — loopback callbacks land on per-flow ephemeral listeners owned by the `pkce` driver.

### See also
Spec: `.kiro/specs/provider-catalog-and-oauth/`

## [Unreleased] — Concurrency model: RAM-only admission

### Changed
- **Scan admission now derives concurrency purely from RAM headroom.** `EffectiveMaxInstances` no longer mixes CPU load and disk pressure into the slot count. CPU saturation throttles scans (the kernel time-slices) but doesn't crash them, so gating new scans on CPU only reduced total throughput. Disk consumption is bursty, not reserved up front; disk now acts as a yes/no admission gate that refuses new scans only when free space is below the critical floor (`XALGORIX_DISK_CRITICAL_MB`, default 1 GB).
- **Per-tool CPU throttling is unchanged** and still lives in the tool-lease layer (`tryAcquireToolLease`), where it correctly queues heavy subprocess launches without blocking scan admission.
- **Dashboard layout.** The "Max N · scan budget · tool cap" caption moved from under the DISK FREE tile to under HOST MEMORY, where the underlying constraint actually lives. DISK FREE now describes its own role.
- **Admission rationale** strings (`/api/status`, the dashboard) only mention dimensions that actually gate admission (RAM and disk-critical). Pre-cleanup, an "instances 4/4 — CPU critical: load X" message was misleading because admission proceeded regardless of CPU.

### Removed
- `XALGORIX_SCAN_CPU_LOAD` env var and its associated `perScanCPULoad` / `autoScanCPULoad` plumbing, the `Capacity().ScanCPULoad` field, the `scan_cpu_load` field on `/api/status`, and the matching settings UI row. The knob hadn't influenced admission since it was a stealth no-op; setting it now logs a one-time deprecation notice on startup.
- Internal `cpuInstanceCapacity` helper (no callers after the refactor).
- Internal `hostMatchesLocalInterface` helper (dead code; `isBlockedTarget` now routes through `ipsMatchLocalInterface`).
- The `level` parameter on `effectiveMaxInstancesForStats` (it was unused after the refactor).

### Fixed
- `effectiveMaxInstancesForStats` no longer calls `memoryInstanceCapacity` twice on the same `stats` snapshot.

## v4.4.19 — Scope guard hardening v2

### Fixed
- **URL-in-query-param bypass closed.** `scopeHostTokenSplit` in `internal/agent/agent.go` now also breaks tokens on `=`, `?`, `#`, and `@`, and a new `extractEmbeddedURLs` sweep pulls every `http://` / `https://` substring out of an arg value before the separator pass. An OOS host smuggled inside a redirect query parameter (e.g. `https://in-scope.example/redirect?next=https://oos.example/path`), a userinfo form (`user@oos.example`, `https://user:pass@oos.example/`), or any of the new delimiters now surfaces as a standalone token and the gated tool call is rejected.
- **Per-arg scan length capped at 8 KiB.** A new `argScanLimitBytes = 8192` constant plus `truncateForScopeScan` helper bound how much of any single Arg_Value the agent-side guard tokenizes. Values ≤ 8 KiB still walk the same path byte-for-byte; values larger than 8 KiB are silently truncated at the largest UTF-8 rune-boundary offset ≤ 8192. The cap never short-circuits to a reject — oversize args fall through to the existing allow path on length alone.
- **Single DNS lookup per `isBlockedTarget` call.** `isBlockedTarget` in `internal/web/server.go` now parses the host as a `net.IP` literal first, otherwise issues exactly one `net.LookupHost` (via a package-level `lookupHost` shim for testability), and threads the resolved IP slice into both the self-listener check (new internal helper `ipsMatchLocalInterface`) and the private-range check. DNS failure preserves the prior `return false` (allow) verdict.
- **OOS hostnames in `add_note` are redacted, not leaked.** A new `(*Agent).redactOutOfScopeHosts` method mirrors the gated tokenization path and substitutes the literal marker `[redacted: out-of-scope host]` for every OOS host span in the `key` and `value` arguments of `add_note`. The agent loop applies redaction in place immediately before `shouldBlockForOutOfScope`, so notes can no longer launder OOS hostnames through `read_notes` on the next iteration. Gated tools continue to reject rather than redact.

### See also
Spec: `.kiro/specs/scope-guard-hardening-v2/requirements.md`

## [Unreleased]

### Breaking changes

#### Default workspace moved to `~/.xalgorix/data/`

The default location for scan output, notes, schedules, and other generated artefacts moved from `$CWD` (the directory the binary was launched from) to `~/.xalgorix/data/`. This is the single most visible part of the stability + workspace-isolation release.

**To retain previous behavior**, run:
```
export XALGORIX_DATA_DIR=$(pwd)
```

A `[MIGRATION]` warning is emitted at startup when legacy markers (`notes.json`, `_schedules/`, `vulnerabilities.json`, or `YYYY-MM-DD/scan-*` directories) are detected in `$CWD` and `XALGORIX_DATA_DIR` is unset.

### Added
- `XALGORIX_LLM_MAX_INFLIGHT`: caps concurrent outbound LLM calls (default: `4 × EffectiveMaxInstances`, minimum 1).
- Health endpoint counters: `panics_recovered`, `path_rejections`, `watchdog_kills`, `admission_refusals`, `llm_inflight_cap`, `data_dir`, `allow_list`, `read_deny`.
- Path_Policy boundary check: every filesystem-touching tool now writes only into `~/.xalgorix/data/`, `~/.xalgorix/`, or `/tmp/`.
- Read-policy: filesystem-touching tools may now READ anywhere on the host (system wordlists, payload directories, `/etc/services`, etc.) so agents can use shared assets without copying them into the workspace. A built-in deny-list still rejects reads of sensitive paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc/shadow`, `/etc/sudoers`, `/proc/kcore`, etc.). Set `XALGORIX_READ_DENY_LIST` (colon-separated) to extend the defaults. The active deny-list is exposed as `read_deny` on `/api/status`.
- Browser tool now acquires Tool_Leases and applies process memory limits.
- Recovery for tool panics, scheduler ticks, HTTP handler panics, and ScanContext close panics.

### Fixed
- Python and terminal tools no longer leak `.tmp/`, `.cache/`, `.config/`, `.local/` directories into `$CWD`. They now create those scratch dirs under the active scan directory or `~/.xalgorix/data/`.
- Tool stdout/stderr now bounded to 1 MB / 512 KB respectively (prevents OOM from runaway output).

### See also
Spec: `.kiro/specs/xalgorix-stability-and-workspace-isolation/requirements.md`

## [Unreleased] — Findings consistency and pagination

### Fixed
- **Findings page no longer truncated to 30 scans.** The Findings dashboard now enumerates every scan on disk and paginates the union with controls for page size [25, 50, 100, 200] (default 50). Findings deduplicate across runs by `(target, endpoint, title, severity)`, with the surviving row linking to the most recent producing scan.
- **Counter flicker eliminated.** The Findings and Overview totals widgets keep prior data during refetches (`keepPreviousData`), so the visible total no longer drops to zero between background polls.
- **Counter monotonicity per scan.** A new `effectiveVulnCount(inst, sess)` helper consolidates the previous triple-source `inst.VulnCount` assignments. Counters now read in-memory while the scan is running and on-disk after teardown — they never visibly drop without a delete.
- **Panic-safe persistence of child findings.** `reporting.PromoteToParent` is invoked on every successful `report_vulnerability` so a child scan's findings reach the parent aggregate immediately. Combined with `MergeVulnsToContext` running in the deferred `cleanup()`, parent records survive child agent panics.

### Added
- **`/api/findings/summary` endpoint.** Returns severity counts derived from on-disk scan records, with an `as_of` timestamp and `etag` for cheap polling. Polled by the WebUI every 10s; honors `If-None-Match` for `304 Not Modified` responses.
- **`vulns_persisted` field in `/api/status`.** Stable on-disk total alongside the existing `vulns` (in-memory) field. Additive change — no breaking change for existing clients.
- **Legacy `~/xalgorix-data/` import.** On first server start after this release, scan records under `~/xalgorix-data/` are non-destructively copied into `cfg.DataDir`. A sentinel file `.legacy-imported` prevents repeated walks. The legacy directory is preserved; you may manually `rm -rf ~/xalgorix-data` after verifying the import via the WebUI banner and Findings page.

### Notes
- The legacy import is intentionally manual to undo. Automation here is out of scope.
- The previous spec's `safe.Recover` wrappers already contain agent-goroutine panics to a single scan; the panic that motivated this work no longer crashes the whole server even before the persistence fixes land. This bugfix focuses on counter and pagination correctness.
