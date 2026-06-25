# Changelog

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
