<div align="center">

<img src="assets/banner.png?v=4.5.13" alt="Xalgorix" width="860" />

<br />

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-111111?style=for-the-badge&logo=linux&logoColor=white)](#installation)

Self-hosted AI security testing with a local Web UI, live agent telemetry, verified findings, and branded PDF reports.

</div>

---

## Quick Start

```bash
git clone https://github.com/xalgord/xalgorix.git
cd xalgorix
make build
sudo install -m 755 build/xalgorix /usr/local/bin/xalgorix
```

Create `~/.xalgorix.env`:

```bash
XALGORIX_LLM=minimax/MiniMax-M2.7
XALGORIX_API_KEY=your_provider_api_key
```

Start the dashboard:

```bash
xalgorix --web
```

Open `http://127.0.0.1:9137`.

> [!IMPORTANT]
> Use Xalgorix only on systems you own or have explicit permission to test.

## Contents

- [Quick Start](#quick-start)
- [Overview](#overview)
- [Screenshots](#screenshots)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Upgrading from previous versions](#upgrading-from-previous-versions)
- [Running](#running)
- [Service Mode](#service-mode)
- [Web UI Workflow](#web-ui-workflow)
- [Scan Modes](#scan-modes)
- [Methodology](#methodology)
- [Reports](#reports)
- [Settings](#settings)
- [Environment Variables](#environment-variables)
- [Provider Prefixes](#provider-prefixes)
- [CLI Reference](#cli-reference)
- [API Summary](#api-summary)
- [Data Storage](#data-storage)
- [Development](#development)
- [Safety Notes](#safety-notes)
- [License](#license)
- [Links](#links)

## Overview

Xalgorix is a self-hosted AI security testing platform for authorized penetration testing and bug bounty workflows. It combines an LLM-driven agent, browser automation, terminal tooling, a 22-phase testing methodology, live WebSocket events, finding management, report generation, and integrations for AgentMail and Discord.

The default experience is the Web UI. From one local dashboard you can start scans, monitor active runs, inspect findings, configure model/provider settings, manage environment variables, generate branded PDF reports, and delete or resume historical scans.

## Screenshots

| Overview dashboard                                      | Scan detail                                      | Findings                                      |
| ------------------------------------------------------- | ------------------------------------------------ | --------------------------------------------- |
| ![Xalgorix overview dashboard](assets/screenshot-1.png) | ![Xalgorix scan detail](assets/screenshot-2.png) | ![Xalgorix findings](assets/screenshot-3.png) |

## Features

| Area           | Capabilities                                                                                                                |
| -------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Dashboard      | Local Web UI on `127.0.0.1:9137` by default, scan management, live status, bulk scan actions, and historical scan recovery. |
| Scanning       | Single target, DAST, wildcard, and multi-target flows with selectable methodology phases.                                   |
| Live telemetry | Tool calls, agent messages, findings, errors, HTTP activity, and LLM activity over WebSockets.                              |
| Findings       | Scan detail pages, severity filters, CVSS details, finding index, and verified finding workflows.                           |
| Reporting      | Branded PDF reports with target/company name, uploaded logo, report list, open/download/delete actions.                     |
| Integrations   | AgentMail test inboxes, verification emails, OTP flows, email triage events, and Discord notifications.                     |
| Configuration  | Dashboard settings for LLM, AgentMail, Discord, proxy, runtime, browser, auth, rate limits, and resources.                  |
| Runtime safety | Resource-aware instance limits and loopback-only binding unless external access is explicitly configured with auth.         |

## Installation

### Requirements

| Requirement    | Notes                                                        |
| -------------- | ------------------------------------------------------------ |
| Linux          | Primary supported platform.                                  |
| Go             | `1.24.2` or newer.                                           |
| Node.js + npm  | Required when building the bundled React Web UI from source. |
| Security tools | Installed on demand only when auto-install is enabled.       |

Check your Go version:

```bash
go version
```

### Build From Source

```bash
git clone https://github.com/xalgord/xalgorix.git
cd xalgorix
make build
sudo install -m 755 build/xalgorix /usr/local/bin/xalgorix
```

`make build` builds the React Web UI into `internal/web/static`, then builds the Go binary.

### Install With Go

```bash
GOPROXY=direct GOSUMDB=off go install github.com/xalgord/xalgorix/v4/cmd/xalgorix@latest
```

## Configuration

Xalgorix loads configuration in this order. Later sources override earlier ones.

| Order | Source                                                         |
| ----- | -------------------------------------------------------------- |
| 1     | `/etc/xalgorix.env`                                            |
| 2     | `/home/<sudo-user>/.xalgorix.env` when launched through `sudo` |
| 3     | `~/.xalgorix.env`                                              |
| 4     | Environment variables already present in the process           |

Create the local environment file:

```bash
nano ~/.xalgorix.env
```

### Minimal Config

```bash
XALGORIX_LLM=minimax/MiniMax-M2.7
XALGORIX_API_KEY=your_provider_api_key
```

### Provider Examples

OpenAI:

```bash
XALGORIX_LLM=openai/gpt-5.4
XALGORIX_API_KEY=sk-...
```

Custom OpenAI-compatible provider:

```bash
XALGORIX_LLM=custom/security-model
XALGORIX_API_BASE=https://your-provider.example/v1
XALGORIX_API_KEY=your_provider_api_key
```

### Optional Integrations

```bash
GEMINI_API_KEY=AIza...
AGENTMAIL_POD=am_us_pod_47
AGENTMAIL_API_KEY=ak_...
XALGORIX_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
XALGORIX_DISCORD_MIN_SEVERITY=high
```

### Dashboard Authentication

```bash
XALGORIX_USERNAME=admin
XALGORIX_PASSWORD=change-this-password
```

> [!TIP]
> Prefer `XALGORIX_PASSWORD_HASH` for production deployments.

## Upgrading from previous versions

This release ships a stability and workspace-isolation pass with one breaking change and a few new knobs worth knowing about.

### Breaking change: default workspace moved to `~/.xalgorix/data/`

Scan output, notes, schedules, and other generated artefacts now live under `~/.xalgorix/data/` instead of `$CWD` (the directory the binary was launched from).

To retain the previous behavior, point `XALGORIX_DATA_DIR` at your current working directory:

```bash
export XALGORIX_DATA_DIR=$(pwd)
```

A `[MIGRATION]` warning is emitted at startup when legacy markers (`notes.json`, `_schedules/`, `vulnerabilities.json`, or `YYYY-MM-DD/scan-*` directories) are detected in `$CWD` and `XALGORIX_DATA_DIR` is unset. Xalgorix never reads, copies, or deletes those legacy files automatically; the warning is informational and only fires once per process.

### New environment variable

| Variable                     | Default                       | Description                                                                                              |
| ---------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------- |
| `XALGORIX_LLM_MAX_INFLIGHT`  | `4 × EffectiveMaxInstances`   | Caps simultaneous outbound LLM calls across all running scans. Minimum `1`. Cancelled waiters do not consume a slot. |

### New health endpoint counters

`GET /api/status` now exposes:

| Field                 | Meaning                                                                              |
| --------------------- | ------------------------------------------------------------------------------------ |
| `panics_recovered`    | Goroutine, HTTP handler, and tool panics that were recovered without crashing.       |
| `path_rejections`     | Filesystem writes refused by Path_Policy (outside `data_dir` / `~/.xalgorix/` / `/tmp`). |
| `watchdog_kills`      | Subprocesses terminated by the per-tool hard-timeout watchdog.                       |
| `admission_refusals`  | Scan admission requests denied due to the concurrency ceiling.                       |
| `llm_inflight_cap`    | Effective `XALGORIX_LLM_MAX_INFLIGHT` value for this process.                        |
| `data_dir`            | Resolved Data_Dir in use.                                                            |
| `allow_list`          | Filesystem roots accepted by Path_Policy.                                            |

## Running

### Web UI

```bash
xalgorix --web
```

Open:

```text
http://127.0.0.1:9137
```

Use a different port:

```bash
xalgorix --web --port 8080
```

### External Access

Bind to another interface only after enabling dashboard authentication:

```bash
XALGORIX_USERNAME=admin XALGORIX_PASSWORD=change-this xalgorix --web --bind 0.0.0.0
```

> [!WARNING]
> The server refuses external binding without dashboard authentication.

### CLI Scan

```bash
xalgorix --target https://example.com
```

With custom instructions:

```bash
xalgorix --target https://app.example.com --instruction "Focus on SQL injection, IDOR, and auth bypass. Avoid destructive tests."
```

## Service Mode

Install and start as a system service:

```bash
sudo xalgorix --start
```

Manage the service:

```bash
sudo xalgorix --restart
sudo xalgorix --stop
sudo xalgorix --uninstall
```

View logs:

```bash
journalctl -u xalgorix -f
```

### Remote Service Access

Expose the service to remote browsers only after enabling dashboard auth:

```bash
sudo tee -a /root/.xalgorix.env >/dev/null <<'EOF'
XALGORIX_BIND=0.0.0.0
XALGORIX_USERNAME=admin
XALGORIX_PASSWORD=change-this
EOF

sudo xalgorix --restart
```

Then open `http://<server-ip>:9137`.

If the process is listening but the page still does not load remotely, allow TCP port `9137` in the server firewall or cloud security group.

## Web UI Workflow

1. Open the dashboard at `http://127.0.0.1:9137`.
2. Go to Settings and confirm the LLM provider, API key, rate limits, and optional integrations.
3. Create a scan from New Scan.
4. Choose a scan mode.
5. Select methodology phases when you want a focused run.
6. Set severity filters when only certain severities should be reported.
7. Add company name and upload a logo for branded reports.
8. Monitor progress from Overview, Scan Detail, or Live Feed.
9. Open finding details, download reports, or manage historical scans from Scans and Reports.

## Scan Modes

| Mode             | Best for                                                                        |
| ---------------- | ------------------------------------------------------------------------------- |
| Single target    | Testing one known URL or host.                                                  |
| Wildcard / multi | Enumerating related targets and scanning the discovered attack surface.         |
| DAST             | Browser-assisted testing for web apps, auth flows, forms, and runtime behavior. |

## Methodology

Xalgorix organizes autonomous testing into 22 phases.

| Phase | Focus                                      |
| ----: | ------------------------------------------ |
|     1 | Reconnaissance                             |
|     2 | Manual vulnerability discovery             |
|     3 | Directory and file discovery               |
|     4 | CORS and cookie analysis                   |
|     5 | Authentication and session testing         |
|     6 | Injection testing                          |
|     7 | SSRF testing                               |
|     8 | IDOR and broken access control             |
|     9 | API and GraphQL testing                    |
|    10 | File upload testing                        |
|    11 | Deserialization and RCE                    |
|    12 | Race conditions and business logic         |
|    13 | Subdomain takeover                         |
|    14 | Open redirect testing                      |
|    15 | Email security testing                     |
|    16 | Cloud and infrastructure                   |
|    17 | WebSocket testing                          |
|    18 | CMS-specific testing                       |
|    19 | Broken link hijacking and content spoofing |
|    20 | Exploit verification                       |
|    21 | Zero-day discovery                         |
|    22 | Final report                               |

Phase selection in the Web UI lets you run every phase or only the subset needed for a specific engagement.

## Reports

Reports are generated as PDF files and can include:

| Section     | Included content                                                                |
| ----------- | ------------------------------------------------------------------------------- |
| Summary     | Executive summary, target metadata, scan metadata, and severity overview.       |
| Findings    | Verified findings, CVSS details, technical analysis, and exploitation proof.    |
| Evidence    | Proof of concept commands, scripts, payload notes, and supporting observations. |
| Remediation | Fix guidance and prioritized next steps.                                        |
| Branding    | Company/target name and uploaded logo.                                          |

Reports are available from the scan detail page and the Reports page. Report rows support opening, downloading, and deletion.

## Settings

Most operational settings can be changed from the Web UI under Settings.

| Area          | Examples                                                            |
| ------------- | ------------------------------------------------------------------- |
| Engagement    | Dashboard request rate limits                                       |
| LLM           | Model, API key, API base, reasoning effort, retries, max iterations |
| AgentMail     | Pod and API key                                                     |
| Notifications | Discord webhook and minimum severity                                |
| Proxy         | Proxy URL, proxy file, rotation, TLS verification                   |
| Runtime       | Workspace, browser path, auto-install controls                      |
| Security      | Dashboard username, password, password hash, bind address           |
| Resources     | CPU/RAM/disk thresholds and scan concurrency budget                 |

Some settings require a restart because they affect process startup or server binding. The UI marks those fields.

## Environment Variables

### Core

| Variable                             | Default          | Description                                            |
| ------------------------------------ | ---------------- | ------------------------------------------------------ |
| `XALGORIX_LLM`                       | none             | Required model name, usually with provider prefix.     |
| `XALGORIX_API_KEY`                   | none             | Required LLM provider API key.                         |
| `XALGORIX_API_BASE`                  | provider default | Custom OpenAI-compatible API base URL.                 |
| `XALGORIX_REASONING_EFFORT`          | `high`           | Reasoning effort: `low`, `medium`, `high`, or `xhigh`. |
| `XALGORIX_LLM_MAX_RETRIES`           | `5`              | Retry count for transient LLM failures.                |
| `XALGORIX_MEMORY_COMPRESSOR_TIMEOUT` | `30`             | Timeout in seconds for context compression.            |
| `XALGORIX_MAX_ITERATIONS`            | `0`              | Agent iteration cap. `0` means unlimited.              |
| `GEMINI_API_KEY`                     | none             | Optional Gemini key for web-search enrichment.         |

### Web and Security

| Variable                 | Default           | Description                        |
| ------------------------ | ----------------- | ---------------------------------- |
| `XALGORIX_BIND`          | `127.0.0.1`       | Web server listen address.         |
| `XALGORIX_USERNAME`      | none              | Dashboard username.                |
| `XALGORIX_PASSWORD`      | none              | Dashboard password.                |
| `XALGORIX_PASSWORD_HASH` | none              | Preferred bcrypt password hash.    |
| `XALGORIX_WORKSPACE`     | current directory | Workspace root for scan execution. |

### Integrations

| Variable                        | Default | Description                              |
| ------------------------------- | ------- | ---------------------------------------- |
| `AGENTMAIL_POD`                 | none    | AgentMail pod identifier.                |
| `AGENTMAIL_API_KEY`             | none    | AgentMail API key.                       |
| `XALGORIX_DISCORD_WEBHOOK`      | none    | Global Discord webhook.                  |
| `XALGORIX_DISCORD_MIN_SEVERITY` | none    | Minimum severity sent to Discord.        |
| `CAIDO_PORT`                    | `0`     | Caido proxy port. `0` means auto-detect. |
| `CAIDO_API_TOKEN`               | none    | Caido API token.                         |

### Rate Limits, Proxy, and Runtime

| Variable                       | Default      | Description                                        |
| ------------------------------ | ------------ | -------------------------------------------------- |
| `XALGORIX_RATE_LIMIT_REQUESTS` | `60`         | Dashboard requests per window.                     |
| `XALGORIX_RATE_LIMIT_WINDOW`   | `60`         | Dashboard rate-limit window in seconds.            |
| `XALGORIX_RATE_RPS`            | `10`         | Sustained outbound request rate.                   |
| `XALGORIX_RATE_BURST`          | `20`         | Outbound burst size.                               |
| `XALGORIX_USE_PROXY`           | `false`      | Enable proxy routing.                              |
| `XALGORIX_PROXY_URL`           | none         | Single proxy URL. Overrides proxy file.            |
| `XALGORIX_PROXY_FILE`          | none         | File containing one proxy per line.                |
| `XALGORIX_PROXY_ROTATION`      | `roundrobin` | Proxy rotation strategy: `roundrobin` or `random`. |
| `XALGORIX_TLS_SKIP_VERIFY`     | `false`      | Skip TLS verification for testing traffic.         |
| `XALGORIX_DISABLE_BROWSER`     | `false`      | Disable browser automation.                        |
| `XALGORIX_BROWSER_PATH`        | auto         | Custom Chrome/Chromium executable path.            |
| `XALGORIX_ALLOW_AUTO_INSTALL`  | root only    | Permit automatic package installation.             |
| `XALGORIX_AUTO_INSTALL_SUDO`   | `false`      | Permit sudo-prefixed auto-installs.                |

## Provider Prefixes

When `XALGORIX_API_BASE` is empty, Xalgorix infers provider defaults from the model prefix.

| Prefix       | Default API base                               |
| ------------ | ---------------------------------------------- |
| `openai/`    | `https://api.openai.com/v1`                    |
| `anthropic/` | `https://api.anthropic.com`                    |
| `deepseek/`  | `https://api.deepseek.com/v1`                  |
| `groq/`      | `https://api.groq.com/openai/v1`               |
| `google/`    | `https://generativelanguage.googleapis.com/v1` |
| `gemini/`    | `https://generativelanguage.googleapis.com/v1` |
| `ollama/`    | `http://localhost:11434/v1`                    |
| `minimax/`   | `https://api.minimax.io/v1`                    |

Model names are not hard-coded to this list. The Settings page accepts typed model IDs so newer provider models can be used without waiting for a UI dropdown update.

## CLI Reference

| Flag                   | Alias | Description                                |
| ---------------------- | ----- | ------------------------------------------ |
| `--web`                | `-w`  | Start the Web UI.                          |
| `--port <port>`        | `-p`  | Web UI port. Default: `9137`.              |
| `--bind <addr>`        | none  | Bind address. Default: `127.0.0.1`.        |
| `--target <target>`    | `-t`  | Target URL, host, IP, or path. Repeatable. |
| `--instruction <text>` | `-i`  | Custom scan instructions.                  |
| `--model <model>`      | `-m`  | Override `XALGORIX_LLM` for this run.      |
| `--update`             | `-up` | Update to the latest release.              |
| `--version`            | `-v`  | Print version.                             |
| `--start`              | none  | Install and start the system service.      |
| `--stop`               | none  | Stop the system service.                   |
| `--restart`            | none  | Restart the system service.                |
| `--uninstall`          | none  | Remove the system service.                 |
| `--help`               | `-h`  | Show help.                                 |

## API Summary

| Method   | Endpoint                     | Purpose                                       |
| -------- | ---------------------------- | --------------------------------------------- |
| `POST`   | `/api/scan`                  | Start or save a scan.                         |
| `POST`   | `/api/stop`                  | Stop all running scans.                       |
| `GET`    | `/api/status`                | Current global status.                        |
| `GET`    | `/api/scans`                 | List scans.                                   |
| `GET`    | `/api/scans/:id`             | Get scan detail.                              |
| `DELETE` | `/api/scans/:id`             | Delete a scan and its report data.            |
| `GET`    | `/api/report/:id`            | Download a PDF report.                        |
| `GET`    | `/api/instances`             | List live and historical instances.           |
| `GET`    | `/api/instances/:id/events`  | Get buffered event history.                   |
| `POST`   | `/api/instances/:id/stop`    | Stop a specific instance.                     |
| `POST`   | `/api/instances/:id/start`   | Start a saved or completed scan as a new run. |
| `POST`   | `/api/instances/:id/restart` | Restart with the same configuration.          |
| `POST`   | `/api/instances/:id/pause`   | Pause a running scan.                         |
| `POST`   | `/api/instances/:id/resume`  | Resume a paused scan.                         |
| `POST`   | `/api/upload-logo`           | Upload a report logo.                         |
| `POST`   | `/api/upload-targets`        | Upload a target list.                         |
| `GET`    | `/api/settings/environment`  | List editable environment settings.           |
| `POST`   | `/api/settings/environment`  | Save environment settings.                    |
| `GET`    | `/api/settings/llm`          | Get LLM settings.                             |
| `POST`   | `/api/settings/llm`          | Save LLM settings.                            |
| `GET`    | `/api/settings/agentmail`    | Get AgentMail settings.                       |
| `POST`   | `/api/settings/agentmail`    | Save AgentMail settings.                      |
| `GET`    | `/ws`                        | WebSocket live event stream.                  |

## Data Storage

Web-mode scan data is stored under:

```text
~/xalgorix-data/
|-- _saved/
|-- logos/
|-- queue_state.json
`-- <target>/
    `-- <date>/
        `-- <scan-id>/
            |-- scan.json
            `-- report.pdf
```

The server keeps historical scan records on disk so the UI can recover after refresh or restart.

## Development

| Task                        | Command                       |
| --------------------------- | ----------------------------- |
| Install Web UI dependencies | `make webui-install`          |
| Build everything            | `make build`                  |
| Run tests                   | `go test ./...`               |
| Run Web UI from source      | `go run ./cmd/xalgorix --web` |
| Run frontend dev server     | `make webui-dev`              |

## Safety Notes

- Use Xalgorix only against authorized targets.
- Do not run active testing against third-party systems without permission.
- Review scan instructions before launching.
- Configure rate limits and proxy settings to match engagement rules.
- Exposing the dashboard externally requires authentication.
- Auto-install is disabled by default for non-root users and should be enabled only when you trust the environment.

## License

Xalgorix is released under the MIT License. See [LICENSE](LICENSE).

## Links

| Resource      | Link                                                                             |
| ------------- | -------------------------------------------------------------------------------- |
| Documentation | [docs.xalgorix.com](https://docs.xalgorix.com)                                   |
| Issues        | [github.com/xalgord/xalgorix/issues](https://github.com/xalgord/xalgorix/issues) |
| Support       | [buymeacoffee.com/xalgord](https://buymeacoffee.com/xalgord)                     |
