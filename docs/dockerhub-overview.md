# Xalgorix — AI Autonomous Penetration Testing

**Self-hosted AI pentester that finds, exploits, and verifies real vulnerabilities.**

Most scanners *detect*. Xalgorix *proves* — an autonomous LLM agent works a full 22-phase methodology, then an independent verifier re-exploits every finding before it's reported, so you get proof with evidence, not a wall of maybes to triage.

This image is **batteries-included**: it's built on Kali Linux with hundreds of offensive-security tools preinstalled, and it keeps every package manager available so the agent can auto-install anything else it needs at runtime.

- 🧠 **An AI agent, not a template engine** — reasons about auth flows, business logic, IDOR/BOLA, and chained exploits signature scanners miss.
- ✅ **Exploit-verified findings** — a separate verifier reproduces each finding; inconclusive ones are flagged, never dressed up as confirmed.
- 🔒 **Self-hosted & private** — runs on your infrastructure with your own LLM key. No target data, keys, or findings leave your machine.
- 🧩 **Bring your own LLM** — OpenAI, Anthropic, DeepSeek, Gemini, Groq, Ollama, or MiniMax.
- 📄 **Audit-ready reports** — branded PDFs with CVSS scores, proof-of-concept, and remediation.

---

## Quick start

```bash
docker run --rm -p 9137:9137 \
  -e XALGORIX_LLM=minimax/MiniMax-M3 \
  -e XALGORIX_API_KEY=your_provider_api_key \
  -v xalgorix-data:/data \
  xalgord/xalgorix:latest
```

Then open **http://127.0.0.1:9137**.

> Use Xalgorix only against systems you own or are explicitly authorized to test.

---

## Reviewing GitHub pull requests (free, no install)

Prefer security review straight on your PRs? Install the **[Xalgorix GitHub App](https://github.com/apps/xalgorix/installations/new)** — it comments a security review on each pull request's diff (injection, broken auth/IDOR, SSRF, secrets, unsafe patterns), updates in place on new commits, and re-runs when you comment `@xalgorix review`. No workflow file, API key, or account required. This container image is for the deeper, self-hosted exploit-verified pentest.

---

## What's inside

An extensive toolset ships preinstalled — `nmap`, `nuclei`, `httpx`, `subfinder`, `dnsx`, `naabu`, `katana`, `ffuf`, `gobuster`, `dalfox`, `feroxbuster`, `sqlmap`, `masscan`, `nikto`, `whatweb`, `hydra`, SecLists, and the broader Kali web/vulnerability/fuzzing/passwords metapackages — plus Chromium for browser-assisted DAST. The Go, Rust (cargo), Python (pipx/pip), and npm toolchains stay in the image, so the agent can install anything not baked in, on demand.

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `XALGORIX_LLM` | ✅ | Model, usually with a provider prefix, e.g. `minimax/MiniMax-M3`, `openai/gpt-5.4`. |
| `XALGORIX_API_KEY` | ✅ | API key for the configured LLM provider. |
| `XALGORIX_API_BASE` | — | Custom OpenAI-compatible base URL. |
| `XALGORIX_USERNAME` / `XALGORIX_PASSWORD` | — | Dashboard auth. **Required** before exposing the dashboard beyond localhost. |
| `XALGORIX_DATA_DIR` | — | Scan output / reports location. Defaults to `/data` (mount a volume). |

- **Port:** `9137` (dashboard + API). The container binds `0.0.0.0` internally; publish with `-p 9137:9137`.
- **Volume:** mount `/data` to persist scans and reports across restarts.

## Tags

| Tag | Meaning |
| --- | --- |
| `latest` | Most recent release. |
| `X.Y.Z` (e.g. `4.5.50`) | A specific, immutable release. |
| `X.Y` (e.g. `4.5`) | Latest patch of that minor line. |

**Platform:** `linux/amd64`. For `arm64` hosts, use the one-line installer or build from source (see the repo).

## Security notes

- The container runs as **root by design** — the engine only enables runtime tool auto-install for uid 0, and `apt`/`go`/`cargo` installs need system write access. Treat the container as a disposable, network-isolated scanning sandbox.
- **Never expose the dashboard publicly without `XALGORIX_USERNAME`/`XALGORIX_PASSWORD`.** The server refuses external binding without auth.
- No scan data, API keys, or findings leave the container unless you configure outbound integrations (Discord/Telegram/webhooks).

## Links

- **Source & docs:** https://github.com/xalgord/xalgorix
- **Documentation:** https://docs.xalgorix.com
- **Hosted (no install):** https://www.xalgorix.com
- **One-line install (any Linux, amd64/arm64):** `curl -sSL https://www.xalgorix.com/install | bash`

Released under the Apache License 2.0.
