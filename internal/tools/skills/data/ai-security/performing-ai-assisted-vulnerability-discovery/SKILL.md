---
name: performing-ai-assisted-vulnerability-discovery
description: Using LLMs to accelerate vulnerability research and pentest workflows — generating syntax-valid fuzzing
  seeds and evolving grammars, fine-tuned mutation dictionaries, parallel agent-based proof-of-vulnerability generation,
  and evidence-driven passive analysis of real HTTP traffic via the Burp MCP server. Covers concrete prompts, AFL++/
  libFuzzer wiring, and Burp+Codex/Gemini/Ollama MCP setup.
domain: cybersecurity
subdomain: ai-security
tags:
- penetration-testing
- ai-security
- fuzzing
- vulnerability-research
- burp-mcp
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Performing AI-Assisted Vulnerability Discovery

## When to Use

- During authorized vulnerability research where complex input formats (SQL, URLs, custom/binary protocols) stall a blind fuzzer
- When bootstrapping a coverage-guided fuzzer (AFL++, libFuzzer, Honggfuzz) that needs syntax-valid, security-relevant seeds
- When you have crash candidates and need to scale proof-of-vulnerability (PoV) generation across many agents/models
- When triaging large volumes of real Burp HTTP traffic and want evidence-driven passive analysis + report drafting
- When working under cost/time budgets (bug-bounty, CTF, AIxCC-style cyber reasoning systems)

## Critical: Techniques Most Often Missed

Teams either ignore LLMs entirely or paste code and hope. The high-value patterns are about
**feeding the model coverage feedback** and **keeping the human/Burp as the source of truth**.

### 1. LLM seed generation for semantic validity (deeper coverage early)

```prompt
SYSTEM: You are a helpful security engineer.
USER: Write a Python3 program that prints 200 unique SQL injection strings targeting common
anti-pattern mistakes (missing quotes, numeric context, stacked queries). Ensure length <= 256
bytes/string so they survive common length limits.
```
```bash
python3 gen_sqli_seeds.py > seeds.txt
afl-fuzz -i seeds.txt -o findings/ -- ./target @@
```
Ask for a single self-contained script and tell it to diversify encoding (UTF-8, URL-encoded, UTF-16-LE).

### 2. Coverage-feedback grammar evolution ("Grammar Guy")

```prompt
The previous grammar triggered 12 % of the program edges. Functions not reached: parse_auth,
handle_upload. Add / modify rules to cover these.
```
```python
for epoch in range(MAX_EPOCHS):
    grammar = llm.refine(grammar, feedback=coverage_stats)   # use diff+patch, not full rewrite
    save(grammar, f"grammar_{epoch}.txt")
    coverage_stats = run_fuzzer(grammar)                     # stop when Δcoverage < ε
```

### 3. Fine-tuned mutation dictionary for memory-safety bugs

```text
# AFL_CUSTOM_MUTATOR dictionary entries suggested by a model fine-tuned on vuln patterns
{"pattern":"%99999999s"}
{"pattern":"AAAAAAAA....<1024>....%n"}
```
Prompt: "Give mutation dictionary entries likely to break memory safety in function X." Empirically >2× faster time-to-crash.

### 4. Parallel agent-based PoV generation

Spawn many lightweight agents (different models/temperatures); each reproduces the crash with `gdb`,
proposes a minimal payload, validates it in a sandbox, and re-queues failures as new fuzz seeds.

### How to CONFIRM a hit (avoid false negatives / hallucinations)

- **Deterministic PoV**: the model's claimed bug must reproduce — feed the exact input to the target
  under `gdb`/ASan and confirm the same crash PC / sanitizer message. No reproduction = not a finding.
- **Coverage delta**: a new grammar/seed set is "working" only if edges/blocks hit actually increase; measure, don't trust the prompt.
- **Evidence-bound (Burp MCP)**: every reported web finding must cite the real request/response in
  Burp — the model is for analysis/reporting, not blind scanning. Re-check the raw traffic.
- Treat all LLM output as untrusted hypotheses; validate before submitting (wrong patches/PoVs cost points/credibility).

## Workflow

### Step 1: Generate and load seeds

```bash
python3 gen_sqli_seeds.py > seeds.txt          # or XSS/path-traversal/binary-blob variants
afl-fuzz -i seeds.txt -o findings/ -- ./target @@
```

### Step 2: Evolve a grammar against coverage

```text
1. Prompt the model for an initial ANTLR/Peach/libFuzzer grammar.
2. Fuzz N minutes; collect edges/blocks hit.
3. Summarize uncovered functions, feed back, ask for diff/patch rules.
4. Merge, re-fuzz, repeat until Δcoverage < ε (mind the token budget).
```

### Step 3: Add a fine-tuned custom mutator

```text
Run static analysis -> function list + AST.
Prompt fine-tuned model for mutation-dictionary tokens per risky function (sprintf wrappers, etc.).
Wire tokens into AFL_CUSTOM_MUTATOR.
```

### Step 4: Scale PoV generation and triage

```text
Static/dynamic analysis -> bug candidates (crash PC, input slice, sanitizer msg).
Orchestrator -> N agents: reproduce (gdb), propose payload, validate in sandbox, submit on success.
Failed attempts re-queue as coverage seeds (feedback loop).
```

### Step 5: Multi-bug super-patch (optional, scoring-aware)

```prompt
Here are 10 stack traces + file snippets. Identify the shared mistake and generate a unified diff
fixing all occurrences.
```
Interleave confirmed (PoV-validated) and speculative patches at a tuned ratio (e.g. 2 speculative : 1 confirmed).

### Step 6: Evidence-driven web analysis with Burp MCP

```bash
# Install the Burp MCP Server BApp (listens on 127.0.0.1:9876), extract the proxy JAR, point a client at the SSE endpoint:
cat > ~/.codex/config.toml <<'EOF'
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
EOF
codex      # then run /mcp to verify the Burp tools list
```
If the MCP handshake fails on strict `Origin`/header checks, front it with a local Caddy reverse proxy that pins `Host`/`Origin` to `127.0.0.1:9876` and strips `User-Agent`/`Accept`/`Accept-Encoding`/`Connection` (which trigger Burp's 403 during SSE init):
```bash
brew install caddy
caddy run --config ~/burp-mcp/Caddyfile &
```

### Step 7: Run evidence-focused analysis prompts (burp-mcp-agents)

```text
passive_hunter.md  broad passive surfacing | idor_hunter.md  IDOR/BOLA/tenant drift
auth_flow_mapper.md  auth vs unauth path diff | ssrf_redirect_hunter.md  SSRF/open-redirect
logic_flaw_hunter.md  multi-step logic flaws | report_writer.md  evidence-focused reporting
```
Prefer **local models** (Ollama: `deepseek-r1:14b` ~16GB, `gpt-oss:20b` ~20GB) when traffic holds secrets; share only the minimum evidence per finding. Tag your traffic so it is auditable:
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **LLM seed generation** | Model emits syntax-valid, security-relevant inputs so the fuzzer reaches deep branches early |
| **Grammar evolution** | Iteratively refine an input grammar using coverage feedback (Grammar Guy pattern) |
| **Custom mutator dict** | Fine-tuned model supplies tokens (`%n`, oversized `%s`) that break memory safety faster |
| **Agent-based PoV** | Many parallel LLM agents reproduce/validate crashes; failures recycle as new seeds |
| **Super-patch** | One unified diff that fixes a root cause shared across multiple crashes |
| **Evidence-driven review** | Burp stays source of truth; the LLM reasons over real requests/responses, no blind scanning |
| **Privacy mode** | Local backends / redaction prevent leaking cookies/PII to cloud models |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **AFL++ / libFuzzer / Honggfuzz** | Coverage-guided fuzzers consuming LLM seeds, grammars, and custom mutators |
| **LLM (GPT/Claude/Mixtral/Llama)** | Seed/grammar generation, mutation dicts, PoV reasoning, patch synthesis |
| **Burp MCP Server (BApp)** | Exposes intercepted HTTP(S) traffic to MCP clients on `127.0.0.1:9876` |
| **mcp-proxy.jar + Caddy** | Bridge stdio↔SSE and normalize headers for the strict MCP handshake |
| **Codex / Gemini CLI / Ollama** | MCP clients/backends (cloud or local) for traffic analysis |
| **burp-mcp-agents** | Prompt pack (passive/idor/ssrf/logic/report hunters) + launcher helpers |
| **Burp AI Agent** | Couples local/cloud LLMs with passive/active analysis and 53+ MCP tools |

## Common Scenarios

### Scenario 1: Stalled parser fuzzing
A binary protocol parser shows flat coverage. LLM-generated syntax-valid seeds plus a coverage-evolved grammar push edges from 12% upward and surface a crash in `handle_upload`.

### Scenario 2: Crash-to-PoV at scale
Dozens of ASan crashes need PoVs under a deadline. Parallel agents reproduce each in `gdb`, generate minimal payloads, and validate in a sandbox, recycling misses as seeds.

### Scenario 3: Passive bug bounty triage
Hundreds of Burp requests are analyzed via the `idor_hunter.md` and `ssrf_redirect_hunter.md` prompts through a local Ollama model, flagging object-ID drift backed by real request/response evidence.

### Scenario 4: Sensitive-data engagement
Traffic contains session cookies/PII, so a local `deepseek-r1:14b` backend with STRICT privacy mode is used, sharing only minimal evidence and keeping an integrity-hashed audit log.

## Output Format

```
## AI-Assisted Discovery Finding

**Technique**: LLM-assisted fuzzing / evidence-driven Burp MCP analysis
**Severity**: Per confirmed vulnerability (set after PoV reproduction)
**Target**: <binary/function or HTTP endpoint>

### Method
- Seeds/grammar: <prompt + coverage delta achieved, e.g. 12% -> 41% edges>
- PoV: <agent/model that reproduced; gdb crash PC + sanitizer message>
- Burp evidence: <request/response IDs cited from Burp history>

### Validation
| Check | Result |
|-------|--------|
| Deterministic reproduction | yes (ASan heap-buffer-overflow @ parse_auth) |
| Coverage increase measured | +29% edges |
| Evidence cited from Burp | req #482 / resp #482 |

### Recommendation
1. Fix the confirmed root cause; consider the super-patch diff if multiple crashes share it
2. Add the generated seeds/grammar to regression fuzzing CI
3. Keep cloud LLM usage in privacy/redaction mode; prefer local models for sensitive traffic; require PoV reproduction before reporting
```
