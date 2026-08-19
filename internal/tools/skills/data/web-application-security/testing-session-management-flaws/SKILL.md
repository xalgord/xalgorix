---
name: testing-session-management-flaws
description: Identifying and exploiting weaknesses in session handling including fixation, weak token entropy,
  missing cookie flags, improper invalidation on logout/password change, and client-side session tampering.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- session-management
- session-fixation
- cookies
- access-control
- owasp
- burpsuite
- web-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Testing Session Management Flaws

## When to Use

- During authorized penetration tests when assessing how an application creates, transports, and destroys sessions
- When the application issues cookies or tokens after login and you need to verify they are bound, scoped, and invalidated correctly
- For validating that logout, password change, email change, and 2FA activation revoke existing sessions
- When testing multi-device / multi-IP scenarios where stolen or replayed cookies must be detected
- During bug bounty programs targeting broken authentication and session handling (OWASP A07:2021)

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target application
- **Burp Suite Professional**: Proxy + Repeater + Sequencer (token randomness analysis)
- **Two test accounts**: User A (attacker) and User B (victim), ideally on two browsers/profiles
- **Two network egress points**: e.g. home IP + VPN/cloud box, to test IP-bound sessions and replay
- **curl / httpie**: For manual cookie crafting and replay outside the browser
- **Browser DevTools**: Application > Storage to inspect cookies, flags, and expiry

## Critical: Checks Most Often Missed

Session bugs are missed when testers only confirm "login works." For every
session, work through this checklist:

- **Find the REAL session cookie first**: apps set many cookies (analytics, CSRF,
  consent). Delete cookies one at a time and re-request a protected page — the one
  whose removal logs you out is the session cookie. Test only that one for the
  flaws below.
- **No invalidation on security events** (the highest-signal miss): capture a
  valid cookie, then in another session perform **logout**, **password change**,
  **email change**, or **2FA activation**. Replay the OLD cookie afterwards. If it
  still works, sessions are not revoked — critical for stolen-session scenarios.
- **Session fixation**: record the cookie value BEFORE authenticating, log in,
  then compare. If the session identifier does NOT change on privilege elevation,
  a pre-set cookie survives login and can be fixed onto a victim.
- **Replay from a different IP / machine / User-Agent**: paste the cookie into a
  request from a second egress IP. If it is accepted with no re-auth or alert, the
  session is not bound to client context.
- **Concurrent logins**: log in as the same user from two machines simultaneously.
  Both staying valid with no notification is often in-scope for sensitive apps.
- **Client-side session data**: base64/JSON-decode the cookie. If it contains
  `user=`, `role=`, `email=`, `isAdmin=` etc., tamper with another user's value and
  replay — server may trust the cookie blindly.
- **Token entropy**: flip ONE bit/byte at a time across the token and replay to
  find which segment is actually validated; a short validated segment = brute
  forceable. Run Burp Sequencer on 5,000+ tokens for true randomness.
- **Missing cookie hardening**: check every session cookie for `HttpOnly`,
  `Secure`, `SameSite`, an over-broad `Domain`, and an excessive/`Max-Age=∞` expiry.
- **Token leakage to third parties**: look for the session value in the URL, in
  `Referer` headers sent to external hosts, or in analytics/error beacons.

## Workflow

### Step 1: Identify the Real Session Cookie Among Many

Enumerate all cookies and determine which one actually maintains the session.

```bash
# Capture the full Set-Cookie set right after login
curl -s -i -X POST "https://target.example.com/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=userA&password=Passw0rd!" | grep -i '^set-cookie:'

# Typical output — only ONE of these is the session:
# Set-Cookie: SESSIONID=8f2a...; Path=/; HttpOnly
# Set-Cookie: _ga=GA1.2.123; Path=/
# Set-Cookie: csrftoken=abc; Path=/
# Set-Cookie: cookieconsent=1; Path=/

# Isolate the session cookie: remove one at a time and hit a protected page.
SESSION="SESSIONID=8f2a9c...; csrftoken=abc; _ga=GA1.2.123"

# Drop _ga -> still authenticated? (expected yes)
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Cookie: SESSIONID=8f2a9c...; csrftoken=abc" \
  "https://target.example.com/account"

# Drop SESSIONID -> logged out / 302 to /login => SESSIONID is the session cookie
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Cookie: csrftoken=abc; _ga=GA1.2.123" \
  "https://target.example.com/account"
```

### Step 2: Audit Cookie Security Flags, Scope, and Expiry

Inspect HttpOnly / Secure / SameSite, the Domain scope, and lifetime.

```bash
# Pull just the session Set-Cookie line and eyeball the attributes
curl -s -i -X POST "https://target.example.com/login" \
  --data "username=userA&password=Passw0rd!" \
  | grep -i 'set-cookie:.*SESSIONID'

# Findings to flag:
#  - Missing HttpOnly  -> readable via document.cookie (XSS can steal it)
#  - Missing Secure    -> sent over plain HTTP, sniffable
#  - SameSite=None (no Secure) or absent -> CSRF / cross-site send
#  - Domain=.example.com -> shared with every subdomain (broad theft surface)
#  - Expires far future / Max-Age huge / no expiry -> long-lived stolen sessions

# Confirm the cookie is actually sent over cleartext HTTP (Secure missing)
curl -s -i "http://target.example.com/account" \
  -H "Cookie: SESSIONID=8f2a9c..." | head -n1
# 200 over http:// with private data = Secure flag missing / not enforced

# Confirm HttpOnly from the browser console (should be inaccessible):
#   document.cookie   // session value must NOT appear here
```

### Step 3: Test Session Fixation (Pre/Post-Auth Comparison)

Verify the session identifier rotates on authentication.

```bash
# 1) Get a pre-auth (anonymous) session cookie by visiting the login page
curl -s -i "https://target.example.com/login" | grep -i 'set-cookie:.*SESSIONID'
# -> SESSIONID=PRE_AUTH_VALUE_1111

# 2) Authenticate USING that same cookie (simulate a planted/fixed value)
curl -s -i -X POST "https://target.example.com/login" \
  -H "Cookie: SESSIONID=PRE_AUTH_VALUE_1111" \
  --data "username=userA&password=Passw0rd!" \
  | grep -i 'set-cookie:.*SESSIONID'

# 3) Compare:
#   - New value issued after login            => SAFE (rotation happens)
#   - SESSIONID still = PRE_AUTH_VALUE_1111    => SESSION FIXATION
#     An attacker who plants PRE_AUTH_VALUE_1111 on a victim (via link/XSS)
#     gains the victim's authenticated session after they log in.

# Confirm exploitability: replay the pre-auth value AFTER victim login
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Cookie: SESSIONID=PRE_AUTH_VALUE_1111" \
  "https://target.example.com/account"   # 200 with victim data = confirmed
```

### Step 4: Test Token Entropy by Bit/Byte Mutation

Find which part of the token is actually validated and measure randomness.

```bash
# Original token
TOK="A1B2C3D4E5F6G7H8I9J0"

# Mutate one character/byte at a time and replay; record which positions
# break the session vs. which are ignored (ignored = not part of secret).
for i in $(seq 0 $((${#TOK}-1))); do
  mutated="${TOK:0:$i}X${TOK:$((i+1))}"
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Cookie: SESSIONID=$mutated" \
    "https://target.example.com/account")
  echo "pos $i -> $code"
done
# If only positions 0-7 affect validity, the effective secret is 8 chars
# -> dramatically smaller keyspace, possibly brute forceable.

# Measure true randomness across many freshly issued tokens with Burp Sequencer:
# Burp > send a login response to Sequencer > "Live capture" 5000+ tokens
# > Analyze. Look for low effective entropy bits, structure, timestamps,
#   or incrementing counters embedded in the token.
```

### Step 5: Test Invalidation on Logout, Password/Email Change, and 2FA

Confirm security-relevant events revoke existing sessions.

```bash
# Capture a known-good cookie for User A
COOKIE="SESSIONID=8f2a9c..."

# --- Logout test ---
# In a SECOND session/browser, click Logout for User A. Then replay COOKIE:
curl -s -o /dev/null -w "after-logout: %{http_code}\n" \
  -H "Cookie: $COOKIE" "https://target.example.com/account"
# 200 = session NOT invalidated on logout (server only cleared client cookie)

# --- Password change test ---
# Change User A's password in another session, then replay the OLD cookie:
curl -s -o /dev/null -w "after-pw-change: %{http_code}\n" \
  -H "Cookie: $COOKIE" "https://target.example.com/account"
# 200 = old sessions survive password reset (critical for compromised creds)

# --- Email change & 2FA activation tests (same pattern) ---
curl -s -o /dev/null -w "after-email-change: %{http_code}\n" \
  -H "Cookie: $COOKIE" "https://target.example.com/account"
curl -s -o /dev/null -w "after-2fa-enable: %{http_code}\n" \
  -H "Cookie: $COOKIE" "https://target.example.com/account"
# Any 200 after these events = stale session remains usable.
```

### Step 6: Test Concurrent / Cross-IP Replay and Client-Side Session Data

Check binding to client context and whether the cookie carries trusted data.

```bash
# --- Concurrent login ---
# Log in as User A from machine 1 and machine 2 at the same time.
# Both sessions valid + no notification = no concurrent-session control.

# --- Replay from a different IP / User-Agent ---
# Take a cookie issued from IP1 and replay it from IP2 (VPN/cloud box):
curl -s -o /dev/null -w "%{http_code}\n" \
  -A "Mozilla/5.0 (different-UA)" \
  -H "Cookie: SESSIONID=8f2a9c..." \
  "https://target.example.com/account"
# 200 from a new IP/UA with no step-up = session not bound to context.

# --- Client-side session data tampering ---
# Decode a stateless/looking cookie:
echo "eyJ1c2VyIjoidXNlckEiLCJyb2xlIjoidXNlciJ9" | base64 -d
# -> {"user":"userA","role":"user"}
# Re-encode another user / elevated role and replay:
NEW=$(echo -n '{"user":"admin","role":"admin"}' | base64)
curl -s -H "Cookie: session=$NEW" "https://target.example.com/account" | head
# Accepted with admin context = server trusts unsigned client-side session data.

# --- Token leakage to third parties ---
# Look for the session value in URLs and Referer to external hosts:
#   - grep Burp history for the token in query strings
#   - load a page with an external <img>/<script> and check the outbound
#     Referer header carries ?sessionid=... to a third-party domain.
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Session Fixation** | Identifier set before login is not rotated, letting an attacker fix a known value onto a victim |
| **Token Entropy** | Amount of unpredictability in a session token; low entropy enables guessing/brute force |
| **HttpOnly** | Cookie flag preventing JavaScript (`document.cookie`) access, mitigating XSS-based theft |
| **Secure** | Cookie flag restricting transmission to HTTPS only, preventing cleartext sniffing |
| **SameSite** | Cookie flag (Strict/Lax/None) controlling cross-site sending; defends against CSRF |
| **Cookie Scope** | `Domain`/`Path` attributes; an over-broad `Domain=.example.com` shares the cookie with all subdomains |
| **Session Invalidation** | Server-side destruction of a session on logout or credential/security changes |
| **Stateless Session** | Session data stored client-side (cookie/JWT); must be signed or it can be tampered |
| **Concurrent Session Control** | Policy limiting or alerting on simultaneous active sessions for one account |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Proxy to capture cookies, Repeater to replay, Sequencer to measure token randomness |
| **Burp Sequencer** | Statistical analysis of token entropy across thousands of samples |
| **EditThisCookie / browser DevTools** | Inspect and edit cookies, view flags, domain scope, and expiry |
| **curl / httpie** | Manual cookie crafting, cross-IP replay, and flag verification |
| **jwt_tool** | Decode and tamper with JWT-based session tokens when used as sessions |
| **OWASP ZAP** | Free proxy alternative with session management testing add-ons |

## Common Scenarios

### Scenario 1: Session Survives Password Reset
After a user changes their password (often because they suspect compromise), the application generates a new session but leaves all previously issued sessions active. An attacker with a stolen cookie retains access indefinitely.

### Scenario 2: Pre-Auth Cookie Fixation
The login flow reuses the anonymous `SESSIONID` issued on the login page instead of rotating it. An attacker plants a known `SESSIONID` on a victim via a crafted link; once the victim logs in, the attacker's pre-known value is now authenticated.

### Scenario 3: Trusted Client-Side Role Cookie
A `session` cookie is base64-encoded JSON `{"user":"bob","role":"user"}` with no signature. Editing `role` to `admin` and replaying grants administrative access because the server trusts the cookie contents.

### Scenario 4: Missing HttpOnly Enables Cookie Theft
The session cookie lacks `HttpOnly`, so a reflected XSS payload reads `document.cookie` and exfiltrates the session, allowing full account takeover without credentials.

## Output Format

```
## Session Management Finding

**Vulnerability**: Session Not Invalidated on Password Change
**Severity**: High (CVSS 8.1)
**Location**: POST /account/change-password and session store
**OWASP Category**: A07:2021 - Identification and Authentication Failures

### Reproduction Steps
1. Log in as User A and capture session cookie SESSIONID=8f2a9c...
2. In a second browser, change User A's password
3. Replay the original SESSIONID against GET /account
4. Observe HTTP 200 with full account access using the pre-change cookie

### Affected Behaviors
| Event | Old Session After Event | Expected |
|-------|-------------------------|----------|
| Logout | Still valid (200) | Invalidated |
| Password change | Still valid (200) | All sessions revoked |
| Email change | Still valid (200) | All sessions revoked |
| 2FA activation | Still valid (200) | Re-authentication required |

### Cookie Hardening Gaps
| Flag/Attribute | Observed | Risk |
|----------------|----------|------|
| HttpOnly | Missing | XSS cookie theft |
| Secure | Missing | Cleartext interception |
| SameSite | Absent | CSRF / cross-site send |
| Domain | .example.com | Shared across all subdomains |

### Impact
- Stolen or leaked sessions remain valid after the victim takes remediation steps
- Account takeover persists through password reset, defeating incident response
- Token entropy reduced to effective 8 characters, enabling offline guessing

### Recommendation
1. Rotate the session identifier on every authentication and privilege change
2. Destroy all server-side sessions on logout, password change, email change, and 2FA enrollment
3. Set HttpOnly, Secure, and SameSite=Lax/Strict on the session cookie; scope Domain tightly
4. Generate session tokens from a CSPRNG with >=128 bits of entropy
5. Bind sessions to client context and enforce concurrent-session limits with alerting
```
