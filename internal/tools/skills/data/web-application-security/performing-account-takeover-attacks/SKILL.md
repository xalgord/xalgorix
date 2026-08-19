---
name: performing-account-takeover-attacks
description: Systematically testing authentication, recovery, and identity flows for account takeover (ATO) — including
  Unicode/normalization email collisions, reusable reset/magic links, pre-account-takeover, response manipulation,
  email-verification bypass, session/cookie reuse, and QR/device-code login abuse. Activates when assessing login,
  signup, password reset, email change, SSO/OAuth, or cross-device login flows.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- account-takeover
- authentication
- owasp
- web-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Performing Account Takeover Attacks

## When to Use

- During authorized assessments of any authentication, registration, or account-recovery flow
- When testing password reset, email change, magic-link, or invite flows for token reuse and host-header poisoning
- When the app supports third-party SSO/OAuth/OIDC and may normalize emails differently than the IdP
- When testing cross-device login surfaces (desktop QR login, TV/device-code, "approve on your phone")
- When you have a limited XSS, CORS misconfig, CSRF, or subdomain takeover that could pivot into ATO

## Prerequisites

- **Authorization**: Engagement scope covering authentication and at least two test accounts (attacker + victim) you own
- **Burp Suite**: For intercepting and replaying reset/verification requests and manipulating headers/responses
- **Two browsers/profiles**: To test session/link binding and reuse across contexts
- **OOB infra**: A domain you control for redirect/exfil tests and a webmail address for confusable-email tests
- **gau / waybackurls**: To hunt for additional reset/magic links in historical data

## Critical: Variants Most Often Missed

ATO scanners check "can I brute force the password". The high-impact bugs live
in the recovery and identity-binding logic. Test every variant below.

```text
# 1. Unicode / normalization email collision (THE classic miss)
victim@gmail.com  vs  vićtim@gmail.com   # app normalizes AFTER binding the artifact
victim@ćompany.com                       # attack the DOMAIN part if IdP verifies local part
# Also compare DB collation vs SMTP vs OAuth/OIDC interpretation of the same mailbox.

# 2. Reusable / non-expiring reset or magic link
#    - works after an email change
#    - works from a 2nd browser/device/profile
#    - find more links via gau / wayback / scan.io

# 3. Pre-account-takeover
#    Register victim@x.com BEFORE they sign up; wait for them to confirm via OAuth.
#    Or: register + verify attacker@x.com, then change email to victim@x.com with
#    NO secondary verification -> verification bypass.

# 4. Password-reset / host-header poisoning
Host: attacker.com
X-Forwarded-For: attacker.com
Referer + Origin + Host all = attacker.com   # then use "resend email"

# 5. Response manipulation (boolean / status oracle)
#    Change 4xx -> 200 OK ; body -> {"success":true} or {}
#    Change auth response false -> true

# 6. Open redirect in magic-link redirect_url/next/return_to/callback
#    Land the post-login redirect on attacker origin first to steal token.

# 7. Session does not invalidate (old cookies keep working after logout / re-login).

# 8. QR / device-code login abuse (treat qrId/device_code like reset tokens):
#    unbound session, reusable codes (double login), predictable codes, weak approval context.

# 9. Privileged param in an authenticated flow:
#    "update security questions" takes a username param -> overwrite ANY account's recovery data.
```

Magic-link / passwordless probe:

```http
POST /api/auth/magic-link HTTP/1.1
Host: target.tld
Content-Type: application/json

{"email":"victim@target.tld","redirect_url":"https://attacker.tld/callback"}
```

Security-question overwrite (IDOR in an authenticated reset flow):

```http
POST /reset.php HTTP/1.1
Host: target.tld
Cookie: PHPSESSID=<low-priv-session>
Content-Type: application/x-www-form-urlencoded

username=admin&new_answer1=A&new_answer2=B&new_answer3=C
```

### How to CONFIRM a hit (avoid false negatives)

- **Email collision**: you receive the victim's reset artifact / are logged in as the victim after submitting a confusable address. Confirm the session resolves to the victim's `userId`, not just a similar email string.
- **Reusable link**: the SAME token authenticates in a second browser, or still works after the victim changes their email/password — confirmed reuse.
- **Pre-ATO**: after the victim confirms via OAuth, your pre-set password still logs into their account.
- **Response manipulation**: forcing `200`/`{"success":true}` actually advances the flow to an authenticated state (you reach a post-auth page or get a valid session cookie), not just a cosmetic UI change.
- **QR/device-code**: approving on one device authenticates a DIFFERENT browser, or the same code logs in twice.
- Always verify with a concrete post-auth action (read victim-only data, change a victim setting) and capture the victim `userId`/email from an authenticated response.

## Workflow

### Step 1: Map the Auth & Recovery Surface
Enumerate login, signup, password reset, email change, invite, SSO callback, and cross-device login endpoints. Note which artifacts are tokens vs links vs codes and where each is delivered (email, URL, fragment, JSON body).

### Step 2: Test Email Normalization Collisions
```text
# Create attacker account with a confusable of the victim address you control mail for
vićtim@yourmaildomain   (or victim+unicode variants)
# Drive forgot-password / email-change / invite with the confusable value
# Watch whether the artifact binds to your raw Unicode address but matches the victim row
```
Cross-check: does the backend send mail to the user-supplied address or to the canonical DB address? If user-supplied, it is usually exploitable.

### Step 3: Attack Reset / Magic-Link Tokens
```bash
# Reuse: capture a valid reset link, then redeem it from a 2nd browser/device
# Persistence: redeem AFTER changing the account email
# Discovery: harvest stale links
gau target.example.com | grep -Ei "reset|token|magic|verify|confirm"
```
Verify single-use and browser/app binding by opening links across two browsers, webmail vs native mail, and browser vs native app.

### Step 4: Host-Header & Response Manipulation
```http
POST /api/forgot-password HTTP/1.1
Host: attacker.com
X-Forwarded-For: attacker.com

{"email":"victim@target.tld"}
```
If the reset email links to `attacker.com/...?token=...`, the victim clicking it leaks the token. Separately, intercept auth/verify responses and flip status/body (`200 OK`, `{"success":true}`) to test client-side trust.

### Step 5: Pre-Account-Takeover & Verification Bypass
```text
A) Register victim@x.com + set password. Wait for victim to sign up via OAuth.
   If regular signup is later "confirmed", your password may still work.
B) Register + verify attacker@x.com, then change email to victim@x.com.
   If no secondary verification on change, victim@x.com is now attacker-controlled.
```

### Step 6: Cross-Device / QR Login Abuse
```text
1. Start QR/device-code flow in the ATTACKER browser; capture the polling/status endpoint and qrId/device_code.
2. Reuse the same qrId/device_code from a SECOND browser or after first login completes (double login).
3. Swap session identifiers between two accounts; check if approval follows the CODE not the originating session.
4. Brute-force short/sequential qrId values; race parallel polling.
5. Replay a stale/redeemed code from the wrong context.
```

### Step 7: Pivot From Other Bugs
Chain CORS misconfig (steal auth data), CSRF (force email/password change), XSS (steal cookies/localStorage; attribute-only login XSS can hook `onkeypress` and exfil keystrokes via `new Image().src`), or subdomain takeover + cookie fixation/tossing.

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Normalization Collision** | UI/DB/SMTP/IdP interpret the same Unicode mailbox differently, binding artifacts to the attacker |
| **Pre-Account-Takeover** | Attacker registers the victim's email before signup; victim's later OAuth confirm hands over the account |
| **Verification Bypass** | Changing a verified email to the victim's with no re-verification authenticates the attacker as the victim |
| **Host-Header Poisoning** | Reset email built from attacker-controlled Host/XFF/Referer/Origin points the link at attacker domain |
| **Response Manipulation** | Flipping client-trusted status/body (`200`, `{"success":true}`, `false->true`) advances auth |
| **Token Reuse** | Reset/magic links that are multi-use, cross-device, or survive email change |
| **QR/Device-Code Abuse** | Unbound sessions, reusable/predictable codes, weak approval context in cross-device login |
| **Session Persistence** | Old cookies still valid after logout/re-login |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Intercept/replay recovery requests, manipulate headers and responses, compare token binding |
| **gau / waybackurls** | Discover additional/stale reset and magic links from historical crawl data |
| **Two browsers/profiles** | Test single-use and session/link binding across contexts |
| **OOB domain** | Capture leaked tokens via open-redirect / host-header poisoning |
| **Unicode/confusable generators** | Produce normalization-collision email variants |
| **OAuth/OIDC debug tooling** | Inspect IdP callback emails and token binding for SSO ATO |

## Common Scenarios

### Scenario 1: Unicode Email Collision
The app stores `victim@gmail.com` but a permissive collation matches `vićtim@gmail.com`. The reset token is bound to the raw attacker-supplied address, so the attacker receives a working reset for the victim's account.

### Scenario 2: One-Click Email-Change Takeover
The attacker initiates an email change, receives the confirmation link, and sends it to the victim. When the victim clicks it, the victim's email is changed to the attacker's value; the attacker then resets the password and owns the account.

### Scenario 3: QR Login Session Swap
A desktop QR login uses a reusable `qrId`. The attacker starts the flow, captures `qrId`, and tricks the victim into approving it; approval follows the code, authenticating the attacker's browser into the victim's account.

## Output Format

```
## Account Takeover Finding

**Vulnerability**: Account Takeover via <variant, e.g. email-change verification bypass>
**Severity**: Critical (CVSS 8.8)
**Location**: POST /api/account/email  (email change flow)
**OWASP Category**: A07:2021 - Identification and Authentication Failures

### Reproduction Steps
1. Register and verify attacker@test.com
2. Change account email to victim@test.com (no secondary verification sent)
3. Backend now treats victim@test.com as verified and attacker-controlled
4. Log out; request password reset for victim@test.com -> reset mail arrives in attacker mailbox
5. Authenticate as victim; confirmed via victim-only profile data (userId 4471)

### Evidence
| Step | Observation |
|------|-------------|
| Email change | 200 OK, no verification email to victim |
| Reset request | Token delivered to attacker mailbox |
| Post-auth | /api/me returns victim userId and PII |

### Impact
Full takeover of any account by email address, with no access to the victim's
mailbox required for the change step.

### Recommendation
1. Require re-verification (and current-password/2FA) on email change
2. Bind reset/magic-link tokens to a single use, short TTL, and the originating session/device
3. Build reset URLs from a server-side allowlisted host, never from request headers
4. Canonicalize emails consistently across UI, DB, SMTP, and IdP; reject confusables
5. Never trust client-side status/body for auth decisions; invalidate sessions on logout and credential change
```
