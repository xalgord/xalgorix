---
name: performing-phishing-simulation-with-gophish
description: GoPhish is an open-source phishing simulation framework used by security teams to conduct authorized phishing
  awareness campaigns. It provides campaign management, email template creation, landing pag
domain: cybersecurity
subdomain: phishing-defense
tags:
- phishing
- email-security
- social-engineering
- dmarc
- awareness
- gophish
- simulation
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---
# Performing Phishing Simulation with GoPhish

## Overview
GoPhish is an open-source phishing simulation framework used by security teams to conduct authorized phishing awareness campaigns. It provides campaign management, email template creation, landing page cloning, and comprehensive reporting. This skill covers deploying GoPhish, creating realistic phishing scenarios, and analyzing campaign results to measure and improve organizational resilience.


## When to Use

- When conducting security assessments that involve performing phishing simulation with gophish
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

- **Deliverability kills the test silently:** if the SEG quarantines the sim, low click rates reflect filtering, not user behavior - allowlist the GoPhish sending IP/domain (or a custom header) in the gateway and confirm delivery to a seed mailbox first.
- **Sending profile authentication:** a from-domain with `-all` SPF and DMARC reject will bounce or junk the sim unless the GoPhish relay is authorized - send through an authenticated relay and verify SPF/DKIM pass.
- **Tracking pixel and link wiring:** omitting `{{.Tracker}}` or `{{.URL}}` means opens/clicks never register; link-wrappers (Safe Links) auto-detonate `{{.URL}}` and inflate click counts - confirm a wrapper isn't pre-fetching the landing page.
- **Landing page must serve over HTTPS:** browsers/SEGs block mixed-content or invalid-cert pages, suppressing submits - install a valid TLS cert and test the full open->click->submit->redirect flow.
- **Credential capture for authorized testing only:** confirm capture is scoped, data is handled per the written authorization, and users redirect to training after submit.
- **Confirm before launch:** send a single test to a seed user and verify the email lands in inbox (not junk), the open registers, the click registers, the landing page renders over HTTPS, the submit is captured, and the API report reflects all four events. Stagger sends so volume doesn't trip rate-based filtering.

## Prerequisites
- GoPhish binary or Docker image (https://github.com/gophish/gophish)
- SMTP server or relay for sending test emails
- Written authorization from management for phishing simulation
- Target email list (HR-approved)
- SSL/TLS certificate for landing pages
- Python 3.8+ for automation scripts

## Key Concepts

### GoPhish Architecture
- **Admin Panel**: Web UI for campaign management (default port 3333)
- **Phishing Server**: Serves landing pages and tracks clicks (default port 80/443)
- **SMTP Configuration**: Outbound email sending profile
- **Campaign Engine**: Orchestrates email delivery, tracking, and reporting

### Campaign Components
1. **Sending Profile**: SMTP server configuration for outbound email
2. **Email Template**: The phishing email content with tracking
3. **Landing Page**: The fake page users are directed to
4. **User Group**: Target recipients for the campaign
5. **Campaign**: Combines all components with scheduling

## Workflow

### Step 1: Deploy GoPhish
```bash
# Docker deployment
docker pull gophish/gophish
docker run -d --name gophish -p 3333:3333 -p 8080:80 gophish/gophish

# Or binary deployment
wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish
./gophish
```

### Step 2: Configure Sending Profile
- Name: "Internal Mail Server"
- SMTP From: awareness-test@yourdomain.com
- Host: smtp.yourdomain.com:587
- Username/Password: Service account credentials
- Enable TLS

### Step 3: Create Email Template
- Use realistic scenarios: password reset, IT notification, HR update
- Include GoPhish tracking pixel: `{{.Tracker}}`
- Include phishing link: `{{.URL}}`
- Personalize with `{{.FirstName}}`, `{{.LastName}}`, `{{.Position}}`

### Step 4: Create Landing Page
- Clone legitimate login page using GoPhish's import feature
- Enable credential capture (for authorized testing only)
- Configure redirect to training page after submission
- Add SSL certificate for HTTPS

### Step 5: Import Users and Launch Campaign
- Import CSV with: First Name, Last Name, Email, Position
- Set campaign schedule (stagger sends to avoid detection)
- Launch and monitor in real-time

### Step 6: Analyze Results with process.py
Use the automation script to pull campaign data via GoPhish API and generate detailed analytics reports.

## Tools & Resources
- **GoPhish**: https://getgophish.com/
- **GoPhish API Docs**: https://docs.getgophish.com/api-documentation/
- **GoPhish GitHub**: https://github.com/gophish/gophish
- **Evilginx2** (for advanced AiTM testing): https://github.com/kgretzky/evilginx2
- **King Phisher**: https://github.com/rsmusllp/king-phisher

## Validation
- Successfully deploy GoPhish and access admin panel
- Create and send a test phishing email to a test mailbox
- Capture simulated credentials on landing page
- Generate campaign report with open/click/submit rates
- Redirect users to awareness training after interaction
