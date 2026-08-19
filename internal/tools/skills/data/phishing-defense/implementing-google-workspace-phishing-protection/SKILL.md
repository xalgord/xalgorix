---
name: implementing-google-workspace-phishing-protection
description: Configure Google Workspace advanced phishing and malware protection settings including pre-delivery scanning,
  attachment protection, spoofing detection, and Enhanced Safe Browsing.
domain: cybersecurity
subdomain: phishing-defense
tags:
- google-workspace
- gmail
- phishing
- email-security
- safe-browsing
- anti-spoofing
- admin-console
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---
# Implementing Google Workspace Phishing Protection

## Overview
Google Workspace provides advanced phishing and malware protection through the Admin Console under Apps > Google Workspace > Gmail > Safety. Key features include Enhanced Pre-Delivery Scanning that examines messages more thoroughly before they reach inboxes, attachment and link protection that scans for malware and checks against known malicious sites, and spoofing detection for domain and employee name impersonation. Google's Advanced Protection Program (APP) provides the strongest account security for high-privilege users.


## When to Use

- When deploying or configuring implementing google workspace phishing protection capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **Safety toggles left default-off:** "similar domain" spoofing, "employee name" spoofing, and inbound-domain-spoofing protections are not all on by default - enable each and set the action to quarantine/spam, not just a banner.
- **Enhanced Safe Browsing not enabled:** it is OFF by default org-wide - turn it on for real-time URL protection, rolling out per OU to gauge false positives.
- **Action set to "warning banner" only:** banners are ignored under time pressure - quarantine high-confidence spoofing rather than relying on user judgement.
- **SPF/DKIM/DMARC half-configured:** `~all` SPF and DKIM enabled in console but never published in DNS, or DMARC parked at `p=none` - publish DKIM, verify SPF, and progress DMARC to enforcement.
- **APP not enrolled for high-risk users:** super admins/execs without the Advanced Protection Program remain phishable - enroll them with FIDO2 keys.
- **Attachment protections scoped to "trusted" too broadly:** encrypted/script/anomalous-attachment protection bypassed for internal senders misses lateral phishing.
- **Verification:** send a lookalike-domain spoof and a delayed-weaponization test from outside; confirm quarantine fires, Enhanced Safe Browsing blocks a test phishing URL at click, and outbound mail shows SPF/DKIM/DMARC pass.

## Prerequisites
- Google Workspace Business Standard or higher license
- Gmail Settings administrator privilege
- Understanding of organizational email flow and third-party integrations
- Access to Google Admin Console (admin.google.com)
- DNS management access for SPF, DKIM, DMARC configuration

## Workflow

### Step 1: Configure Advanced Phishing Protection
- Navigate to Admin Console > Apps > Google Workspace > Gmail > Safety
- Enable "Protect against domain spoofing based on similar domain names"
- Enable "Protect against spoofing of employee names"
- Enable "Protect against inbound emails spoofing your domain"
- Set action for detected spoofing: quarantine or move to spam with warning banner
- Apply settings to all organizational units or specific high-risk groups

### Step 2: Enable Enhanced Pre-Delivery Scanning
- In Safety settings, enable "Enhanced pre-delivery message scanning"
- This adds additional delay (seconds) to scan messages more thoroughly
- Configure to detect phishing attempts that evade initial filters
- Enable "Identify links behind shortened URLs"
- Enable "Scan linked images" for image-based phishing detection

### Step 3: Configure Attachment Protection
- Enable "Protect against encrypted attachments from untrusted senders"
- Enable "Protect against attachments with scripts from untrusted senders"
- Enable "Protect against anomalous attachment types in emails"
- Configure action: warn users, move to spam, or quarantine
- Create exceptions for known legitimate encrypted file senders

### Step 4: Enable Enhanced Safe Browsing
- Navigate to Admin Console > Security > Gmail Enhanced Safe Browsing
- Enable Enhanced Safe Browsing for the organization (off by default)
- This provides real-time protection against phishing URLs in emails
- Configure at organizational unit level for phased rollout
- Monitor user feedback for false positive impact

### Step 5: Enroll High-Risk Users in Advanced Protection Program
- Identify high-privilege accounts: super admins, executives, finance leadership
- Enroll users in Google's Advanced Protection Program (APP)
- APP requires FIDO2 security keys for authentication
- APP blocks third-party app access unless explicitly approved
- APP provides enhanced scanning for Gmail and Drive downloads

### Step 6: Configure Email Authentication
- Publish SPF record: `v=spf1 include:_spf.google.com ~all`
- Enable DKIM signing in Admin Console > Apps > Google Workspace > Gmail > Authenticate email
- Configure DMARC with monitoring: `v=DMARC1; p=none; rua=mailto:dmarc@company.com`
- Progress DMARC to enforcement per organizational readiness

## Tools & Resources
- **Google Admin Console**: Central management for all security settings
- **Google Workspace Security Investigation Tool**: Threat analysis and response
- **Google Security Center**: Security health recommendations and dashboard
- **Gmail Security Sandbox**: Attachment detonation for enterprise licenses
- **Google Advanced Protection Program**: Strongest account security

## Validation
- Spoofing protection blocks test email with lookalike domain
- Pre-delivery scanning catches test phishing with delayed weaponization
- Attachment protection warns on test encrypted attachment
- Enhanced Safe Browsing blocks known phishing URL clicked in email
- APP-enrolled accounts reject non-FIDO2 authentication attempts
- SPF, DKIM, DMARC all pass for outbound messages
