---
name: detecting-business-email-compromise
description: Business Email Compromise (BEC) is a sophisticated fraud scheme where attackers impersonate executives, vendors,
  or trusted partners to trick employees into transferring funds, sharing sensitive data,
domain: cybersecurity
subdomain: phishing-defense
tags:
- phishing
- email-security
- social-engineering
- dmarc
- awareness
- bec
- fraud
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
atlas_techniques:
- AML.T0052
- AML.T0088
nist_ai_rmf:
- GOVERN-6.2
- MAP-5.2
d3fend_techniques:
- Restore Object
- Restore Configuration
- Application Configuration Hardening
- Application Hardening
- Disable Remote Access
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---
# Detecting Business Email Compromise

## Overview
Business Email Compromise (BEC) is a sophisticated fraud scheme where attackers impersonate executives, vendors, or trusted partners to trick employees into transferring funds, sharing sensitive data, or changing payment details. Unlike traditional phishing, BEC often contains no malicious links or attachments, relying purely on social engineering. This skill covers detection techniques using email gateway rules, behavioral analytics, and financial process controls.


## When to Use

- When investigating security incidents that require detecting business email compromise
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **SPF passes but the sender is spoofed:** a cousin domain or free-webmail account passes SPF/DKIM/DMARC for ITS OWN domain while the display name reads "CFO" - auth "pass" does not mean the brand is genuine. Alert on VIP display name + external/free domain.
- **No malicious payload:** pure-text BEC has no URL/attachment to detonate, so sandboxes are blind - lean on Reply-To mismatch, first-contact-to-finance, and payment-change keyword + urgency rules.
- **False-invoice / bank-change:** the highest-loss variant changes vendor banking details inside a real-looking thread - require out-of-band callback verification, not email confirmation.
- **Account compromise is internal:** mail originates from a real mailbox, so all reputation/auth checks pass - detect via inbox-rule creation (T1114.003), impossible travel, and auto-forward rules hiding replies.
- **Lookalike domains:** add homoglyph detection (`rn`->`m`, capital-I/lowercase-l) against your domain and top vendors.
- **Validate + FP tuning:** run BEC test scenarios (CEO gift-card, vendor bank change, W-2 request) and confirm rules trigger; whitelist legitimate first-time senders (recruiters, new vendors) by role to keep finance/AP alerts low-noise.

## Prerequisites
- Email security gateway with BEC detection capabilities
- Understanding of organizational financial processes and approval chains
- Access to email logs and SIEM platform
- Knowledge of social engineering tactics

## Key Concepts

### BEC Attack Types (FBI IC3 Classification)
1. **CEO Fraud**: Attacker impersonates CEO, requests urgent wire transfer
2. **Account Compromise**: Employee email compromised, used to request payments from vendors
3. **False Invoice Scheme**: Fake invoices from "vendor" with changed bank details
4. **Attorney Impersonation**: Impersonates legal counsel for urgent confidential transfers
5. **Data Theft**: Requests W-2, tax forms, or PII from HR

### Detection Indicators
- Urgency and secrecy language ("confidential", "do not discuss with others")
- New or changed payment instructions
- Executive communication outside normal patterns
- Display name matches executive but email domain differs
- Reply-to address differs from From address
- First-time communication pattern between sender and recipient
- Request for gift cards or cryptocurrency

## Workflow

### Step 1: Configure BEC-Specific Email Rules
- Flag emails with VIP display names from external domains
- Detect financial keywords combined with urgency language
- Alert on first-time sender to finance/accounting staff
- Check for Reply-To domain mismatch

### Step 2: Deploy Behavioral Analytics
- Baseline normal communication patterns per user
- Detect anomalous requests (unusual recipient, unusual time, unusual request type)
- Monitor for email forwarding rule changes (T1114.003)

### Step 3: Implement Financial Controls
- Dual-authorization for wire transfers above threshold
- Out-of-band verification for payment detail changes (phone callback)
- Vendor payment change verification process
- Finance team training on BEC red flags

### Step 4: Monitor for Account Compromise
- Detect impossible travel in email login locations
- Alert on email forwarding rule creation
- Monitor for mailbox delegation changes
- Check for inbox rules hiding BEC-related emails

## Tools & Resources
- **Microsoft Defender for O365 Anti-BEC**: Built-in BEC detection
- **Proofpoint Email Fraud Defense**: BEC-specific solution
- **Abnormal Security**: AI-driven BEC detection
- **FBI IC3 BEC Advisory**: https://www.ic3.gov/
- **FinCEN BEC Advisory**: Financial institution guidance

## Validation
- BEC detection rules trigger on test scenarios
- Financial controls prevent unauthorized transfers in drills
- Account compromise detection catches simulated attacks
- Reduced BEC susceptibility in awareness assessments
