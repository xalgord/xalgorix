---
name: analyzing-malicious-url-with-urlscan
description: URLScan.io is a free service for scanning and analyzing suspicious URLs. It captures screenshots, DOM content,
  HTTP transactions, JavaScript behavior, and network connections of web pages in an isolat
domain: cybersecurity
subdomain: phishing-defense
tags:
- phishing
- email-security
- social-engineering
- dmarc
- awareness
- url-analysis
- threat-intelligence
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
atlas_techniques:
- AML.T0052
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---
# Analyzing Malicious URL with URLScan

## Overview
URLScan.io is a free service for scanning and analyzing suspicious URLs. It captures screenshots, DOM content, HTTP transactions, JavaScript behavior, and network connections of web pages in an isolated environment. This skill covers using URLScan's web interface and API to investigate phishing URLs, credential harvesting pages, and malicious redirects without exposing the analyst's system to risk.


## When to Use

- When investigating security incidents that require analyzing malicious url with urlscan
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Cloaking and geofencing:** phishing kits serve a benign page to datacenter/scanner IPs (urlscan's egress) and reveal the real credential form only to victim geos/User-Agents. A clean verdict over a generic landing page is NOT proof of safety - re-scan with `country=` set to the target region and a mobile UA.
- **Cached vs. live result:** verify you are not viewing a stale scan; submit a fresh `visibility: private` scan because attackers rotate payloads and tear down infrastructure within hours.
- **MFA/AiTM proxies:** an AiTM page (Evilginx/Tycoon 2FA) mirrors the real login and often shows a legitimate-looking Microsoft/Okta screenshot - judge on the domain, cert, and redirect chain, not the screenshot.
- **CAPTCHA / Cloudflare Turnstile gates** and multi-hop redirects can stop the crawler before the phishing page loads; follow the redirect chain manually and look for the gate.
- **Confirm a hit:** correlate the urlscan verdict (malicious) with a credential `<form action>` posting off-domain, a newly registered domain (<30 days), brand logos served from a non-brand ASN, and a second source (VirusTotal/PhishTank). Do not conclude benign from a single clean scan.
- **FP tuning:** legitimate SSO and link-wrappers (Proofpoint urldefense, Microsoft Safe Links) also chain redirects - allowlist known wrapper domains before alerting.

## Prerequisites
- URLScan.io account (free tier available, API key for automation)
- Python 3.8+ with requests library
- Understanding of HTTP protocols and web technologies
- Familiarity with phishing URL patterns

## Key Concepts

### URLScan Capabilities
1. **Safe browsing**: Renders URLs in isolated Chromium instance
2. **Screenshot capture**: Visual snapshot of the rendered page
3. **DOM analysis**: Full HTML content after JavaScript execution
4. **Network log**: All HTTP requests made by the page (HAR format)
5. **Certificate analysis**: SSL/TLS certificate details
6. **Technology detection**: Identifies web frameworks and libraries
7. **IP/ASN mapping**: Infrastructure intelligence
8. **Verdict**: Community and automated classification

### Phishing URL Red Flags
- Newly registered domains (< 30 days)
- Free hosting services (Wix, GitHub Pages, Firebase)
- URL shorteners hiding final destination
- Excessive subdomain depth (login.microsoft.com.evil.com)
- Brand name in subdomain or path, not domain
- Non-standard ports
- Data URIs or base64-encoded content
- JavaScript-heavy pages with minimal HTML

## Workflow

### Step 1: Submit URL to URLScan
```
Web: Navigate to https://urlscan.io and submit the suspicious URL
API: POST https://urlscan.io/api/v1/scan/
     Header: API-Key: your-api-key
     Body: {"url": "https://suspicious-url.com", "visibility": "private"}
```

### Step 2: Analyze Results
- Review screenshot for brand impersonation
- Check redirects and final destination URL
- Examine DOM for credential input forms
- Review network requests for data exfiltration endpoints
- Check SSL certificate validity and issuer

### Step 3: Extract IOCs
- Domains and IPs contacted
- URLs in redirect chain
- SHA-256 hashes of page resources
- JavaScript file hashes

### Step 4: Cross-Reference with Threat Intelligence
Use the `scripts/process.py` to automate URL scanning, extract IOCs, and cross-reference with VirusTotal, PhishTank, and Google Safe Browsing.

## Tools & Resources
- **URLScan.io**: https://urlscan.io/
- **URLScan API**: https://urlscan.io/docs/api/
- **VirusTotal URL Scanner**: https://www.virustotal.com/
- **PhishTank**: https://phishtank.org/
- **Google Safe Browsing**: https://transparencyreport.google.com/safe-browsing/search
- **Any.Run**: https://any.run/ (interactive sandbox)
- **Hybrid Analysis**: https://www.hybrid-analysis.com/

## Validation
- Successfully scan a suspicious URL via API
- Extract screenshot and identify brand impersonation
- Document complete redirect chain
- Generate IOC list from scan results
- Cross-reference findings with at least 2 threat intelligence sources
