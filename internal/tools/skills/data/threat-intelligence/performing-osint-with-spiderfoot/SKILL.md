---
name: performing-osint-with-spiderfoot
description: Automate OSINT collection using SpiderFoot REST API and CLI for target profiling, module-based reconnaissance,
  and structured result analysis across 200+ data sources
domain: cybersecurity
subdomain: threat-intelligence
tags:
- osint
- spiderfoot
- reconnaissance
- threat-intelligence
- attack-surface
- target-profiling
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
---

# Performing OSINT with SpiderFoot

## Overview

SpiderFoot is an open-source OSINT automation tool with 200+ modules that integrates with data sources for threat intelligence and attack surface mapping. This skill uses the SpiderFoot REST API and CLI (sf.py/spiderfoot-cli) to create and manage scans, select modules by use case (footprint, investigate, passive), parse structured results for domains, IPs, email addresses, leaked credentials, and DNS records, and generate target intelligence profiles.


## When to Use

- When conducting security assessments that involve performing osint with spiderfoot
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Detection Gaps & Validation

- **Coverage = enabled modules + API keys:** SpiderFoot's 200+ modules are mostly inert without keys - lacking VirusTotal, Shodan, and HaveIBeenPwned keys, the `investigate`/`footprint` use cases silently skip the richest sources and return a thin profile that looks "clean." Audit which modules actually ran (and which errored on a missing key) before concluding a target has no exposure.
- **Passive vs active tradeoff:** the `passive` use case avoids touching the target but misses live ports/banners; `footprint`/`investigate` actively probe and can tip off the target or trip a WAF. Choose the scan type deliberately - a passive-only scan is not evidence the attack surface is small.
- **Stale and recycled data:** OSINT sources lag reality - dead subdomains, expired breach credentials, and recycled combolists produce findings that no longer apply. Check first/last-seen dates.
- **Name-collision false positives:** email/name/username pivots match unrelated people and orgs; a "leaked credential" hit may belong to a different entity sharing the keyword. Confirm the identifier truly maps to the target (matching domain, corroborating record) before reporting.
- **How to confirm:** treat SpiderFoot output as leads - validate high-impact findings (an exposed service, a leaked credential) directly against the authoritative source before acting.

## Prerequisites

- SpiderFoot 4.0+ installed or SpiderFoot HX cloud account
- Python 3.8+ with requests library
- SpiderFoot server running on default port 5001
- Optional: API keys for VirusTotal, Shodan, HaveIBeenPwned modules

## Steps

1. Connect to SpiderFoot REST API or use CLI interface
2. Create a new scan with target specification (domain, IP, email, name)
3. Select scan modules by use case (all, footprint, investigate, passive)
4. Monitor scan progress via API polling
5. Retrieve and parse scan results by data element type
6. Extract key findings: subdomains, IPs, emails, leaked credentials
7. Generate structured OSINT intelligence report

## Expected Output

JSON report containing OSINT findings organized by data type (domains, IPs, emails, credentials, DNS records), module source attribution, and target profile summary with risk indicators.
