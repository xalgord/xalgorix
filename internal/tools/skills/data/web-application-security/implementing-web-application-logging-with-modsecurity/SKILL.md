---
name: implementing-web-application-logging-with-modsecurity
description: 'Configure ModSecurity WAF with OWASP Core Rule Set (CRS) for web application logging, tune rules to reduce false
  positives, analyze audit logs for attack detection, and implement custom SecRules for application-specific threats. The
  analyst configures SecRuleEngine, SecAuditEngine, and CRS paranoia levels to balance security coverage with operational
  stability. Activates for requests involving WAF configuration, ModSecurity rule tuning, web application audit logging, or
  CRS deployment.

  '
domain: cybersecurity
subdomain: web-application-security
tags:
- modsecurity
- waf
- crs
- owasp
- web-security
- audit-logging
- rule-tuning
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
atlas_techniques:
- AML.T0070
- AML.T0066
- AML.T0082
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---
# Implementing Web Application Logging with ModSecurity

## Overview

ModSecurity is an open-source WAF engine that works with Apache, Nginx, and IIS. The OWASP
Core Rule Set (CRS) provides generic attack detection rules covering SQL injection, XSS,
RCE, LFI, and other OWASP Top 10 attacks. ModSecurity logs full request/response data in
audit logs for forensic analysis and generates alerts that feed into SIEM platforms.


## When to Use

- When deploying or configuring implementing web application logging with modsecurity capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **Engine left in `DetectionOnly`**: the most common silent failure. CRS matches, alerts fire, but nothing is ever blocked. Grep the active config for `SecRuleEngine` — if it's `DetectionOnly` (or the post-tuning switch to `On` never happened), the WAF is a logger, not a control.
- **`SecRequestBodyAccess Off` or module not enabled per-vhost**: POST/JSON bodies are never inspected, so SQLi/XSS in request bodies sail through even at high paranoia. Confirm `SecRequestBodyAccess On` and that the directive applies to the served vhost, not just the global context.
- **Anomaly threshold too high / blocking rule (949110) excluded**: CRS is scoring-based; if `tx.inbound_anomaly_score_threshold` is raised or `SecRuleRemoveById 949110` (the blocking evaluator) was used to "fix false positives", individual rules match but the request is never denied.
- **Over-broad `SecRuleRemoveById`/`SecRuleRemoveByTag`**: disabling whole families (e.g. `942xxx`) to silence FPs blinds SQLi detection entirely. Prefer targeted `SecRuleUpdateTargetById` exclusions for specific params.
- **Paranoia Level 1 only**: PL1 misses many evasions; obfuscated payloads pass. Note PL is a coverage/FP tradeoff, not a "set and forget" default.
- **`SecAuditEngine` off or `SecAuditLogParts` missing request/response body parts (no `IJ`/`E`)**: alerts exist but the forensic body is gone, so triage is impossible; and logs that never reach the SIEM (local file only) mean no alerting.
- **VERIFY it actually blocks**: send a known-malicious request and require a `403`, not a `200`: `curl -i "https://target/?q=union+select+1,2,3--"` and `curl -i "https://target/?x=<script>alert(1)</script>"`. Then confirm the matching audit entry exists (e.g. rule id `942100`, anomaly score increment) in the audit log and that it was forwarded to the SIEM. A `200` with only a log line = detection only, control not enforced. Also test a request-body payload (`curl -i -d "q=' OR 1=1-- -"`) to prove body inspection works, not just query strings.

## Prerequisites

- Web server (Apache 2.4+ or Nginx) with ModSecurity v3 module
- OWASP CRS v4.x installed
- Log aggregation infrastructure (ELK, Splunk, or Wazuh)

## Steps

1. Install ModSecurity and configure SecRuleEngine in DetectionOnly mode
2. Deploy OWASP CRS v4 and set paranoia level (PL1-PL4)
3. Configure SecAuditEngine for relevant-only logging
4. Tune false positives with SecRuleRemoveById and rule exclusions
5. Switch to blocking mode (SecRuleEngine On) after tuning period
6. Forward audit logs to SIEM for correlation and alerting

## Expected Output

```
ModSecurity: Warning. Pattern match "(?:union\s+select)" [file "/etc/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "45"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]
```
