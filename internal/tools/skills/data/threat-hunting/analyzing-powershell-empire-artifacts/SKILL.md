---
name: analyzing-powershell-empire-artifacts
description: Detect PowerShell Empire framework artifacts in Windows event logs by identifying Base64 encoded launcher patterns,
  default user agents, staging URL structures, stager IOCs, and known Empire module signatures in Script Block Logging events.
domain: cybersecurity
subdomain: threat-hunting
tags:
- PowerShell-Empire
- threat-hunting
- Script-Block-Logging
- base64
- stager
- C2
- MITRE-ATT&CK
- T1059.001
- forensics
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
nist_ai_rmf:
- GOVERN-1.1
- MEASURE-2.7
- MANAGE-3.1
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Analyzing PowerShell Empire Artifacts

## Overview

PowerShell Empire is a post-exploitation framework consisting of listeners, stagers, and agents. Its artifacts leave detectable traces in Windows event logs, particularly PowerShell Script Block Logging (Event ID 4104) and Module Logging (Event ID 4103). This skill analyzes event logs for Empire's default launcher string (`powershell -noP -sta -w 1 -enc`), Base64 encoded payloads containing `System.Net.WebClient` and `FromBase64String`, known module invocations (Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation), and staging URL patterns.


## When to Use

- When investigating security incidents that require analyzing powershell empire artifacts
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Logging downgrade is the #1 evasion.** Empire can run under PowerShell v2 (`powershell -version 2`), which never emits Script Block Logging (4104). Hunt EID 400/600 engine-start events showing `EngineVersion=2.0` and the v2 downgrade itself, not just 4104.
- **Reassemble before you match.** Large payloads are split across multiple 4104 events (`MessageNumber`/`MessageTotal`); regexing each fragment independently misses the Base64 blob and `FromBase64String`. Stitch fragments by ScriptBlockId first.
- **Don't pin on default strings.** The literal launcher `-noP -sta -w 1 -enc`, the default URIs (`/login/process.php`, `/admin/get.php`), and stock user agents are all configurable in Empire 4.x / malleable profiles. Match on behavior (`System.Net.WebClient` + `DownloadData` + `IEX`) and AMSI-bypass patterns, not one fixed string.
- **Coverage check:** confirm 4104 (and ideally 4103 Module Logging) are enabled via GPO and that AMSI hasn't been patched in-process (`amsiInitFailed` writes).
- **Validate the rule fires:** run a benign `powershell -enc <base64 of Write-Host hi>` and confirm your pipeline captures the 4104 event and your decoder reconstructs the cleartext.
- **Tune false positives:** SCCM, Intune, and admin tooling legitimately use `-enc`/`-EncodedCommand`. Allowlist by signing cert and known ScriptBlock hashes rather than suppressing `-enc` wholesale.

## Prerequisites

- Python 3.9+ with access to Windows Event Log or exported EVTX files
- PowerShell Script Block Logging (Event ID 4104) enabled via Group Policy
- Module Logging (Event ID 4103) enabled for comprehensive coverage

## Key Detection Patterns

1. **Default launcher** — `powershell -noP -sta -w 1 -enc` followed by Base64 blob
2. **Stager indicators** — `System.Net.WebClient`, `DownloadData`, `DownloadString`, `FromBase64String`
3. **Module signatures** — Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation, Invoke-PSInject, Invoke-DCOM
4. **User agent strings** — default Empire user agents in HTTP listener configuration
5. **Staging URLs** — `/login/process.php`, `/admin/get.php` and similar default URI patterns

## Output

JSON report with matched IOCs, decoded Base64 payloads, timeline of suspicious events, MITRE ATT&CK technique mappings, and severity scores.
