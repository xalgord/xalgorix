---
name: hunting-for-data-staging-before-exfiltration
description: Detect data staging activity before exfiltration by monitoring for archive creation with 7-Zip/RAR, unusual temp
  folder access, large file consolidation, and staging directory patterns via EDR and process telemetry
domain: cybersecurity
subdomain: threat-hunting
tags:
- data-staging
- exfiltration
- t1074
- archive-detection
- edr
- threat-hunting
- dlp
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
- Platform Hardening
- File Format Verification
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting for Data Staging Before Exfiltration

## Overview

Before exfiltrating data, adversaries typically stage collected files in a central location (MITRE ATT&CK T1074). This involves creating archives with tools like 7-Zip, RAR, or tar, consolidating files from multiple directories, and using temporary or hidden staging directories. This skill detects staging behavior by analyzing process creation logs for archiver activity, monitoring file system events in common staging paths, and identifying anomalous file consolidation patterns.


## When to Use

- When investigating security incidents that require hunting for data staging before exfiltration
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Archive-less staging is the #1 miss.** Adversaries consolidate with `robocopy`/`xcopy`/`Copy-Item` into one folder and exfil raw — no 7z.exe/rar.exe ever runs. Hunt Sysmon EID 11 (FileCreate) bursts into a single dir, not just archiver EID 1.
- **Renamed archivers evade Image-name rules.** `7z.exe` copied to `svchost.exe` defeats `Image=*\7z.exe`. Match Sysmon EID 1 `OriginalFileName` and `Hashes`, not the on-disk name.
- **Encrypted/split archives defeat DLP content inspection** (`7z a -pPASS -v50m`); the `.7z.001` split pattern and password flag (`-p`) are stronger signals than file content.
- **Validate the hunt fires:** run Atomic Red Team T1074.001, or `7z a -p -v25m C:\Windows\Temp\s.7z C:\Users\*\Documents` — confirm Sysmon EID 1 (with archiver OriginalFileName) and EID 11 writes to a staging path both trigger your rule.
- **FP tuning:** backup jobs (Veeam, nightly robocopy), user-driven WinRAR, and installer temp extraction. Baseline by parent process, signer, schedule, and whether the dir is later read by an upload process (T1567).

## Prerequisites

- EDR or Sysmon telemetry with process creation and file system events
- Windows Event Logs (Event ID 4688) or Sysmon Event ID 1, 11
- Python 3.8+ with standard library
- Access to process creation logs in JSON/CSV format

## Steps

1. **Detect Archive Tool Execution** — Monitor for 7z.exe, rar.exe, tar, zip, and WinRAR process creation with compression arguments
2. **Identify Staging Directories** — Flag file writes to common staging locations (Recycle Bin, %TEMP%, ProgramData, hidden directories)
3. **Detect Large File Consolidation** — Identify patterns of multiple file reads followed by writes to a single directory
4. **Monitor Sensitive Path Access** — Track bulk reads from document directories, database paths, and network shares
5. **Analyze Archive Metadata** — Extract and analyze archive file sizes, creation times, and source paths
6. **Score Staging Risk** — Apply heuristic scoring based on archive size, source diversity, staging path suspicion, and timing
7. **Generate Hunt Report** — Produce a structured report with staging event timeline and MITRE ATT&CK mapping

## Expected Output

- JSON report of detected staging events with risk scores
- Archive creation timeline with source file analysis
- MITRE ATT&CK mapping (T1074.001, T1074.002, T1560)
- Staging directory heat map showing suspicious write activity
