---
name: analyzing-windows-prefetch-with-python
description: Parse Windows Prefetch files using the windowsprefetch Python library to reconstruct application execution history,
  detect renamed or masquerading binaries, and identify suspicious program execution patterns.
domain: cybersecurity
subdomain: digital-forensics
tags:
- digital-forensics
- windows
- prefetch
- execution-history
- incident-response
- malware-analysis
mitre_attack:
- T1059
- T1204
- T1036
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
---
# Analyzing Windows Prefetch with Python

## Overview

Windows Prefetch files (.pf) record application execution data including executable names, run counts, timestamps, loaded DLLs, and accessed directories. This skill covers parsing Prefetch files using the windowsprefetch Python library to reconstruct execution timelines, detect renamed or masquerading binaries by comparing executable names with loaded resources, and identifying suspicious programs that may indicate malware execution or lateral movement.


## When to Use

- When investigating security incidents that require analyzing windows prefetch with python
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Prefetch can be disabled or absent.** It is off by default on Windows Server, and `EnablePrefetcher` (HKLM\SYSTEM\...\Memory Management\PrefetchParameters) may be set to 0 by hardening or by an attacker. No `.pf` does not mean no execution — confirm the setting before concluding.
- **Run-time history is shallow.** Windows 8.1/10/11 store only the **last 8** execution timestamps; Windows 7 stores **one**. Earlier runs are lost. The "first executed" estimate is the `.pf` creation time minus ~10 seconds, not an exact start.
- **Renamed/masquerading binaries:** the hash in `EXECUTABLE-HASH.pf` is derived from the full path, so the *same* binary run from two paths yields two different `.pf` files — and a renamed malware keeps its real loaded-DLL fingerprint. Compare referenced DLLs/directories, not just the name.
- **Anti-forensics that defeat this analysis:** deletion of `C:\Windows\Prefetch\*.pf`, disabling the Prefetcher, and `.pf` timestomping. Carve deleted `.pf` (header `MAM\x04` / `SCCA`) from unallocated space and VSS.
- **Validate / cross-corroborate:** confirm execution against Amcache, ShimCache/AppCompatCache, SRUM `SRUDB.dat` (app usage + bytes), and Security.evtx EID 4688. The volume serial in the `.pf` should match the system under analysis.
- **Interpretation false positives:** a high run count on `svchost.exe`/`explorer.exe` is normal; flag on *path*, *first-seen during incident window*, and *loaded-resource anomalies*, never run count alone.

## Prerequisites

- Python 3.9+ with `windowsprefetch` library (pip install windowsprefetch)
- Windows Prefetch files from C:\Windows\Prefetch\ (versions 17-30 supported)
- Understanding of Windows Prefetch file naming conventions (EXECUTABLE-HASH.pf)

## Steps

### Step 1: Collect Prefetch Files
Gather .pf files from target system's C:\Windows\Prefetch\ directory.

### Step 2: Parse Execution History
Extract executable name, run count, last execution timestamps, and volume information.

### Step 3: Detect Suspicious Execution
Flag known attack tools (mimikatz, psexec, etc.), renamed binaries, and unusual execution patterns.

### Step 4: Build Execution Timeline
Reconstruct chronological execution timeline from all Prefetch files.

## Expected Output

JSON report with execution history, suspicious executables, renamed binary indicators, and timeline reconstruction.

## Example Output

```text
$ python3 prefetch_analyzer.py --dir /evidence/Windows/Prefetch --output /analysis/prefetch_report

Windows Prefetch Analyzer v2.1
================================
Source: /evidence/Windows/Prefetch/
Prefetch Format: Windows 10 (MAM compressed, version 30)
Files Found: 234

--- Execution Timeline (Incident Window: 2024-01-15 to 2024-01-18) ---
Last Executed (UTC)     | Run Count | Filename                    | Hash     | Path
------------------------|-----------|-----------------------------|----------|------------------------------------------
2024-01-15 14:33:15     | 1         | Q4_REPORT.XLSM-2A1B3C4D.pf | 2A1B3C4D | C:\Users\jsmith\Downloads\Q4_Report.xlsm
2024-01-15 14:35:44     | 1         | POWERSHELL.EXE-A2B3C4D5.pf  | A2B3C4D5 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2024-01-15 14:36:30     | 3         | UPDATE_CLIENT.EXE-B3C4D5E6.pf| B3C4D5E6| C:\ProgramData\Updates\update_client.exe
2024-01-15 15:10:22     | 1         | NETSCAN.EXE-C4D5E6F7.pf     | C4D5E6F7 | C:\Users\jsmith\Downloads\netscan.exe
2024-01-16 02:28:00     | 1         | PROCDUMP64.EXE-D5E6F7A8.pf  | D5E6F7A8 | C:\Windows\Temp\procdump64.exe
2024-01-16 02:30:15     | 2         | MIMIKATZ.EXE-E6F7A8B9.pf    | E6F7A8B9 | C:\Windows\Temp\mimikatz.exe
2024-01-16 02:40:00     | 4         | PSEXEC.EXE-F7A8B9C0.pf      | F7A8B9C0 | C:\Users\jsmith\AppData\Local\Temp\psexec.exe
2024-01-17 02:45:00     | 1         | SDELETE64.EXE-A8B9C0D1.pf   | A8B9C0D1 | C:\Windows\Temp\sdelete64.exe
2024-01-18 03:00:45     | 1         | WEVTUTIL.EXE-B9C0D1E2.pf    | B9C0D1E2 | C:\Windows\System32\wevtutil.exe

--- Renamed Binary Detection ---
ALERT: UPDATE_CLIENT.EXE loaded DLLs consistent with Cobalt Strike beacon:
  Referenced DLLs: wininet.dll, ws2_32.dll, advapi32.dll, dnsapi.dll, netapi32.dll
  Volume: \VOLUME{01d94f2a3b5c7d8e-A4E73F21} (C:)
  Directories referenced:
    C:\ProgramData\Updates\
    C:\Windows\System32\

--- Execution Frequency Analysis ---
Most Executed (Top 5):
  1. SVCHOST.EXE          (267 runs)
  2. CHROME.EXE           (189 runs)
  3. EXPLORER.EXE         (156 runs)
  4. RUNTIMEBROKER.EXE    (134 runs)
  5. OUTLOOK.EXE          (98 runs)

First-Time Executions (Never seen before incident window):
  6 executables first run between 2024-01-15 and 2024-01-18

Summary:
  Total prefetch files:         234
  Suspicious executables:       6
  Renamed binary indicators:    1 (update_client.exe)
  Anti-forensics tools:         2 (sdelete64.exe, wevtutil.exe)
  JSON report: /analysis/prefetch_report/prefetch_timeline.json
```
