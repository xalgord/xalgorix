---
name: detecting-credential-dumping-techniques
description: Detect LSASS credential dumping, SAM database extraction, and NTDS.dit theft using Sysmon Event ID 10, Windows
  Security logs, and SIEM correlation rules
domain: cybersecurity
subdomain: threat-detection
tags:
- credential-dumping
- lsass
- mimikatz
- sysmon
- active-directory
- windows-security
- defense-evasion
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Token Binding
- Execution Isolation
- File Metadata Consistency Validation
- Restore Access
- Application Protocol Command Analysis
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
---

# Detecting Credential Dumping Techniques

## Overview

Credential dumping (MITRE ATT&CK T1003) is a post-exploitation technique where adversaries extract authentication credentials from OS memory, registry hives, or domain controller databases. This skill covers detection of LSASS memory access via Sysmon Event ID 10 (ProcessAccess), SAM registry hive export via reg.exe, NTDS.dit extraction via ntdsutil/vssadmin, and comsvcs.dll MiniDump abuse. Detection rules analyze GrantedAccess bitmasks, suspicious calling processes, and known tool signatures.


## When to Use

- When investigating security incidents that require detecting credential dumping techniques
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Variants most often missed:** rules keyed only on a direct `lsass.exe` handle open (Sysmon EID 10, GrantedAccess `0x1010`/`0x1410`) miss `rundll32 comsvcs.dll, MiniDump <PID> dump.bin full`, MiniDumpWriteDump via signed tools (procdump `-ma`, Task Manager, Process Explorer), direct syscalls / unhooked `NtReadVirtualMemory` (Dumpert, nanodump) that bypass userland EDR hooks, and **handle duplication** where a sacrificial process opens LSASS and the dumper calls `NtDuplicateObject` (TargetProcess = lsass but SourceProcess != dumper, so the 4656/EID 10 source looks benign).
- **False negatives:** SAM/SYSTEM theft via `esentutl /y` or VSS `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*\Windows\System32\config\SAM` instead of `reg save`; NTDS.dit via DCSync (no on-host dump at all — watch EID 4662 with replication GUIDs `1131f6aa`/`1131f6ad`). PPL/RunAsPPL and Credential Guard change but do not eliminate access paths.
- **Validate the rule fires:** Atomic Red Team T1003.001 (`#1` procdump LSASS, `#3` comsvcs MiniDump, `#7` direct syscall nanodump), T1003.002 (reg save SAM), T1003.003 (ntdsutil/vssadmin). Confirm EID 10 GrantedAccess masks `0x1010`/`0x1438`/`0x143a` and the MiniDump command line all alert.
- **FP tuning:** baseline legitimate LSASS readers — AV/EDR agents (MsMpEng.exe), `wininit.exe`, backup agents, and crash/WER (`werfault.exe`). Allowlist by signed SourceImage + expected GrantedAccess rather than muting lsass access wholesale.

## Prerequisites

- Sysmon v14+ deployed with ProcessAccess logging (Event ID 10) for lsass.exe
- Windows Security audit policy enabling process creation (Event ID 4688) with command line logging
- Splunk or Elastic SIEM ingesting Sysmon and Windows Security logs
- Python 3.8+ for log analysis

## Steps

1. Configure Sysmon to log ProcessAccess events targeting lsass.exe
2. Forward Sysmon Event ID 10 and Windows Event ID 4688 to SIEM
3. Create detection rules for known GrantedAccess patterns (0x1010, 0x1FFFFF)
4. Detect comsvcs.dll MiniDump and procdump.exe targeting LSASS PID
5. Alert on reg.exe SAM/SECURITY/SYSTEM hive export commands
6. Detect ntdsutil/vssadmin shadow copy creation for NTDS.dit theft
7. Correlate detections with user/host context for risk scoring

## Expected Output

JSON report containing detected credential dumping indicators with technique classification, severity ratings, process details, MITRE ATT&CK mapping, and Splunk/Elastic detection queries.
