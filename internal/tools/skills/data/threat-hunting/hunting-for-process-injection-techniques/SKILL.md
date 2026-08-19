---
name: hunting-for-process-injection-techniques
description: Detect process injection techniques (T1055) including CreateRemoteThread, process hollowing, and DLL injection
  via Sysmon Event IDs 8 and 10 and EDR process telemetry
domain: cybersecurity
subdomain: threat-hunting
tags:
- process-injection
- t1055
- sysmon
- createremotethread
- dll-injection
- edr
- threat-hunting
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting for Process Injection Techniques

## Overview

Process injection (MITRE ATT&CK T1055) allows adversaries to execute code in the address space of another process, enabling defense evasion and privilege escalation. This skill detects injection techniques via Sysmon Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess with suspicious access rights), and analysis of source-target process relationships to distinguish legitimate from malicious injection.


## When to Use

- When investigating security incidents that require hunting for process injection techniques
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Evasions that produce NO Sysmon EID 8:** thread hijacking (`SetThreadContext`), APC injection (`QueueUserAPC`/`NtQueueApcThread`, early-bird), mapping injection (`NtMapViewOfSection`), and process hollowing (`NtUnmapViewOfSection` + `WriteProcessMemory`) all skip `CreateRemoteThread`. They surface only as EID 10 ProcessAccess with `PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD`.
- **Userland-hook bypass:** indirect/direct syscalls and unhooked NTDLL defeat EDR inline hooks, leaving little or no telemetry — corroborate with EID 7 (ImageLoad of unbacked/floating modules) and kernel ETW.
- **EID 10 noise:** CSRSS, lsass, AV/EDR, and debuggers legitimately open high-access handles. Tune to cross-process opens where GrantedAccess masks `0x1F0FFF`/`0x1FFFFF` AND the source is unsigned or unusual; treat `0x1000`/`0x1400` read-only as benign.
- **Validate the hunt fires:** run Atomic Red Team T1055.001 (process hollowing), T1055.002, and `mavinject.exe` APC, then confirm EID 8 GrantedAccess and EID 10 access masks are captured.
- **FP tuning:** allowlist known injector→target pairs (e.g., MsMpEng.exe, vmtoolsd) by signer, not by image name alone.

## Prerequisites

- Sysmon installed with Event IDs 8 and 10 enabled
- Process creation logs (Sysmon Event ID 1 or Windows 4688)
- Python 3.8+ with standard library
- JSON-formatted Sysmon event logs

## Steps

1. **Parse Sysmon Events** — Ingest Event IDs 1, 8, and 10 from JSON log files
2. **Detect CreateRemoteThread** — Flag Event ID 8 with suspicious source-target process pairs
3. **Analyze ProcessAccess Rights** — Identify Event ID 10 with dangerous access masks (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD)
4. **Build Process Relationship Graph** — Map source-to-target injection relationships
5. **Filter Known Legitimate Pairs** — Exclude known benign injection patterns (AV, debuggers, system processes)
6. **Score Injection Severity** — Apply risk scoring based on source process, target process, and access rights
7. **Generate Hunt Report** — Produce structured report with MITRE sub-technique mapping

## Expected Output

- JSON report of detected injection events with severity scores
- Process injection relationship graph
- MITRE ATT&CK sub-technique mapping (T1055.001-T1055.012)
- False positive exclusion recommendations
