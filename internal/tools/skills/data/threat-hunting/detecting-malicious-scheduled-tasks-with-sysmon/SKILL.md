---
name: detecting-malicious-scheduled-tasks-with-sysmon
description: 'Detect malicious scheduled task creation and modification using Sysmon Event IDs 1 (Process Create for schtasks.exe),
  11 (File Create for task XML), and Windows Security Event 4698/4702. The analyst correlates task creation with suspicious
  parent processes, public directory paths, and encoded command arguments to identify persistence and lateral movement via
  scheduled tasks. Activates for requests involving scheduled task detection, Sysmon persistence hunting, or T1053.005 Scheduled
  Task/Job analysis.

  '
domain: cybersecurity
subdomain: threat-hunting
tags:
- sysmon
- scheduled-tasks
- persistence
- detection
- threat-hunting
- windows-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Execution Isolation
- Process Termination
- Hardware-based Process Isolation
- Platform Monitoring
- Process Suspension
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---
# Detecting Malicious Scheduled Tasks with Sysmon

## Overview

Adversaries abuse Windows Task Scheduler (schtasks.exe, at.exe) for persistence (T1053.005)
and lateral movement. Sysmon Event ID 1 captures schtasks.exe process creation with full
command-line arguments, while Event ID 11 captures task XML files written to
C:\Windows\System32\Tasks\. Windows Security Event 4698 logs task registration details.
This skill covers building detection rules that correlate these events to identify
malicious scheduled tasks created from suspicious paths, with encoded payloads, or
targeting remote systems.


## When to Use

- When investigating security incidents that require detecting malicious scheduled tasks with sysmon
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **schtasks.exe isn't the only path.** Tasks created via the Schedule COM API (`ITaskService`), PowerShell `Register-ScheduledTask`, or a direct XML drop into `C:\Windows\System32\Tasks\` never spawn schtasks.exe, so Sysmon EID 1 misses them. Cover Security **4698** (task registered) and Sysmon **EID 11** (file create in `\Tasks\`) as well.
- **4698 is off by default.** It requires "Audit Other Object Access Events" — verify with `auditpol /get /subcategory:"Other Object Access Events"` or you get zero registration events.
- **LOLBin/legacy variants:** `at.exe` and COM-based creation bypass schtasks command-line rules entirely.
- **Hidden/Tarrask tasks:** deleting the task's `SD` (security descriptor) value under `HKLM\...\Schedule\TaskCache\Tree\` hides it from `schtasks` and the Task Scheduler UI. Hunt Sysmon EID 12/13 registry events for a task `Tree` key created without a corresponding `SD` value.
- **Payload red flags:** alert when the task Action contains `-enc`/`-e`/`FromBase64String`, or runs from `C:\Users\Public`, `C:\ProgramData`, `%APPDATA%`, or `%TEMP%`; and on remote creation (`schtasks /s`).
- **Validate the rule fires:** run `schtasks /create /tn test /tr calc.exe /sc minute` and confirm EID 1 + 4698 + EID 11 all fire; repeat via `Register-ScheduledTask` to confirm the non-schtasks path is covered.
- **Tune false positives:** Google, Edge, and Adobe updaters create tasks routinely. Baseline by task path + signed binary and alert only on new/unsigned authors.

## Prerequisites

- Sysmon installed with a detection-focused configuration (e.g., SwiftOnSecurity or Olaf Hartong)
- Windows Event Log forwarding to SIEM (Splunk, Elastic, or Sentinel)
- PowerShell ScriptBlock Logging enabled (Event 4104)

## Steps

1. Configure Sysmon to log Event IDs 1, 11, 12, 13 with task-related filters
2. Build detection rules for schtasks.exe /create with suspicious arguments
3. Correlate Event 4698 (task registered) with Sysmon Event 1 (process create)
4. Hunt for tasks executing from public directories or with encoded commands
5. Alert on remote task creation (schtasks /s) for lateral movement detection

## Expected Output

```
[CRITICAL] Suspicious Scheduled Task Detected
  Task: \Microsoft\Windows\UpdateCheck
  Command: powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGU...
  Created By: DOMAIN\compromised_user
  Parent Process: cmd.exe (PID 4532)
  Source: \\192.168.1.50 (remote creation)
  MITRE: T1053.005 - Scheduled Task/Job
```
