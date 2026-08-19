---
name: hunting-for-lateral-movement-via-wmi
description: Detect WMI-based lateral movement by analyzing Windows Event ID 4688 process creation and Sysmon Event ID 1 for
  WmiPrvSE.exe child process patterns, remote process execution, and WMI event subscription persistence.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- lateral-movement
- wmi
- sysmon
- mitre-attack
- process-creation
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---
# Hunting for Lateral Movement via WMI

## Overview

Windows Management Instrumentation (WMI) is commonly abused for lateral movement via `wmic process call create` or Win32_Process.Create() to execute commands on remote hosts. Detection focuses on identifying WmiPrvSE.exe spawning child processes (cmd.exe, powershell.exe) in Windows Security Event ID 4688 and Sysmon Event ID 1 logs, along with WMI-Activity/Operational events (5857, 5860, 5861) for event subscription persistence.


## When to Use

- When investigating security incidents that require hunting for lateral movement via wmi
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **`WmiPrvSE.exe → cmd/powershell` is only one path.** Script-based consumers execute under `scrcons.exe`, and consumers that only write files/registry fire no child process at all. Rules keyed solely on WmiPrvSE child processes miss these.
- **Subscription persistence needs Sysmon EID 19/20/21**, not 4688: EID 19 = `__EventFilter`, 20 = `__EventConsumer`, 21 = `__FilterToConsumerBinding`. If those aren't enabled, WMI persistence (T1546.003) is invisible even though execution (T1047) may be logged.
- **Remote WMI rides DCOM:** expect inbound TCP 135 then an ephemeral 49152-65535 port preceding the WmiPrvSE process creation.
- **Validate the hunt fires:** run Atomic Red Team T1047 (`wmic /node:<host> process call create "cmd /c ..."`) and create a test `__EventFilter`/`CommandLineEventConsumer` binding; confirm Sysmon EID 1 (WmiPrvSE parent) and EID 19/20/21 all fire.
- **FP tuning:** SCCM, vulnerability scanners, and monitoring agents legitimately use WMI remoting and subscriptions — baseline by source host, account, and binding name.

## Prerequisites

- Windows Security Event Logs with Process Creation auditing enabled (Event 4688 with command line)
- Sysmon installed with Event ID 1 (Process Creation) configured
- Python 3.9+ with `python-evtx`, `lxml` libraries
- Understanding of WMI architecture and WmiPrvSE.exe behavior

## Steps

### Step 1: Parse Process Creation Events
Extract Event ID 4688 and Sysmon Event 1 entries from EVTX files.

### Step 2: Detect WmiPrvSE Child Processes
Flag processes where ParentImage/ParentProcessName is WmiPrvSE.exe, indicating remote WMI execution.

### Step 3: Analyze Command Line Patterns
Identify suspicious command lines matching WMI lateral movement patterns (cmd.exe /q /c, output redirection to admin$ share).

### Step 4: Check WMI Event Subscriptions
Parse WMI-Activity/Operational log for event consumer creation indicating persistence.

## Expected Output

JSON report with WMI-spawned processes, suspicious command lines, WMI event subscription alerts, and timeline of lateral movement activity.
