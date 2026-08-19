---
name: hunting-for-registry-run-key-persistence
description: Detect MITRE ATT&CK T1547.001 registry Run key persistence by analyzing Sysmon Event ID 13 logs and registry
  queries to identify malicious auto-start entries.
domain: cybersecurity
subdomain: threat-hunting
tags:
- persistence
- registry-run-keys
- t1547-001
- sysmon
- threat-hunting
- windows-forensics
- mitre-attack
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
# Hunting for Registry Run Key Persistence

## Overview

Registry Run keys (T1547.001) are one of the most commonly used persistence mechanisms by adversaries. When a program is added to a Run key in the Windows registry, it executes automatically when a user logs in. Attackers abuse keys under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, and their RunOnce counterparts to maintain persistence. Sysmon Event ID 13 (RegistryEvent - Value Set) captures registry value modifications including the target object path, the process that made the change, and the new value. Detection involves monitoring these events for suspicious executables in temp directories, encoded PowerShell commands, LOLBin paths, and processes that do not normally create Run key entries. Chaining Event 13 with Event 1 (Process Creation) and Event 11 (FileCreate) strengthens detection by confirming payload creation and execution.


## When to Use

- When investigating security incidents that require hunting for registry run key persistence
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Filter completeness is everything:** EID 13 fires only for paths in your Sysmon RegistryEvent rules. Confirm coverage of HKLM and HKCU `...\CurrentVersion\Run`, `RunOnce`, `RunOnceEx`, `\Policies\Explorer\Run`, AND `Wow6432Node` variants — partial configs are the dominant false-negative.
- **Value-only persistence:** encoded PowerShell, `mshta http`, or `rundll32` written straight into the value leaves no EID 11 FileCreate, and chaining to EID 1 fails when the LOLBin itself is the registered command.
- **Self-erasing evidence:** RunOnce auto-deletes its value at execution; a same-day EID 13 with empty `Details` may be the only trace.
- **Offline hives:** logged-off users' Run keys live in unmounted NTUSER.DAT, invisible to live `reg query`.
- **Validate:** run Atomic T1547.001 writing a Run value via both reg.exe and PowerShell; confirm `TargetObject`, `Details`, and `Image` populate.
- **FP tuning:** baseline OneDrive, Teams, Spotify, and vendor updaters by signed image + expected value string.

## Prerequisites

- Windows systems with Sysmon installed and configured to log Event ID 13
- Sysmon config with RegistryEvent rules for Run/RunOnce keys
- Python 3.9+ with `json`, `xml.etree.ElementTree`, `re` modules
- SIEM or log aggregator collecting Sysmon logs (Splunk, Elastic, Sentinel)
- Knowledge of legitimate auto-start programs for baseline comparison

## Steps

1. Collect Sysmon Event ID 13 logs filtered for Run/RunOnce key paths
2. Parse event XML/JSON for TargetObject, Details (value written), Image (modifying process)
3. Flag entries where the value points to temp directories, AppData, or ProgramData
4. Detect encoded PowerShell commands or script interpreters in registry values
5. Identify LOLBin abuse (mshta.exe, rundll32.exe, regsvr32.exe, wscript.exe)
6. Compare against known-good baseline of legitimate auto-start entries
7. Check if the modifying process (Image) is unusual (cmd.exe, powershell.exe, python.exe)
8. Chain with Event ID 1 to verify if the registered binary was recently created
9. Generate detection report with MITRE ATT&CK mapping and severity scores
10. Produce Sigma/Splunk detection rules from findings

## Expected Output

A JSON report listing suspicious Run key entries with the registry path, value written, modifying process, timestamp, MITRE technique mapping, severity rating, and recommended Sigma detection rules.
