---
name: hunting-for-unusual-service-installations
description: Detect suspicious Windows service installations (MITRE ATT&CK T1543.003) by parsing System event logs for Event
  ID 7045, analyzing service binary paths, and identifying indicators of persistence mechanisms.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- T1543.003
- service-installation
- persistence
- Event-7045
- Sysmon
- Windows-services
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Platform Hardening
- System Configuration Permissions
- Restore Object
- Restore Database
- Asset Inventory
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting for Unusual Service Installations

## Overview

Attackers frequently install malicious Windows services for persistence and privilege escalation (MITRE ATT&CK T1543.003 — Create or Modify System Process: Windows Service). Event ID 7045 in the System event log records every new service installation. This skill parses .evtx log files to extract service installation events, flags suspicious binary paths (temp directories, PowerShell, cmd.exe, encoded commands), and correlates with known attack patterns.


## When to Use

- When investigating security incidents that require hunting for unusual service installations
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **7045 doesn't cover modification:** EID 7045 (System) logs new user-mode and kernel-driver service installs, but `sc config` / registry edits of an EXISTING service's `ImagePath` raise NO 7045 — hunt EID 4697 (Security, needs "Audit Security System Extension") and Sysmon EID 13 on `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath`.
- **Install-run-delete:** PsExec-style services that install, run, then remove may leave only 7045 + 7036/7034/7009 — correlate those to catch the transient.
- **svchost-hosted services:** the payload is in `\Parameters\ServiceDll`, not `ImagePath` — inspect that value too.
- **BYOVD / kernel drivers:** malicious `.sys` loads as a service (type 1) — cross-check Sysmon EID 6 DriverLoad and signature/revocation status.
- **Validate:** run Atomic T1543.003 (create service via sc.exe and PowerShell); confirm 7045 `ImagePath` + `ServiceType` are captured.
- **FP tuning:** baseline signed vendor agents (EDR, backup) and built-in Windows services by signer + path.

## Prerequisites

- Python 3.9+ with `python-evtx`, `lxml`
- Windows System event log (.evtx) files
- Access to live System event log (optional, for real-time monitoring)
- Sysmon logs for enhanced process tracking (optional)

## Steps

1. Parse System.evtx for Event ID 7045 (new service installed)
2. Extract service name, binary path, service type, and account
3. Flag services with suspicious binary paths (temp dirs, encoded commands)
4. Detect PowerShell-based service creation patterns
5. Identify services running as LocalSystem with unusual paths
6. Cross-reference with known legitimate service baselines
7. Generate threat hunting report with MITRE ATT&CK T1543.003 mapping

## Expected Output

- JSON report listing all new service installations with risk scores, suspicious indicators, and remediation recommendations
- Timeline of service installation events with binary path analysis
