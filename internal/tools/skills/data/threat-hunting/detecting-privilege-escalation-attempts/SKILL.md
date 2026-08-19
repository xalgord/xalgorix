---
name: detecting-privilege-escalation-attempts
description: Detect privilege escalation attempts including token manipulation, UAC bypass, unquoted service paths, kernel
  exploits, and sudo/doas abuse across Windows and Linux.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- privilege-escalation
- token-manipulation
- uac-bypass
- proactive-detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Token Binding
- Executable Denylisting
- Execution Isolation
- Restore Access
- Reissue Credential
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Detecting Privilege Escalation Attempts

## When to Use

- When proactively hunting for indicators of detecting privilege escalation attempts in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **Token manipulation barely logs:** T1134 SeDebugPrivilege/`DuplicateTokenEx` abuse rarely emits a clean Security EID — rely on Sysmon EID 10 (ProcessAccess to a higher-integrity PID with `0x1410`/`0x1FFFFF`) plus 4688 with `TokenElevationType = %%1937` (full token). If 4688 command-line auditing is off, the escalation is invisible.
- **UAC-bypass blind spots:** fodhelper/computerdefaults/eventvwr leave no UAC consent event (4673/4674 are noisy and usually disabled) — hunt Sysmon EID 12/13 on `HKCU\...\ms-settings\shell\open\command` and EID 1 where these auto-elevate binaries spawn cmd/powershell.
- **Unquoted service path (T1574.009)** fires at service start via EID 7045/4697 + 4688 with parent `services.exe` — easy to miss if service-install auditing is disabled.
- **Evasions:** named-pipe impersonation (Potato variants) looks like normal RPC; kernel exploits (T1068) may only surface as an Application-log crash (EID 1000).
- **Validate:** run Atomic Red Team **T1548.002** (fodhelper) and **T1134.001** to confirm the registry-set and token-elevation searches fire end-to-end.
- **Tune FPs:** legitimate installers and `consent.exe`-driven elevations are expected — baseline by parent process and signing status, not binary name alone.

## Prerequisites

- EDR platform with process and network telemetry (CrowdStrike, MDE, SentinelOne)
- SIEM with relevant log data ingested (Splunk, Elastic, Sentinel)
- Sysmon deployed with comprehensive configuration
- Windows Security Event Log forwarding enabled
- Threat intelligence feeds for IOC correlation

## Workflow

1. **Formulate Hypothesis**: Define a testable hypothesis based on threat intelligence or ATT&CK gap analysis.
2. **Identify Data Sources**: Determine which logs and telemetry are needed to validate or refute the hypothesis.
3. **Execute Queries**: Run detection queries against SIEM and EDR platforms to collect relevant events.
4. **Analyze Results**: Examine query results for anomalies, correlating across multiple data sources.
5. **Validate Findings**: Distinguish true positives from false positives through contextual analysis.
6. **Correlate Activity**: Link findings to broader attack chains and threat actor TTPs.
7. **Document and Report**: Record findings, update detection rules, and recommend response actions.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1134 | Access Token Manipulation |
| T1548.002 | UAC Bypass |
| T1068 | Exploitation for Privilege Escalation |
| T1574.009 | Unquoted Service Path |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CrowdStrike Falcon | EDR telemetry and threat detection |
| Microsoft Defender for Endpoint | Advanced hunting with KQL |
| Splunk Enterprise | SIEM log analysis with SPL queries |
| Elastic Security | Detection rules and investigation timeline |
| Sysmon | Detailed Windows event monitoring |
| Velociraptor | Endpoint artifact collection and hunting |
| Sigma Rules | Cross-platform detection rule format |

## Common Scenarios

1. **Scenario 1**: Potato exploit for SYSTEM token impersonation
2. **Scenario 2**: Fodhelper.exe UAC bypass technique
3. **Scenario 3**: PrintSpoofer privilege escalation from service to SYSTEM
4. **Scenario 4**: CVE kernel exploit for local privilege escalation

## Output Format

```
Hunt ID: TH-DETECT-[DATE]-[SEQ]
Technique: T1134
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
