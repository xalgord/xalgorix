---
name: detecting-suspicious-powershell-execution
description: Detect suspicious PowerShell execution patterns including encoded commands, download cradles, AMSI bypass attempts,
  and constrained language mode evasion.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- powershell
- execution
- t1059
- amsi
- proactive-detection
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

# Detecting Suspicious Powershell Execution

## When to Use

- When proactively hunting for indicators of detecting suspicious powershell execution in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **Script Block Logging (4104) is the ground truth:** EID 4104 captures the deobfuscated script. With the GPO off you only have 4688/Sysmon EID 1 command lines, which obfuscation defeats — confirm 4104 and 4103 (Module Logging) are enabled and forwarded.
- **`-EncodedCommand` and aliases:** rules keyed on the literal `powershell.exe -enc` miss `-e`, `-ec`, `pwsh`, and renamed/copied binaries — match on EID 1 `OriginalFileName = PowerShell.EXE` plus base64 entropy, not the image name.
- **AMSI bypass + downgrade:** `[Ref].Assembly...amsiInitFailed` and `-Version 2` downgrade attacks evade AMSI/4104; the `Microsoft-Windows-PowerShell` ETW provider can be patched out in-process — treat a host that suddenly *stops* emitting 4104 as suspicious, not clean.
- **LOLBin proxies:** `IEX (New-Object Net.WebClient).DownloadString` and execution via `msbuild`/`installutil` sidestep powershell.exe.
- **Validate:** run Atomic Red Team **T1059.001** (encoded command + download cradle) and confirm the 4104 keyword and encoded-command searches fire.
- **Tune FPs:** SCCM, Intune, and admin automation generate encoded/long PowerShell — baseline by signing cert and parent (allow `WmiPrvSE`/`ccmexec` parents) before alerting.

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
| T1059.001 | PowerShell |
| T1059.003 | Windows Command Shell |
| T1562.001 | Disable or Modify Tools |

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

1. **Scenario 1**: Base64 encoded PowerShell command launched by macro document
2. **Scenario 2**: IEX download cradle fetching payload from C2 server
3. **Scenario 3**: AMSI bypass via reflection patching before payload execution
4. **Scenario 4**: PowerShell Empire agent communicating with C2

## Output Format

```
Hunt ID: TH-DETECT-[DATE]-[SEQ]
Technique: T1059.001
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
