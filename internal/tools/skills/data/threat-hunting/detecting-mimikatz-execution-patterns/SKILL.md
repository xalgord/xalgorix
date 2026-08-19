---
name: detecting-mimikatz-execution-patterns
description: Detect Mimikatz execution through command-line patterns, LSASS access signatures, binary indicators, and in-memory
  detection of known modules.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- mimikatz
- credential-dumping
- edr
- t1003
- proactive-detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Execution Isolation
- Process Termination
- Hardware-based Process Isolation
- Web Session Access Mediation
- Process Suspension
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Detecting Mimikatz Execution Patterns

## When to Use

- When proactively hunting for indicators of detecting mimikatz execution patterns in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **String/hash signatures are trivially evaded.** Renamed binaries, in-memory execution (Invoke-Mimikatz, reflective PE load, Cobalt Strike BOFs), and renamed module strings (`sekurlsa::logonpasswords`) defeat command-line and file-hash detection. Don't anchor on `mimikatz` keywords.
- **The durable signal is LSASS access.** Hunt Sysmon **EID 10** ProcessAccess targeting `lsass.exe` with `GrantedAccess` of `0x1010`, `0x1410`, `0x143a`, or `0x1fffff` from a non-system process. Verify EID 10 is enabled and lsass is not excluded in the Sysmon config — a common gap.
- **LOLBin dumping bypasses mimikatz entirely:** `rundll32 comsvcs.dll MiniDump <pid> ...`, Task Manager "Create dump file", and `procdump -ma lsass.exe` produce a dump with no mimikatz artifacts. Hunt these command lines plus EID 11 writes of `*.dmp`.
- **Protection changes the picture:** RunAsPPL and Credential Guard block classic reads (attackers may avoid lsass). The Microsoft-Windows-Threat-Intelligence ETW provider catches suspicious lsass handle opens that user-mode logging misses.
- **Validate the rule fires:** run `procdump -ma lsass.exe` (or lab mimikatz `sekurlsa::logonpasswords`) and confirm both the EID 10 GrantedAccess query and the comsvcs/dmp query trigger.
- **Tune false positives:** AV/EDR (e.g., MsMpEng), backup, and DLP agents legitimately open lsass. Allowlist signed security tools by image path rather than suppressing all lsass access.

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
| T1003.001 | LSASS Memory |
| T1003.006 | DCSync |
| T1558.003 | Kerberoasting |
| T1558.001 | Golden Ticket |

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

1. **Scenario 1**: Standard sekurlsa::logonpasswords credential dump
2. **Scenario 2**: PowerShell Invoke-Mimikatz reflective loading
3. **Scenario 3**: DCSync from non-DC host
4. **Scenario 4**: Golden ticket creation for persistence

## Output Format

```
Hunt ID: TH-DETECT-[DATE]-[SEQ]
Technique: T1003.001
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
