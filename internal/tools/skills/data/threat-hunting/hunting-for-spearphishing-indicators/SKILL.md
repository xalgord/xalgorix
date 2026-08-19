---
name: hunting-for-spearphishing-indicators
description: Hunt for spearphishing campaign indicators across email logs, endpoint telemetry, and network data to detect
  targeted email attacks.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- spearphishing
- initial-access
- email-security
- t1566
- proactive-detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- File Metadata Consistency Validation
- Application Protocol Command Analysis
- Identifier Analysis
- Content Format Conversion
- Message Analysis
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting For Spearphishing Indicators

## When to Use

- When proactively hunting for indicators of hunting for spearphishing indicators in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **Delivery variants gateways miss:** HTML smuggling (JS-built blob, nothing inbound to scan), ISO/IMG/VHD containers that strip MOTW, password-protected ZIPs (uninspectable), QR-code phish in PDFs, and OneNote `.one` attachments.
- **Endpoint pivot is the reliable signal:** hunt Office/Outlook spawning children — EID 1 where `ParentImage` is winword/excel/outlook.exe and child is powershell/wscript/mshta/cmd — plus EID 11 writes of `.iso`/`.lnk`/`.hta` to `%TEMP%`/Downloads.
- **MOTW check:** absence of a `Zone.Identifier` ADS on a freshly downloaded payload is itself suspicious (container-bypass indicator).
- **Pure-link blind spot:** credential-harvest links leave no endpoint artifact — you need proxy/URL logs, not EDR, to see them.
- **Validate:** run Atomic T1566.001 (macro spawns child process); confirm the parent→child EID 1 chain fires.
- **FP tuning:** baseline legitimate Office automation/add-ins and known mail-merge senders.

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
| T1566.001 | Spearphishing Attachment |
| T1566.002 | Spearphishing Link |
| T1566.003 | Spearphishing via Service |

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

1. **Scenario 1**: Macro-enabled Excel executing PowerShell downloader
2. **Scenario 2**: HTML smuggling delivering ISO with LNK payload
3. **Scenario 3**: Credential harvesting link as SharePoint notification
4. **Scenario 4**: QR code phishing in PDF attachment

## Output Format

```
Hunt ID: TH-HUNTIN-[DATE]-[SEQ]
Technique: T1566.001
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
