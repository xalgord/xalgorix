---
name: detecting-service-account-abuse
description: Detect abuse of service accounts through anomalous interactive logons, privilege escalation, lateral movement,
  and unauthorized access patterns.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- service-accounts
- privilege-escalation
- t1078
- proactive-detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Restore Access
- Password Authentication
- Biometric Authentication
- Strong Password Policy
- Restore User Account Access
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Detecting Service Account Abuse

## When to Use

- When proactively hunting for indicators of detecting service account abuse in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **Interactive logon is the signal:** service accounts should only show 4624 Type 5 (service) or Type 3 (network). Hunt 4624 **Type 2 (interactive)** and **Type 10 (RemoteInteractive/RDP)** for any `svc_*` account — but only if those logon types are collected (Type 10 needs RDP/TS auditing on the destination).
- **Kerberoasting precursor:** T1558.003 shows as 4769 TGS requests with `Ticket Encryption Type 0x17 (RC4)` for the service account's SPN — if 4769 auditing is disabled on DCs, the roasting is invisible.
- **Baseline host and time-of-day:** compare each service account's source-host set and hours against a 30-day baseline; a backup or SQL account suddenly touching a DC or a new subnet is the tell.
- **Evasions:** attackers reuse the account's *expected* Type 3 logon from an already-allowed host, so volume/destination anomalies — not logon type alone — catch them; gMSA abuse can look fully legitimate.
- **Validate:** force an interactive RDP logon with a test service account and run Atomic **T1558.003** Kerberoast to confirm the 4624 Type 10 and 4769 RC4 searches fire.
- **Tune FPs:** patch windows, clustering, and admin troubleshooting create legitimate off-hours service-account activity — allowlist known maintenance windows and jump hosts.

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
| T1078.002 | Domain Accounts |
| T1078.001 | Default Accounts |
| T1021 | Remote Services |

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

1. **Scenario 1**: Service account RDP to domain controller
2. **Scenario 2**: SQL service accessing file shares outside scope
3. **Scenario 3**: Backup service lateral movement off-hours
4. **Scenario 4**: Compromised svc with DA privileges used for DCSync

## Output Format

```
Hunt ID: TH-DETECT-[DATE]-[SEQ]
Technique: T1078.002
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
