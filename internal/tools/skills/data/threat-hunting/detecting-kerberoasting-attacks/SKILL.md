---
name: detecting-kerberoasting-attacks
description: Detect Kerberoasting attacks by monitoring for anomalous Kerberos TGS requests targeting service accounts with
  SPNs for offline password cracking.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- kerberoasting
- credential-access
- kerberos
- t1558
- proactive-detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Application Protocol Command Analysis
- Network Isolation
- Network Traffic Analysis
- Client-server Payload Profiling
- Network Traffic Community Deviation
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Detecting Kerberoasting Attacks

## When to Use

- When proactively hunting for indicators of detecting kerberoasting attacks in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **AES roasting evades RC4-only rules.** The classic signal is 4769 with `TicketEncryptionType=0x17` (RC4) and `TicketOptions=0x40810000`, but modern Rubeus supports `/aes` to request AES (0x12/0x11) tickets that bypass any RC4-only detection. Also alert when an account that normally authenticates with AES suddenly requests RC4.
- **Audit subcategory must be on.** No 4769 is produced unless "Audit Kerberos Service Ticket Operations" is enabled on DCs — verify with `auditpol /get /subcategory:"Kerberos Service Ticket Operations"`.
- **Volume drowns the signal.** 4769 fires on every service access. Filter `ServiceName != krbtgt`, drop machine (`$`) accounts and known SPNs, then threshold on many *distinct* SPNs requested by one account in a short window.
- **Targeted roasting hides under thresholds.** A single high-value SPN roast won't trip a count rule — keep a separate low-volume rule for RC4 requests against sensitive service accounts.
- **AS-REP roasting is a different path:** hunt 4768 with `PreAuthType=0` (0x17) for accounts flagged DONT_REQ_PREAUTH.
- **Validate the rule fires:** run `Rubeus.exe kerberoast` or Impacket `GetUserSPNs.py` against a lab SPN and confirm the 0x17 burst query returns it.
- **Tune false positives:** legacy apps and older SQL Server SPNs legitimately use RC4. Allowlist those specific SPNs rather than ignoring RC4 entirely.

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
| T1558.003 | Kerberoasting |
| T1558.004 | AS-REP Roasting |
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

1. **Scenario 1**: Rubeus kerberoast targeting all SPN accounts
2. **Scenario 2**: GetUserSPNs.py from Impacket requesting RC4 tickets
3. **Scenario 3**: Targeted kerberoast against high-privilege service accounts
4. **Scenario 4**: AS-REP roasting accounts without pre-authentication

## Output Format

```
Hunt ID: TH-DETECT-[DATE]-[SEQ]
Technique: T1558.003
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
