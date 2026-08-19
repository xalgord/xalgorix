---
name: hunting-for-living-off-the-cloud-techniques
description: Hunt for adversary abuse of legitimate cloud services for C2, data staging, and exfiltration including abuse
  of Azure, AWS, GCP services, and SaaS platforms.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- cloud-abuse
- c2
- lotc
- saas
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

# Hunting For Living Off The Cloud Techniques

## When to Use

- When proactively hunting for indicators of hunting for living off the cloud techniques in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **Reputation-based detection is useless here.** C2 over trusted SaaS — Discord/Slack/Telegram webhooks, Microsoft Graph API, Google Drive, Notion, Pastebin — terminates at high-reputation domains your allowlists already trust (T1102/T1567/T1537). Block volume/beacon-timing analysis and JA3/JARM, not domain reputation.
- **OAuth/refresh-token abuse leaves no malware** on disk; the access looks like a normal API client.
- **Cloud-native C2 (Azure Functions, AWS Lambda) originates from provider IP ranges** indistinguishable from legitimate cloud egress.
- **TLS hides the payload** — without inspection you only have destination + timing; lean on periodicity/jitter analysis to surface beacons to SaaS endpoints.
- **Validate the hunt fires:** simulate exfil to a Telegram bot (`api.telegram.org/bot.../sendDocument`) or a Graph API upload, then confirm EDR/proxy network telemetry and your beacon-detection logic flag the periodic SaaS traffic.
- **FP tuning:** legitimate corporate use of the exact same SaaS. Baseline per-user/per-host normal destinations and data volume, and alert on deviation rather than the service itself.

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
| T1102 | Web Service |
| T1567 | Exfiltration Over Web Service |
| T1537 | Transfer Data to Cloud Account |

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

1. **Scenario 1**: C2 over Discord webhooks for command delivery
2. **Scenario 2**: Data exfiltration to Telegram bot API
3. **Scenario 3**: Malware using Azure Functions for dynamic C2
4. **Scenario 4**: Staging stolen data on Google Docs or Notion pages

## Output Format

```
Hunt ID: TH-HUNTIN-[DATE]-[SEQ]
Technique: T1102
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
