---
name: hunting-for-scheduled-task-persistence
description: Hunt for adversary persistence via Windows Scheduled Tasks by analyzing task creation events, suspicious task
  actions, and unusual scheduling patterns.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- scheduled-tasks
- persistence
- t1053
- proactive-detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Execution Isolation
- Process Termination
- Hardware-based Process Isolation
- Platform Monitoring
- Process Suspension
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting For Scheduled Task Persistence

## When to Use

- When proactively hunting for indicators of hunting for scheduled task persistence in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **Audit subcategory off by default:** Security EID 4698 (task created) / 4702 (updated) only log when "Object Access > Other Object Access Events" auditing is enabled — absence of 4698 does NOT mean no tasks. Corroborate with Microsoft-Windows-TaskScheduler/Operational (EID 106/140/200), itself frequently disabled.
- **Action-type evasion:** tasks using a `ComHandler` CLSID instead of an exec path, and tasks written directly to the registry `...\Schedule\TaskCache\Tree`, bypass schtasks.exe EID 1 command-line hunting.
- **Hidden tasks:** deleting the SD (SDDL) value removes a task from `schtasks /query` and the GUI while it still runs — diff TaskCache GUIDs to surface them.
- **Cross-platform:** Linux cron (T1053.003) / at (T1053.002) need auditd watches on `/etc/cron*` and crontab, not Windows logs.
- **Validate:** run Atomic T1053.005 (`schtasks /create`) and `Register-ScheduledTask`; confirm 4698 + TaskScheduler/Operational fire.
- **FP tuning:** baseline GoogleUpdate, Adobe, OneDrive, and SCCM tasks under `\Microsoft\`.

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
| T1053.005 | Scheduled Task |
| T1053.003 | Cron |
| T1053.002 | At |

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

1. **Scenario 1**: Cobalt Strike persistence via schtasks creating periodic beacon
2. **Scenario 2**: Ransomware scheduled task for re-execution after reboot
3. **Scenario 3**: APT encoded PowerShell task running every 30 minutes
4. **Scenario 4**: Insider task to periodically copy sensitive files

## Output Format

```
Hunt ID: TH-HUNTIN-[DATE]-[SEQ]
Technique: T1053.005
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
