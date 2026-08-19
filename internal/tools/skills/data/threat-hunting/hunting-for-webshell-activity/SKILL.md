---
name: hunting-for-webshell-activity
description: Hunt for web shell deployments on internet-facing servers by analyzing file creation in web directories, suspicious
  process spawning from web servers, and anomalous HTTP patterns.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- webshell
- persistence
- web-server
- t1505
- proactive-detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Restore Access
- Process Termination
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting For Webshell Activity

## When to Use

- When proactively hunting for indicators of hunting for webshell activity in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **File-create hunting misses a lot:** shells appended to existing legit `.aspx`/`.php`, stored in a database, loaded as an in-memory IIS module (T1505.004), or served via handler mapping under a benign extension. Hash/signature scans miss obfuscated one-liners like `<?php @eval($_POST['x']);?>`.
- **Process lineage is the durable signal:** w3wp.exe / httpd / tomcat / php-cgi spawning cmd.exe/powershell/whoami (EID 1, ParentImage = web server) catches even unknown shells; EID 11 FileCreate in webroot by the web-server process (not a deploy pipeline) is high-signal.
- **Low-and-slow operators:** China Chopper uses tiny intermittent POSTs that hide in netflow — needs web/proxy log content inspection, not volume thresholds.
- **Validate:** drop a benign test `.aspx` that runs `whoami`; confirm the w3wp→cmd EID 1 chain and the EID 11 write both fire.
- **FP tuning:** baseline legitimate CI/CD deploys and admin maintenance scripts that legitimately write to webroot.

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
| T1505.003 | Web Shell |
| T1190 | Exploit Public-Facing Application |
| T1059.001 | PowerShell |

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

1. **Scenario 1**: China Chopper web shell via IIS vulnerability
2. **Scenario 2**: ASPXSpy through vulnerable upload
3. **Scenario 3**: PHP shell hidden in image file
4. **Scenario 4**: JSP shell via Tomcat manager console

## Output Format

```
Hunt ID: TH-HUNTIN-[DATE]-[SEQ]
Technique: T1505.003
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
