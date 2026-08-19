---
name: detecting-pass-the-hash-attacks
description: Detect Pass-the-Hash attacks by analyzing NTLM authentication patterns, identifying Type 3 logons with NTLM where
  Kerberos is expected, and correlating with credential dumping.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- pass-the-hash
- credential-access
- t1550
- proactive-detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Token Binding
- Execution Isolation
- Restore Access
- Application Protocol Command Analysis
- Process Termination
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Detecting Pass The Hash Attacks

## When to Use

- When proactively hunting for indicators of detecting pass the hash attacks in the environment
- After threat intelligence indicates active campaigns using these techniques
- During incident response to scope compromise related to these techniques
- When EDR or SIEM alerts trigger on related indicators
- During periodic security assessments and purple team exercises

## Detection Gaps & Validation

- **NTLM logging is the blind spot:** PtH surfaces as Security EID 4624 Type 3 with `Authentication Package = NTLM` and `Logon Process = NtLmSsp` on a host/account that normally uses Kerberos. If NTLM auditing (`Restrict NTLM: Audit NTLM authentication`) and DC EID 4776 are not enabled, the hash use is invisible — confirm both are on.
- **Local-account hashes (RID 500) skip DC logs:** lateral movement with a local admin hash only logs on the destination, not the DC. Hunt 4624 Type 3 where `TargetUserName` is a local account and `LogonGuid` is all-zero (no Kerberos TGT was ever requested).
- **LogonGuid = {00000000-0000-...}** reliably separates NTLM 4624s from Kerberos; attackers cannot fake a TGT they never obtained.
- **Evasions:** over-pass-the-hash converts the hash to a Kerberos ticket so activity shows as 4768/4769 and defeats NTLM-only rules; Impacket sets `Logon Process = User32`/`seclogo` only on legacy paths.
- **Validate the rule fires:** run Atomic Red Team **T1550.002** (Mimikatz `sekurlsa::pth` or Impacket `psexec.py -hashes`) from a test host and confirm the 4624 Type 3 / 4776 events land in the SIEM within the search window.
- **Tune FPs:** scheduled tasks, vuln scanners (Nessus/Qualys), and clustered apps generate legitimate NTLM Type 3 logons — baseline service accounts and exclude known source IPs, not account names.

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
| T1550.002 | Pass the Hash |
| T1550.003 | Pass the Ticket |
| T1078 | Valid Accounts |

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

1. **Scenario 1**: Mimikatz sekurlsa::pth with stolen NTLM hash
2. **Scenario 2**: Impacket psexec.py remote execution with hash
3. **Scenario 3**: CrackMapExec hash spraying across hosts
4. **Scenario 4**: WMI lateral movement via pass-the-hash

## Output Format

```
Hunt ID: TH-DETECT-[DATE]-[SEQ]
Technique: T1550.002
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
