---
name: hunting-for-dcsync-attacks
description: Detect DCSync attacks by analyzing Windows Event ID 4662 for unauthorized DS-Replication-Get-Changes requests
  from non-domain-controller accounts.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- dcsync
- active-directory
- credential-access
- t1003.006
- mimikatz
- windows
- dfir
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Application Protocol Command Analysis
- Network Isolation
- Network Traffic Analysis
- Client-server Payload Profiling
- Platform Monitoring
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting for DCSync Attacks

## When to Use

- When hunting for DCSync credential theft (MITRE ATT&CK T1003.006)
- After detecting Mimikatz or similar tools in the environment
- During incident response involving Active Directory compromise
- When monitoring for unauthorized domain replication requests
- During purple team exercises testing AD attack detection

## Detection Gaps & Validation

- **No SACL = no telemetry.** Event 4662 is only generated if "Audit Directory Service Access" is enabled AND the domain object's SACL audits the replication extended rights. Without both, DCSync is completely invisible — verify the SACL before trusting a "clean" result.
- **Both GUIDs matter:** flag `DS-Replication-Get-Changes` (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) AND `DS-Replication-Get-Changes-All` (1131f6ad-...). Get-Changes-All is the strong signal; Get-Changes alone can be benign.
- **Source-based detection blind spots:** an attacker running from a real DC or relaying a DC machine account won't trip the "non-DC source" filter.
- **Validate the hunt fires:** run `mimikatz lsadump::dcsync /user:krbtgt` or Impacket `secretsdump.py -just-dc` from a non-DC host; confirm 4662 with AccessMask 0x100 and the replication GUID appears and your rule alerts.
- **FP tuning:** legitimate DCs replicating, Azure AD Connect / Entra Connect (`MSOL_` / `AAD_` accounts), some backup/migration tools. Whitelist by exact account **and** source IP, never by name substring alone.

## Prerequisites

- Windows Security Event Log forwarding enabled (Event ID 4662)
- Audit Directory Service Access enabled via Group Policy
- Domain Computers SACL configured on Domain Object for machine account detection
- SIEM with Windows event data ingested (Splunk, Elastic, Sentinel)
- Knowledge of legitimate domain controller accounts and replication partners

## Workflow

1. **Enable Auditing**: Ensure Audit Directory Service Access is enabled on domain controllers.
2. **Collect Events**: Gather Windows Event ID 4662 with AccessMask 0x100 (Control Access).
3. **Filter Replication GUIDs**: Search for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All.
4. **Identify Non-DC Sources**: Flag events where SubjectUserName is not a domain controller machine account.
5. **Correlate with Network**: Cross-reference source IPs against known DC addresses.
6. **Validate Findings**: Exclude legitimate replication tools (Azure AD Connect, SCCM).
7. **Respond**: Disable compromised accounts, reset krbtgt, investigate lateral movement.

## Key Concepts

| Concept | Description |
|---------|-------------|
| DCSync | Technique abusing AD replication protocol to extract password hashes |
| Event ID 4662 | Directory Service Access audit event |
| DS-Replication-Get-Changes | GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 |
| DS-Replication-Get-Changes-All | GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |
| AccessMask 0x100 | Control Access right indicating extended rights verification |
| T1003.006 | OS Credential Dumping: DCSync |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Windows Event Viewer | Direct event log analysis |
| Splunk | SIEM correlation of Event 4662 |
| Elastic Security | Detection rules for DCSync patterns |
| Mimikatz lsadump::dcsync | Attack tool used to perform DCSync |
| Impacket secretsdump.py | Python-based DCSync implementation |
| BloodHound | Identify accounts with replication rights |

## Output Format

```
Hunt ID: TH-DCSYNC-[DATE]-[SEQ]
Technique: T1003.006
Domain Controller: [DC hostname]
Subject Account: [Account performing replication]
Source IP: [Non-DC IP address]
GUID Accessed: [Replication GUID]
Risk Level: [Critical/High/Medium/Low]
Recommended Action: [Disable account, reset krbtgt, investigate]
```
