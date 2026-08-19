---
name: detecting-golden-ticket-forgery
description: Detect Kerberos Golden Ticket forgery by analyzing Windows Event ID 4769 for RC4 encryption downgrades (0x17),
  abnormal ticket lifetimes, and krbtgt account anomalies in Splunk and Elastic SIEM
domain: cybersecurity
subdomain: threat-detection
tags:
- golden-ticket
- kerberos
- active-directory
- mimikatz
- splunk
- credential-theft
- windows-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Token Binding
- Restore Access
- Reissue Credential
- Decoy User Credential
- Authentication Cache Invalidation
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
---

# Detecting Golden Ticket Forgery

## Overview

A Golden Ticket attack (MITRE ATT&CK T1558.001) involves forging a Kerberos Ticket Granting Ticket (TGT) using the krbtgt account NTLM hash, granting unrestricted access to any service in the Active Directory domain. This skill detects Golden Ticket usage by analyzing Event ID 4769 for RC4 encryption type (0x17) in environments enforcing AES, identifying tickets with abnormal lifetimes exceeding domain policy, correlating TGS requests with missing corresponding TGT requests (Event ID 4768), and detecting krbtgt password age anomalies.


## When to Use

- When investigating security incidents that require detecting golden ticket forgery
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Variants most often missed:** detection keyed on RC4 (`0x17`) downgrade misses **Diamond** and **Sapphire** tickets, which request a real TGT (genuine 4768 exists) then decrypt/modify the PAC and re-encrypt with AES (`0x12`) — so "RC4 in an AES domain" and "orphaned 4769 with no 4768" both fail. Modern Mimikatz/Rubeus forge AES tickets by default when the AES key is known.
- **False negatives:** a forged TGT means **no 4768 is ever generated** on the DC for the initial grant — only 4769 (TGS) and downstream 4624 appear, so TGT-centric rules see nothing. Watch for 4769 where the account name does not match a real principal, lifetimes exceeding `MaxTicketAge`/`MaxRenewAge` (default 10h/7d), or krbtgt-signed tickets after a single krbtgt reset (KB5008380 PAC validation flags tickets failing the new signature once DCs are in Enforcement mode).
- **Validate the rule fires:** Atomic Red Team T1558.001 (Rubeus/mimikatz `golden` ticket creation and `ptt`). Confirm alerts on 4769 with abnormal lifetime, krbtgt password-age anomaly, and PAC validation failure events (Microsoft-Windows-Kerberos `Event 4` / KDC errors) post-KB5008380.
- **FP tuning:** long-lived service tickets from scheduled tasks and clustered services produce benign long lifetimes; baseline per-service. Reset krbtgt **twice** so historical legitimate tickets are not mistaken for forgeries during rotation windows.

## Prerequisites

- Windows Domain Controller with Kerberos audit logging enabled
- Splunk or Elastic SIEM ingesting Windows Security event logs
- Python 3.8+ for offline event log analysis
- Knowledge of domain Kerberos encryption policy (AES vs RC4)

## Steps

1. Audit domain Kerberos encryption policy to establish AES-only baseline
2. Forward Event IDs 4768 and 4769 to SIEM platform
3. Detect RC4 (0x17) encryption in TGS requests where AES is enforced
4. Identify TGS requests without corresponding TGT requests (forged ticket indicator)
5. Alert on ticket lifetimes exceeding MaxTicketAge domain policy
6. Monitor krbtgt account password age and last reset date
7. Correlate findings with host/user context for risk scoring

## Expected Output

JSON report with Golden Ticket indicators including RC4 downgrades, orphaned TGS requests, abnormal ticket lifetimes, and risk-scored alerts with MITRE ATT&CK technique mapping.
