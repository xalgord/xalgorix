---
name: detecting-pass-the-ticket-attacks
description: Detect Kerberos Pass-the-Ticket (PtT) attacks by analyzing Windows Event IDs 4768, 4769, and 4771 for anomalous
  ticket usage patterns in Splunk and Elastic SIEM
domain: cybersecurity
subdomain: threat-detection
tags:
- kerberos
- pass-the-ticket
- active-directory
- splunk
- elastic
- credential-theft
- windows-security
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
- DE.AE-06
- ID.RA-05
---

# Detecting Pass-the-Ticket Attacks

## Overview

Pass-the-Ticket (PtT) is a credential theft technique (MITRE ATT&CK T1550.003) where adversaries steal Kerberos tickets (TGT or TGS) from one system and replay them on another to authenticate without knowing the user's password. This skill teaches detection of PtT attacks by correlating Windows Security Event IDs 4768 (TGT request), 4769 (TGS request), and 4771 (pre-authentication failure) for anomalies such as ticket reuse across different hosts, RC4 encryption downgrades, and unusual service ticket request volumes.


## When to Use

- When investigating security incidents that require detecting pass the ticket attacks
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Variants most often missed:** rules that hunt only for RC4 (`TicketEncryptionType 0x17`) downgrades miss PtT with AES tickets (`0x12`) stolen from LSASS/`kirbi` files and replayed intact — encryption type looks normal. The strongest signal is **reuse from a non-origin host**: a TGT/TGS first seen on Host A appearing in 4769/4624 from Host B with no intervening 4768, or a 4769 whose source IP/workstation differs from where the TGT was issued.
- **False negatives:** overpass-the-hash and ticket replay can occur with **no 4768 at all** (ticket imported via `Rubeus ptt`), so TGT-centric rules see nothing — correlate 4769 (service ticket) + 4624 Logon Type 3 across hosts and compare against the 4768 origin. NAT, VPN concentrators, and load-balanced egress collapse many users to one IP and hide cross-host reuse; pivot on workstation name / TargetUserName instead of IP alone.
- **Validate the rule fires:** Atomic Red Team T1550.003 (Rubeus/mimikatz dump + `ptt`/`/ptt`). Confirm the correlation alerts when the same ticket is used from a second host and when a 4769 appears with no matching 4768 for that principal.
- **FP tuning:** Kerberos clock skew, ticket renewal, RODC referrals, and roaming/Wi-Fi-to-VPN handoffs generate benign multi-host patterns — baseline per-user host counts and exclude known jump hosts/admin bastions before alerting.

## Prerequisites

- Windows Domain Controller with advanced audit policy enabled (Audit Kerberos Authentication Service, Audit Kerberos Service Ticket Operations)
- Splunk or Elastic SIEM ingesting Windows Security event logs
- Sysmon deployed on endpoints for supplementary process telemetry
- Python 3.8+ with `requests` library

## Steps

1. Enable Kerberos audit logging on Domain Controllers via Group Policy
2. Forward Event IDs 4768, 4769, and 4771 to SIEM platform
3. Deploy detection rules for RC4 encryption downgrade (TicketEncryptionType 0x17)
4. Create correlation rule for ticket reuse across multiple source IPs
5. Build baseline of normal TGS request volume per user/host
6. Alert on standard deviation anomalies in ticket request patterns
7. Investigate flagged events with enrichment from Active Directory

## Expected Output

JSON report containing detected PtT indicators including anomalous ticket requests, RC4 downgrades, cross-host ticket reuse events, and risk-scored users with MITRE ATT&CK technique mapping.
