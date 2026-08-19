---
name: hunting-for-ntlm-relay-attacks
description: Detect NTLM relay attacks by analyzing Windows Event 4624 logon type 3 with NTLMSSP authentication, identifying
  IP-to-hostname mismatches, Responder traffic signatures, SMB signing status, and suspicious authentication patterns across
  the domain.
domain: cybersecurity
subdomain: threat-hunting
tags:
- NTLM-relay
- Windows-events
- Event-4624
- NTLMSSP
- Responder
- SMB-signing
- credential-access
- T1557.001
- Active-Directory
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

# Hunting for NTLM Relay Attacks

## Overview

NTLM relay attacks intercept and forward NTLM authentication messages to gain unauthorized access to network resources. Attackers use tools like Responder for LLMNR/NBT-NS poisoning and ntlmrelayx for credential relay. This skill detects relay activity by querying Windows Security Event 4624 (successful logon) for type 3 network logons with NTLMSSP authentication, identifying mismatches between WorkstationName and source IpAddress, detecting rapid multi-host authentication from single accounts, and auditing SMB signing configuration across domain hosts.


## When to Use

- When investigating security incidents that require hunting for ntlm relay attacks
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Same-subnet relays defeat the IP-hostname mismatch.** When the relay source and victim share a subnet (or the attacker preserves `WorkstationName`), the 4624 WorkstationName-vs-IpAddress check produces no anomaly.
- **SMB-signing audit covers only SMB.** LDAP and HTTP relay paths — notably AD CS web enrollment (ESC8) and PetitPotam/PrinterBug coercion — are missed. Watch 4624 Type 3 NTLMSSP targeting the CA enrollment host.
- **Kerberos-only environments are still vulnerable** via authentication coercion (PetitPotam EFSRPC, PrinterBug Spoolss): hunt Event 5145 named-pipe access to `\pipe\efsrpc`, `\pipe\spoolss`, `\pipe\lsarpc`, `\pipe\netlogon`, `\pipe\samr`.
- **Validate the hunt fires:** in a lab run `Responder` + `ntlmrelayx.py` (or a coercer like `PetitPotam.py`) and confirm 4624 LogonType 3 with `AuthenticationPackageName=NTLM`, a `WorkstationName`≠resolved-IP, and 5145 pipe access all appear and alert.
- **FP tuning:** legacy apps and scanners that still use NTLM, plus NAT/load-balancers that legitimately cause IP-hostname mismatches — whitelist by known service accounts and source ranges.

## Prerequisites

- Python 3.9+ with Windows Event Log access or exported logs
- Windows Security audit logging enabled (Event ID 4624, 4625, 5145)
- Network access for SMB signing status checks

## Key Detection Areas

1. **IP-hostname mismatch** — WorkstationName in Event 4624 does not resolve to the source IpAddress
2. **NTLMSSP authentication** — logon events using NTLM instead of Kerberos from domain-joined hosts
3. **Machine account relay** — computer accounts (ending in $) authenticating from unexpected IPs
4. **Rapid authentication** — single account authenticating to multiple hosts within seconds
5. **Named pipe access** — Event 5145 showing access to Spoolss, lsarpc, netlogon, samr pipes
6. **SMB signing disabled** — hosts not enforcing SMB signing, enabling relay attacks

## Output

JSON report with suspected relay events, IP-hostname correlation anomalies, SMB signing audit results, and MITRE ATT&CK mapping to T1557.001.
