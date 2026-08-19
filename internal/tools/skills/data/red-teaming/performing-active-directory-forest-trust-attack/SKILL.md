---
name: performing-active-directory-forest-trust-attack
description: Enumerate and audit Active Directory forest trust relationships using impacket for SID filtering analysis, trust
  key extraction, cross-forest SID history abuse detection, and inter-realm Kerberos ticket assessment.
domain: cybersecurity
subdomain: red-team
tags:
- active-directory
- forest-trust
- impacket
- SID-filtering
- kerberos
- red-team
- trust-enumeration
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
---

# Performing Active Directory Forest Trust Attack

## Overview

Active Directory forest trusts enable authentication across organizational boundaries but introduce attack surface if misconfigured. This skill uses impacket to enumerate trust relationships, analyze SID filtering configuration, detect SID history abuse vectors, perform cross-forest SID lookups via LSA/LSAT RPC calls, and assess inter-realm Kerberos ticket configurations for trust ticket forgery risks.


## When to Use

- When conducting security assessments that involve performing active directory forest trust attack
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

- SID history injection is the classic missed win: after compromising a child domain, forge an inter-realm TGT with the parent's Enterprise Admins SID (519) in ExtraSids — `mimikatz "kerberos::golden /user:Administrator /domain:child.corp.local /sid:<child-SID> /sids:<parent-SID>-519 /krbtgt:<hash> /ptt"` or Rubeus `golden`. SID filtering being disabled (TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL / quarantine off on intra-forest trusts) is what makes this land.
- Disable SID filtering check is skipped constantly — confirm with `netdom trust child.corp.local /domain:parent.corp.local /quarantine` and trustAttributes flags; intra-forest trusts do NOT filter SIDs 519/518/512 by default.
- Unconstrained delegation + printer bug across the trust: coerce a foreign DC (`SpoolSample`/`PetitPotam`) to a server you control with unconstrained delegation in the other forest, then capture its TGT.
- Don't forget the foreign-account angle: enumerate FSPs and accounts with sIDHistory pointing across the trust (`Get-ADUser -Filter {sIDHistory -like '*'}`).
- Positive signal: a forged/cross-realm ticket grants access to a parent/foreign-forest resource — `dir \\dc.parent.corp.local\C$` succeeds, or `klist` shows an inter-realm TGT (krbtgt/PARENT) accepted.
- Don't conclude the trust is non-exploitable until: (1) trust direction AND transitivity checked (inbound/bidirectional + transitive enables more), (2) SID filtering/quarantine state confirmed per-trust, (3) ExtraSids golden ticket tested, (4) unconstrained-delegation hosts on both sides enumerated, and (5) ADCS in the foreign forest checked for cross-trust enrollment.

## Prerequisites

- Python 3.9+ with `impacket`, `ldap3`
- Domain credentials with read access to AD trust objects
- Network access to Domain Controllers (ports 389, 445, 88)
- Authorized penetration testing engagement or lab environment


> **Legal Notice:** This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Steps

1. Enumerate forest trust relationships via LDAP trusted domain objects
2. Query trust attributes and SID filtering status for each trust
3. Perform SID lookups across trust boundaries using LsarLookupNames3
4. Enumerate foreign security principals in trusted domains
5. Check for SID history on cross-forest accounts
6. Assess trust direction and transitivity for lateral movement paths
7. Generate trust security audit report with risk findings

## Expected Output

- JSON report listing all trust relationships, SID filtering status, foreign principals, trust direction/transitivity, and risk assessment
- Cross-forest attack path analysis with remediation recommendations
