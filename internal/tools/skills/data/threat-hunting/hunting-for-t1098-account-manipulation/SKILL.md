---
name: hunting-for-t1098-account-manipulation
description: Hunt for MITRE ATT&CK T1098 account manipulation including shadow admin creation, SID history injection, group
  membership changes, and credential modifications using Windows Security Event Logs.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- t1098
- account-manipulation
- active-directory
- persistence
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Token Binding
- Restore Access
- Application Protocol Command Analysis
- Password Authentication
- Biometric Authentication
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---
# Hunting for T1098 Account Manipulation

## Overview

MITRE ATT&CK T1098 (Account Manipulation) covers adversary actions to maintain or expand access to compromised accounts, including adding credentials, modifying group memberships, SID history injection, and creating shadow admin accounts. This skill covers detecting these techniques through Windows Security Event Log analysis (Event IDs 4738, 4728, 4732, 4756, 4670, 5136), correlating group membership changes with privilege escalation indicators, and identifying anomalous account modification patterns.


## When to Use

- When investigating security incidents that require hunting for t1098 account manipulation
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Event coverage must be complete:** 4720 (created), 4722/4724 (enabled/pw reset), 4728/4732/4756 (added to global/local/universal privileged groups), 4738 (changed), 5136 (DS object modified), 4767 (unlocked). Missing any subcategory ("Audit User Account Management", "Audit Security Group Management", or DS-access SACL for 5136 — off by default) creates blind spots.
- **Stealth variants raise no group-add event:** AdminSDHolder ACL backdoor → hunt EID 4780 (AdminSDHolder applied); SID-History injection (mimikatz `sid::add`, DCShadow) → hunt 4765/4766.
- **Shadow credentials:** writing `msDS-KeyCredentialLink` (Whisker-style) leaves only a 5136 attribute change, no password/group event.
- **DC vs member server:** group/credential events log on the domain controller that processed them — hunting only member servers misses domain-level changes.
- **Validate:** run Atomic T1098 (add user to Administrators, reset password); confirm 4728/4724 fire on the DC.
- **FP tuning:** baseline IDM/JIT provisioning and helpdesk service accounts that legitimately modify groups.

## Prerequisites

- Windows Security Event Logs (EVTX format) or SIEM access
- Python 3.9+ with `python-evtx`, `lxml` libraries
- Understanding of Active Directory group structure and SID architecture
- Familiarity with MITRE ATT&CK T1098 sub-techniques

## Steps

### Step 1: Parse Account Modification Events
Extract Event IDs 4738 (user account changed), 4728/4732/4756 (member added to security groups), and 5136 (directory service object modified).

### Step 2: Detect Privileged Group Changes
Flag additions to Domain Admins, Enterprise Admins, Schema Admins, Administrators, and Backup Operators groups.

### Step 3: Identify Shadow Admin Indicators
Detect accounts receiving AdminSDHolder protection, direct privilege assignment, or SID history injection.

### Step 4: Correlate with Attack Timeline
Cross-reference account changes with authentication events to identify initial compromise and persistence establishment.

## Expected Output

JSON report with detected account manipulation events, privileged group changes, shadow admin indicators, and timeline correlation.
