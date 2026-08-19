---
name: configuring-ldap-security-hardening
description: Harden LDAP directory services against common attacks including credential harvesting, LDAP injection, anonymous
  binding, and channel binding bypass. Covers LDAPS enforcement, channel binding, LDAP si
domain: cybersecurity
subdomain: identity-access-management
tags:
- iam
- identity
- access-control
- ldap
- directory-services
- hardening
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
---
# Configuring LDAP Security Hardening

## Overview
Harden LDAP directory services against common attacks including credential harvesting, LDAP injection, anonymous binding, and channel binding bypass. Covers LDAPS enforcement, channel binding, LDAP signing, access control lists, and monitoring for LDAP-based attacks.


## When to Use

- When deploying or configuring configuring ldap security hardening capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **LDAPS available but cleartext still allowed:** enabling 636/TLS does not disable port 389 simple binds, so credentials still cross the wire in plaintext and downgrade attacks succeed. Verify LDAP signing is *Required* (`Domain controller: LDAP server signing requirements = Require signing`) and confirm a `ldapsearch -x -H ldap://dc` simple bind is rejected.
- **Channel binding not enforced:** without LDAP channel binding (CBT), an attacker relays NTLM to LDAPS (the classic AD CS/PetitPotam relay). Confirm event 3039/3074 are clean after setting `LdapEnforceChannelBinding=2` and test with `ntlmrelayx` against `ldaps://` — it must fail.
- **Anonymous bind / over-broad reads:** `dsHeuristics` 7th char enabling anonymous binds, or authenticated users able to read `ms-Mcs-AdmPwd` (LAPS) and `userPassword`. Verify anonymous bind returns no entries and audit ACLs on sensitive attributes.
- **LDAP injection in apps:** app filters built by string concatenation allow `*)(uid=*))(|(uid=*` style injection. Confirm inputs are escaped per RFC 4515.
- **Verification:** run `Get-ADObject -SearchBase "CN=Directory Service,..." -Properties dSHeuristics`; confirm signing/CBT registry values on every DC; capture a bind with Wireshark and assert no cleartext `bindRequest` and that the session is TLS 1.2+.

## Prerequisites

- Familiarity with identity access management concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives
- Implement comprehensive configuring ldap security hardening capability
- Establish automated discovery and monitoring processes
- Integrate with enterprise IAM and security tools
- Generate compliance-ready documentation and reports
- Align with NIST 800-53 access control requirements

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Account Management | AC-2 | Lifecycle management |
| Access Enforcement | AC-3 | Policy-based access control |
| Least Privilege | AC-6 | Minimum necessary permissions |
| Audit Logging | AU-3 | Authentication and access events |
| Identification | IA-2 | User and service identification |

## Verification
- [ ] Implementation tested in non-production environment
- [ ] Security policies configured and enforced
- [ ] Audit logging enabled and forwarding to SIEM
- [ ] Documentation and runbooks complete
- [ ] Compliance evidence generated
