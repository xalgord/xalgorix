---
name: performing-privileged-account-discovery
description: Discover and inventory all privileged accounts across enterprise infrastructure including domain admins, local
  admins, service accounts, database admins, cloud IAM roles, and application admin account
domain: cybersecurity
subdomain: identity-access-management
tags:
- iam
- identity
- access-control
- privileged-access
- discovery
- inventory
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
---
# Performing Privileged Account Discovery

## Overview
Discover and inventory all privileged accounts across enterprise infrastructure including domain admins, local admins, service accounts, database admins, cloud IAM roles, and application admin accounts. Covers automated scanning, risk classification, and onboarding to PAM.


## When to Use

- When conducting security assessments that involve performing privileged account discovery
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Coverage Gaps & Validation

- **Single-source discovery:** scanning only AD privileged groups misses most privilege. Enumerate every plane: AD `AdminCount=1`/AdminSDHolder, local administrators on each member server, SPN/service accounts, AWS IAM (`AdministratorAccess`, `iam:*`, access keys), Azure Global/Privileged Role Admin and managed identities, GCP Owner/Editor, and DB fixed roles (`sysadmin`, `DBA`, superuser).
- **Indirect / nested privilege:** effective admin via nested AD groups, group-in-group on cloud roles, and role-assumption chains is missed by direct-membership queries — expand recursively.
- **Non-human and shadow admin:** service accounts, API keys/tokens with admin scope, app-local admin roles, and CI/CD pipeline identities are privileged accounts that no group membership reveals.
- **Stale/orphaned accounts:** accounts whose owner left or whose application was decommissioned still hold privilege; correlate to last-logon and HR status.
- **Validate completeness:** reconcile discovery output against each authoritative source independently (AD, every IdP, each cloud IAM, each database) rather than trusting one aggregated feed — the count delta between native exports and your inventory is the discovery gap. Confirm every discovered privileged account is onboarded to PAM, not merely listed.

## Prerequisites

- Familiarity with identity access management concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives
- Implement comprehensive performing privileged account discovery capability
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
