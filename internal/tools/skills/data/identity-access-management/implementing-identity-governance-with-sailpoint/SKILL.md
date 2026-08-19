---
name: implementing-identity-governance-with-sailpoint
description: Deploy SailPoint IdentityNow or IdentityIQ for identity governance and administration. Covers identity lifecycle
  management, access request workflows, certification campaigns, role mining, SOD policy
domain: cybersecurity
subdomain: identity-access-management
tags:
- iam
- identity
- access-control
- governance
- sailpoint
- iga
- lifecycle
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
---
# Implementing Identity Governance with SailPoint

## Overview
Deploy SailPoint IdentityNow or IdentityIQ for identity governance and administration. Covers identity lifecycle management, access request workflows, certification campaigns, role mining, SOD policy enforcement, and compliance reporting for enterprise IAM.


## When to Use

- When deploying or configuring implementing identity governance with sailpoint capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

Governance theater is common — campaigns run and reports look clean while access keeps drifting:

- **Rubber-stamp certifications:** reviewers bulk-approve everything. Pull the campaign decision stats from IdentityNow (`GET /v3/certifications/{id}/decision-summary`) and flag any reviewer with ~100% approve rate and near-zero dwell time; those certifications are not real attestations.
- **Aggregation/account correlation gaps:** orphan and uncorrelated accounts never enter a campaign, so they are never reviewed. Run the source aggregation and confirm uncorrelated-account count is ~0; entitlements on un-aggregated sources are invisible to SOD and certs.
- **SOD policies defined but in "simulate"/not enforced:** verify each Separation-of-Duties policy is `active`/enforcing (not preview) and check the violation report has named owners and remediation, not just a count.
- **Joiner/Mover/Leaver de-provisioning not closing the loop:** test a mover — change a user's department and confirm old entitlements are *removed*, not just new ones added (accumulation is the #1 silent failure). For leavers, confirm the leaver event actually disables/deletes downstream accounts, not only the authoritative source record.
- **Role explosion / birthright over-grant:** confirm mined roles map to least privilege and that birthright access does not silently include privileged entitlements.
- **Audit events not reaching SIEM:** verify access-grant, cert-decision, and SOD-violation events are forwarded and alertable, not just stored in SailPoint.

## Prerequisites

- Familiarity with identity access management concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives
- Implement comprehensive implementing identity governance with sailpoint capability
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
