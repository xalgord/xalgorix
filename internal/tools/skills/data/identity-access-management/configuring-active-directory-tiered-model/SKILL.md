---
name: configuring-active-directory-tiered-model
description: Implement Microsoft's Enhanced Security Admin Environment (ESAE) tiered administration model for Active Directory.
  Covers Tier 0/1/2 separation, privileged access workstations (PAWs), administrative f
domain: cybersecurity
subdomain: identity-access-management
tags:
- iam
- identity
- access-control
- active-directory
- tiered-model
- paw
- esae
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
---
# Configuring Active Directory Tiered Model

## Overview
Implement Microsoft's Enhanced Security Admin Environment (ESAE) tiered administration model for Active Directory. Covers Tier 0/1/2 separation, privileged access workstations (PAWs), administrative forest design, authentication policy silos, and credential theft mitigation.


## When to Use

- When deploying or configuring configuring active directory tiered model capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **Tier-0 contamination:** a Domain Admin logs on interactively to a Tier 1/2 server (or Tier 0 admins browse the web from a DC), exposing credentials to theft. Verify with authentication policy silos and check event 4624 LogonType 2/10 on tier-0 assets for non-tier-0 principals — there should be none.
- **Silos not enforced:** authentication policies are created but assigned in audit-only mode, so cross-tier logons still succeed. Confirm `Get-ADAuthenticationPolicy` shows `Enforce=$true` and the TGT lifetime is short; test that a Tier 1 account is denied a TGT against a Tier 0 host.
- **PAW gaps:** admins use the PAW but it has internet/email access, or RDP into servers from a normal workstation. Verify PAWs block outbound internet (proxy/firewall) and that "Deny log on through Remote Desktop" GPOs separate the tiers.
- **Nested/transitive group leakage:** a Tier 2 group is nested into a Tier 0 group (e.g. via Account Operators or built-in container ACLs), silently granting privilege. Audit recursive membership of Domain Admins/Enterprise Admins and protect with AdminSDHolder.
- **Verification:** run `whoami /groups` and BloodHound from a Tier 2 account to confirm no path reaches Tier 0; confirm `Protected Users` group membership for all tier-0 admins and that LAPS randomizes local admin passwords per host.

## Prerequisites

- Familiarity with identity access management concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives
- Implement comprehensive configuring active directory tiered model capability
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
