---
name: implementing-passwordless-authentication-with-fido2
description: Deploy FIDO2/WebAuthn passwordless authentication using security keys and platform authenticators. Covers WebAuthn
  API integration, FIDO2 server configuration, passkey enrollment, biometric authentica
domain: cybersecurity
subdomain: identity-access-management
tags:
- iam
- identity
- access-control
- authentication
- fido2
- webauthn
- passwordless
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
atlas_techniques:
- AML.T0051
- AML.T0054
- AML.T0056
nist_ai_rmf:
- MEASURE-2.7
- MEASURE-2.5
- GOVERN-6.1
- MAP-5.1
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
---
# Implementing Passwordless Authentication with FIDO2

## Overview
Deploy FIDO2/WebAuthn passwordless authentication using security keys and platform authenticators. Covers WebAuthn API integration, FIDO2 server configuration, passkey enrollment, biometric authentication, and migration from password-based systems aligned with NIST SP 800-63B AAL3.


## When to Use

- When deploying or configuring implementing passwordless authentication with fido2 capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

A FIDO2 deployment that still trusts passwords or skips verification is not phishing-resistant — check these:

- **Password fallback left on:** users register a passkey but the login form still accepts password (or password+OTP), so attackers phish the weaker path. Confirm passwordless is *enforced* for the target population and test that a password-only login is rejected, not silently allowed.
- **`userVerification: discouraged`:** the credential becomes single-factor — anyone holding the key authenticates with no PIN/biometric. Verify the server requests `user_verification: required` and that `verify_authentication_response()` actually checks the UV flag in the authenticator data.
- **Sign-count / clone detection skipped:** confirm the server rejects or alarms when the returned `signCount` is not greater than the stored value; a flat or regressing counter indicates a cloned authenticator.
- **RP ID / origin mismatch:** an over-broad `rpId` or unvalidated `clientDataJSON.origin` lets credentials be replayed from look-alike domains. Verify origin and `rpId` are validated server-side against the exact expected host.
- **Attestation not validated where required (AAL3):** for high-assurance accounts, confirm attestation conveyance is `direct`/`enterprise` and the attestation chain + AAGUID are checked, not `none`.
- **No backup authenticator / weak recovery:** confirm ≥2 credentials per account and that account recovery never falls back to email or SMS alone, which defeats phishing resistance.

## Prerequisites

- Familiarity with identity access management concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives
- Implement comprehensive implementing passwordless authentication with fido2 capability
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
