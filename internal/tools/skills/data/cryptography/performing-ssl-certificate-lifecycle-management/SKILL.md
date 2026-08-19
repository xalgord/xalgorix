---
name: performing-ssl-certificate-lifecycle-management
description: SSL/TLS certificate lifecycle management encompasses the full process of requesting, issuing, deploying, monitoring,
  renewing, and revoking X.509 certificates. Poor certificate management is a leading
domain: cybersecurity
subdomain: cryptography
tags:
- cryptography
- ssl
- certificates
- pki
- tls
- key-management
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
---
# Performing SSL Certificate Lifecycle Management

## Overview

SSL/TLS certificate lifecycle management encompasses the full process of requesting, issuing, deploying, monitoring, renewing, and revoking X.509 certificates. Poor certificate management is a leading cause of outages and security incidents. This skill covers automating the entire certificate lifecycle using Python and ACME protocol tools.


## When to Use

- When conducting security assessments that involve performing ssl certificate lifecycle management
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Common Misconfigurations & Verification

- **Monitoring leaf expiry only:** outages often come from an expired **intermediate** or root in the chain, not the leaf. Validate and monitor the full chain; check intermediate `notAfter` too with `openssl x509 -enddate -noout`.
- **Incomplete chain served:** a server that sends the leaf but omits the intermediate breaks validation on clients without a cached intermediate. Verify with `openssl s_client -connect host:443 -showcerts` and `openssl verify -untrusted chain.pem leaf.pem` returning `OK`.
- **SAN vs CN mismatch:** modern clients ignore CN; the hostname must be in `subjectAltName`. Confirm with `openssl x509 -text | grep -A1 "Subject Alternative Name"`.
- **Weak key / signature:** reject RSA <2048 (prefer ECDSA P-256) and any SHA-1 signature; check `Signature Algorithm`.
- **No revocation checking or OCSP stapling:** enable OCSP stapling and verify revoked certs are detected via CRL/OCSP, not assumed valid.
- **Renewal not automated / no CT monitoring:** ACME auto-renewal should fire well before expiry (e.g., 30 days); monitor Certificate Transparency logs for mis-issuance.
- **Verification:** assert CSR is valid PKCS#10, the chain validates to a trusted root, an expiring cert triggers the alert threshold, a **revoked certificate is flagged via OCSP/CRL**, and the inventory accounts for every deployed endpoint.

## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Generate Certificate Signing Requests (CSRs) programmatically
- Parse and validate X.509 certificates
- Monitor certificate expiration across infrastructure
- Automate renewal using ACME protocol (Let's Encrypt)
- Implement certificate revocation checking (CRL and OCSP)
- Track certificate inventory across multiple domains

## Key Concepts

### Certificate Lifecycle Stages

1. **Request**: Generate key pair and CSR
2. **Issuance**: CA validates and issues certificate
3. **Deployment**: Install certificate on servers
4. **Monitoring**: Track expiration and health
5. **Renewal**: Request new certificate before expiry
6. **Revocation**: Invalidate compromised certificates

### Certificate Types

| Type | Validation | Use Case |
|------|-----------|----------|
| DV (Domain Validation) | Domain ownership | Websites, APIs |
| OV (Organization Validation) | Domain + org identity | Business sites |
| EV (Extended Validation) | Full legal verification | E-commerce, banking |
| Wildcard | *.domain.com | Multi-subdomain |
| SAN/UCC | Multiple domains | Multi-domain hosting |

## Security Considerations

- Set up automated monitoring for all certificates
- Use ECDSA (P-256) certificates for better performance over RSA
- Enable OCSP stapling on all servers
- Implement Certificate Transparency log monitoring
- Maintain inventory of all certificates and their locations
- Plan for CA compromise scenarios (key pinning, backup CAs)

## Validation Criteria

- [ ] CSR generation produces valid PKCS#10 request
- [ ] Certificate parsing extracts all relevant fields
- [ ] Expiration monitoring detects certificates within threshold
- [ ] Certificate chain validation verifies trust path
- [ ] OCSP checking detects revoked certificates
- [ ] Certificate inventory tracks all deployed certificates
