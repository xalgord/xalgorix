---
name: configuring-certificate-authority-with-openssl
description: A Certificate Authority (CA) is the trust anchor in a PKI hierarchy, responsible for issuing, signing, and revoking
  digital certificates. This skill covers building a two-tier CA hierarchy (Root CA +
domain: cybersecurity
subdomain: cryptography
tags:
- cryptography
- pki
- certificate-authority
- openssl
- x509
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
---
# Configuring Certificate Authority with OpenSSL

## Overview

A Certificate Authority (CA) is the trust anchor in a PKI hierarchy, responsible for issuing, signing, and revoking digital certificates. This skill covers building a two-tier CA hierarchy (Root CA + Intermediate CA) using OpenSSL and the Python cryptography library, including CRL distribution, OCSP responder configuration, and certificate policy management.


## When to Use

- When deploying or configuring configuring certificate authority with openssl capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **No `nameConstraints` on the intermediate CA:** an unconstrained intermediate can sign a cert for *any* domain. Add a critical `nameConstraints=permitted;DNS:.example.com` extension and verify with `openssl x509 -text -noout | grep -A2 "Name Constraints"`.
- **Missing `basicConstraints=critical,CA:TRUE,pathlen:0`:** without `pathlen:0` an issuing CA can mint further sub-CAs. Confirm the leaf certs have `CA:FALSE`.
- **Weak signature algorithm:** a CA signing with `sha1WithRSAEncryption` (or MD5) is trivially forgeable. Force `-sha256`/`-sha384` and reject SHA-1 with `openssl x509 -text | grep "Signature Algorithm"`.
- **Root key online / not air-gapped, or RSA <4096 / not P-384:** root keys must be offline. Use 4096-bit RSA or P-384 ECDSA.
- **`keyUsage` not marked critical or includes too much:** CA certs need `keyCertSign,cRLSign` only; leaf certs must NOT have `keyCertSign`.
- **No CRL/OCSP distribution point:** revocation is impossible. Verify `crlDistributionPoints` and `authorityInfoAccess` are present.
- **Verify the chain end-to-end:** `openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem` must return `OK`, and a cert signed by an untrusted/rogue CA MUST be **rejected**. Test that a cert violating a name constraint fails validation, not just that valid ones pass.

## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Create a Root CA with self-signed certificate
- Create an Intermediate CA signed by the Root CA
- Issue server and client certificates from the Intermediate CA
- Configure Certificate Revocation Lists (CRLs)
- Implement certificate policies and constraints
- Build a complete PKI hierarchy programmatically

## Key Concepts

### CA Hierarchy

```
Root CA (offline, air-gapped)
  |
  +-- Intermediate CA (online, operational)
        |
        +-- Server Certificates
        +-- Client Certificates
        +-- Code Signing Certificates
```

### Certificate Extensions

| Extension | Purpose | Critical |
|-----------|---------|----------|
| basicConstraints | CA:TRUE/FALSE, pathLenConstraint | Yes |
| keyUsage | keyCertSign, cRLSign, digitalSignature | Yes |
| extendedKeyUsage | serverAuth, clientAuth, codeSigning | No |
| subjectKeyIdentifier | Hash of public key | No |
| authorityKeyIdentifier | Issuer's key identifier | No |
| crlDistributionPoints | URL to CRL | No |
| authorityInfoAccess | OCSP responder URL | No |

## Security Considerations

- Root CA private key must be stored offline (air-gapped HSM)
- Use minimum 4096-bit RSA or P-384 ECDSA for CA keys
- Set path length constraints on intermediate CAs
- Implement certificate policies (OIDs)
- Enable CRL and OCSP for revocation checking
- Audit all certificate issuance operations

## Validation Criteria

- [ ] Root CA self-signed certificate is valid
- [ ] Intermediate CA certificate chains to Root CA
- [ ] Issued certificates chain to Intermediate -> Root
- [ ] Path length constraints are enforced
- [ ] CRL is generated and accessible
- [ ] Revoked certificates appear in CRL
- [ ] Certificate policies are correctly embedded
