---
name: implementing-rsa-key-pair-management
description: RSA (Rivest-Shamir-Adleman) is the most widely deployed asymmetric cryptographic algorithm, used for digital
  signatures, key exchange, and encryption. This skill covers generating, storing, rotating,
domain: cybersecurity
subdomain: cryptography
tags:
- cryptography
- rsa
- key-management
- pki
- asymmetric-encryption
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
---
# Implementing RSA Key Pair Management

## Overview

RSA (Rivest-Shamir-Adleman) is the most widely deployed asymmetric cryptographic algorithm, used for digital signatures, key exchange, and encryption. This skill covers generating, storing, rotating, and managing RSA key pairs following NIST SP 800-57 key management guidelines, including key serialization formats (PEM, DER, PKCS#8), passphrase protection, and key strength validation.


## When to Use

- When deploying or configuring implementing rsa key pair management capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **PKCS#1 v1.5 encryption (padding oracle):** `RSA/PKCS1v15` decryption that reveals padding-validity (via errors or timing) enables a Bleichenbacher attack to recover plaintext. Use **RSA-OAEP** (`padding.OAEP` with SHA-256) for encryption, never `PKCS1v15` for new systems.
- **PKCS#1 v1.5 signatures:** prefer **RSA-PSS** for signing; if PKCS1v15 verification must stay for legacy, pin the exact hash and never mix.
- **Key too small / weak:** reject keys `<2048` bits (use ≥3072 for new deployments). Validate the modulus bit length and run a weak-key check (small factors, low public exponent like e=3 with no OAEP, shared primes / ROCA).
- **Unprotected private key:** encrypt private keys with a strong passphrase (`BestAvailableEncryption`, AES-256) in PKCS#8, and store with `0600` permissions — never commit unencrypted PEMs.
- **No key rotation / versioning:** rotate at least annually and retain old public keys for verifying historical signatures only.
- **Mandatory tests:** an RSA-PSS signature over a **tampered message is REJECTED**; verification with the wrong public key is REJECTED; OAEP decryption of a corrupted ciphertext fails cleanly without leaking padding state; loading the private key with a wrong passphrase fails; `key.key_size >= 3072` is asserted.

## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Generate RSA key pairs with appropriate key sizes (2048, 3072, 4096 bits)
- Serialize keys in PEM and DER formats with PKCS#8
- Protect private keys with strong passphrase encryption
- Implement key rotation with versioning
- Extract public key components and fingerprints
- Validate key strength and detect weak keys
- Sign and verify data using RSA-PSS

## Key Concepts

### RSA Key Sizes and Security Strength

| Key Size (bits) | Security Strength (bits) | Recommended Until |
|-----------------|-------------------------|-------------------|
| 2048            | 112                     | 2030              |
| 3072            | 128                     | Beyond 2030       |
| 4096            | ~140                    | Beyond 2030       |

### RSA Padding Schemes

| Scheme | Use Case | Standard |
|--------|----------|----------|
| OAEP   | Encryption | PKCS#1 v2.2 (RFC 8017) |
| PSS    | Signatures | PKCS#1 v2.2 (RFC 8017) |
| PKCS#1 v1.5 | Legacy only | Deprecated for new systems |

### Key Storage Formats

- **PEM**: Base64-encoded with headers, human-readable
- **DER**: Binary ASN.1 encoding, compact
- **PKCS#8**: Standard for private key encapsulation
- **PKCS#12/PFX**: Bundled key + certificate, password-protected

## Security Considerations

- Minimum 3072-bit keys for new deployments (NIST recommendation)
- Always protect private keys with AES-256-CBC passphrase encryption
- Use RSA-PSS for signatures (not PKCS#1 v1.5)
- Use RSA-OAEP for encryption (not PKCS#1 v1.5)
- Store private keys with restrictive file permissions (0600)
- Implement key rotation at least annually

## Validation Criteria

- [ ] Key generation produces valid RSA key pair
- [ ] Public key can be extracted from private key
- [ ] Private key is protected with passphrase
- [ ] RSA-PSS signature verification succeeds
- [ ] Tampered signature verification fails
- [ ] Key fingerprint is computed correctly
- [ ] Key rotation maintains old key access for verification
