---
name: implementing-jwt-signing-and-verification
description: JSON Web Tokens (JWT) defined in RFC 7519 are compact, URL-safe tokens used for authentication and authorization
  in web applications. This skill covers implementing secure JWT signing with HMAC-SHA256
domain: cybersecurity
subdomain: cryptography
tags:
- cryptography
- jwt
- authentication
- token-security
- digital-signatures
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
---
# Implementing JWT Signing and Verification

## Overview

JSON Web Tokens (JWT) defined in RFC 7519 are compact, URL-safe tokens used for authentication and authorization in web applications. This skill covers implementing secure JWT signing with HMAC-SHA256, RSA-PSS, and EdDSA algorithms, along with verification, token expiration, claims validation, and defense against common JWT attacks (algorithm confusion, none algorithm, key injection).


## When to Use

- When deploying or configuring implementing jwt signing and verification capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **`alg: none` accepted:** a token with header `{"alg":"none"}` and no signature must be **rejected**. Never call a decode that allows unsigned tokens; pass an explicit `algorithms=[...]` allowlist.
- **Algorithm confusion (RS256 → HS256):** if the verifier picks the algorithm from the token header, an attacker re-signs with HS256 using the *public* key as the HMAC secret. Pin the expected algorithm server-side; never let the token choose. Verify a token signed with HS256-using-the-RSA-public-key is rejected.
- **Missing claim validation:** always verify `exp` (and `nbf`), and enforce `aud` and `iss` against expected values — a valid signature on a token meant for another audience must still be rejected. Reject expired tokens (test with a past `exp`).
- **Weak HMAC secret:** HS256 with a short/guessable secret is brute-forceable (e.g. with `hashcat -m 16500`); use ≥256-bit random secrets, or prefer RS256/ES256/EdDSA.
- **`kid`/`jku`/`jwk` header injection:** do not fetch keys from attacker-controlled URLs or trust an embedded JWK; resolve `kid` against a pinned key set only.
- **Mandatory tests:** a tampered payload (re-base64'd claims) is **REJECTED**; `alg:none` is REJECTED; algorithm-confusion forgery is REJECTED; expired and wrong-`aud` tokens are REJECTED; only a correctly signed, in-date, correct-audience token verifies.

## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Implement JWT signing with HS256, RS256, ES256, and EdDSA
- Verify JWT signatures and validate standard claims
- Implement token expiration, not-before, and audience validation
- Defend against algorithm confusion and none algorithm attacks
- Implement JWT key rotation with JWK Sets
- Build a complete authentication middleware

## Key Concepts

### JWT Algorithms

| Algorithm | Type | Key | Security Level |
|-----------|------|-----|---------------|
| HS256 | Symmetric (HMAC) | Shared secret | 128-bit |
| RS256 | Asymmetric (RSA) | RSA key pair | 112-bit |
| ES256 | Asymmetric (ECDSA) | P-256 key pair | 128-bit |
| EdDSA | Asymmetric (Ed25519) | Ed25519 pair | 128-bit |

### Common JWT Attacks

- **Algorithm confusion**: Switching from RS256 to HS256, using public key as HMAC secret
- **None algorithm**: Setting alg=none to bypass signature verification
- **Key injection**: Embedding key in JWK header
- **Weak secrets**: Brute-forcing short HMAC secrets
- **Token replay**: Reusing valid tokens without expiration

## Security Considerations

- Always validate the algorithm header against an allowlist
- Never accept alg=none in production
- Use asymmetric algorithms (RS256, ES256) for distributed systems
- Set short expiration times (15 min for access tokens)
- Implement token refresh mechanism
- Store secrets securely (not in source code)

## Validation Criteria

- [ ] JWT signing produces valid tokens for all algorithms
- [ ] Signature verification rejects tampered tokens
- [ ] Expired tokens are rejected
- [ ] Algorithm confusion attack is prevented
- [ ] None algorithm is rejected
- [ ] JWK key rotation works correctly
- [ ] Claims validation enforces all required claims
