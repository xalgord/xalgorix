---
name: performing-cryptographic-audit-of-application
description: A cryptographic audit systematically reviews an application's use of cryptographic primitives, protocols, and
  key management to identify vulnerabilities such as weak algorithms, insecure modes, hardco
domain: cybersecurity
subdomain: cryptography
tags:
- cryptography
- audit
- security-review
- compliance
- vulnerability-assessment
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
---
# Performing Cryptographic Audit of Application

## Overview

A cryptographic audit systematically reviews an application's use of cryptographic primitives, protocols, and key management to identify vulnerabilities such as weak algorithms, insecure modes, hardcoded keys, insufficient entropy, and protocol misconfigurations. This skill covers building an automated crypto audit tool that scans Python and configuration files for common cryptographic weaknesses.


## When to Use

- When conducting security assessments that involve performing cryptographic audit of application
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

Automated crypto audits routinely under-report because scanners only grep for obvious names. The items below are the ones most often skipped — check every one before concluding a codebase is clean.

- **Hardcoded keys/secrets beyond `password=`:** base64/hex byte-string literals passed straight into `AESGCM(key)` or `Fernet(key)`, IVs/nonces defined as constants, and `.pem`/`.env` files committed to the repo. Grep for `Cipher(`, `os.urandom` results assigned at module scope, and high-entropy string literals — not just the word "secret".
- **Weak PRNG for crypto:** `random.random()`, `random.randint`, `numpy.random`, or `time`-seeded values used for keys/IVs/tokens/salts. Flag any non-`secrets`/`os.urandom` source feeding a crypto API.
- **Deprecated TLS / cipher config:** `ssl.PROTOCOL_TLSv1`, `ssl_version=TLSv1_1`, `CERT_NONE`/`check_hostname=False`, and server configs allowing SSLv3/TLS1.0/1.1 or RC4/3DES/EXPORT suites. Audit config files and live endpoints, not just code.
- **Insecure modes / weak KDF hiding in wrappers:** `modes.ECB()`, static IVs, `PBKDF2` with low iterations, MD5/SHA-1 used as a "KDF", and `hashlib.md5(password)` for storage.
- **Positive signal (how to confirm a real finding vs. noise):** a true positive is reachable application code where attacker-influenced data meets the weak primitive — confirm the call is live (not test/vendored/dead code), trace the key/IV to its actual source, and show the concrete impact (e.g., ECB on PII, MD5 for password storage). Report severity, file:line, and remediation; keep false positives <10% by excluding `tests/`, fixtures, and non-security hash uses (e.g., MD5 for a cache key).

## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Detect usage of deprecated algorithms (MD5, SHA-1, DES, RC4)
- Identify insecure cipher modes (ECB) and padding schemes
- Find hardcoded keys, passwords, and secrets in source code
- Verify TLS/SSL configuration strength
- Check key derivation function parameters
- Validate random number generator usage
- Produce a structured audit report with findings and remediation

## Key Concepts

### Cryptographic Weakness Categories

| Category | Examples | Risk Level |
|----------|----------|------------|
| Weak Hashing | MD5, SHA-1 for integrity/signatures | High |
| Insecure Encryption | DES, 3DES, RC4, Blowfish | High |
| Bad Cipher Mode | ECB mode for any block cipher | High |
| Insufficient Key Size | RSA < 2048, AES-128 for long-term | Medium |
| Hardcoded Secrets | Keys/passwords in source code | Critical |
| Weak KDF | Low iteration PBKDF2, plain MD5 | High |
| Poor Entropy | time-based seeds, predictable IVs | High |
| Deprecated Protocols | SSLv3, TLS 1.0, TLS 1.1 | High |

## Security Considerations

- Review both application code and configuration files
- Check third-party dependencies for known crypto vulnerabilities
- Verify certificates and TLS configurations on deployed servers
- Ensure secrets are loaded from environment variables or vaults
- Review key storage and rotation practices

## Validation Criteria

- [ ] Scanner detects all injected test weaknesses
- [ ] MD5/SHA-1 usage for security purposes is flagged
- [ ] ECB mode usage is flagged
- [ ] Hardcoded keys/passwords are detected
- [ ] Weak KDF parameters are identified
- [ ] Report includes severity, location, and remediation
- [ ] False positive rate is below 10%
