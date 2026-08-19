---
name: performing-hash-cracking-with-hashcat
description: Hash cracking is an essential skill for penetration testers and security auditors to evaluate password strength.
  Hashcat is the world's fastest password recovery tool, supporting over 300 hash types w
domain: cybersecurity
subdomain: cryptography
tags:
- cryptography
- hash-cracking
- password-security
- hashcat
- penetration-testing
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
---
# Performing Hash Cracking with Hashcat

## Overview

Hash cracking is an essential skill for penetration testers and security auditors to evaluate password strength. Hashcat is the world's fastest password recovery tool, supporting over 300 hash types with GPU acceleration. This skill covers using hashcat for authorized password auditing, understanding attack modes, creating effective rule sets, and generating hash analysis reports. This is strictly for authorized penetration testing and password policy assessment.


## When to Use

- When conducting security assessments that involve performing hash cracking with hashcat
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

Cracking engagements under-report weak passwords mostly because of coverage gaps, not GPU limits. Confirm you have closed each gap below before declaring a hash "uncrackable."

- **Wrong hash mode (`-m`):** misidentifying the hash wastes the whole run. Verify with `hashid`/`hashcat --identify`; watch for look-alikes — raw MD5 (`-m 0`) vs. md5crypt (`-m 500`), NTLM (`-m 1000`) vs. NetNTLMv2 (`-m 5600`), bcrypt (`-m 3200`), sha512crypt (`-m 1800`), Kerberos AS-REP/TGS-REP (`-m 18200`/`-m 13100`).
- **Mask/attack-mode coverage gaps (`-a`):** running only `-a 0` dictionary and stopping. Add rules (`-a 0 -r rules/best64.rule`, `dive.rule`), hybrid (`-a 6`/`-a 7` for appended/prepended digits like `Password2024!`), and targeted masks (`-a 3 ?u?l?l?l?l?d?d?s`). Cover full keyspace for short passwords (`?a` up to 8 for fast hashes).
- **Wordlist gaps:** not using rockyou + org-specific terms, leaked/breach lists, or `--increment` on masks; ignoring keyboard walks and language-specific lists.
- **Slow-hash strategy:** for bcrypt/sha512crypt/Argon2 don't brute-force — prioritize curated wordlists + best64 rules and accept partial coverage; report what was *not* attempted.
- **Positive signal (confirming a meaningful result):** a "hit" is a recovered plaintext in the potfile (`hashcat --show -m <mode> hashes.txt`) — verify it actually re-hashes to the target. Report the **distribution** (cracked %, length/complexity, reused/policy-violating passwords), not raw passwords, and note remaining keyspace so an uncracked hash is reported as "not cracked within scope," never "strong."

## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Identify hash types from captured hashes
- Execute dictionary, brute-force, and rule-based attacks
- Create custom hashcat rules for targeted cracking
- Analyze password strength from cracking results
- Generate compliance reports on password policy effectiveness
- Benchmark GPU performance for hash cracking

## Key Concepts

### Hashcat Attack Modes

| Mode | Flag | Description | Use Case |
|------|------|-------------|----------|
| Dictionary | -a 0 | Wordlist attack | Known password patterns |
| Combination | -a 1 | Combine two wordlists | Compound passwords |
| Brute-force | -a 3 | Mask-based enumeration | Short passwords |
| Rule-based | -a 0 -r | Dictionary + transformation rules | Complex variations |
| Hybrid | -a 6/7 | Wordlist + mask | Passwords with appended numbers |

### Common Hash Types

| Hash Mode | Type | Example Use |
|-----------|------|-------------|
| 0 | MD5 | Legacy web apps |
| 100 | SHA-1 | Legacy systems |
| 1000 | NTLM | Windows credentials |
| 1800 | sha512crypt | Linux /etc/shadow |
| 3200 | bcrypt | Modern web apps |
| 13100 | Kerberos TGS-REP | Active Directory |

## Security Considerations

- Only perform hash cracking with explicit written authorization
- Secure all captured hash data in transit and at rest
- Report all cracked passwords immediately to asset owners
- Use results to improve password policies, not exploit users
- Destroy cracked password data after engagement concludes
- Follow rules of engagement for penetration test scope

## Validation Criteria

- [ ] Hash type identification is correct
- [ ] Dictionary attack cracks weak passwords
- [ ] Rule-based attack cracks policy-compliant passwords
- [ ] Mask attack cracks short passwords
- [ ] Results report shows password strength distribution
- [ ] All operations performed within authorized scope
