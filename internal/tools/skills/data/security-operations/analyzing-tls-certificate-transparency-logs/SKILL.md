---
name: analyzing-tls-certificate-transparency-logs
description: 'Queries Certificate Transparency logs via crt.sh and pycrtsh to detect phishing domains, unauthorized certificate
  issuance, and shadow IT. Monitors newly issued certificates for typosquatting and brand impersonation using Levenshtein
  distance. Use for proactive phishing domain detection and certificate monitoring.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- analyzing
- tls
- certificate
- transparency
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
atlas_techniques:
- AML.T0073
- AML.T0052
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Analyzing TLS Certificate Transparency Logs


## When to Use

- When investigating security incidents that require analyzing tls certificate transparency logs
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **CT only sees CA-issued certs:** attackers using self-signed certs, internal CAs, or plain-IP/no-TLS phishing pages never appear in crt.sh. CT is a lead source, not full coverage — pair it with passive DNS and registrar feeds.
- **Levenshtein misses real typosquats:** homoglyph/IDN attacks (`xn--` punycode, Cyrillic `а` for Latin `a`), combosquats (`example-login.com`, `secure-example.net`), and different-TLD clones (`example.co`, `example-support.io`) have large edit distance from the base domain yet are high-risk. Add homoglyph normalization, keyword-permutation (dnstwist-style), and TLD-swap checks, not edit distance alone.
- **Wildcard and SAN blind spots:** a single `*.attacker.com` cert hides the actual phishing FQDN; always parse every entry in the `name_value`/SAN list, not just the CN.
- **Latency and dedup:** CT entries can lag issuance by minutes-to-hours and crt.sh returns many precert/leaf duplicates per cert — dedupe on serial+issuer and don't treat "not yet in CT" as safe.
- **Validate the query fires:** issue a free Let's Encrypt cert for a lookalike test domain and confirm your `c.search("%.example.com")` surfaces it within the polling window. **FP tuning:** legitimate vendors, CDNs (Cloudflare/Fastly), and marketing microsites issue brand-adjacent certs — maintain an allowlist of known-good issuers and registered owned domains.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Query crt.sh Certificate Transparency database to find certificates issued for
domains similar to your organization's brand, detecting phishing infrastructure.

```python
from pycrtsh import Crtsh

c = Crtsh()
# Search for certificates matching a domain
certs = c.search("example.com")
for cert in certs:
    print(cert["id"], cert["name_value"])

# Get full certificate details
details = c.get(certs[0]["id"], type="id")
```

Key analysis steps:
1. Query crt.sh for all certificates matching your domain pattern
2. Identify certificates with typosquatting variations (Levenshtein distance)
3. Flag certificates from unexpected CAs
4. Monitor for wildcard certificates on suspicious subdomains
5. Cross-reference with known phishing infrastructure

## Examples

```python
from pycrtsh import Crtsh
c = Crtsh()
certs = c.search("%.example.com")
for cert in certs:
    print(f"Issuer: {cert.get('issuer_name')}, Domain: {cert.get('name_value')}")
```
