---
name: detecting-exfiltration-over-dns-with-zeek
description: Detect DNS-based data exfiltration by analyzing Zeek dns.log for high-entropy subdomains and anomalous query
  patterns
domain: cybersecurity
subdomain: network-security
tags:
- dns-exfiltration
- zeek
- entropy-analysis
- threat-hunting
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---


# Detecting Exfiltration over DNS with Zeek

## Overview

DNS tunneling and exfiltration is a technique used by attackers to bypass firewalls and DLP controls by encoding stolen data into DNS query subdomains. Legitimate DNS queries have predictable entropy and length patterns, while exfiltration queries contain encoded data with high Shannon entropy, unusually long subdomain labels, and high volumes of unique subdomains per parent domain.

This skill analyzes Zeek dns.log files (TSV format) to detect exfiltration indicators. The agent computes Shannon entropy for each subdomain component, identifies queries exceeding the 63-character DNS label limit, counts unique subdomains per parent domain, and flags domains that exceed configurable thresholds. These techniques detect tools like dnscat2, iodine, dns2tcp, and custom DNS tunneling implementations.


## When to Use

- When investigating security incidents that require detecting exfiltration over dns with zeek
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **DoH/DoT never lands in dns.log:** if the host tunnels over `https://` (443) or DoT (853), Zeek's DNS analyzer produces no record to score. Pivot to `ssl.log` SNI of public resolvers from non-browser hosts and `conn.log` 853, and treat absence of dns.log for a chatty host as suspicious, not clean.
- **Low-and-slow defeats per-window counts:** a tunnel pacing a few queries/min stays under "50 unique subdomains within the log window." Aggregate unique-subdomain counts per parent domain across hours/days, and add a sustained-rate-per-source signal, not just a single-window threshold.
- **Word-list encoding lowers entropy:** dictionary-based encoders (and lowercase chunking) keep label entropy under 3.5/4.0. Combine entropy with label-length, label-count, and unique-subdomain ratio so a low-entropy-but-high-cardinality domain still scores.
- **Answer-side data is missed:** exfil via large TXT/NULL/CNAME *answers* won't show in QNAME analysis. Parse `qtype_name` and `answers` for TXT/NULL/CNAME abuse and oversized responses.
- **Validate the detector fires:** generate a known tunnel in a lab (`iodine`, `dnscat2 --dns`) to a controlled domain, run the parser over the resulting `dns.log`, and confirm the domain appears in `flagged_domains` with `high_entropy`/`long_labels`. Verify `#fields` header parsing by `zeek-cut query qtype_name answers` — a column-offset bug silently zeroes results.
- **FP tuning:** baseline and whitelist CDN, AV/EDR telemetry, and cloud SaaS domains that legitimately produce long, high-cardinality subdomains before alerting.

## Prerequisites

- Python 3.9 or later with math and collections modules (stdlib)
- Zeek dns.log files in TSV format with standard field headers
- Network capture data processed by Zeek 5.0+ or later
- Understanding of DNS protocol structure and query types

## Steps

1. **Parse Zeek dns.log headers**: Read the TSV file, extract the `#fields` header line to identify column positions for `ts`, `id.orig_h`, `query`, `qtype_name`, `rcode_name`, and `answers`.

2. **Extract and decompose queries**: For each DNS query, split the FQDN into subdomain labels and parent domain. Skip queries to known safe domains and internal zones.

3. **Compute Shannon entropy**: Calculate the information entropy of each subdomain label. Legitimate subdomains typically have entropy below 3.5, while encoded/encrypted data produces entropy above 4.0.

4. **Detect long labels**: Flag DNS labels exceeding 52 characters (approaching the 63-character maximum). Long labels are a strong indicator of data tunneling.

5. **Count unique subdomains per domain**: Track how many distinct subdomains each parent domain receives. Domains with more than 50 unique subdomains within the log window are suspicious.

6. **Identify query volume anomalies**: Calculate queries-per-minute per source IP per domain. Exfiltration tools generate sustained high-volume query streams that differ from normal browsing.

7. **Score and rank domains**: Combine entropy, label length, uniqueness count, and query volume into a composite risk score. Rank domains by score and output the top suspicious domains.

8. **Generate detection report**: Produce a JSON report with flagged domains, their evidence indicators, originating source IPs, and recommended response actions.

## Expected Output

```json
{
  "analysis_summary": {
    "total_queries_analyzed": 145832,
    "unique_domains": 3421,
    "flagged_domains": 3,
    "entropy_threshold": 3.5
  },
  "flagged_domains": [
    {
      "domain": "data.evil-c2.com",
      "unique_subdomains": 892,
      "avg_entropy": 4.72,
      "max_label_length": 61,
      "source_ips": ["10.0.1.45"],
      "risk_score": 9.4,
      "indicators": ["high_entropy", "long_labels", "high_subdomain_count"]
    }
  ]
}
```
