---
name: analyzing-ransomware-network-indicators
description: Identify ransomware network indicators including C2 beaconing patterns, TOR exit node connections, data exfiltration
  flows, and encryption key exchange via Zeek conn.log and NetFlow analysis
domain: cybersecurity
subdomain: threat-hunting
tags:
- ransomware
- c2-beaconing
- zeek
- netflow
- tor
- exfiltration
- network-forensics
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- File Metadata Consistency Validation
- Certificate Analysis
- Application Protocol Command Analysis
- Content Format Conversion
- File Content Analysis
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Analyzing Ransomware Network Indicators

## Overview

Before and during ransomware execution, adversaries establish C2 channels, exfiltrate data, and download encryption keys. This skill analyzes Zeek conn.log and NetFlow data to detect beaconing patterns (regular-interval callbacks), connections to known TOR exit nodes, large outbound data transfers, and suspicious DNS activity associated with ransomware families.


## When to Use

- When investigating security incidents that require analyzing ransomware network indicators
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Jitter defeats tight interval math.** Cobalt Strike/ransomware loaders sleep with randomized jitter (often 0-50%), inflating the coefficient of variation so a strict CV threshold misses them. Widen the CV window and bucket by destination + JA3 over 24h rather than per-flow.
- **HTTPS hides the payload.** `conn.log` only sees byte counts. Pair it with `ssl.log` (JA3/JA3S fingerprints, self-signed or short-lived certs) and `x509.log` to catch C2 that looks like normal TLS.
- **Stale TOR lists = false negatives.** Exit-node lists rotate constantly; refresh hourly, and remember bridges/obfs4 never appear on exit-node feeds at all.
- **Exfil over allowed channels:** large uploads to sanctioned cloud storage or DNS tunneling slip past outbound byte-ratio rules. Add `dns.log` checks for high query-length, high-entropy subdomains, and TXT-record volume; aggregate low-and-slow transfers per destination over days, not per connection.
- **Validate the rule fires:** generate a fixed-interval `curl` beacon (e.g., every 60s) to a lab host and confirm the beaconing query flags it; touch a known TOR exit IP and confirm the enrichment/alert triggers.
- **Tune false positives:** OS/AV update checks, NTP, and SaaS telemetry beacon on regular intervals. Allowlist known update and telemetry ASNs/domains before alerting.

## Prerequisites

- Zeek conn.log files or NetFlow CSV/JSON exports
- Python 3.8+ with standard library
- TOR exit node list (fetched from Tor Project or threat intel feeds)
- Optional: Known ransomware C2 IOC list

## Steps

1. **Parse Connection Logs** — Ingest Zeek conn.log (TSV) or NetFlow records into structured format
2. **Detect Beaconing Patterns** — Calculate connection interval statistics (mean, stddev, coefficient of variation) to identify periodic callbacks
3. **Check TOR Exit Node Connections** — Cross-reference destination IPs against current TOR exit node list
4. **Identify Data Exfiltration** — Flag connections with unusually high outbound byte ratios to external IPs
5. **Analyze DNS Patterns** — Detect DGA-like domain queries and high-entropy subdomains
6. **Score and Correlate** — Apply composite risk scoring across all indicator types
7. **Generate Report** — Produce structured report with timeline and MITRE ATT&CK mapping

## Expected Output

- JSON report with beaconing detections and interval statistics
- TOR exit node connection alerts
- Data exfiltration flow analysis
- Composite ransomware risk score with MITRE mapping (T1071, T1573, T1041)
