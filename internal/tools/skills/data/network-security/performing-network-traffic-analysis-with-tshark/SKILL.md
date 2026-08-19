---
name: performing-network-traffic-analysis-with-tshark
description: Automate network traffic analysis using tshark and pyshark for protocol statistics, suspicious flow detection,
  DNS anomaly identification, and IOC extraction from PCAP files
domain: cybersecurity
subdomain: network-security
tags:
- tshark
- pyshark
- pcap
- packet-analysis
- network-forensics
- wireshark
- traffic-analysis
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---

# Performing Network Traffic Analysis with TShark

## Overview

This skill automates packet capture analysis using tshark (Wireshark CLI) and pyshark (Python wrapper). It extracts protocol distribution statistics, identifies suspicious network flows (port scans, beaconing, data exfiltration), extracts IOCs (IPs, domains, URLs), and detects DNS tunneling patterns from PCAP files.


## When to Use

- When conducting security assessments that involve performing network traffic analysis with tshark
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Detection Gaps & Validation

- **Snaplen truncation:** capturing with a small `-s` (snaplen) cuts payloads and breaks reassembly. Capture full frames (`-s 0`) or you'll miss DNS answers, HTTP bodies, and IOC strings.
- **Capture vs display filter confusion:** a BPF capture filter (`-f "port 53"`) drops packets permanently; a display filter (`-Y "dns"`) only hides them. Using `-f` when you meant `-Y` silently discards evidence — capture broadly, filter with `-Y`.
- **Encrypted traffic blind spot:** TLS hides URLs and payloads. Pivot to metadata — SNI (`-Y "tls.handshake.extensions_server_name"`), JA3, cert CN, and conn duration/bytes — instead of assuming "nothing malicious."
- **Drops and sampling:** check tshark's end-of-capture "packets dropped" and the kernel `if_drop`; a saturated link or ring buffer (`-b`) silently loses the beacon you're hunting. Sampled NetFlow (1:1000) misses low-volume C2 entirely.
- **Display-filter mistakes:** `ip.addr != x` and `!(ip.addr == x)` are not equivalent, and `http.request` misses HTTP/2-over-TLS. Validate the filter returns the expected baseline count before trusting a zero result.
- **How to validate:** re-run the logic in the Wireshark GUI, cross-check counts with `-z io,stat,0` and `-z conv,ip`, and confirm against a known-good PCAP that your detection actually fires before reporting "clean."

## Prerequisites

- tshark (Wireshark CLI) installed and in PATH
- Python 3.8+ with pyshark library
- PCAP or PCAPNG capture file for analysis

## Steps

1. **Extract Protocol Statistics** — Generate protocol hierarchy and conversation statistics from the capture
2. **Identify Top Talkers** — Rank source/destination IPs by volume and connection count
3. **Detect Suspicious Flows** — Flag port scanning patterns, unusual port usage, and high-frequency connections
4. **Extract Network IOCs** — Pull unique IPs, domains from DNS queries, and URLs from HTTP traffic
5. **Analyze DNS Traffic** — Detect DNS tunneling via high-entropy subdomain queries and excessive TXT records
6. **Generate Analysis Report** — Produce structured report with flow summaries and threat indicators

## Expected Output

- JSON report with protocol statistics and top talkers
- Suspicious flow detections with severity ratings
- Extracted IOCs (IPs, domains, URLs)
- DNS anomaly analysis results
