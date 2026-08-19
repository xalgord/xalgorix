---
name: analyzing-network-packets-with-scapy
description: Craft, send, sniff, and dissect network packets using Scapy for protocol analysis, network reconnaissance, and
  traffic anomaly detection in authorized security testing
domain: cybersecurity
subdomain: network-security
tags:
- scapy
- packet-analysis
- network-forensics
- protocol-dissection
- pcap
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

# Analyzing Network Packets with Scapy

## Overview

Scapy is a Python packet manipulation library that enables crafting, sending, sniffing, and dissecting network packets at granular protocol layers. This skill covers using Scapy for security-relevant tasks including TCP/UDP/ICMP packet crafting, pcap file analysis, protocol field extraction, SYN scan implementation, DNS query analysis, and detecting anomalous traffic patterns such as unusually fragmented packets or malformed headers.


## When to Use

- When investigating security incidents that require analyzing network packets with scapy
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Offline analysis misses what was never captured:** `rdpcap()` only sees what the tap/SPAN forwarded. Truncated snaplen (`tcpdump -s 96`) strips payload so DNS-tunnel `qry.name` entropy and HTTP bodies vanish — capture full frames (`-s 0`) before scoring.
- **Scapy reassembles nothing by default:** a SYN-flood ratio check on raw packets misreads retransmits; sessionize with `sessions()`/`packet.sessions()` and follow streams before judging TCP flag ratios, or fragmented C2 (IP `frag`/`MF` bit set) is read as benign noise.
- **Encrypted blind spots:** DNS-over-HTTPS/DoT (443/853) and TLS exfil have no plaintext `DNSQR.qname` to measure — entropy heuristics silently return nothing. Pivot on SNI from the `TLS` ClientHello, JA3 hashing, and packet-size/timing rather than concluding "no tunneling."
- **Validate the detector actually fires:** craft a positive sample — `IP()/UDP()/DNS(qd=DNSQR(qname="<60-char-base64>.evil.com"))` written with `wrpcap()` — feed it back through your analysis script, and confirm the high-entropy/long-label rule flags it. No flag means the threshold or layer filter is wrong.
- **FP tuning:** CDN hostnames, DNS SRV/TXT lookups, and chatty mDNS produce long/odd labels legitimately; baseline `qname` length distribution per host and whitelist known resolvers before alerting.

## Prerequisites

- Python 3.8+ with `scapy` library installed (`pip install scapy`)
- Root/administrator privileges for raw socket operations (sniffing, sending)
- Npcap (Windows) or libpcap (Linux) for packet capture
- Authorization to perform packet operations on target network

## Steps

1. Read and parse pcap/pcapng files with `rdpcap()` for offline analysis
2. Extract protocol layers (IP, TCP, UDP, DNS, HTTP) and field values
3. Compute traffic statistics: top talkers, protocol distribution, port frequency
4. Detect SYN flood patterns by analyzing TCP flag ratios
5. Identify DNS exfiltration indicators via query length and entropy analysis
6. Craft custom probe packets for authorized network testing
7. Export findings as structured JSON report

## Expected Output

JSON report containing packet statistics, protocol distribution, top source/destination IPs, detected anomalies (SYN floods, DNS tunneling indicators, fragmentation attacks), and per-flow summaries.
