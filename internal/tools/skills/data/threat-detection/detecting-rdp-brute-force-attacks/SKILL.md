---
name: detecting-rdp-brute-force-attacks
description: Detect RDP brute force attacks by analyzing Windows Security Event Logs for failed authentication patterns (Event
  ID 4625), successful logons after failures (Event ID 4624), NLA failures, and source IP frequency analysis.
domain: cybersecurity
subdomain: threat-detection
tags:
- threat-detection
- rdp
- brute-force
- windows-event-logs
- blue-team
- siem
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
---
# Detecting RDP Brute Force Attacks

## Overview

RDP brute force attacks target Windows Remote Desktop Protocol services by attempting rapid credential guessing against exposed RDP endpoints. Detection relies on analyzing Windows Security Event Logs for Event ID 4625 (failed logon with Logon Type 10 or 3) and correlating with Event ID 4624 (successful logon) to identify compromised accounts. This skill covers parsing EVTX files with python-evtx, identifying attack patterns through source IP frequency analysis, detecting NLA bypass attempts, and generating actionable detection reports.


## When to Use

- When investigating security incidents that require detecting rdp brute force attacks
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Variants most often missed:** counting only Event ID 4625 with **Logon Type 10** (RemoteInteractive) misses NLA-fronted attempts that surface as **Type 3** (network) and credential-validation failures on the DC (4776) rather than the RDP host — correlate 4625 Type 3/10 plus 4776 across both. When **NLA is enforced**, failures may be rejected at the CredSSP/TLS layer and never write a 4625 at all; supplement with `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS`/TerminalServices-RemoteConnectionManager EID 1149 and 4625 Sub Status codes (`0xC000006A` bad password, `0xC0000064` no such user, `0xC0000234` locked out).
- **False negatives:** **slow/distributed (low-and-slow)** spraying — one attempt per account per hour from rotating source IPs — defeats per-IP-per-window thresholds; pivot to per-target-account failure aggregation and global failed-logon rate. A single 4624 Type 10 success following a burst of 4625s from the same IP is the key compromise signal that count-only rules drop.
- **Validate the rule fires:** Atomic Red Team T1110.001/T1110.003 (password guess/spray) against RDP, and T1021.001 (RDP lateral movement) to confirm the 4625→4624 Type 10 correlation alerts. Verify both Type 3 and Type 10 paths trigger.
- **FP tuning:** exclude vulnerability scanners, expired-password storms after policy changes, and service accounts with stale cached creds; baseline normal source IPs/geos and alert on first-seen external IP rather than raw failure counts alone.

## Prerequisites

- Python 3.9+ with `python-evtx`, `lxml` libraries
- Windows Security EVTX log files (exported from Event Viewer or collected via WEF)
- Understanding of Windows authentication Event IDs (4624, 4625, 4776)
- Familiarity with RDP Logon Types (Type 3 for NLA, Type 10 for RemoteInteractive)

## Steps

### Step 1: Export Security Event Logs
Export Windows Security logs to EVTX format using Event Viewer or wevtutil:
```
wevtutil epl Security C:\logs\security.evtx
```

### Step 2: Parse Failed Logon Events
Use python-evtx to parse Event ID 4625 entries, extracting source IP, target username, failure reason (Sub Status), and Logon Type fields.

### Step 3: Analyze Attack Patterns
Identify brute force patterns by:
- Counting failed logons per source IP within time windows
- Detecting username spray attacks (many usernames from one IP)
- Correlating 4625 failures with subsequent 4624 success from same IP

### Step 4: Generate Detection Report
Produce a JSON report with top attacking IPs, targeted accounts, time-based analysis, and compromise indicators.

## Expected Output

JSON report containing:
- Total failed logon events and unique source IPs
- Top attacking IPs ranked by failure count
- Targeted usernames and failure sub-status codes
- Successful logons following brute force attempts (potential compromises)
- Time-series analysis of attack intensity
