---
name: detecting-insider-threat-with-ueba
description: Implement User and Entity Behavior Analytics using Elasticsearch/OpenSearch to build behavioral baselines, calculate
  anomaly scores, perform peer group analysis, and detect insider threat indicators such as data exfiltration, privilege abuse,
  and unauthorized access patterns.
domain: cybersecurity
subdomain: threat-detection
tags:
- ueba
- insider-threat
- anomaly-detection
- elasticsearch
- behavior-analytics
- machine-learning
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

# Detecting Insider Threat with UEBA

## Overview

User and Entity Behavior Analytics (UEBA) moves beyond static rule-based detection to model normal behavior for users, hosts, and applications, then flag statistically significant deviations that may indicate insider threats. Using Elasticsearch as the analytics backend, this skill covers building behavioral baselines from authentication logs, file access events, and network activity, computing risk scores using statistical deviation and peer group comparison, and correlating multiple low-confidence indicators into high-confidence insider threat alerts.


## When to Use

- When investigating security incidents that require detecting insider threat with ueba
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Variants most often missed:** **baseline poisoning** — a patient insider slowly ramps data-access volume over the 30-day rolling window so the mean/stddev shifts with them and the z-score never breaches threshold. Counter with longer fixed reference baselines, EWMA with capped adaptation, and absolute (not just relative) volume ceilings.
- **Cold-start / sparse data:** new hires, role changes, and rarely-active service accounts have no stable baseline, so anomaly scores are meaningless or wildly noisy — fall back to peer-group medians until N days of data exist, and suppress scoring below a minimum event count.
- **Peer-group errors:** mis-assigned or overly broad peer groups (e.g., "all of Engineering") hide deviations because a malicious user looks normal against a heterogeneous cohort; validate group homogeneity and re-derive groups when org/role attributes change.
- **Validate the analytics fire:** replay a labeled scenario — off-hours logon (4624 outside baseline window) + large DLP/file-server egress + first-time access to a new share — and confirm the composite score crosses the SOC threshold. Inject a synthetic user whose volume is 5σ above peer median and verify ranking. Map exfil indicators to T1567/T1048 and privilege abuse to T1078.
- **FP tuning:** suppress quarter-end/payroll/backup bursts, planned migrations, and admin maintenance windows via calendar-aware allowlists; require ≥2 independent indicators before alerting to cut single-signal noise.

## Prerequisites

- Elasticsearch 8.x or OpenSearch 2.x cluster with security audit data
- Log sources: Active Directory authentication, VPN, DLP, file server access, email
- Python 3.9+ with elasticsearch client library
- Baseline period of 30+ days of normal user activity data
- Defined peer groups based on department, role, or job function

## Steps

### Step 1: Ingest and Normalize Activity Logs
Configure log pipelines to ingest authentication, file access, email, and network logs into Elasticsearch with a unified user identity field.

### Step 2: Build Behavioral Baselines
Calculate per-user baselines for login times, data volume, application usage, and access patterns over a rolling 30-day window using Elasticsearch aggregations.

### Step 3: Calculate Anomaly Scores
Compare current activity against baselines using z-score deviation and peer group comparison to generate per-user risk scores.

### Step 4: Correlate and Alert
Combine multiple anomalous indicators (unusual hours + large downloads + new system access) into composite risk scores that trigger SOC investigation workflows.

## Expected Output

JSON report containing per-user risk scores, anomalous activity details, peer group deviations, and recommended investigation actions.
