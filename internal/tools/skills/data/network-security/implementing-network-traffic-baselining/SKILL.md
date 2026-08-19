---
name: implementing-network-traffic-baselining
description: Build network traffic baselines from NetFlow/IPFIX data using Python pandas for statistical analysis, z-score
  anomaly detection, and hourly/daily traffic pattern profiling
domain: cybersecurity
subdomain: network-security
tags:
- netflow
- ipfix
- traffic-analysis
- baselining
- anomaly-detection
- pandas
- network-monitoring
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---

# Implementing Network Traffic Baselining

## Overview

Network traffic baselining establishes normal communication patterns by analyzing historical NetFlow/IPFIX data to create statistical profiles of expected behavior. This skill uses Python pandas to compute hourly and daily traffic distributions, per-host byte/packet counts, protocol ratios, and top-N talker profiles. Anomalies are detected using z-score thresholds and IQR (interquartile range) outlier methods, enabling SOC analysts to identify deviations such as data exfiltration spikes, beaconing patterns, and unusual port usage.


## When to Use

- When deploying or configuring implementing network traffic baselining capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **Z-score assumes normality:** network volume is heavy-tailed and diurnal, so a global z-score flags every business-hours peak and misses off-hours exfil. Baseline per hour-of-day/day-of-week and prefer IQR/MAD for skewed data rather than one mean/stddev over all time.
- **Baseline window too short or polluted:** under ~7 days, or a window that already contains the incident, bakes anomalies into "normal." Confirm the training period is clean and long enough to cover weekly cycles.
- **Sampled NetFlow skews volumes:** sampled exports (e.g. 1:1000) and **active-timeout flow splitting** make one long transfer look like many small flows. Normalize for sampling rate and account for `flowDuration` before summing bytes/packets.
- **Aggregation hides per-host spikes:** baselining only total throughput masks a single host's exfil; profile per-source-IP too.

**Verification:** validate the detector against ground truth before relying on it — inject a synthetic spike (a host sending 10x its baseline bytes in one hour) and confirm it surfaces with a high z-score/IQR flag, and confirm a normal diurnal peak does **not**. Spot-check that flagged flows are reproducible in the raw NetFlow (matching `srcip`, `bytes`, timestamp). A model that fires on every daily peak, or stays silent when you inject a known spike, is mis-tuned — not validating a quiet network.

## Prerequisites

- NetFlow v5/v9 or IPFIX flow data exported as CSV or JSON
- Python 3.8+ with pandas and numpy libraries
- Historical flow data (minimum 7 days recommended for baseline)

## Steps

1. Ingest NetFlow/IPFIX records from CSV or JSON exports
2. Compute hourly and daily traffic volume distributions (bytes, packets, flows)
3. Build per-source-IP baseline profiles with mean, median, standard deviation
4. Calculate protocol and port distribution baselines
5. Apply z-score anomaly detection to identify statistical outliers
6. Flag flows exceeding IQR-based thresholds as potential anomalies
7. Generate baseline report with anomaly alerts

## Expected Output

JSON report containing traffic baselines (hourly/daily profiles), per-host statistics, detected anomalies with z-scores, and top talker rankings with deviation indicators.
