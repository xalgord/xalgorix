---
name: detecting-beaconing-patterns-with-zeek
description: 'Performs statistical analysis of Zeek conn.log connection intervals to detect C2 beaconing patterns. Uses the
  ZAT library to load Zeek logs into Pandas DataFrames, calculates inter-arrival time standard deviation, and flags periodic
  connections with low jitter. Use when hunting for command-and-control callbacks in network data.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- detecting
- beaconing
- patterns
- with
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Detecting Beaconing Patterns with Zeek


## When to Use

- When investigating security incidents that require detecting beaconing patterns with zeek
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Jitter defeats low-std-dev rules:** modern C2 (Cobalt Strike `jitter`, Sliver, malleable profiles) randomizes sleep ±20–50%, inflating the standard deviation so a raw `std_dev`-only test misses it. Use the coefficient of variation (CV = std/mean) and also bucket inter-arrival times into a histogram / FFT to find a dominant period despite jitter; flag CV below ~0.1–0.3 rather than near-zero.
- **Too few samples = false negative:** the `len(intervals) > 10` gate silently skips slow beacons (hourly/daily callbacks) over short capture windows. Beaconing detection needs long-haul conn.log data (24h+); state the window and don't treat short captures as clean.
- **Connection merging/long-lived sessions hide periodicity:** keep-alive or HTTP/2 multiplexed sessions appear as one long `duration` row, not repeated connections — supplement timing with small, consistent `orig_bytes`/`resp_bytes` per connection (data-size regularity is a strong beacon signal).
- **Destination evasion:** beacons to CDNs, domain-fronted fronts, or rotating IPs scatter across `id.resp_h`. Group by SNI/`server_name` (ssl.log) or destination domain, not just resp IP.
- **Validate the query fires:** generate a synthetic beacon (e.g., `curl` in a 60s cron with random jitter) into the test conn.log and confirm the src/dst pair surfaces with low CV. **FP tuning:** NTP, software-update pollers, telemetry, and monitoring agents beacon legitimately — allowlist known destinations and known service accounts before alerting.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Load Zeek conn.log data using ZAT (Zeek Analysis Tools), group connections by
source/destination pairs, and compute timing statistics to identify beaconing.

```python
from zat.log_to_dataframe import LogToDataFrame
import numpy as np

log_to_df = LogToDataFrame()
conn_df = log_to_df.create_dataframe('/path/to/conn.log')

# Group by src/dst pair and calculate inter-arrival time
for (src, dst), group in conn_df.groupby(['id.orig_h', 'id.resp_h']):
    times = group['ts'].sort_values()
    intervals = times.diff().dt.total_seconds().dropna()
    if len(intervals) > 10:
        std_dev = np.std(intervals)
        mean_interval = np.mean(intervals)
        # Low std_dev relative to mean = likely beaconing
```

Key analysis steps:
1. Parse Zeek conn.log into DataFrame with ZAT LogToDataFrame
2. Group connections by source IP and destination IP pairs
3. Calculate inter-arrival time intervals between consecutive connections
4. Compute standard deviation and coefficient of variation
5. Flag pairs with low coefficient of variation as potential beacons

## Examples

```python
from zat.log_to_dataframe import LogToDataFrame
log_to_df = LogToDataFrame()
df = log_to_df.create_dataframe('conn.log')
print(df[['id.orig_h', 'id.resp_h', 'ts', 'duration']].head())
```
