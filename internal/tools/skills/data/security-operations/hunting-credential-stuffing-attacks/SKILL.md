---
name: hunting-credential-stuffing-attacks
description: 'Detects credential stuffing attacks by analyzing authentication logs for login velocity anomalies, ASN diversity,
  password spray patterns, and geographic distribution of failed logins. Uses statistical analysis on Splunk or raw log data.
  Use when investigating account takeover campaigns or building detection rules for auth abuse.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- hunting
- credential
- stuffing
- attacks
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Hunting Credential Stuffing Attacks


## When to Use

- When investigating security incidents that require hunting credential stuffing attacks
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Low-and-slow defeats velocity thresholds:** the `ip_per_account > 50` rule misses attackers who throttle to a few attempts per account per hour spread over days. Add a long-window cumulative count and a low global success-rate signal (<1% across many accounts) rather than only burst velocity.
- **Residential/mobile proxies collapse ASN signals:** botnets routing through residential proxy networks (e.g., rotating ISP IPs) defeat "cloud/proxy ASN concentration" and geo-impossibility heuristics, since each request looks like an ordinary home user. Lean on request-fingerprint uniformity (identical `user_agent`, header order, JA3/TLS fingerprint, missing browser telemetry) across otherwise-diverse IPs.
- **"Failed-only" analysis hides the win:** grouping just on `status == "failed"` misses the successful takeover at the end of a spray. Correlate a success immediately following many failures from the same fingerprint/IP cluster, and watch for first-time-seen device + success.
- **MFA/credential events:** stuffing often shows as password-correct-but-MFA-challenged spikes — include MFA-prompt and `ResultType` partial-success events, not just hard auth failures.
- **Validate the rule fires:** replay a labeled credential-stuffing dataset (many IPs × many accounts, ~0.5% success) and confirm `accounts_under_attack` and the password-spray frame populate; verify timestamps parse so velocity windows aren't skewed. **FP tuning:** corporate NAT/VPN egress, password managers retrying, and load tests look like distributed failures — allowlist known egress IPs and service accounts.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Analyze authentication logs to detect credential stuffing by identifying patterns
of distributed login failures, high IP diversity, and suspicious ASN distribution.

```python
import pandas as pd
from collections import Counter

# Load auth logs
df = pd.read_csv("auth_logs.csv", parse_dates=["timestamp"])

# Credential stuffing indicator: many IPs trying few accounts
ip_per_account = df[df["status"] == "failed"].groupby("username")["source_ip"].nunique()
accounts_under_attack = ip_per_account[ip_per_account > 50]
```

Key detection indicators:
1. High unique source IPs per failed username
2. Low success rate across many accounts (< 1%)
3. ASN concentration from cloud/proxy providers
4. Geographic impossibility (same account, distant locations)
5. User-agent uniformity across distributed IPs

## Examples

```python
# Password spray: one password tried across many accounts
spray = df[df["status"] == "failed"].groupby(["source_ip", "password_hash"]).agg(
    accounts=("username", "nunique")).reset_index()
sprays = spray[spray["accounts"] > 10]
```
