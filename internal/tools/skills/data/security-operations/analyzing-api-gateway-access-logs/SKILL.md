---
name: analyzing-api-gateway-access-logs
description: 'Parses API Gateway access logs (AWS API Gateway, Kong, Nginx) to detect BOLA/IDOR attacks, rate limit bypass,
  credential scanning, and injection attempts. Uses pandas for statistical analysis of request patterns and anomaly detection.
  Use when investigating API abuse or building API-specific threat detection rules.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- analyzing
- api
- gateway
- access
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Analyzing API Gateway Access Logs


## When to Use

- When investigating security incidents that require analyzing api gateway access logs
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **UUID/slug BOLA hides from `nunique` thresholds:** attackers who harvest IDs from list endpoints access objects one-by-one, so the `unique_ids > 50` rule misses them. Add a per-user ratio of `resource_id` accessed vs. `resource_id` the user owns, not just raw counts.
- **Rate-limit bypass is invisible if you key only on `source_ip`:** rotated `X-Forwarded-For`, `X-Real-IP`, or per-request API keys spread one campaign across many apparent clients. Group on JA3/TLS fingerprint or `user_id` too, and watch for clients that always sit just under the 429 threshold.
- **Encoded injection slips regex:** test `id=1%2527%2520OR` (double URL-encode), JSON-body params, and base64 blobs — the gateway log often stores the decoded form in one field and raw in another; scan both.
- **Validate the query fires:** replay a known BOLA burst (one token, 200 sequential IDs) and a 401 spray into the log set and confirm both `suspicious` and `scanners` frames populate. If the gateway samples logs (AWS API Gateway access logging at <100%), low-and-slow abuse is dropped before analysis — confirm sampling rate first.
- **FP tuning:** mobile clients pre-fetching catalogs and monitoring/synthetic probes legitimately touch many IDs and emit 401s on token expiry; allowlist their `user_agent`/service accounts before alerting.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Parse API gateway access logs to identify attack patterns including broken object
level authorization (BOLA), excessive data exposure, and injection attempts.

```python
import pandas as pd

df = pd.read_json("api_gateway_logs.json", lines=True)
# Detect BOLA: same user accessing many different resource IDs
bola = df.groupby(["user_id", "endpoint"]).agg(
    unique_ids=("resource_id", "nunique")).reset_index()
suspicious = bola[bola["unique_ids"] > 50]
```

Key detection patterns:
1. BOLA/IDOR: sequential resource ID enumeration
2. Rate limit bypass via header manipulation
3. Credential scanning (401 surges from single source)
4. SQL/NoSQL injection in query parameters
5. Unusual HTTP methods (DELETE, PATCH) on read-only endpoints

## Examples

```python
# Detect 401 surges indicating credential scanning
auth_failures = df[df["status_code"] == 401]
scanner_ips = auth_failures.groupby("source_ip").size()
scanners = scanner_ips[scanner_ips > 100]
```
