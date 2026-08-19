---
name: implementing-endpoint-detection-with-wazuh
description: Deploy and configure Wazuh SIEM/XDR for endpoint detection including agent management, custom decoder and rule
  XML creation, alert querying via the Wazuh REST API, and automated response actions.
domain: cybersecurity
subdomain: security-operations
tags:
- siem
- xdr
- wazuh
- endpoint-detection
- custom-rules
- incident-response
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_ai_rmf:
- GOVERN-1.1
- MEASURE-2.7
- MANAGE-3.1
- MANAGE-2.4
- MEASURE-3.1
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---
# Implementing Endpoint Detection with Wazuh

## Overview

Wazuh is an open-source SIEM and XDR platform for endpoint monitoring, threat detection, and compliance. This skill covers managing agents via the Wazuh REST API, creating custom decoders and rules in XML for organization-specific detections, querying alerts, and testing rule logic using the logtest endpoint.


## When to Use

- When deploying or configuring implementing endpoint detection with wazuh capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **Agent registered but not enrolled/connected:** `agent_control -l` or `GET /agents?status=disconnected` shows `Never connected`/`disconnected`. Usually a `1514/udp` (enrollment `1515/tcp`) block or a stale key. Re-key with `manage_agents` and confirm `Agent ... is now active` in `/var/ossec/logs/ossec.log`.
- **Custom rule/decoder silently not firing:** rules in `/var/ossec/etc/rules/local_rules.xml` need a matching decoder first. Validate with `/var/ossec/bin/wazuh-logtest` (or the `/logtest` API) — "Phase 2: completed decoding" with no extracted fields means your decoder `regex`/`prematch` missed, so the rule never evaluates.
- **Rule ID collision / level 0:** custom `rule id` must be 100000–120000 and `level` > 0, or the alert is dropped before reaching the indexer.
- **Confirm a hit end to end:** feed a known-bad line through logtest, then `GET /alerts` (or query the `wazuh-alerts-*` index) for that rule ID. No index document means the analysisd→filebeat→indexer path (template/ingest) is broken, not your rule.
- **Active response never runs:** check `<command>`/`<active-response>` `location` and `ossec-execd` logs; a missing `executable` on the agent OS fails silently.

## Prerequisites

- Wazuh Manager 4.x deployed with API enabled
- Python 3.9+ with `requests` library
- API credentials (username/password for JWT authentication)
- Understanding of Wazuh decoder and rule XML syntax

## Steps

### Step 1: Authenticate to Wazuh API
Obtain JWT token via POST to /security/user/authenticate.

### Step 2: List and Monitor Agents
Query agent status, versions, and last keep-alive via /agents endpoint.

### Step 3: Query Security Alerts
Search alerts by rule ID, severity, agent, or time range.

### Step 4: Test Custom Rules with Logtest
Use the /logtest endpoint to validate decoder and rule logic against sample log lines.

## Expected Output

JSON report with agent inventory, alert statistics, rule coverage, and logtest validation results.
