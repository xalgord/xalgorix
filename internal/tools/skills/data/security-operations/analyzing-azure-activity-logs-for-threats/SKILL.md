---
name: analyzing-azure-activity-logs-for-threats
description: 'Queries Azure Monitor activity logs and sign-in logs via azure-monitor-query to detect suspicious administrative
  operations, impossible travel, privilege escalation, and resource modifications. Builds KQL queries for threat hunting in
  Azure environments. Use when investigating suspicious Azure tenant activity or building cloud SIEM detections.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- azure
- cloud-security
- azure-monitor
- kql
- threat-hunting
- activity-logs
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Analyzing Azure Activity Logs for Threats


## When to Use

- When investigating security incidents that require analyzing azure activity logs for threats
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **`AzureActivity` ≠ `AuditLogs` ≠ `SigninLogs`:** role-assignment writes land in `AzureActivity` (`operationName` `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`), but Azure AD directory-role grants (Global Admin) only appear in `AuditLogs` (`OperationName == "Add member to role"`). Querying one table misses the other entire escalation path.
- **Plane gap:** `AzureActivity` covers ARM control-plane only — data-plane actions (Key Vault secret *reads*, Storage blob GETs) require resource-specific diagnostic logs (`AzureDiagnostics`/`StorageRead`) to be explicitly enabled, or the access is invisible.
- **Impossible-travel false negatives:** attackers using residential proxies or Azure datacenter egress in the victim's region defeat geo-velocity. Correlate on device/`ResultType`, `AuthenticationRequirement`, and new `UserAgent` rather than geo alone.
- **Service-principal blind spot:** SP and managed-identity sign-ins are in `AADServicePrincipalSignInLogs`/`AADManagedIdentitySignInLogs`, not `SigninLogs` — automation-based privilege abuse is missed if you only watch interactive sign-ins.
- **Validate the query fires:** in a lab, assign a role and confirm the `take 10` returns the event within the diagnostic-settings latency (often 5–15 min); a 24h `timespan` can hide delayed ingestion. Check the workspace actually receives `AzureActivity` (diagnostic setting → Log Analytics) before trusting an empty result.
- **FP tuning:** PIM just-in-time activations, IaC pipelines (Terraform/Bicep service principals), and Azure Policy remediation tasks generate legitimate role writes — exclude their object IDs.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Use azure-monitor-query to execute KQL queries against Azure Log Analytics workspaces,
detecting suspicious admin operations and sign-in anomalies.

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from datetime import timedelta

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(
    workspace_id="WORKSPACE_ID",
    query="AzureActivity | where OperationNameValue has 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' | take 10",
    timespan=timedelta(hours=24),
)
```

Key detection queries:
1. Role assignment changes (privilege escalation)
2. Resource group and subscription modifications
3. Key vault secret access from new IPs
4. Network security group rule changes
5. Conditional access policy modifications

## Examples

```python
# Detect new Global Admin role assignments
query = '''
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue has "Global Administrator"
'''
```
