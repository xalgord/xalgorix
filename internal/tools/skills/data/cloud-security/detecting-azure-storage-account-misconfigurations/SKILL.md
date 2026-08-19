---
name: detecting-azure-storage-account-misconfigurations
description: Audit Azure Blob and ADLS storage accounts for public access exposure, weak or long-lived SAS tokens, missing
  encryption at rest, disabled HTTPS-only traffic, and outdated TLS versions using the azure-mgmt-storage Python SDK.
domain: cybersecurity
subdomain: cloud-security
tags:
- Azure
- storage-accounts
- blob-storage
- ADLS
- SAS-tokens
- encryption
- public-access
- cloud-misconfiguration
- azure-mgmt-storage
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
atlas_techniques:
- AML.T0070
- AML.T0066
- AML.T0082
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detecting Azure Storage Account Misconfigurations

## Overview

Azure Storage accounts are a frequent target for attackers due to misconfigured public access, long-lived SAS tokens, missing encryption, and outdated TLS versions. This skill uses the azure-mgmt-storage Python SDK with StorageManagementClient to enumerate all storage accounts in a subscription, inspect their security properties, list blob containers for public access settings, and generate a risk-scored audit report identifying critical misconfigurations.


## When to Use

- When investigating security incidents that require detecting azure storage account misconfigurations
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

Where `azure-mgmt-storage` audits give false assurance:
- **Container ACLs override the account flag.** `allow_blob_public_access=False` on the account still leaves containers whose `public_access` is `Blob`/`Container` exposed — you must enumerate `blob_containers.list()` and check each container's `public_access`, not just `StorageAccount.allow_blob_public_access`.
- **`minimum_tls_version == None`** on older API versions means the default `TLS1_0`, i.e. **non-compliant**, not "unknown" — treat null as a finding.
- **SAS issuance is invisible to this SDK.** `StorageManagementClient` cannot see account-SAS / user-delegation SAS tokens or their scope/lifetime — that requires Storage Analytics logs or Defender for Storage.
- **`network_rule_set.default_action == 'Deny'` with `bypass` including `AzureServices`** still exposes data to trusted Microsoft services across tenants.
- `require_infrastructure_encryption` defaults to `None`/`False` — absence is not "double-encrypted."

Validate: assert the service principal holds Reader on **every** target subscription (a mis-scoped SP makes `storage_accounts.list()` return empty silently, faking a clean result); cross-check one supposedly private container with an anonymous `GET .../container?restype=container&comp=list` (200 + XML listing = real exposure).

## Prerequisites

- Python 3.9+ with `azure-mgmt-storage`, `azure-identity`
- Azure service principal with Reader role on target subscription
- Environment variables: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID

## Key Detection Areas

1. **Public blob access** — `allow_blob_public_access` enabled on storage account or individual containers set to Blob/Container access level
2. **HTTPS enforcement** — `enable_https_traffic_only` disabled, allowing unencrypted HTTP traffic
3. **Minimum TLS version** — accounts accepting TLS 1.0 or TLS 1.1 instead of minimum TLS 1.2
4. **Encryption at rest** — storage service encryption not enabled or missing customer-managed keys
5. **Network rules** — default action set to Allow instead of Deny, exposing storage to all networks
6. **SAS token risks** — account-level SAS with overly broad permissions or excessive lifetime

## Output

JSON report with per-account findings, severity ratings (Critical/High/Medium/Low), and remediation recommendations aligned with CIS Azure Benchmark controls.
