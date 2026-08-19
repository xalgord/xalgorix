---
name: performing-gcp-penetration-testing-with-gcpbucketbrute
description: Perform GCP security testing using GCPBucketBrute for storage bucket enumeration, gcloud IAM privilege escalation
  path analysis, and service account permission auditing
domain: cybersecurity
subdomain: cloud-security
tags:
- gcp
- cloud-pentesting
- bucket-enumeration
- iam-audit
- privilege-escalation
- gcpbucketbrute
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

# Performing GCP Penetration Testing with GCPBucketBrute

## Overview

This skill covers Google Cloud Platform security testing using GCPBucketBrute for storage bucket enumeration and access permission testing, combined with gcloud CLI IAM enumeration to identify privilege escalation paths. The approach tests for publicly accessible buckets, overly permissive IAM bindings, and service account key exposure.


## When to Use

- When conducting security assessments that involve performing gcp penetration testing with gcpbucketbrute
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

- **Run both unauthenticated AND authenticated:** GCPBucketBrute tests anonymous access by default, but a bucket that 403s anonymously may grant `storage.objects.list` to `allAuthenticatedUsers` (any Google account). Run it again with a logged-in account (omit `-u`) or you'll miss this entire class.
- **Custom keywords matter:** the default permutation set misses real buckets that use project/app prefixes. Feed company-specific terms via `-k`/`--keyword` plus a custom wordlist.
- **Check write, not just read:** `TestIamPermissions` reports the caller's perms - look for `storage.buckets.setIamPolicy` and `storage.objects.create`, not only `storage.objects.get`. Write/ACL access is the higher-impact, commonly-skipped finding.
- **IAM privesc beyond project roles:** check `iam.serviceAccounts.actAs`, `iam.serviceAccounts.getAccessToken`, `iam.serviceAccountKeys.create`, and `setIamPolicy` at project/folder/org level via `gcloud projects get-iam-policy` and `gcloud iam service-accounts get-iam-policy`. `roles/iam.serviceAccountTokenCreator` over a higher-priv SA = full impersonation.
- **Default Compute/AppEngine SAs** frequently retain `roles/editor` - check them explicitly.

**How to confirm a hit (avoid false negatives):** a permission returned by `TestIamPermissions` is a claim - prove it. Actually `gsutil ls gs://bucket` and `gsutil cp` a test object for read/write; for impersonation run `gcloud auth print-access-token --impersonate-service-account=SA` and use the token. **Don't conclude negative until:** you tested both unauth and authenticated, enumerated with custom keywords, walked `actAs`/token-creator chains, and inspected the default service accounts.

## Prerequisites

- Python 3.8+ with google-cloud-storage library
- GCPBucketBrute installed from RhinoSecurityLabs GitHub
- gcloud CLI authenticated with test credentials
- Authorized penetration testing scope for target GCP project
- google-api-python-client and google-auth libraries

## Steps

1. **Enumerate Storage Buckets** — Use GCPBucketBrute with keyword permutations to discover accessible GCP storage buckets
2. **Test Bucket Permissions** — Call TestIamPermissions API on each discovered bucket to determine read/write/admin access levels
3. **Audit IAM Bindings** — Enumerate project-level IAM policies to identify overly permissive role bindings
4. **Check Service Account Keys** — Identify service accounts with user-managed keys and test for privilege escalation via impersonation
5. **Test Privilege Escalation Paths** — Check for iam.serviceAccounts.actAs, setIamPolicy, and other privilege escalation vectors
6. **Generate Findings Report** — Produce a structured security assessment with risk severity ratings

## Expected Output

- JSON report of discovered buckets with permission levels
- IAM privilege escalation path analysis
- Service account security assessment
- Risk-scored findings with remediation recommendations
