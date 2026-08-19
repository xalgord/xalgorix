---
name: implementing-deception-based-detection-with-canarytoken
description: Deploy and monitor Canary Tokens via the Thinkst Canary API for deception-based breach detection using web bug
  tokens, DNS tokens, document tokens, and AWS key tokens.
domain: cybersecurity
subdomain: deception-technology
tags:
- canarytoken
- deception
- honeytokens
- breach-detection
- Thinkst-Canary
- tripwire
- early-warning
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-06
- PR.IR-01
---

# Implementing Deception-Based Detection with Canarytoken

## Overview

Canary Tokens are lightweight tripwire mechanisms that alert when an attacker accesses a resource. This skill uses the Thinkst Canary REST API to programmatically create tokens (web bugs, DNS tokens, MS Word documents, AWS API keys), deploy them to strategic locations, monitor for triggered alerts, and generate deception coverage reports.


## When to Use

- When deploying or configuring implementing deception based detection with canarytoken capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

Canarytokens fail when they are placed where no attacker will look, or when the
trigger path is broken so the alert never reaches anyone:

- **Token too obvious or mislabeled:** a file named `passwords_REAL.docx` on the
  desktop screams trap. Name tokens to match genuine bait (`AWS_prod_keys.txt`,
  `VPN-config-backup`) and seed them where lateral movement actually lands -
  file shares, `.aws/credentials`, browser history, config repos.
- **DNS/HTTP egress blocked:** DNS tokens never fire if internal resolvers
  can't reach the canarytokens domain, and web-bug tokens die behind an
  egress-filtering proxy. Verify the token's callback path resolves from the
  segment where it is deployed.
- **AWS key token without CloudTrail context:** the token alerts on use, but
  confirm the alerting channel (Console/webhook) is actually monitored.
- **Document tokens stripped:** DLP or Office sanitizers can remove the embedded
  web bug; confirm the token survives the document's real storage path.
- **How to confirm a hit:** trip each token yourself - open the Word doc,
  resolve the DNS hostname, `curl` the web bug, run `aws sts get-caller-identity`
  with the decoy key - and verify the alert lands in the console and downstream
  channel with correct source attribution.

## Prerequisites

- Thinkst Canary Console or canarytokens.org account
- API auth token from Canary Console
- Python 3.9+ with `requests`
- File system access for deploying document and file tokens

## Steps

1. Authenticate to the Canary Console API using auth_token
2. Create web bug (HTTP) tokens for embedding in documents and web pages
3. Create DNS tokens for monitoring DNS resolution attempts
4. Create MS Word document tokens for file share deployment
5. List all active tokens and their trigger history
6. Query recent alerts for triggered token events
7. Generate deception coverage report with deployment recommendations

## Expected Output

- JSON report listing all deployed Canary Tokens, trigger history, alert details, and coverage analysis
- Deployment map showing token types across network segments
