---
name: implementing-security-chaos-engineering
description: 'Implements security chaos engineering experiments that deliberately disable or degrade security controls to
  verify detection and response capabilities. Tests WAF bypass, firewall rule removal, log pipeline disruption, and EDR disablement
  scenarios using boto3 and subprocess. Use when validating SOC detection coverage and resilience.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- implementing
- security
- chaos
- engineering
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
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Implementing Security Chaos Engineering


## When to Use

- When deploying or configuring implementing security chaos engineering capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **No rollback / no blast-radius guard:** running an experiment without a guaranteed `finally: rollback_fn()` and a tight timeout can leave a security group open or CloudTrail disabled. Always wrap setup→verify→rollback and assert post-conditions (rule removed, trail logging) before declaring done.
- **"No alert" misread as resilience:** a quiet console can mean detection works OR that the log pipeline you just broke is what feeds it. Distinguish *control failed silently* from *detection failed* by checking the detection source directly (GuardDuty findings, Config evaluation, SIEM ingestion lag).
- **Verifying the trigger fired, not the response:** an alert in the console is not containment. Measure end to end — detection time AND that the response action (isolate, page, ticket) actually executed within SLA.
- **Running against prod without scoping:** experiments belong in a tagged, isolated account/segment with abort conditions. Confirm the abort path works before the real run.
- **Confirm the experiment was observable at all:** leave the control broken briefly and verify the alert appears; if nothing fires you have a detection gap, not a passed experiment.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Design and execute security chaos experiments that intentionally break security
controls to verify that detection, alerting, and response systems work correctly.

```python
# Example: Verify detection when a security group is opened
import boto3
ec2 = boto3.client("ec2")

# Chaos experiment: temporarily add 0.0.0.0/0 rule
ec2.authorize_security_group_ingress(
    GroupId="sg-12345",
    IpProtocol="tcp", FromPort=22, ToPort=22,
    CidrIp="0.0.0.0/0",
)
# Verify: does GuardDuty/Config alert fire within SLA?
# Rollback: remove the rule after verification
```

Key experiments:
1. Open a security group and verify Config Rule alerts
2. Disable CloudTrail and verify detection time
3. Create IAM admin user and verify alert triggers
4. Simulate log pipeline failure and check monitoring gaps
5. Deploy test malware hash and verify EDR response

## Examples

```python
# Rollback function for safe experiment execution
def run_experiment(setup_fn, verify_fn, rollback_fn, timeout=300):
    try:
        setup_fn()
        result = verify_fn(timeout)
    finally:
        rollback_fn()
    return result
```
