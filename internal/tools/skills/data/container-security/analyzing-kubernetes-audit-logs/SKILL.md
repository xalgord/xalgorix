---
name: analyzing-kubernetes-audit-logs
description: 'Parses Kubernetes API server audit logs (JSON lines) to detect exec-into-pod, secret access, RBAC modifications,
  privileged pod creation, and anonymous API access. Builds threat detection rules from audit event patterns. Use when investigating
  Kubernetes cluster compromise or building k8s-specific SIEM detection rules.

  '
domain: cybersecurity
subdomain: container-security
tags:
- analyzing
- kubernetes
- audit
- logs
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
---

# Analyzing Kubernetes Audit Logs


## When to Use

- When investigating security incidents that require analyzing kubernetes audit logs
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **`level: Metadata` hides the payload:** at Metadata level the `requestObject` is dropped, so privileged-pod detection (`securityContext.privileged`, `hostPID`, capability adds) and secret *values* are invisible. Use `level: RequestResponse` for `pods` create/update and for `clusterrolebindings` to see the escalation body.
- **Subresources are separate:** `pods/exec` and `pods/attach` are distinct from `pods` - a rule matching only `resource == "pods"` misses every shell-in. Match the subresource explicitly.
- **`omitStages: ["RequestReceived"]`** combined with a low default level can silently discard events; confirm your policy emits the `ResponseComplete` stage for sensitive verbs.
- **Anonymous access:** match `user.username == "system:anonymous"` or group `system:unauthenticated`, not just missing users.
- **Secret enumeration at Metadata** shows the verb/name but not which keys were read - escalate to Request level for the secrets you care about.
- **How to validate the rule fires:** run `kubectl exec -it <pod> -- sh` and `kubectl get secret <name> -o yaml` against a test namespace, then grep the audit log for `pods/exec` and `secrets` events with your username. If nothing appears, the audit policy level is too low or the stage is omitted.

## Prerequisites

- Familiarity with container security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Parse Kubernetes audit log files (JSON lines format) to detect security-relevant
events including unauthorized access, privilege escalation, and data exfiltration.

```python
import json

with open("/var/log/kubernetes/audit.log") as f:
    for line in f:
        event = json.loads(line)
        verb = event.get("verb")
        resource = event.get("objectRef", {}).get("resource")
        user = event.get("user", {}).get("username")
        if verb == "create" and resource == "pods/exec":
            print(f"Pod exec by {user}")
```

Key events to detect:
1. pods/exec and pods/attach (shell into containers)
2. secrets access (get/list/watch)
3. clusterrolebindings creation (RBAC escalation)
4. Privileged pod creation
5. Anonymous or system:unauthenticated access

## Examples

```python
# Detect secret enumeration
if verb in ("get", "list") and resource == "secrets":
    print(f"Secret access: {user} -> {event['objectRef'].get('name')}")
```
