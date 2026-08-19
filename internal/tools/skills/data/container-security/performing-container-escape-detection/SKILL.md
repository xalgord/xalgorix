---
name: performing-container-escape-detection
description: 'Detects container escape attempts by analyzing namespace configurations, privileged container checks, dangerous
  capability assignments, and host path mounts using the kubernetes Python client. Identifies CVE-2022-0492 style escapes
  via cgroup abuse. Use when auditing container security posture or investigating escape attempts.

  '
domain: cybersecurity
subdomain: container-security
tags:
- performing
- container
- escape
- detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
---

# Performing Container Escape Detection


## When to Use

- When conducting security assessments that involve performing container escape detection
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Detection Gaps & Validation

A pod-spec audit that only reads `securityContext.privileged` misses most real escape paths. The fields below are the ones detection scripts routinely skip:

- **Beyond `privileged`:** check `allowPrivilegeEscalation`, `procMount: Unmasked`, `seccompProfile: Unconfined`/absent, and added capabilities individually - `SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH` (CVE-2022-0492 via cgroup release_agent), `NET_RAW`, `SYS_MODULE`, `BPF`. A non-privileged pod with `SYS_ADMIN` still escapes.
- **All container types:** iterate `spec.containers` **and** `spec.initContainers` and `spec.ephemeralContainers` - debug/ephemeral containers are a common blind spot.
- **Host exposure:** `hostPID`/`hostIPC`/`hostNetwork`, and hostPath mounts beyond `/` and `/etc` (`/var/run/docker.sock`, `/var/run/containerd`, `/proc`, `/sys`, kubelet dirs). Check the mount is writable, not just present.
- **Pod-level vs container-level securityContext:** a setting on one does not imply the other; read both.

**Validate, don't conclude-safe from one field:** a single clean field is not a clean pod - enumerate the full matrix above. Where authorized, confirm a finding by actually attempting the escape in a throwaway namespace (e.g. mount host root from a `SYS_ADMIN` pod, or read `/host/etc/shadow` via a hostPath mount). Cross-check the live audit against runtime detection (Tetragon/Falco) - a static "no privileged pods" result does not mean no escape occurred.

## Prerequisites

- Familiarity with container security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Audit Kubernetes pods for container escape vectors including privileged mode,
dangerous capabilities, host namespace sharing, and writable hostPath mounts.

```python
from kubernetes import client, config
config.load_kube_config()
v1 = client.CoreV1Api()

pods = v1.list_pod_for_all_namespaces()
for pod in pods.items:
    for container in pod.spec.containers:
        sc = container.security_context
        if sc and sc.privileged:
            print(f"PRIVILEGED: {pod.metadata.namespace}/{pod.metadata.name}")
```

Key escape vectors:
1. Privileged containers (full host access)
2. CAP_SYS_ADMIN capability
3. Host PID/Network/IPC namespace sharing
4. Writable hostPath mounts to / or /etc
5. Docker socket mount (/var/run/docker.sock)

## Examples

```python
# Check for docker socket mounts
for vol in pod.spec.volumes or []:
    if vol.host_path and "docker.sock" in (vol.host_path.path or ""):
        print(f"Docker socket exposed: {pod.metadata.name}")
```
