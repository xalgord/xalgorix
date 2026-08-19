---
name: analyzing-memory-forensics-with-lime-and-volatility
description: 'Performs Linux memory acquisition using LiME (Linux Memory Extractor) kernel module and analysis with Volatility
  3 framework. Extracts process lists, network connections, bash history, loaded kernel modules, and injected code from Linux
  memory images. Use when performing incident response on compromised Linux systems.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- memory-forensics
- linux-forensics
- lime
- volatility
- incident-response
- kernel-modules
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Analyzing Memory Forensics with LiME and Volatility


## When to Use

- When investigating security incidents that require analyzing memory forensics with lime and volatility
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Acquisition smear is the #1 false negative:** LiME captures memory live, so page tables and process lists shift mid-dump on a busy host. A torn capture makes `linux.pslist` walk a broken `task_struct` list and silently drop processes. Prefer `format=lime` (timestamped, structured) over `format=raw`, capture with the box as quiet as possible, and hash the image immediately.
- **Profile/symbol mismatch yields empty output:** Volatility 3 needs an ISF symbol table matching the exact kernel (`uname -r` + build). A wrong banner makes every Linux plugin return nothing — that is a tooling failure, not a clean host. Verify with `vol3 -f mem.lime banners.Banners` before concluding negative.
- **`pslist` vs `psscan`:** rootkits unlink `task_struct` from the active list. Always diff `linux.pslist` against `linux.psscan` (pool/scan-based) — a process in psscan but not pslist is a hidden-process indicator.
- **LKM rootkits hook syscalls:** `linux.lsmod` only shows registered modules; a module that unregisters itself won't appear. Corroborate with `linux.check_syscall`/`linux.check_afinfo` for hooked syscall and netfilter pointers, and `linux.malfind` for injected/anonymous executable VMAs.
- **Validate the workflow fires:** run a benign test (e.g., a `nc` listener + a deleted-but-running binary) on the lab host, capture, and confirm `linux.sockstat` shows the socket and `linux.bash` recovers the command history before trusting results on evidence.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Acquire Linux memory using LiME kernel module, then analyze with Volatility 3
to extract forensic artifacts from the memory image.

```bash
# LiME acquisition
insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Volatility 3 analysis
vol3 -f /evidence/memory.lime linux.pslist
vol3 -f /evidence/memory.lime linux.bash
vol3 -f /evidence/memory.lime linux.sockstat
```

```python
import volatility3
from volatility3.framework import contexts, automagic
from volatility3.plugins.linux import pslist, bash, sockstat

# Programmatic Volatility 3 usage
context = contexts.Context()
automagics = automagic.available(context)
```

Key analysis steps:
1. Acquire memory with LiME (format=lime or format=raw)
2. List processes with linux.pslist, compare with linux.psscan
3. Extract bash command history with linux.bash
4. List network connections with linux.sockstat
5. Check loaded kernel modules with linux.lsmod for rootkits

## Examples

```bash
# Full forensic workflow
vol3 -f memory.lime linux.pslist | grep -v "\[kthread\]"
vol3 -f memory.lime linux.bash
vol3 -f memory.lime linux.malfind
vol3 -f memory.lime linux.lsmod
```
