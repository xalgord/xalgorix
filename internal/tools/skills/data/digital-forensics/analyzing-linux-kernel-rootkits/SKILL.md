---
name: analyzing-linux-kernel-rootkits
description: Detect kernel-level rootkits in Linux memory dumps using Volatility3 linux plugins (check_syscall, lsmod, hidden_modules),
  rkhunter system scanning, and /proc vs /sys discrepancy analysis to identify hooked syscalls, hidden kernel modules, and
  tampered system structures.
domain: cybersecurity
subdomain: digital-forensics
tags:
- rootkit
- linux
- kernel
- volatility3
- memory-forensics
- malware-analysis
- rkhunter
- forensics
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
---

# Analyzing Linux Kernel Rootkits

## Overview

Linux kernel rootkits operate at ring 0, modifying kernel data structures to hide processes, files, network connections, and kernel modules from userspace tools. Detection requires either memory forensics (analyzing physical memory dumps with Volatility3) or cross-view analysis (comparing /proc, /sys, and kernel data structures for inconsistencies). This skill covers using Volatility3 Linux plugins to detect syscall table hooks, hidden kernel modules, and modified function pointers, supplemented by live system scanning with rkhunter and chkrootkit.


## When to Use

- When investigating security incidents that require analyzing linux kernel rootkits
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Most-missed artifacts:** beyond `linux.check_syscall`/`lsmod`, run `linux.hidden_modules`, `linux.check_afinfo`/`tty_check`, `linux.kmsg`, and `linux.malfind`, and look for `ftrace`/kprobes hooks and modified `/sys/kernel/`. Modern LKM rootkits (Diamorphine, Reptile) hook via ftrace or function-pointer overwrite rather than the syscall table, so a clean syscall table is not a clean kernel.
- **Cross-view is the core validation:** never trust one source. Compare module lists from `/proc/modules`, `lsmod`, `/sys/module/`, and the kernel kobject list; compare processes from the `task_struct` list vs `/proc` vs `pid_hash`. A delta between any two views is the rootkit's hiding signature - corroborate each hidden PID/connection across memory, `ss`, and `/proc/net/tcp`.
- **Anti-forensics that defeats this analysis:** rootkits hook `read`/`getdents64`, so live `rkhunter`/`chkrootkit`/`ls` lie. Always work from a memory image acquired with LiME/AVML, and verify modified `ps`/`netstat`/`ss` binaries by SHA-256 against the distro package - do not run the suspect binaries.
- **Profile/ISF must match exactly:** a Volatility3 symbol table for the wrong kernel build silently yields empty or bogus output that looks like "no rootkit." Confirm the `uname -r`/banner from the dump matches the ISF before trusting any plugin.
- **Interpretation pitfalls (false positives):** legitimate out-of-tree modules (NVIDIA, VirtualBox, eBPF/EDR agents like Falco/CrowdStrike) hook syscalls and appear as "unknown" modules; live patching (kpatch/ksplice) and hypervisor introspection also alter pointers. Baseline against a known-good kernel of the same version before declaring a hook malicious.

## Prerequisites

- Volatility3 installed (pip install volatility3)
- Linux memory dump (acquired via LiME, AVML, or /proc/kcore)
- Volatility3 Linux symbol table (ISF) matching the target kernel version
- rkhunter and chkrootkit for live system scanning
- Reference known-good kernel image for comparison

## Steps

### Step 1: Acquire Memory Dump
Capture Linux physical memory using LiME kernel module or AVML for cloud instances.

### Step 2: Analyze with Volatility3
Run linux.check_syscall, linux.lsmod, linux.hidden_modules, and linux.check_idt plugins to detect rootkit artifacts.

### Step 3: Cross-View Analysis
Compare module lists from /proc/modules, lsmod, and /sys/module to identify modules hidden from one view but present in another.

### Step 4: Live System Scanning
Run rkhunter and chkrootkit to detect known rootkit signatures, suspicious files, and modified system binaries.

## Expected Output

JSON report containing detected syscall hooks, hidden kernel modules, modified IDT entries, suspicious /proc discrepancies, and rkhunter findings.

## Example Output

```text
$ sudo python3 rootkit_analyzer.py --memory /evidence/linux-mem.lime --profile Ubuntu2204

Linux Kernel Rootkit Analysis Report
=====================================
Memory Image: /evidence/linux-mem.lime
Kernel Version: 5.15.0-91-generic (Ubuntu 22.04 LTS)
Analysis Time: 2024-01-18 09:15:32 UTC

[+] Scanning syscall table for hooks...
    Syscall Table Base: 0xffffffff82200300
    Total syscalls checked: 449

    HOOKED SYSCALLS DETECTED:
    ┌─────────┬──────────────────┬──────────────────────┬──────────────────────┐
    │ NR      │ Syscall          │ Expected Address     │ Current Address      │
    ├─────────┼──────────────────┼──────────────────────┼──────────────────────┤
    │ 0       │ sys_read         │ 0xffffffff8139a0e0   │ 0xffffffffc0a12000   │
    │ 2       │ sys_open         │ 0xffffffff8139b340   │ 0xffffffffc0a12180   │
    │ 78      │ sys_getdents64   │ 0xffffffff813f5210   │ 0xffffffffc0a12300   │
    │ 62      │ sys_kill         │ 0xffffffff8110c4a0   │ 0xffffffffc0a12480   │
    └─────────┴──────────────────┴──────────────────────┴──────────────────────┘
    WARNING: 4 syscall hooks detected - rootkit behavior confirmed

[+] Checking for hidden kernel modules...
    Loaded modules (lsmod):         147
    Modules in kobject list:        149
    HIDDEN MODULES:
      - "netfilter_helper" at 0xffffffffc0a10000 (size: 12288)
      - "kworker_sched"    at 0xffffffffc0a14000 (size: 8192)

[+] Scanning /proc for discrepancies...
    Processes in task_struct list: 234
    Processes visible in /proc:   231
    HIDDEN PROCESSES:
      - PID 31337  cmd: "[kworker/0:3]"   (disguised as kernel thread)
      - PID 31442  cmd: "rsyslogd"         (fake, real rsyslogd is PID 892)
      - PID 31500  cmd: ""                 (unnamed process)

[+] Checking IDT entries...
    IDT entries scanned: 256
    Modified entries: 0 (clean)

[+] Running rkhunter scan...
    Checking for known rootkits:        68 variants checked
    Diamorphine rootkit:                WARNING - signatures match
    System binary checks:
      /usr/bin/ps:     MODIFIED (SHA-256 mismatch)
      /usr/bin/netstat: MODIFIED (SHA-256 mismatch)
      /usr/bin/ls:     MODIFIED (SHA-256 mismatch)
      /usr/sbin/ss:    OK

[+] Network analysis...
    Hidden connections (not in /proc/net/tcp):
      ESTABLISHED  0.0.0.0:0 -> 198.51.100.47:4443 (PID 31337)
      ESTABLISHED  0.0.0.0:0 -> 198.51.100.47:8080 (PID 31442)

Summary:
  Rootkit Type:         Loadable Kernel Module (LKM)
  Probable Family:      Diamorphine variant
  Syscall Hooks:        4 (read, open, getdents64, kill)
  Hidden Modules:       2
  Hidden Processes:     3
  Hidden Connections:   2 (C2: 198.51.100.47)
  Modified Binaries:    3 (/usr/bin/ps, netstat, ls)
  Risk Level:           CRITICAL
```
