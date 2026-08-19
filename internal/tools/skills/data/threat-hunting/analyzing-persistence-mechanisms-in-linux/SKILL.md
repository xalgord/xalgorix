---
name: analyzing-persistence-mechanisms-in-linux
description: Detect and analyze Linux persistence mechanisms including crontab entries, systemd service units, LD_PRELOAD
  hijacking, bashrc modifications, and authorized_keys backdoors using auditd and file integrity monitoring
domain: cybersecurity
subdomain: threat-hunting
tags:
- linux-persistence
- crontab
- systemd
- ld-preload
- auditd
- threat-hunting
- incident-response
mitre_attack:
- T1053.003
- T1543.002
- T1574.006
- T1546.004
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Process Termination
- Content Format Conversion
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Analyzing Persistence Mechanisms in Linux

## Overview

Adversaries establish persistence on Linux systems through crontab jobs, systemd service/timer units, LD_PRELOAD library injection, shell profile modifications (.bashrc, .profile), SSH authorized_keys backdoors, and init script manipulation. This skill scans for all known persistence vectors, checks file timestamps and integrity, and correlates findings with auditd logs to build a timeline of persistence installation.


## When to Use

- When investigating security incidents that require analyzing persistence mechanisms in linux
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Watch rules not loaded = no events.** auditd is the whole detection here; confirm with `auditctl -l` and that `-w /etc/crontab -p wa`, `-w /etc/ld.so.preload`, and the `~/.ssh/authorized_keys` paths are actually armed. A FIM-only setup will miss in-memory and transient artifacts.
- **Vectors commonly skipped:** per-user crontabs in `/var/spool/cron/crontabs/`, `systemd-run` transient units (never touch disk), user units in `~/.config/systemd/user/`, `at` jobs in `/var/spool/cron/atjobs`, `/etc/update-motd.d/`, udev rules, `~/.config/autostart`, and PAM/`/etc/ld.so.conf.d` modules.
- **Don't trust mtime.** Attackers `touch -r` to backdate files; pivot to inode `ctime` and auditd `SYSCALL`/`PROCTITLE` records for the real write time.
- **LD_PRELOAD evasion:** injection via a per-process env var (not `/etc/ld.so.preload`) leaves no file to scan — catch it in auditd `execve` environment or `/proc/<pid>/environ`.
- **Validate the rule fires:** add `auditctl -w /etc/crontab -p wa -k cron_persist`, append a benign line to `/etc/crontab`, then `ausearch -k cron_persist` — you should see the write with the acting UID.
- **Tune false positives:** package managers legitimately install systemd units and cron jobs. Baseline each finding against the package DB (`dpkg -S <path>` / `rpm -qf <path>`) and alert only on files not owned by any package.

## Prerequisites

- Root or sudo access on target Linux system (or forensic image)
- auditd configured with file watch rules on persistence paths
- Python 3.8+ with standard library (os, subprocess, json)
- Optional: OSSEC/Wazuh agent for file integrity monitoring alerts

## Steps

1. **Scan Crontab Entries** — Enumerate all user crontabs, /etc/cron.d/, /etc/cron.daily/, and anacron jobs for suspicious commands
2. **Audit Systemd Units** — Check /etc/systemd/system/ and ~/.config/systemd/user/ for non-package-managed service and timer units
3. **Detect LD_PRELOAD Hijacking** — Check /etc/ld.so.preload and LD_PRELOAD environment variable for injected shared libraries
4. **Inspect Shell Profiles** — Scan .bashrc, .bash_profile, .profile, /etc/profile.d/ for injected commands or reverse shells
5. **Check SSH Authorized Keys** — Audit all authorized_keys files for unauthorized public keys with command restrictions
6. **Correlate Auditd Logs** — Search auditd logs for file modification events on persistence paths to build an installation timeline
7. **Generate Persistence Report** — Produce a risk-scored report of all discovered persistence mechanisms

## Expected Output

- JSON report of all persistence mechanisms found with risk scores
- Timeline of persistence installation from auditd correlation
- MITRE ATT&CK technique mapping (T1053, T1543, T1574, T1546)
- Remediation commands for each detected persistence mechanism
