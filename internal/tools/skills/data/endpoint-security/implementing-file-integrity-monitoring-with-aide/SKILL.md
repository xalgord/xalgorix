---
name: implementing-file-integrity-monitoring-with-aide
description: Configure AIDE (Advanced Intrusion Detection Environment) for file integrity monitoring including baseline creation,
  scheduled integrity checks, change detection, and alerting
domain: cybersecurity
subdomain: endpoint-security
tags:
- aide
- file-integrity
- hids
- baseline
- intrusion-detection
- compliance
- linux-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
---

# Implementing File Integrity Monitoring with AIDE

## Overview

AIDE (Advanced Intrusion Detection Environment) is a host-based intrusion detection system that monitors file and directory integrity using cryptographic checksums. This skill covers generating AIDE configuration files, initializing baseline databases, running integrity checks, parsing change reports, and setting up automated cron-based monitoring with alerting.


## When to Use

- When deploying or configuring implementing file integrity monitoring with aide capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **Baseline DB stored on the host:** if `aide.db.gz` lives at its default `/var/lib/aide/aide.db.gz` on the monitored system, an attacker with root simply re-runs `aide --init` and copies `aide.db.new.gz` over it, erasing evidence. Store the baseline (and `aide.conf`) read-only off-host or on signed/immutable media, and compare against that copy.
- **DB never updated after legit changes:** after patching, admins run `aide --update` and blindly promote `aide.db.new.gz` to the baseline, masking any malicious change made in the same window. Diff the report before promoting, and update the DB out-of-band.
- **Weak rule selection:** lines using `p+i` only (perms/inode) miss content tampering. Confirm critical paths use a hashing ruleset (e.g., `Checksums = sha256+sha512`) and that `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/boot` are actually in scope and not shadowed by a later `!exclude`.
- **Check not scheduled / output unread:** a cron job that writes to a local file no one reads is not monitoring. Verify the cron entry exists and routes results to a SIEM or mailbox.
- **Verification:** touch a canary change (`chmod o+w /etc/passwd` or add a file under `/usr/bin`), run `aide --check`, and confirm it reports the added/changed entry with a checksum mismatch; then revert. A clean report after a known change means the rules or DB path are wrong.

## Prerequisites

- AIDE installed on target Linux system (apt install aide / yum install aide)
- Root or sudo access for file system scanning
- Python 3.8+ with standard library

## Steps

1. **Generate AIDE Configuration** — Create aide.conf with monitoring rules for critical directories (/etc, /bin, /sbin, /usr/bin, /boot)
2. **Initialize Baseline Database** — Run aide --init to create the initial file integrity baseline
3. **Run Integrity Check** — Execute aide --check to compare current state against baseline
4. **Parse Change Report** — Extract added, removed, and changed files from AIDE output
5. **Configure Automated Monitoring** — Generate cron job for scheduled integrity checks
6. **Generate Compliance Report** — Produce structured report of all file changes with severity classification

## Expected Output

- AIDE configuration file (aide.conf)
- Baseline database creation status
- JSON report of file changes (added/removed/changed) with severity
- Cron job configuration for automated monitoring
