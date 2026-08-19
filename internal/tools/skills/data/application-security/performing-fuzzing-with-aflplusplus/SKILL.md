---
name: performing-fuzzing-with-aflplusplus
description: 'Perform coverage-guided fuzzing of compiled binaries using AFL++ (American Fuzzy Lop Plus Plus) to discover
  memory corruption, crashes, and security vulnerabilities. The tester instruments target binaries with afl-cc/afl-clang-fast,
  manages input corpora with afl-cmin and afl-tmin, runs parallel fuzzing campaigns with afl-fuzz, and triages crashes using
  CASR or GDB scripts. Activates for requests involving binary fuzzing, crash discovery, coverage-guided testing, or AFL++
  fuzzing campaigns.

  '
domain: cybersecurity
subdomain: application-security
tags:
- fuzzing
- aflplusplus
- coverage-guided
- crash-triage
- binary-analysis
- security-testing
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
- PR.PS-01
- PR.PS-04
- ID.RA-01
- PR.DS-10
---
# Performing Fuzzing with AFL++

## Overview

AFL++ is a community-maintained fork of American Fuzzy Lop (AFL) that provides coverage-guided
fuzzing for compiled binaries. It instruments targets at compile time or via QEMU/Unicorn mode
for binary-only fuzzing, then mutates input corpora to discover new code paths. AFL++ includes
advanced scheduling (MOpt, rare), custom mutators, CMPLOG for input-to-state comparison solving,
and persistent mode for high-throughput fuzzing.


## When to Use

- When conducting security assessments that involve performing fuzzing with aflplusplus
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Common Misconfigurations & Verification

A campaign that runs for hours with zero crashes is usually a setup problem, not a secure target.

- **No sanitizer, so bugs go silent:** instrument with `AFL_USE_ASAN=1 afl-cc` (or `afl-clang-fast`). Without ASAN/UBSAN a heap overflow corrupts memory without crashing and AFL++ never flags it.
- **Empty or trivial seed corpus:** starting `-i` with one tiny file leaves the fuzzer unable to reach parser logic. Provide diverse valid inputs, then prune with `afl-cmin`, and shrink each with `afl-tmin`.
- **No dictionary for structured formats:** without `-x dict/` (magic bytes, keywords, tokens) AFL++ wastes cycles guessing format headers. Supply a format dictionary.
- **Single-core run wastes the box:** use `-M main` + several `-S sec1 sec2 ...` secondaries to fuzz in parallel and share finds via the sync dir.
- **Coverage stall ignored:** `map density` flat and `pending` near zero for hours means saturation — add CMPLOG (`-c`), MOpt, or new seeds rather than letting it spin.

**Verify the harness can actually find bugs:** compile a build with a planted bug (e.g. an unchecked `strcpy` on input) and confirm AFL++ surfaces it in `crashes/` within minutes and that `afl-tmin` + CASR/GDB reproduce it. If the planted bug is never found, fix instrumentation/seeds before trusting a clean run.

## Prerequisites

- AFL++ installed (`apt install afl++` or build from source)
- Target binary source code (for compile-time instrumentation) or QEMU mode for binary-only
- Initial seed corpus of valid inputs for the target format
- Linux system with /proc/sys/kernel/core_pattern configured

## Steps

1. Instrument the target binary with `afl-cc` or `afl-clang-fast`
2. Prepare seed corpus directory with minimal valid inputs
3. Minimize corpus with `afl-cmin` to remove redundant seeds
4. Run `afl-fuzz` with appropriate flags (-i input -o output)
5. Monitor fuzzing progress via afl-whatsup and UI stats
6. Triage crashes with `afl-tmin` minimization and CASR/GDB analysis
7. Report unique crashes with reproduction steps

## Expected Output

```
+++ Findings +++
  unique crashes: 12
  unique hangs: 3
  last crash: 00:02:15 ago
+++ Coverage +++
  map density: 4.23% / 8.41%
  paths found: 1847
  exec speed: 2145/sec
```
