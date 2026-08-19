---
name: extracting-memory-artifacts-with-rekall
description: 'Uses Rekall memory forensics framework to analyze memory dumps for process hollowing, injected code via VAD
  anomalies, hidden processes, and rootkit detection. Applies plugins like pslist, psscan, vadinfo, malfind, and dlllist to
  extract forensic artifacts from Windows memory images. Use during incident response memory analysis.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- extracting
- memory
- artifacts
- with
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Extracting Memory Artifacts with Rekall


## When to Use

- When performing authorized security testing that involves extracting memory artifacts with rekall
- When analyzing malware samples or attack artifacts in a controlled environment
- When conducting red team exercises or penetration testing engagements
- When building detection capabilities based on offensive technique understanding

## Detection Gaps & Validation

- **Profile mismatch returns empty output, not "clean":** Rekall's `autodetect=["rsds"]` and remote profile fetch fail closed — a wrong/missing profile makes `pslist`, `malfind`, and `netscan` yield nothing. Note that Rekall is archived/unmaintained and struggles with recent Windows 10/11 builds; if results look empty, suspect profile/version, not absence of compromise, and cross-check with Volatility 3.
- **Acquisition smear and page-file gaps:** a live dump captured on a busy host can tear `EPROCESS` lists so `pslist` (active-list walk) drops processes; injected pages may be paged out and absent from the raw image. Diff `pslist` against `psscan` (pool scan) to surface unlinked/hidden PIDs, and document the acquisition method.
- **`malfind` misses fileless/reflective loads with normal protections:** process hollowing that restores legitimate `PAGE_EXECUTE_READ` and matching VAD names evades the RWX/private-memory heuristic. Corroborate with `vadinfo` mismatches (mapped image vs. on-disk), `ldrmodules` for unlinked DLLs, and `dlllist` vs. `ldrmodules` gaps.
- **Rootkit hooks need explicit checks:** hidden network sockets and SSDT/IRP hooks won't show in `netscan`/`pslist` alone — run the hook/callback plugins too.
- **Validate the workflow fires:** in a lab, inject shellcode (e.g., a benign hollowed notepad) and confirm `malfind` flags the RWX VAD and the `psscan-pslist` diff reveals a hidden test PID before trusting findings on real evidence.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Use Rekall to analyze memory dumps for signs of compromise including process
injection, hidden processes, and suspicious network connections.

```python
from rekall import session
from rekall import plugins

# Create a Rekall session with a memory image
s = session.Session(
    filename="/path/to/memory.raw",
    autodetect=["rsds"],
    profile_path=["https://github.com/google/rekall-profiles/raw/master"]
)

# List processes
for proc in s.plugins.pslist():
    print(proc)

# Detect injected code
for result in s.plugins.malfind():
    print(result)
```

Key analysis steps:
1. Load memory image and auto-detect profile
2. Run pslist and psscan to find hidden processes
3. Use malfind to detect injected/hollowed code in process VADs
4. Examine network connections with netscan
5. Extract suspicious DLLs and drivers with dlllist/modules

## Examples

```python
from rekall import session
s = session.Session(filename="memory.raw")
# Compare pslist vs psscan for hidden processes
pslist_pids = set(p.pid for p in s.plugins.pslist())
psscan_pids = set(p.pid for p in s.plugins.psscan())
hidden = psscan_pids - pslist_pids
print(f"Hidden PIDs: {hidden}")
```
