---
name: detecting-dll-sideloading-attacks
description: Detect DLL side-loading attacks where adversaries place malicious DLLs alongside legitimate applications to hijack
  execution flow for defense evasion.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- dll-sideloading
- defense-evasion
- t1574
- edr
- proactive-detection
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
- Platform Hardening
- File Format Verification
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Detecting DLL Sideloading Attacks

## When to Use

- When investigating potential DLL hijacking in enterprise environments
- After EDR alerts on unsigned DLLs loaded by signed applications
- When hunting for APT persistence using legitimate application wrappers
- During incident response to identify trojanized applications
- When threat intel indicates DLL sideloading campaigns targeting specific software

## Detection Gaps & Validation

- **EID 7 is often filtered off.** Sysmon Image Load logging is high-volume and many configs (even SwiftOnSecurity) exclude common signers or whole processes. Confirm ImageLoaded is enabled and your target host process is not in an exclude rule, or you'll never see the sideload.
- **"Signed" is not "trusted."** Attackers sign DLLs or abuse signed-then-appended code, so `SignatureStatus=Valid` alone is meaningless. Check that the signer is the expected vendor and compare the cert thumbprint and module hash to a known-good baseline.
- **Path is the real signal:** alert on EID 7 where the loaded DLL path is outside the app's install directory, especially user-writable dirs (`%APPDATA%`, `%TEMP%`, `C:\ProgramData`, `C:\Users\Public`), and on the legit EXE itself running from those locations (decoy wrapper).
- **Known LOLBAS targets:** OneDriveStandaloneUpdater.exe, dllhost.exe, and WinSxS binaries are frequent sideload hosts — diff their loaded-module set against a clean baseline.
- **Phantom DLLs** (app searches for a non-existent DLL) won't show a known-bad hash — hunt the search-order miss + a new file appearing on the search path.
- **Validate the rule fires:** copy a signed binary plus a benign unsigned DLL named after one of its real dependencies into `%TEMP%`, run it, and confirm EID 7 logs the unsigned DLL loading from the temp path.
- **Tune false positives:** browsers and Electron apps legitimately load unsigned modules from AppData. Baseline each app's expected module set and alert only on new/unexpected module hashes.

## Prerequisites

- EDR with DLL load monitoring (CrowdStrike, MDE, SentinelOne)
- Sysmon Event ID 7 (Image Loaded) with hash verification
- Application whitelisting or DLL integrity monitoring
- Software inventory of legitimate applications and expected DLL paths
- Code signing verification capabilities

## Workflow

1. **Identify Sideloading Targets**: Research known vulnerable applications that load DLLs without full path qualification (LOLBAS, DLL-sideload databases).
2. **Monitor DLL Load Events**: Query Sysmon Event ID 7 for DLL loads where the DLL path differs from the application's expected directory.
3. **Check DLL Signatures**: Flag unsigned or untrusted DLLs loaded by signed executables.
4. **Detect Path Anomalies**: Identify legitimate executables running from unusual locations (Temp, AppData, Public) that may be decoy wrappers.
5. **Hash Verification**: Compare loaded DLL hashes against known-good versions and threat intel feeds.
6. **Correlate with Process Behavior**: Check if the host process exhibits unusual behavior (network connections, child processes) after loading the suspicious DLL.
7. **Document and Remediate**: Report sideloading instances, quarantine malicious DLLs, and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1574.002 | DLL Side-Loading |
| T1574.001 | DLL Search Order Hijacking |
| T1574.006 | Dynamic Linker Hijacking |
| T1574.008 | Path Interception by Search Order Hijacking |
| DLL Search Order | Windows DLL loading priority path |
| Side-Loading | Placing malicious DLL where legitimate app loads it |
| Phantom DLL | DLL that legitimate apps try to load but does not exist |
| DLL Proxying | Malicious DLL forwarding calls to legitimate DLL |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Event ID 7 DLL load monitoring |
| CrowdStrike Falcon | DLL load detection with process context |
| Microsoft Defender for Endpoint | DLL load anomaly detection |
| Process Monitor | Real-time DLL load tracing |
| DLL Export Viewer | Verify DLL export functions |
| Sigcheck | Digital signature verification |
| pe-sieve | PE analysis for proxied DLLs |

## Common Scenarios

1. **Legitimate App Wrapper**: Adversary copies signed application (e.g., OneDrive updater) to temp folder alongside malicious DLL with same name as expected dependency.
2. **Phantom DLL Exploitation**: Malicious DLL placed in PATH location where legitimate app searches for non-existent DLL.
3. **DLL Proxy Loading**: Malicious version.dll proxies all exports to real version.dll while executing malicious code on DllMain.
4. **Software Update Hijack**: Attacker replaces DLL in update staging directory before legitimate updater loads it.

## Output Format

```
Hunt ID: TH-SIDELOAD-[DATE]-[SEQ]
Technique: T1574.002
Host Application: [Legitimate signed executable]
Sideloaded DLL: [Malicious DLL name and path]
Expected DLL Path: [Where DLL should legitimately be]
DLL Signed: [Yes/No]
App Location: [Expected/Anomalous]
Host: [Hostname]
Risk Level: [Critical/High/Medium/Low]
```
