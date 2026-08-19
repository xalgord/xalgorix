---
name: performing-thick-client-application-penetration-test
description: Conduct a thick client application penetration test to identify insecure local storage, hardcoded credentials,
  DLL hijacking, memory manipulation, and insecure API communication in desktop applications using dnSpy, Procmon, and Burp
  Suite.
domain: cybersecurity
subdomain: penetration-testing
tags:
- thick-client
- desktop-application
- dnSpy
- Procmon
- DLL-hijacking
- binary-analysis
- API-interception
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
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
---

# Performing Thick Client Application Penetration Test

## Overview

Thick client (fat client) penetration testing assesses the security of desktop applications that run locally on user machines and communicate with backend servers. Unlike web applications, thick clients present a broader attack surface including local file storage, binary analysis, memory manipulation, DLL injection, process interception, and client-server communication. Common targets include banking applications, ERP clients (SAP GUI), trading platforms, healthcare systems, and legacy enterprise software.


## When to Use

- When conducting security assessments that involve performing thick client application penetration test
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

- **Local storage of secrets** — config files, registry (`HKCU\Software\...`), local SQLite/SQL Express DBs, Windows Credential Manager, and `%APPDATA%` files routinely hold cleartext passwords, connection strings, and tokens. Procmon shows exactly where the app writes.
- **Decompile and read the binary, don't just run it** — .NET via dnSpy / Java via JD-GUI / native via Ghidra exposes hardcoded creds, weak crypto (DES/MD5/base64-as-"encryption"), embedded API keys, and disabled cert validation. This is the step most often skipped.
- **DLL hijacking / sideloading** — Procmon filtered on `NAME NOT FOUND` + `.dll` in writable paths reveals load-order hijacks; a planted DLL = code execution and a real privesc/persistence finding.
- **Intercepting non-HTTP and pinned traffic** — Burp catches HTTP, but raw TCP/UDP needs Echo Mirage/Frida, and cert pinning must be bypassed (patch in dnSpy or Frida hook) before declaring the channel secure.
- **Memory and client-side trust** — dump process memory for plaintext secrets/session tokens, and test client-side authorization/license checks that can be patched (set-next-statement, Cheat Engine) since the server may trust the client.
- **Backend API auth** — the thick client often calls APIs with no server-side authz; test IDOR/BFLA/mass-assignment against captured API calls.
- **How to confirm**: prove findings with artifacts — the decompiled method showing the hardcoded credential, a Procmon trace of the secret written to disk, a SQLite dump with cleartext passwords, a planted-DLL executing your payload, or a memory string showing the token. Don't conclude the app is secure until you've decompiled it and traced where it stores data; don't conclude the channel is protected until you've defeated pinning and intercepted non-HTTP traffic.

## Prerequisites

- Application installer and valid credentials
- Windows/Linux test machine (isolated)
- Tools: dnSpy, Procmon, Process Hacker, Wireshark, Burp Suite, Echo Mirage, Fiddler, IDA Pro/Ghidra
- Administrative access to test machine


> **Legal Notice:** This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Phase 1 — Information Gathering

### Static Analysis

```powershell
# Identify application technology
# Check file properties, signatures, framework (.NET, Java, C++, Electron)
file application.exe
# .NET -> dnSpy, JetBrains dotPeek
# Java -> JD-GUI, JADX
# C/C++ -> Ghidra, IDA Pro
# Electron -> extract asar archive

# Check for .NET framework
Get-ChildItem -Path "C:\Program Files\TargetApp" -Recurse -Filter "*.dll" |
  ForEach-Object { [System.Reflection.AssemblyName]::GetAssemblyName($_.FullName).FullName }

# Strings analysis
strings application.exe | findstr -i "password\|secret\|api\|key\|token\|jdbc\|connection"

# Check for hardcoded credentials
strings application.exe | findstr -i "username\|user=\|pass=\|pwd=\|admin"

# Review configuration files
type "C:\Program Files\TargetApp\app.config"
type "C:\Program Files\TargetApp\settings.xml"
type "%APPDATA%\TargetApp\config.json"

# Check for certificate pinning
strings application.exe | findstr -i "cert\|pin\|ssl\|tls"
```

### .NET Decompilation with dnSpy

```
# Open application in dnSpy
1. Launch dnSpy
2. File > Open > Select application.exe and DLLs
3. Search for:
   - "password", "secret", "connectionString"
   - Authentication methods
   - Encryption/decryption functions
   - API endpoints and keys
   - License validation logic

# Look for:
- Hardcoded credentials in source
- Insecure encryption (DES, MD5, base64 "encryption")
- SQL queries (potential injection)
- Disabled certificate validation
- Debug/verbose logging with sensitive data
```

## Phase 2 — Dynamic Analysis

### Process Monitoring

```powershell
# Monitor file system activity with Procmon
# Filters:
#   Process Name = application.exe
#   Operation = CreateFile, WriteFile, ReadFile, RegSetValue

# Key observations:
# - Where does the app store data? (AppData, temp, registry)
# - Does it write credentials to disk?
# - Does it create temporary files with sensitive data?
# - What registry keys does it access?

# Monitor with Process Hacker
# Check: loaded DLLs, network connections, handles, tokens

# Monitor network traffic
# Wireshark filter: ip.addr == <server_ip>
# Check for: unencrypted credentials, API keys, tokens
```

### Traffic Interception

```bash
# Intercept HTTP/HTTPS traffic with Burp Suite
# Configure system proxy: 127.0.0.1:8080
# Install Burp CA certificate in Windows certificate store

# For non-HTTP protocols, use Echo Mirage
# Inject into process and intercept TCP/UDP traffic

# For HTTPS with certificate pinning:
# Method 1: Patch certificate validation in dnSpy
# Method 2: Use Frida to hook SSL validation
frida -l bypass_ssl_pinning.js -f application.exe

# Fiddler for .NET applications
# Enable HTTPS decryption
# Monitor API calls, request/response bodies
```

## Phase 3 — Vulnerability Testing

### Authentication Bypass

```
# Test local authentication bypass
1. Open dnSpy, find authentication method
2. Set breakpoint on credential validation
3. Modify return value to bypass (Debug > Set Next Statement)
4. Or: Patch binary to always return true

# Test for credential storage
# Check: registry, config files, SQLite databases, Windows Credential Manager
reg query "HKCU\Software\TargetApp" /s
type "%APPDATA%\TargetApp\user.db"
# SQLite: sqlite3 user.db ".dump"
```

### DLL Hijacking

```powershell
# Identify DLL search order vulnerability
# Use Procmon to find DLLs loaded from writable paths
# Filter: Result = NAME NOT FOUND, Path ends with .dll

# Create malicious DLL
# msfvenom -p windows/exec CMD=calc.exe -f dll -o hijacked.dll
# Place in application directory or writable PATH directory

# DLL sideloading
# If app loads DLL without full path:
# 1. Create DLL with same exports
# 2. Place in app directory
# 3. DLL loads before legitimate version
```

### Memory Analysis

```powershell
# Dump process memory
# Use Process Hacker > Process > Properties > Memory
# Search for plaintext credentials, tokens, session IDs

# Strings from memory dump
strings process_dump.dmp | findstr -i "password\|token\|session\|bearer"

# Modify memory values (license bypass, privilege escalation)
# Use Cheat Engine or x64dbg to:
# 1. Find memory address of authorization variable
# 2. Modify value (e.g., isAdmin = 0 -> isAdmin = 1)
```

### Input Validation

```
# SQL Injection in local database
# Test input fields with: ' OR 1=1--
# If app uses local SQLite/SQL Server Express

# Command injection
# Test fields that interact with OS:
# File paths: ..\..\..\..\windows\system32\cmd.exe
# Print/export: | calc.exe

# Buffer overflow
# Send oversized input to text fields
# Monitor with x64dbg for crashes
# Check for SEH-based or stack-based overflows
```

## Phase 4 — API Security Testing

```bash
# Capture API calls from thick client
# In Burp Suite, analyze:

# IDOR (Insecure Direct Object Reference)
# Change user IDs in requests to access other users' data
# GET /api/users/1001 -> GET /api/users/1002

# Authorization bypass
# Remove or modify JWT tokens
# Test role escalation: change role claim from "user" to "admin"

# Mass assignment
# Add additional parameters to API requests
# POST /api/profile {"name": "test", "isAdmin": true}

# Rate limiting
# Test for brute-force protection on login API
# Test for account lockout bypass
```

## Findings Template

| Finding | Severity | CVSS | Remediation |
|---------|----------|------|-------------|
| Hardcoded database credentials in binary | Critical | 9.1 | Use secure credential storage (DPAPI, vault) |
| DLL hijacking via writable app directory | High | 7.8 | Use full DLL paths, validate DLL signatures |
| Plaintext credentials in memory | High | 7.5 | Zero memory after use, use SecureString |
| No certificate pinning | Medium | 6.5 | Implement certificate pinning |
| Local SQLite DB with cleartext passwords | Critical | 9.0 | Use bcrypt/Argon2 hashing |
| Disabled SSL validation in code | High | 8.1 | Enable proper certificate validation |

## References

- dnSpy: https://github.com/dnSpy/dnSpy
- Procmon: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- OWASP Thick Client Testing Guide: https://owasp.org/www-project-thick-client-top-10/
- Ghidra: https://ghidra-sre.org/
- Echo Mirage: https://sourceforge.net/projects/echomirage/
