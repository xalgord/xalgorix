---
name: performing-ssl-tls-security-assessment
description: Assess SSL/TLS server configurations using the sslyze Python library to evaluate cipher suites, certificate chains,
  protocol versions, HSTS headers, and known vulnerabilities like Heartbleed and ROBOT.
domain: cybersecurity
subdomain: network-security
tags:
- network-security
- ssl
- tls
- sslyze
- certificate
- cipher-suites
- vulnerability-assessment
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---
# Performing SSL/TLS Security Assessment

## Overview

Assess SSL/TLS server configurations using sslyze, a fast Python-based scanning library. This skill covers evaluating supported protocol versions (SSLv2/3, TLS 1.0-1.3), cipher suite strength, certificate chain validation, HSTS enforcement, OCSP stapling, and scanning for known vulnerabilities including Heartbleed, ROBOT, and session renegotiation weaknesses.


## When to Use

- When conducting security assessments that involve performing ssl tls security assessment
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

- **SNI and vhosts:** scanning the IP without `-servername`/SNI returns the default vhost's cert and ciphers, not the target's. Always set SNI (`openssl s_client -connect host:443 -servername host`; sslyze uses the hostname) or you assess the wrong service.
- **Beyond 443:** STARTTLS services (SMTP 25/587, IMAP 143, POP3 110, LDAP 389, FTPS, MySQL, PostgreSQL) need explicit STARTTLS probing — `testssl.sh --starttls smtp host:587`. A 443-only scan misses them entirely.
- **Full protocol/cipher matrix:** don't stop at "TLS 1.2 supported" — enumerate SSLv2/SSLv3/TLS1.0/1.1 still enabled, weak ciphers (RC4, 3DES, EXPORT, NULL, CBC), and cipher order/forward secrecy. One accepted legacy protocol is the finding.
- **Cert chain and trust:** check the *full* chain order, intermediate completeness, expiry, SAN coverage, and signature algorithm. A leaf that validates in a browser may still ship an incomplete chain that breaks non-browser clients.
- **Vuln checks need the precondition:** Heartbleed needs the heartbeat extension; ROBOT needs RSA key exchange. Flag only after the specific check confirms it, never from version alone.
- **How to confirm a hit:** corroborate sslyze with `testssl.sh` and a manual `openssl s_client -cipher 'RC4' -tls1` handshake that actually completes — a completed handshake on a weak protocol/cipher is the proof; a lone scanner line is a candidate.
- **Don't conclude "secure"** until you've tested every TLS-bearing port, set SNI, and checked STARTTLS plus the legacy-protocol matrix.

## Prerequisites

- Python 3.9+ with `sslyze` library (pip install sslyze)
- Network access to target HTTPS servers on port 443
- Understanding of TLS protocol versions and cipher suite classifications

## Steps

### Step 1: Configure Server Scan
Create ServerScanRequest with ServerNetworkLocation specifying target hostname and port.

### Step 2: Execute TLS Scan
Use sslyze Scanner to queue and execute scans for all TLS check commands concurrently.

### Step 3: Analyze Results
Evaluate accepted cipher suites, certificate validity, protocol versions, and vulnerability scan results.

### Step 4: Generate Security Report
Produce a JSON report with compliance findings and remediation recommendations.

## Expected Output

JSON report with supported protocols, accepted cipher suites, certificate details, vulnerability results (Heartbleed, ROBOT), and HSTS status.
