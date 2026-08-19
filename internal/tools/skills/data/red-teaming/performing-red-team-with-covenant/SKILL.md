---
name: performing-red-team-with-covenant
description: Conduct red team operations using the Covenant C2 framework for authorized adversary simulation, including listener
  setup, grunt deployment, task execution, and lateral movement tracking.
domain: cybersecurity
subdomain: red-team
tags:
- red-team
- c2
- covenant
- adversary-simulation
- penetration-testing
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
---
# Performing Red Team Operations with Covenant C2

## Overview

Covenant is a collaborative .NET C2 framework for red teamers that provides a Swagger-documented REST API for managing listeners, launchers, grunts (agents), and tasks. This skill covers automating Covenant operations through its API for authorized red team engagements: creating HTTP/HTTPS listeners, generating binary and PowerShell launchers, deploying grunts, executing tasks on compromised hosts, and tracking lateral movement.


## When to Use

- When conducting security assessments that involve performing red team with covenant
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

- **Launcher/Grunt staging choice matters:** pick the launcher (Binary/PowerShell/MSBuild/InstallUtil) that fits the delivery and the host's defenses — a missing check-in is usually a staging/evasion failure, not a dead C2.
- **OPSEC on the profile:** tune jitter/delay and use a custom HTTP profile (realistic URIs, headers, Host); default Covenant profiles are heavily signatured.
- **Evasion:** expect AMSI/ETW to block in-memory .NET — apply an AMSI bypass/obfuscation and confirm the launcher actually executed.
- **Comms paths:** verify the listener bind/port, egress (proxy-aware HTTP, or an SMB named-pipe Grunt for internal pivots), and that any redirector forwards correctly.
- **Confirm a hit:** an active Grunt appears in the Covenant dashboard with periodic check-ins and a `Task` (e.g. `whoami`) returns output. Don't conclude failure until listener/profile/egress reachability is verified and you've confirmed AV/AMSI did not kill the launcher.

## Prerequisites

- Covenant C2 server deployed (Docker or .NET 6)
- Python 3.9+ with `requests` library
- Covenant API token (obtained via /api/users/login)
- Written authorization for red team engagement
- Isolated lab or authorized target environment

## Steps

### Step 1: Authenticate to Covenant API
Obtain a JWT token by posting credentials to /api/users/login endpoint.

### Step 2: Create Listener
Configure an HTTP or HTTPS listener with callback URLs and bind address.

### Step 3: Generate Launcher
Create a binary, PowerShell, or MSBuild launcher tied to the listener for grunt deployment.

### Step 4: Deploy and Manage Grunts
Monitor grunt callbacks, execute tasks, and collect output from compromised hosts.

### Step 5: Document Operations
Generate an operations report documenting all actions, timestamps, and findings.

## Expected Output

JSON report with listener configuration, active grunts, executed tasks, and task output for engagement documentation.
