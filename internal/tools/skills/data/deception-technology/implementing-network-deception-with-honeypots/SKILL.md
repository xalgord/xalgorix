---
name: implementing-network-deception-with-honeypots
description: Deploy and manage network honeypots using OpenCanary, T-Pot, or Cowrie to detect unauthorized access, lateral
  movement, and attacker reconnaissance.
domain: cybersecurity
subdomain: deception-technology
tags:
- deception
- honeypot
- opencanary
- cowrie
- t-pot
- detection
- lateral-movement
- network-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-06
- PR.IR-01
---

# Implementing Network Deception with Honeypots

## When to Use

- When deploying deception technology to detect lateral movement
- To create early warning indicators for network intrusion
- During security architecture design to add detection depth
- When monitoring for unauthorized internal scanning or credential theft
- To gather threat intelligence on attacker techniques and tools

## Common Misconfigurations & Verification

Honeypots most often provide false comfort because they are deployed in
monitor-only mode, are trivially fingerprintable, or sit where no attacker will
ever reach them:

- **Monitor-only / no alerting:** Cowrie or OpenCanary capture sessions to a
  local log that nobody reads. Confirm log forwarding to the SIEM (syslog/
  webhook) actually delivers and a detection rule fires, not just that the file
  grows.
- **Fingerprintable deployment:** default Cowrie hostname `svr04`, the canonical
  T-Pot banner set, or an SSH server that responds too perfectly tips off
  attackers who then avoid it. Customize banners, hostnames, and filesystem
  contents away from known defaults.
- **Placed off the attack path:** a honeypot on an isolated VLAN with no
  reachable services sees only internet background noise. Place decoys inside
  segments where lateral movement and internal scanning actually occur, with
  realistic SSH/SMB/RDP services exposed.
- **No baseline for noise:** mass scanner traffic drowns real signal; tune out
  known scanner ranges so a credentialed login attempt stands out.
- **How to confirm it works:** from a separate host, run an SSH login against
  Cowrie, an SMB connection and an `nmap` sweep against OpenCanary/T-Pot, and
  verify each interaction produces a forwarded alert with correct source IP,
  service, and credentials captured.

## Prerequisites

- Linux server or VM for honeypot deployment (Ubuntu 22.04+ recommended)
- Python 3.8+ with pip for OpenCanary installation
- Docker for T-Pot or containerized deployment
- Network segment with appropriate VLAN configuration
- SIEM integration for alert forwarding (syslog, webhook, or file-based)
- Firewall rules allowing inbound connections to honeypot services

## Workflow

1. **Plan Deployment**: Select honeypot types and network placement strategy.
2. **Install Honeypot**: Deploy OpenCanary, Cowrie, or T-Pot on dedicated host.
3. **Configure Services**: Enable emulated services (SSH, HTTP, SMB, FTP, RDP).
4. **Set Up Alerting**: Configure log forwarding to SIEM and alert channels.
5. **Deploy Canary Tokens**: Place credential files, shares, and DNS entries.
6. **Monitor Interactions**: Analyze honeypot logs for attacker activity.
7. **Tune and Maintain**: Update configurations based on detection results.

## Key Concepts

| Concept | Description |
|---------|-------------|
| OpenCanary | Lightweight Python honeypot with modular service emulation |
| Cowrie | Medium-interaction SSH/Telnet honeypot capturing commands |
| T-Pot | Multi-honeypot platform with ELK stack visualization |
| Canary Token | Tripwire credential or file that alerts when accessed |
| Low-Interaction | Emulates services at protocol level without full OS |
| High-Interaction | Full OS honeypot capturing complete attacker sessions |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| OpenCanary | Modular honeypot daemon with service emulation |
| Cowrie | SSH/Telnet honeypot with session recording |
| T-Pot | All-in-one multi-honeypot platform |
| Dionaea | Malware-capturing honeypot for exploit detection |
| Splunk/Elastic | SIEM for honeypot alert aggregation |

## Output Format

```
Alert: HONEYPOT-[SERVICE]-[DATE]-[SEQ]
Honeypot: [Hostname/IP]
Service: [SSH/HTTP/SMB/FTP/RDP]
Source IP: [Attacker IP]
Interaction: [Login attempt/Port scan/File access]
Credentials Used: [Username:Password if applicable]
Commands Executed: [For SSH honeypots]
Risk Level: [Critical/High/Medium/Low]
```
