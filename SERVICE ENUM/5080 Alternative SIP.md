# Port 5080 - Alternative SIP / VoIP / Web Services

## Overview

Port 5080 wird von nmap oft als "onscreen" identifiziert, aber das ist meist eine **Fehlidentifikation**.

**Häufigste Services:**
- FreeSWITCH / SIP (Alternative SIP Port)
- Web Management Interfaces (HTTP/HTTPS)
- Cisco / VoIP Management
- AirWatch / Workspace ONE
- OnScreen Data Service (selten)

---

## 🎯 Was Port 5080 WIRKLICH sein kann

### 1. FreeSWITCH / SIP (Häufigste Option!)

Wenn Port 5060 (Standard SIP) auch offen ist, ist 5080 sehr wahrscheinlich **SIP-related**!

**FreeSWITCH** ist eine open-source Telefonie-Platform die oft Port 5080 nutzt.

#### Nmap SIP Enumeration
```bash
# SIP Methods
nmap -p 5080 --script sip-methods TARGET_IP
nmap -p 5080 --script sip-enum-users TARGET_IP

# Detaillierte Service Detection
nmap -p 5080 -sV -sC --version-intensity 9 TARGET_IP

# UDP SIP (wichtig!)
nmap -p 5080 -sU --script sip-methods,sip-enum-users TARGET_IP
```

#### SIPVicious Suite
```bash
# Server Check
svmap TARGET_IP:5080

# Extension Enumeration
svwar -m INVITE -e 100-999 TARGET_IP -p 5080
svwar -m REGISTER -e 1000-1999 TARGET_IP -p 5080

# Password Cracking (mit gefundenen Extensions)
svcrack -u 100 -d /usr/share/wordlists/rockyou.txt TARGET_IP -p 5080
svcrack -u 1000 -d passwords.txt TARGET_IP -p 5080
```

#### Manual SIP Testing
```bash
# SIP OPTIONS Request (TCP)
nc TARGET_IP 5080
# Dann eingeben:
OPTIONS sip:TARGET_IP:5080 SIP/2.0
Via: SIP/2.0/TCP YOUR_IP:5060
From: <sip:test@TARGET_IP>
To: <sip:test@TARGET_IP>
Call-ID: test123
CSeq: 1 OPTIONS
Content-Length: 0

[ENTER][ENTER]

# UDP Version
nc -u TARGET_IP 5080
# Dann gleiche OPTIONS Request
```

#### FreeSWITCH HTTP Endpoints
```bash
# Typische FreeSWITCH Web Endpoints
curl http://TARGET_IP:5080/
curl http://TARGET_IP:5080/api
curl http://TARGET_IP:5080/portal
curl http://TARGET_IP:5080/verto
curl http://TARGET_IP:5080/ws
curl http://TARGET_IP:5080/jsonrpc

# HTTPS testen
curl -k https://TARGET_IP:5080/
```

#### FreeSWITCH Default Credentials
```bash
# Web Interface
admin:admin
freeswitch:freeswitch
user:user

# SIP Extensions (häufig)
1000:1234
1001:1234
100:100
```

#### FreeSWITCH Known Vulnerabilities
```bash
# CVE-2021-41105 - Command Injection
searchsploit freeswitch

# Metasploit
msfconsole
msf6 > search freeswitch
msf6 > use exploit/linux/misc/freeswitch_event_socket_cmd_exec
```

---

### 2. Web Interface (HTTP/HTTPS)

Port 5080 wird oft als **alternativer HTTP/HTTPS Port** verwendet.

#### Basic HTTP/HTTPS Testing
```bash
# HTTP
curl http://TARGET_IP:5080
curl -I http://TARGET_IP:5080
curl -v http://TARGET_IP:5080

# HTTPS
curl -k https://TARGET_IP:5080
curl -k -I https://TARGET_IP:5080
curl -kv https://TARGET_IP:5080

# Mit verschiedenen User-Agents
curl -A "Mozilla/5.0" http://TARGET_IP:5080
curl -A "Chrome/90.0" http://TARGET_IP:5080
```

#### Web Technology Detection
```bash
# Whatweb
whatweb http://TARGET_IP:5080
whatweb https://TARGET_IP:5080

# Wappalyzer (CLI)
wappalyzer http://TARGET_IP:5080

# Nikto
nikto -h http://TARGET_IP:5080
nikto -h https://TARGET_IP:5080 -ssl
```

#### Directory Brute Force
```bash
# Gobuster
gobuster dir -u http://TARGET_IP:5080 -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u https://TARGET_IP:5080 -w /usr/share/wordlists/dirb/common.txt -k

# Dirbuster wordlist
gobuster dir -u http://TARGET_IP:5080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Feroxbuster (schneller)
feroxbuster -u http://TARGET_IP:5080 -w /usr/share/wordlists/dirb/common.txt

# ffuf
ffuf -u http://TARGET_IP:5080/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

#### Common Web Paths to Check
```bash
# Admin Panels
curl http://TARGET_IP:5080/admin
curl http://TARGET_IP:5080/administrator
curl http://TARGET_IP:5080/login
curl http://TARGET_IP:5080/console
curl http://TARGET_IP:5080/portal
curl http://TARGET_IP:5080/manager

# API Endpoints
curl http://TARGET_IP:5080/api
curl http://TARGET_IP:5080/api/v1
curl http://TARGET_IP:5080/rest
curl http://TARGET_IP:5080/graphql

# Monitoring/Management
curl http://TARGET_IP:5080/status
curl http://TARGET_IP:5080/health
curl http://TARGET_IP:5080/metrics
curl http://TARGET_IP:5080/actuator
```

#### SSL/TLS Analysis (if HTTPS)
```bash
# SSL Certificate Info
openssl s_client -connect TARGET_IP:5080 2>/dev/null | openssl x509 -noout -text

# SSL Scan
sslscan TARGET_IP:5080

# Testssl.sh
testssl.sh TARGET_IP:5080
```

---

### 3. Cisco / VoIP Management Interface

Oft Teil von Cisco Unified Communications Manager (CUCM) oder andere VoIP Systeme.

#### Cisco Specific Paths
```bash
# Cisco UCM Admin
curl http://TARGET_IP:5080/ccmadmin
curl http://TARGET_IP:5080/ccmuser
curl http://TARGET_IP:5080/ccmcip

# Cisco EM (Extension Mobility)
curl http://TARGET_IP:5080/em
curl http://TARGET_IP:5080/emapp/EMAppServlet

# Cisco Self-Service Portal
curl http://TARGET_IP:5080/ucmuser
curl http://TARGET_IP:5080/selfservice

# HTTPS Variants
curl -k https://TARGET_IP:5080/ccmadmin
curl -k https://TARGET_IP:5080/ccmuser
```

#### Cisco Default Credentials
```bash
# Common Cisco Defaults
admin:admin
administrator:cisco
CCMAdministrator:cisco
CCMAdministrator:password
```

#### Cisco Enumeration
```bash
# Version Detection
curl http://TARGET_IP:5080/ccmadmin/versioninfo.do
curl -k https://TARGET_IP:5080/ccmadmin/versioninfo.do

# Login Page
curl http://TARGET_IP:5080/ccmadmin/showHome.do
```

---

### 4. AirWatch / Workspace ONE (VMware)

AirWatch/Workspace ONE nutzt manchmal Port 5080 für Management.

#### AirWatch Paths
```bash
# AirWatch Console
curl http://TARGET_IP:5080/AirWatch
curl http://TARGET_IP:5080/AirWatch/Login
curl http://TARGET_IP:5080/workspace

# API Endpoints
curl http://TARGET_IP:5080/api
curl http://TARGET_IP:5080/api/help

# Admin Console
curl http://TARGET_IP:5080/admin
curl http://TARGET_IP:5080/console
```

#### AirWatch Default Credentials
```bash
# Common Defaults
admin:admin
administrator:password
airwatch:airwatch
```

---

### 5. OnScreen Data Service (Selten!)

Die eigentliche "OnScreen" Software (daher die nmap Fehlidentifikation).

#### Banner Grabbing
```bash
# TCP Banner
nc TARGET_IP 5080

# Telnet
telnet TARGET_IP 5080

# Automated Banner Grab
echo "" | nc -w 3 TARGET_IP 5080

# Mit Timeout
timeout 3 nc TARGET_IP 5080
```

#### Protocol Testing
```bash
# Test verschiedene Protocols
echo "HELP" | nc TARGET_IP 5080
echo "?" | nc TARGET_IP 5080
echo "VERSION" | nc TARGET_IP 5080
echo "STATUS" | nc TARGET_IP 5080
```

---

## 🔍 Systematische Enumeration

### Step 1: Service Identification

```bash
# Nmap Detailliert
nmap -p 5080 -sV -sC --version-intensity 9 TARGET_IP

# TCP + UDP gleichzeitig
nmap -p 5080 -sV -sU -sT TARGET_IP

# Alle Scripts
nmap -p 5080 --script="*5080*" TARGET_IP
nmap -p 5080 --script="sip-*" TARGET_IP
```

### Step 2: Banner Grabbing

```bash
# HTTP Banner
echo -e "GET / HTTP/1.1\r\nHost: TARGET_IP\r\n\r\n" | nc TARGET_IP 5080

# HTTP mit verschiedenen Methods
echo -e "OPTIONS / HTTP/1.1\r\nHost: TARGET_IP\r\n\r\n" | nc TARGET_IP 5080
echo -e "HEAD / HTTP/1.1\r\nHost: TARGET_IP\r\n\r\n" | nc TARGET_IP 5080

# SIP Banner
echo -e "OPTIONS sip:TARGET_IP:5080 SIP/2.0\r\nVia: SIP/2.0/TCP YOUR_IP:5060\r\n\r\n" | nc TARGET_IP 5080

# Raw Connection
timeout 3 nc -v TARGET_IP 5080 < /dev/null
```

### Step 3: Protocol Detection

```bash
# HTTP Test
curl -I http://TARGET_IP:5080 2>&1 | head -10

# HTTPS Test
curl -k -I https://TARGET_IP:5080 2>&1 | head -10

# SIP Test
nmap -p 5080 --script sip-methods TARGET_IP
```

### Step 4: UDP Testing (wichtig für SIP!)

```bash
# UDP Port Check
nmap -p 5080 -sU TARGET_IP

# UDP SIP
nmap -p 5080 -sU --script sip-methods TARGET_IP

# UDP Banner
echo "" | nc -u -w 3 TARGET_IP 5080

# SIP auf UDP
svmap -p 5080 TARGET_IP
```

---

## 🎯 Komplettes Enumeration Script

```bash
#!/bin/bash
# port-5080-enum.sh

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

OUTPUT_DIR="port5080_enum_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[*] Enumerating Port 5080 on $TARGET"
echo "[*] Output directory: $OUTPUT_DIR"

# 1. Service Detection
echo "[+] Nmap Service Detection..."
nmap -p 5080 -sV -sC --version-intensity 9 $TARGET -oN $OUTPUT_DIR/nmap_tcp.txt

# 2. UDP Check
echo "[+] UDP Check..."
sudo nmap -p 5080 -sU -sV $TARGET -oN $OUTPUT_DIR/nmap_udp.txt

# 3. Banner Grabbing
echo "[+] Banner Grabbing..."
echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\n\r\n" | nc -w 3 $TARGET 5080 > $OUTPUT_DIR/banner_http.txt 2>&1
echo -e "OPTIONS sip:$TARGET:5080 SIP/2.0\r\n\r\n" | nc -w 3 $TARGET 5080 > $OUTPUT_DIR/banner_sip.txt 2>&1
timeout 3 nc -u $TARGET 5080 < /dev/null > $OUTPUT_DIR/banner_udp.txt 2>&1

# 4. HTTP Test
echo "[+] HTTP Tests..."
curl -v http://$TARGET:5080 > $OUTPUT_DIR/http_response.txt 2>&1
curl -I http://$TARGET:5080 > $OUTPUT_DIR/http_headers.txt 2>&1

# 5. HTTPS Test
echo "[+] HTTPS Tests..."
curl -kv https://$TARGET:5080 > $OUTPUT_DIR/https_response.txt 2>&1
curl -kI https://$TARGET:5080 > $OUTPUT_DIR/https_headers.txt 2>&1

# 6. SIP Tests
echo "[+] SIP Enumeration..."
nmap -p 5080 --script sip-methods,sip-enum-users $TARGET -oN $OUTPUT_DIR/sip_tcp.txt
sudo nmap -p 5080 -sU --script sip-methods,sip-enum-users $TARGET -oN $OUTPUT_DIR/sip_udp.txt

# 7. SIPVicious (if available)
if command -v svmap &> /dev/null; then
    echo "[+] SIPVicious Tests..."
    svmap $TARGET:5080 > $OUTPUT_DIR/svmap.txt 2>&1
    svwar -m INVITE -e 100-199 $TARGET -p 5080 > $OUTPUT_DIR/svwar_100.txt 2>&1 &
    svwar -m INVITE -e 1000-1099 $TARGET -p 5080 > $OUTPUT_DIR/svwar_1000.txt 2>&1 &
fi

# 8. Whatweb
if command -v whatweb &> /dev/null; then
    echo "[+] Whatweb..."
    whatweb http://$TARGET:5080 > $OUTPUT_DIR/whatweb_http.txt 2>&1
    whatweb https://$TARGET:5080 > $OUTPUT_DIR/whatweb_https.txt 2>&1
fi

# 9. Nikto (Background)
if command -v nikto &> /dev/null; then
    echo "[+] Nikto (running in background)..."
    nikto -h http://$TARGET:5080 -output $OUTPUT_DIR/nikto.txt 2>&1 &
fi

# 10. Common Paths
echo "[+] Testing Common Paths..."
echo "=== HTTP ===" > $OUTPUT_DIR/common_paths.txt
for path in / /admin /administrator /login /console /portal /api /manager /status /verto /ws /AirWatch /ccmadmin /ccmuser /em; do
    code=$(curl -s -o /dev/null -w "%{http_code}" http://$TARGET:5080$path)
    echo "$path: HTTP $code" | tee -a $OUTPUT_DIR/common_paths.txt
done

echo "=== HTTPS ===" >> $OUTPUT_DIR/common_paths.txt
for path in / /admin /administrator /login /console /portal /api; do
    code=$(curl -k -s -o /dev/null -w "%{http_code}" https://$TARGET:5080$path)
    echo "$path: HTTPS $code" | tee -a $OUTPUT_DIR/common_paths.txt
done

# Wait for background jobs
wait

echo ""
echo "[✓] Enumeration Complete!"
echo "[*] Results in: $OUTPUT_DIR/"
echo ""
echo "[*] Summary of interesting findings:"
grep -v "404" $OUTPUT_DIR/common_paths.txt 2>/dev/null | grep -v "000"
```

**Ausführen:**
```bash
chmod +x port-5080-enum.sh
./port-5080-enum.sh TARGET_IP
```

---

## 💡 Quick Test Commands

```bash
TARGET=TARGET_IP  # <-- ANPASSEN!

# === QUICK TESTS ===

# Test 1: HTTP
curl -I http://$TARGET:5080

# Test 2: HTTPS
curl -k -I https://$TARGET:5080

# Test 3: SIP
nmap -p 5080 --script sip-methods $TARGET

# Test 4: Banner Grab
echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\n\r\n" | nc $TARGET 5080

# Test 5: Browser
firefox http://$TARGET:5080 &

# Test 6: SIPVicious
svmap $TARGET:5080

# Test 7: UDP SIP
nmap -p 5080 -sU --script sip-methods $TARGET
```

---

## 🔥 Häufigste Szenarien

### Szenario 1: FreeSWITCH / VoIP (80% Wahrscheinlichkeit wenn Port 5060 auch offen)

**Indicators:**
- Port 5060 (SIP) ist auch offen
- Banner enthält "FreeSWITCH" oder "SIP/2.0"
- Response auf SIP OPTIONS Request

**Exploitation:**
```bash
# Extension Enumeration
svwar -m INVITE -e 100-999 $TARGET -p 5080

# Password Spray gefundene Extensions
svcrack -u 100 -d passwords.txt $TARGET -p 5080

# Default Credentials
# admin:admin, 1000:1234

# CVE Check
searchsploit freeswitch
```

---

### Szenario 2: Web Management Interface (15% Wahrscheinlichkeit)

**Indicators:**
- HTTP Response Codes (200, 301, 302, 401, 403)
- HTML im Response
- Server Header vorhanden

**Exploitation:**
```bash
# Directory Brute Force
gobuster dir -u http://$TARGET:5080 -w /usr/share/wordlists/dirb/common.txt

# Default Creds testen
# admin:admin, admin:password

# Vulnerability Scanning
nikto -h http://$TARGET:5080
```

---

### Szenario 3: Cisco VoIP Management (5% Wahrscheinlichkeit)

**Indicators:**
- /ccmadmin, /ccmuser paths existieren
- Cisco im Banner oder Title

**Exploitation:**
```bash
# Cisco Paths
curl http://$TARGET:5080/ccmadmin
curl http://$TARGET:5080/ccmuser

# Default Creds
# administrator:cisco
# CCMAdministrator:cisco
```

---

## 📋 Tools Overview

### Nmap Scripts
```bash
# SIP specific
sip-methods
sip-enum-users
sip-call-spoof

# HTTP specific
http-enum
http-methods
http-title
http-headers
```

### SIP Tools
- **svmap** - SIP Server Scanner
- **svwar** - SIP Extension Scanner
- **svcrack** - SIP Password Cracker
- **sipvicious** - SIP Vulnerability Scanner

### Web Tools
- **gobuster** - Directory Brute Force
- **nikto** - Web Vulnerability Scanner
- **whatweb** - Web Technology Identifier
- **feroxbuster** - Fast Directory Brute Force

---

## 🚨 Common Misidentifications

**Nmap sagt "onscreen"** → Meist FALSCH!

Checke stattdessen für:
1. SIP/VoIP (besonders wenn Port 5060 offen)
2. HTTP/HTTPS Web Interface
3. Cisco/VoIP Management
4. Custom Application

---

## 🎯 Next Steps - Priorität

### Priority 1: Service Identification
```bash
nmap -p 5080 -sV -sC --version-intensity 9 TARGET_IP
```

### Priority 2: Browser Test (schnellster Visual Check)
```bash
firefox http://TARGET_IP:5080 &
firefox https://TARGET_IP:5080 &
```

### Priority 3: SIP Test (wenn Port 5060 auch offen)
```bash
svmap TARGET_IP:5080
nmap -p 5080 --script sip-methods TARGET_IP
```

### Priority 4: HTTP Enumeration
```bash
curl -I http://TARGET_IP:5080
gobuster dir -u http://TARGET_IP:5080 -w /usr/share/wordlists/dirb/common.txt
```

---

## Related Ports

- **5060** - Standard SIP Port (TCP/UDP)
- **5061** - SIP over TLS
- **8021** - FreeSWITCH Event Socket Layer (ESL)
- **8080** - Alternative HTTP Port
- **8443** - Alternative HTTPS Port

---

**TL;DR:**
- Port 5080 ist wahrscheinlich **SIP/FreeSWITCH** (wenn 5060 auch offen) oder **Web Interface**
- Nmap "onscreen" ist meist falsch
- Teste: Browser + SIP + HTTP
