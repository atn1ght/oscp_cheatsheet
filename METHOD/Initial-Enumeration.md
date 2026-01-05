# INITIAL ENUMERATION - OSCP METHODOLOGY

## 1. HOST DISCOVERY (Wahrscheinlichkeit: 90%)

```bash
# Nmap Host Discovery
nmap -sn 192.168.1.0/24                          # Ping sweep
nmap -sn -PS22,80,443 192.168.1.0/24             # TCP SYN ping
nmap -sn -PU 192.168.1.0/24                      # UDP ping

# Mit Nmap-Ausgabe
nmap -sn 192.168.1.0/24 -oG - | grep "Up" | cut -d " " -f 2

# Netdiscover (falls verfügbar)
netdiscover -r 192.168.1.0/24

# Masscan (sehr schnell)
masscan -p80,443,22 192.168.1.0/24 --rate=1000
```

## 2. PORT SCANNING (Wahrscheinlichkeit: 100%)

### Quick Scan (Initial)
```bash
# Top 1000 Ports - IMMER ZUERST!
nmap -p- --min-rate=1000 -T4 <IP>                # Alle Ports schnell

# Top Ports mit Service Detection
nmap -sV -sC --top-ports=100 <IP> -oA quick_scan

# Alle TCP Ports (kann lange dauern)
nmap -p- -T4 <IP> -oN all_ports.txt
```

### Full Scan (Detailed)
```bash
# Auf gefundene Ports detailliert scannen
nmap -p22,80,443,445,3389 -sV -sC -A <IP> -oA detailed_scan

# Mit allen NSE Scripts
nmap -p22,80,443 -sV --script=default,vuln <IP>

# UDP Scan (auf wichtigste Ports)
sudo nmap -sU -sV --top-ports=20 <IP> -oN udp_scan.txt

# Häufigste OSCP Ports:
21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,3389,5985,8080
```

## 3. SERVICE ENUMERATION (Wahrscheinlichkeit: 100%)

### HTTP/HTTPS (Wahrscheinlichkeit: 95%)
```bash
# Whatweb
whatweb http://<IP>

# Nikto
nikto -h http://<IP>

# Directory Brute Force - KRITISCH FÜR OSCP!
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak
feroxbuster -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Spezifische Wordlists
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Vhost Enumeration
gobuster vhost -u http://<domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### SMB (Wahrscheinlichkeit: 80%)
```bash
# Enum4linux - OSCP STANDARD!
enum4linux -a <IP>

# SMBMap
smbmap -H <IP>
smbmap -H <IP> -u guest -p ''
smbmap -H <IP> -u null -p ''

# SMBClient
smbclient -L //<IP>/ -N
smbclient //<IP>/share -N

# CrackMapExec
crackmapexec smb <IP> --shares
crackmapexec smb <IP> -u '' -p '' --shares
crackmapexec smb <IP> -u 'guest' -p '' --shares

# Nmap SMB Scripts
nmap -p445 --script=smb-enum-shares,smb-enum-users <IP>
```

### FTP (Wahrscheinlichkeit: 60%)
```bash
# Anonymous Login testen
ftp <IP>
# Username: anonymous
# Password: anonymous

# Nmap FTP Scripts
nmap -p21 --script=ftp-anon,ftp-bounce,ftp-syst <IP>

# Rekursiv downloaden
wget -r ftp://anonymous:anonymous@<IP>
```

### SSH (Wahrscheinlichkeit: 70%)
```bash
# Banner Grabbing
nc <IP> 22

# User Enumeration (OpenSSH < 7.7)
python3 /usr/share/exploitdb/exploits/linux/remote/45939.py <IP> -U users.txt

# SSH Brute Force (VORSICHTIG!)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<IP>
```

### SNMP (Wahrscheinlichkeit: 40%)
```bash
# Community String Brute Force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP>

# SNMPWalk
snmpwalk -v2c -c public <IP>
snmpwalk -v2c -c private <IP>

# SNMP Enumeration
snmp-check <IP> -c public
```

### LDAP (Wahrscheinlichkeit: 50% - Windows AD)
```bash
# LDAP Enumeration
ldapsearch -x -h <IP> -s base namingcontexts
ldapsearch -x -h <IP> -b "dc=domain,dc=local"

# Nmap LDAP Scripts
nmap -p389 --script=ldap-search,ldap-rootdse <IP>
```

### NFS (Wahrscheinlichkeit: 30%)
```bash
# Show Mounts
showmount -e <IP>

# Mount Share
mkdir /tmp/nfs
mount -t nfs <IP>:/share /tmp/nfs

# List Contents
ls -la /tmp/nfs
```

## 4. VULNERABILITY SCANNING (Wahrscheinlichkeit: 70%)

```bash
# Nmap Vuln Scripts
nmap -p- --script=vuln <IP>

# Searchsploit nach Service Version
searchsploit <service> <version>

# Nikto für Web
nikto -h http://<IP>

# Enum4linux für Windows
enum4linux -a <IP>
```

## 5. INITIAL ACCESS VECTORS (OSCP)

### Häufigste Initial Access (OSCP Wahrscheinlichkeit):

1. **Web Application Exploitation** (60%)
   - SQLi, LFI, RFI, File Upload, RCE

2. **SMB Null Session** (40%)
   - Credentials in shares, sensitive files

3. **Default Credentials** (30%)
   - Tomcat, Jenkins, FTP, SSH

4. **Anonymous FTP** (25%)
   - SSH keys, config files, source code

5. **Weak Passwords** (20%)
   - SSH, RDP, SMB brute force

6. **Known CVEs** (15%)
   - Public exploits, Metasploit modules

7. **Information Disclosure** (10%)
   - Version disclosure, debug info, stack traces

## 6. OSCP-SPEZIFISCHE ENUMERATION

### Immer checken:
```bash
# robots.txt
curl http://<IP>/robots.txt

# .git Exposure
wget -r http://<IP>/.git/

# Backup Files
curl http://<IP>/index.php.bak
curl http://<IP>/backup.zip

# Default Pages
curl http://<IP>/phpinfo.php
curl http://<IP>/info.php

# Config Files
curl http://<IP>/config.php.bak
curl http://<IP>/web.config
```

### Windows-spezifisch:
```bash
# SMB Signing
nmap -p445 --script=smb-security-mode <IP>

# Windows Version
crackmapexec smb <IP>

# RPC Enumeration
rpcclient -U "" -N <IP>
> enumdomusers
> enumdomgroups
```

### Linux-spezifisch:
```bash
# OS Detection
nmap -O <IP>

# SSH Banner
nc <IP> 22

# SNMP Enumeration
snmpwalk -v2c -c public <IP>
```

## 7. ENUMERATION CHECKLISTS

### Web Application Checklist (95% OSCP Maschinen haben Web!):
```
☐ Directory Brute Force (gobuster/feroxbuster)
☐ robots.txt, sitemap.xml
☐ Source Code Review (View Source)
☐ Technology Stack (Wappalyzer, whatweb)
☐ Hidden Parameters (Burp, param fuzzing)
☐ File Upload Functionality
☐ Login Forms (SQLi, weak passwords)
☐ Cookie Analysis
☐ LFI/RFI Testing
☐ Command Injection
☐ API Endpoints
☐ Default Credentials
```

### SMB Checklist (80% Windows Maschinen):
```
☐ Null Session (smbclient, enum4linux)
☐ Guest Access
☐ Share Enumeration
☐ Writable Shares
☐ Sensitive Files in Shares
☐ User Enumeration
☐ Password Policy
☐ SMB Signing
```

### General Checklist:
```
☐ Full Port Scan
☐ Service Version Detection
☐ OS Detection
☐ Default Credentials
☐ Anonymous Access
☐ Public Exploits (searchsploit)
☐ CVE Search
☐ Weak Passwords
☐ Information Disclosure
```

## 8. HÄUFIGE OSCP SZENARIEN

### Szenario 1: Web + Linux (Wahrscheinlichkeit: 40%)
```
1. Port Scan → 22 (SSH), 80 (HTTP)
2. Gobuster → /admin, /uploads, /backup
3. LFI/RFI oder File Upload
4. Initial Shell (www-data)
5. Linpeas → SUID, Sudo, Cronjobs
6. Privilege Escalation → root
```

### Szenario 2: Windows + SMB (Wahrscheinlichkeit: 30%)
```
1. Port Scan → 135, 139, 445, 3389
2. enum4linux → Users, Shares
3. SMB Null Session → Credentials
4. evil-winrm oder psexec
5. WinPEAS → Privesc vectors
6. Privilege Escalation → SYSTEM
```

### Szenario 3: Web + Windows (Wahrscheinlichkeit: 20%)
```
1. Port Scan → 80, 443, 445, 5985
2. Directory Brute Force
3. Upload .aspx shell
4. Initial Shell (iis apppool\web)
5. WinPEAS → SeImpersonate, AlwaysInstallElevated
6. Potato Exploits oder stored credentials
7. SYSTEM shell
```

### Szenario 4: Multi-Service (Wahrscheinlichkeit: 10%)
```
1. Multiple Services (FTP, SMB, Web, etc.)
2. Credentials from one service
3. Credential reuse on another service
4. Pivot through services
5. Shell access
6. Privilege Escalation
```

## 9. ENUMERATION TOOLS PRIORITÄT

### Must-Have (100% OSCP Usage):
```
1. nmap
2. gobuster/feroxbuster
3. nikto
4. enum4linux (Windows)
5. smbclient/smbmap
6. searchsploit
```

### High Priority (70%+ Usage):
```
7. whatweb
8. crackmapexec
9. hydra
10. wfuzz
11. ffuf
12. ldapsearch
```

### Medium Priority (40%+ Usage):
```
13. snmpwalk
14. rpcclient
15. showmount
16. netcat
```

## 10. TIME MANAGEMENT

### Initial Enumeration (15-30 Minuten):
```
0-5 min:   Port Scan (quick)
5-10 min:  Service Enumeration
10-15 min: Web Directory Brute Force (if web exists)
15-20 min: SMB Enumeration (if Windows)
20-30 min: Detailed scanning of interesting services
```

### Wenn nach 30 Minuten nichts gefunden:
```
- Deeper directory bruteforce (larger wordlists)
- UDP Scan
- Vulnerability scanning
- Manual testing (SQLi, LFI, etc.)
- Different wordlists
- Parameter fuzzing
```

## 11. HÄUFIGE FEHLER VERMEIDEN

```
❌ Nur Quick Scan (fehlende Ports!)
✅ Immer Full Port Scan (-p-)

❌ Keine Directory Enumeration
✅ IMMER gobuster/feroxbuster bei Web!

❌ SMB Enumeration vergessen
✅ enum4linux bei Windows!

❌ Nur Default Wordlist
✅ Mehrere Wordlists versuchen

❌ UDP Scan vergessen
✅ Mindestens Top UDP Ports scannen

❌ Version Disclosure ignorieren
✅ Immer searchsploit nach Versionen!
```

## 12. GOLDEN RULES FÜR OSCP

```
1. DOKUMENTIERE ALLES! (Screenshots, Commands, Outputs)
2. Port Scan MUSS vollständig sein (-p-)
3. Bei Web: Directory Bruteforce ist PFLICHT!
4. Bei Windows: enum4linux/SMB Enumeration ist PFLICHT!
5. Immer searchsploit nach Service-Versionen!
6. Default Credentials IMMER testen!
7. Wenn stuck: Zurück zur Enumeration!
8. Credentials notieren - oft wiederverwendet!
9. Time Management: Max 30min Enumeration, dann weitergehen
10. Try Harder = Better Enumeration!
```
