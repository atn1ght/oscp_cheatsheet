# HTTPS ENUMERATION (Port 443)

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p443 <IP>                              # Service/Version detection
openssl s_client -connect <IP>:443               # SSL/TLS handshake info
openssl s_client -connect <IP>:443 </dev/null 2>/dev/null | grep "subject\|issuer"
curl -I https://<IP>                             # HTTP headers
wget --server-response --spider https://<IP> 2>&1 | grep "Server:"
nc -nv <IP> 443                                  # Manual banner grab
```

## SSL/TLS CERTIFICATE ENUMERATION
```bash
# Get certificate details
openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -text
openssl s_client -connect <IP>:443 -showcerts </dev/null 2>/dev/null

# Extract certificate information
openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -subject
openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -issuer
openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -dates
openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -fingerprint

# Check Subject Alternative Names (SANs) - reveals other domains/subdomains
openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
nmap -p443 --script ssl-cert <IP>               # Nmap SSL cert script

# Download certificate
openssl s_client -connect <IP>:443 </dev/null 2>/dev/null | openssl x509 -outform PEM > cert.pem
```

## SSL/TLS CIPHER SUITE ENUMERATION
```bash
# Enumerate supported ciphers
nmap --script ssl-enum-ciphers -p443 <IP>       # Comprehensive cipher enumeration
sslscan <IP>:443                                 # Detailed SSL/TLS analysis
sslyze --regular <IP>:443                        # Python-based SSL scanner

# Test specific cipher suites
openssl s_client -cipher 'ECDHE-RSA-AES256-GCM-SHA384' -connect <IP>:443
openssl s_client -cipher 'DES-CBC3-SHA' -connect <IP>:443  # Test weak cipher

# Test SSL/TLS versions
openssl s_client -ssl3 -connect <IP>:443         # SSLv3 (should fail)
openssl s_client -tls1 -connect <IP>:443         # TLS 1.0
openssl s_client -tls1_1 -connect <IP>:443       # TLS 1.1
openssl s_client -tls1_2 -connect <IP>:443       # TLS 1.2
openssl s_client -tls1_3 -connect <IP>:443       # TLS 1.3

# testssl.sh (comprehensive testing)
testssl.sh https://<IP>                          # Full SSL/TLS audit
testssl.sh --protocols https://<IP>              # Test protocols only
testssl.sh --vulnerable https://<IP>             # Check for vulnerabilities
```

## WEB ENUMERATION (Same as HTTP but over SSL)
```bash
# Directory brute forcing
gobuster dir -u https://<IP> -w /usr/share/wordlists/dirb/common.txt -k
dirbuster -u https://<IP> -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -u https://<IP>/FUZZ -w /usr/share/wordlists/dirb/common.txt -k

# Nikto scan
nikto -h https://<IP> -ssl                       # Web vulnerability scanner

# Whatweb
whatweb https://<IP> -a 3                        # Aggressive web fingerprinting

# Nmap HTTP scripts
nmap -p443 --script "http-* and ssl-*" <IP>      # All HTTP + SSL scripts
nmap -p443 --script http-enum <IP>               # Common directories/files
nmap -p443 --script http-headers <IP>            # HTTP headers
nmap -p443 --script http-methods <IP>            # Allowed HTTP methods
nmap -p443 --script http-title <IP>              # Page title
nmap -p443 --script http-robots.txt <IP>         # Robots.txt

# cURL reconnaissance
curl -k https://<IP>/robots.txt                  # Check robots.txt
curl -k https://<IP>/sitemap.xml                 # Check sitemap
curl -k -I https://<IP>                          # Headers only
curl -k -X OPTIONS https://<IP> -v               # Check OPTIONS method
curl -k https://<IP> -s | grep -oP '(?<=href=")[^"]*'  # Extract links
```

## VIRTUAL HOST DISCOVERY
```bash
# Vhost brute forcing
gobuster vhost -u https://<domain> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -k
ffuf -u https://<IP> -H "Host: FUZZ.<domain>" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k

# Manual vhost testing
curl -k https://<IP> -H "Host: admin.<domain>"
curl -k https://<IP> -H "Host: dev.<domain>"
curl -k https://<IP> -H "Host: test.<domain>"
curl -k https://<IP> -H "Host: staging.<domain>"
```

## SSL/TLS VULNERABILITY SCANNING
```bash
# Heartbleed (CVE-2014-0160)
nmap -p443 --script ssl-heartbleed <IP>
sslscan --heartbleed <IP>:443
python heartbleed-poc.py <IP>

# POODLE (CVE-2014-3566) - SSLv3 vulnerability
nmap -p443 --script ssl-poodle <IP>
testssl.sh --poodle https://<IP>

# BEAST (CVE-2011-3389)
testssl.sh --beast https://<IP>

# CRIME (CVE-2012-4929)
nmap -p443 --script ssl-known-key <IP>

# DROWN (CVE-2016-0800)
nmap -p443 --script ssl-drown <IP>
testssl.sh --drown https://<IP>

# Logjam
nmap -p443 --script ssl-dh-params <IP>

# FREAK
testssl.sh --freak https://<IP>

# Sweet32 (CVE-2016-2183)
testssl.sh --sweet32 https://<IP>

# Certificate validation issues
nmap -p443 --script ssl-cert-intaddr <IP>       # Internal IP in cert
nmap -p443 --script ssl-date <IP>                # Check TLS date
```

## CLIENT CERTIFICATE AUTHENTICATION TESTING
```bash
# Check if client certificates are required
curl -k https://<IP>                             # Without cert
curl -k --cert client.pem https://<IP>           # With cert
openssl s_client -connect <IP>:443 -cert client.crt -key client.key

# Generate client certificate (if needed)
openssl req -x509 -newkey rsa:4096 -keyout client.key -out client.crt -days 365 -nodes

# Test certificate verification
curl --cacert ca.crt https://<IP>                # With CA validation
curl -k https://<IP>                             # Without validation (-k)
```

## SNI (SERVER NAME INDICATION) ENUMERATION
```bash
# Test SNI with different hostnames
openssl s_client -connect <IP>:443 -servername <domain>
curl -k https://<IP> --resolve <domain>:443:<IP>

# Enumerate SNI
nmap -p443 --script ssl-cert --script-args hostnames=<domain> <IP>

# SNI brute force
for name in admin api dev test staging; do
    echo "Testing: $name.<domain>"
    openssl s_client -connect <IP>:443 -servername $name.<domain> 2>/dev/null | grep "subject"
done
```

## HTTP/2 ENUMERATION
```bash
# Check for HTTP/2 support
curl -k -I --http2 https://<IP>
nghttp -nv https://<IP>                          # HTTP/2 client
h2t scan https://<IP>                            # HTTP/2 security scanner

# Nmap HTTP/2 detection
nmap -p443 --script http2-version <IP>
```

## WEB APPLICATION FINGERPRINTING
```bash
# CMS detection
whatweb https://<IP> -a 3                        # Identify CMS/framework
wappalyzer https://<IP>                          # Technology detection

# WordPress
wpscan --url https://<IP> --disable-tls-checks   # WordPress scanner

# Joomla
joomscan -u https://<IP>                         # Joomla scanner

# Drupal
droopescan scan drupal -u https://<IP>           # Drupal scanner
```

## SUBDOMAIN ENUMERATION
```bash
# From certificate SANs
openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -text | grep -oP '(?<=DNS:)[^,]*'

# DNS brute forcing
dnsrecon -d <domain> -t brt -D /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
sublist3r -d <domain>                            # Subdomain enumeration
amass enum -d <domain>                           # Advanced subdomain enum
```

## API ENDPOINT DISCOVERY
```bash
# Common API paths
curl -k https://<IP>/api/v1
curl -k https://<IP>/api/v2
curl -k https://<IP>/rest/v1
curl -k https://<IP>/graphql
curl -k https://<IP>/swagger.json
curl -k https://<IP>/api-docs
curl -k https://<IP>/openapi.json

# API fuzzing
ffuf -u https://<IP>/api/FUZZ -w /usr/share/wordlists/api-endpoints.txt -k
```

## PROXY DETECTION & BYPASS
```bash
# Detect reverse proxy
curl -k -I https://<IP>                          # Look for X-Forwarded, Via, X-Cache headers

# IP disclosure via headers
curl -k https://<IP> -H "X-Forwarded-For: 127.0.0.1"
curl -k https://<IP> -H "X-Real-IP: 127.0.0.1"
curl -k https://<IP> -H "X-Originating-IP: 127.0.0.1"

# Host header injection
curl -k https://<IP> -H "Host: localhost"
curl -k https://<IP> -H "Host: 127.0.0.1"
```

## HTTPS REDIRECT & HSTS TESTING
```bash
# Check HSTS header
curl -k -I https://<IP> | grep -i strict-transport-security

# Test redirect from HTTP to HTTPS
curl -I http://<IP>                              # Should redirect to HTTPS

# Check security headers
curl -k -I https://<IP> | grep -E "X-Frame-Options|X-Content-Type-Options|Content-Security-Policy"
```

## WEB SHELL UPLOAD & TESTING
```bash
# After finding upload functionality
curl -k -X POST -F "file=@shell.php" https://<IP>/upload.php
curl -k https://<IP>/uploads/shell.php?cmd=whoami

# Common upload paths
https://<IP>/uploads/
https://<IP>/files/
https://<IP>/images/
https://<IP>/assets/
```

## INTERESTING FILES & DIRECTORIES
```bash
# Common files to check
curl -k https://<IP>/robots.txt
curl -k https://<IP>/sitemap.xml
curl -k https://<IP>/.git/config
curl -k https://<IP>/.env
curl -k https://<IP>/config.php
curl -k https://<IP>/web.config
curl -k https://<IP>/crossdomain.xml
curl -k https://<IP>/clientaccesspolicy.xml
curl -k https://<IP>/.well-known/security.txt
curl -k https://<IP>/admin
curl -k https://<IP>/phpmyadmin
curl -k https://<IP>/manager/html                # Tomcat
curl -k https://<IP>/wp-admin                    # WordPress
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/ssl_version           # SSL version scanner
use auxiliary/scanner/http/cert                  # Certificate scanner
use auxiliary/scanner/http/ssl                   # SSL scanner
use auxiliary/scanner/http/dir_scanner           # Directory scanner
use auxiliary/scanner/http/http_header           # HTTP header scanner
use auxiliary/scanner/ssl/openssl_heartbleed     # Heartbleed scanner
```

## CURL ADVANCED TECHNIQUES
```bash
# Follow redirects
curl -k -L https://<IP>

# Custom user agent
curl -k -A "Mozilla/5.0" https://<IP>

# Save cookies
curl -k -c cookies.txt https://<IP>

# Use cookies
curl -k -b cookies.txt https://<IP>

# POST data
curl -k -X POST -d "user=admin&pass=admin" https://<IP>/login

# JSON POST
curl -k -X POST -H "Content-Type: application/json" -d '{"user":"admin"}' https://<IP>/api

# Upload file
curl -k -X POST -F "file=@test.txt" https://<IP>/upload

# Basic auth
curl -k -u admin:password https://<IP>

# Proxy through Burp
curl -k -x http://127.0.0.1:8080 https://<IP>
```

## COMMON MISCONFIGURATIONS
```
☐ Self-signed certificate                       # Indicates dev/test environment
☐ Expired certificate                            # Poor maintenance
☐ Certificate name mismatch                      # Possible MITM or misconfiguration
☐ Weak ciphers enabled (RC4, DES, 3DES)         # Cryptographic vulnerabilities
☐ SSLv3/TLS1.0 enabled                          # Outdated protocols
☐ Missing HSTS header                            # Downgrade attacks possible
☐ Insecure certificate chain                     # Trust issues
☐ Private IP in certificate SAN                  # Information disclosure
☐ Heartbleed vulnerability                       # Memory leak
☐ Certificate reveals internal hostnames         # Information gathering
☐ Missing security headers                       # XSS, clickjacking possible
☐ Directory listing enabled                      # Information disclosure
```

## QUICK WIN CHECKLIST
```
☐ Check certificate for SANs (subdomains/domains)
☐ Test for Heartbleed (OpenSSL < 1.0.1g)
☐ Check for SSLv3/TLS1.0 support (POODLE, BEAST)
☐ Test weak ciphers (RC4, DES, 3DES)
☐ Directory brute forcing
☐ Check robots.txt and sitemap.xml
☐ Test for common vulnerabilities (SQLi, XSS, LFI)
☐ Look for default credentials on web apps
☐ Check for .git, .env, backup files
☐ Virtual host enumeration
☐ API endpoint discovery
☐ Test HTTP methods (PUT, DELETE, etc.)
☐ Check security headers (HSTS, CSP, etc.)
☐ Test for subdomain takeover
☐ Search for admin panels/login pages
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive HTTPS scan
nmap -sV -p443 --script "ssl-* and http-*" -oA https_enum <IP>

# Quick SSL/TLS vulnerability check
testssl.sh --vulnerable --severity HIGH https://<IP>

# Fast directory enumeration
gobuster dir -u https://<IP> -w /usr/share/wordlists/dirb/common.txt -k -t 50
```

## ADVANCED TECHNIQUES
```bash
# Certificate transparency logs
curl -s "https://crt.sh/?q=%.<domain>&output=json" | jq -r '.[].name_value' | sort -u

# OCSP stapling test
openssl s_client -connect <IP>:443 -status 2>/dev/null | grep -A17 "OCSP Response"

# Session resumption test
openssl s_client -connect <IP>:443 -reconnect 2>/dev/null | grep "Session-ID"

# TLS compression test (CRIME)
openssl s_client -connect <IP>:443 2>/dev/null | grep Compression

# Test TLS renegotiation
openssl s_client -connect <IP>:443 2>/dev/null | grep "Secure Renegotiation"

# Check for CAA records
dig CAA <domain>                                 # Certificate Authority Authorization
```
