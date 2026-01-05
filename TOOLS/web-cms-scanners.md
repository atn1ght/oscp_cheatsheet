# Web & CMS Scanner Suite

Umfassende Web Application & CMS Vulnerability Scanner.

---

## Nikto

### Was ist Nikto?

Open-Source Web Server Scanner. Findet gefährliche Files, veraltete Software, Misconfigurations.

### Installation

```bash
# Kali (pre-installed)
nikto -Version

# Oder GitHub
git clone https://github.com/sullo/nikto
cd nikto/program
./nikto.pl -h
```

### Basis-Usage

```bash
# Simple Scan
nikto -h http://target.com

# HTTPS
nikto -h https://target.com

# Mit Port
nikto -h http://target.com:8080

# Multiple Targets
nikto -h targets.txt
```

### Erweiterte Optionen

```bash
# Scan-Tuning (welche Tests)
nikto -h http://target.com -Tuning 123456789ab

# Tuning Options:
# 1 - Interesting File / Seen in logs
# 2 - Misconfiguration / Default File
# 3 - Information Disclosure
# 4 - Injection (XSS/Script/HTML)
# 5 - Remote File Retrieval
# 6 - Denial of Service
# 7 - Remote File Retrieval - Inside Web Root
# 8 - Command Execution / Remote Shell
# 9 - SQL Injection
# a - Authentication Bypass
# b - Software Identification
# x - Reverse Tuning (alles AUSSER specified)

# Nur bestimmte Tests
nikto -h http://target.com -Tuning 9  # Nur SQL Injection

# Mit Authentication
nikto -h http://target.com -id admin:password

# Custom Headers
nikto -h http://target.com -H "Authorization: Bearer TOKEN"

# Through Proxy
nikto -h http://target.com -useproxy http://proxy:8080

# Output Formats
nikto -h http://target.com -o nikto_output.txt         # Text
nikto -h http://target.com -o nikto_output.html -Format htm  # HTML
nikto -h http://target.com -o nikto_output.xml -Format xml   # XML
```

### Nützliche Flags

```bash
# No SSL Checks (faster)
nikto -h https://target.com -nossl

# Follow Redirects
nikto -h http://target.com -followredirects

# Vhosts Testing
nikto -h http://target.com -vhost subdomain.target.com

# Update Database
nikto -update
```

---

## WPScan (WordPress)

### Was ist WPScan?

WordPress Security Scanner. Findet Vulnerabilities in WP Core, Plugins, Themes.

### Installation

```bash
# Kali
sudo apt install wpscan

# Oder gem
gem install wpscan

# API Token (für vuln data)
wpscan --api-token YOUR_TOKEN --url http://target.com
# Get token: https://wpscan.com/
```

### Basis-Enumeration

```bash
# Basic Scan
wpscan --url http://target.com

# Enumerate Users
wpscan --url http://target.com --enumerate u

# Enumerate Plugins
wpscan --url http://target.com --enumerate p

# Enumerate Themes
wpscan --url http://target.com --enumerate t

# Enumerate All
wpscan --url http://target.com --enumerate ap,at,u
# ap = All Plugins
# at = All Themes
# u = Users
```

### Erweiterte Enumeration

```bash
# Vulnerable Plugins
wpscan --url http://target.com --enumerate vp

# Timthumbs
wpscan --url http://target.com --enumerate tt

# Config Backups
wpscan --url http://target.com --enumerate cb

# DB Exports
wpscan --url http://target.com --enumerate dbe

# Alles
wpscan --url http://target.com --enumerate ap,at,tt,cb,dbe,u,m
```

### Password Attack

```bash
# Brute Force
wpscan --url http://target.com --passwords /usr/share/wordlists/rockyou.txt --usernames admin

# User Enumeration dann Brute Force
wpscan --url http://target.com --enumerate u
wpscan --url http://target.com --passwords passwords.txt --usernames admin,john,editor
```

### Mit API Token

```bash
# Vulnerability Database Check
wpscan --url http://target.com --api-token YOUR_TOKEN --enumerate vp

# Update API Database
wpscan --update
```

### Output

```bash
# JSON Output
wpscan --url http://target.com -o output.json -f json

# CLI Output
wpscan --url http://target.com -o output.txt -f cli-no-color
```

---

## Joomscan (Joomla)

### Was ist Joomscan?

Joomla Vulnerability Scanner.

### Installation

```bash
# Kali
sudo apt install joomscan

# Oder GitHub
git clone https://github.com/OWASP/joomscan
cd joomscan
perl joomscan.pl
```

### Usage

```bash
# Basic Scan
joomscan -u http://target.com

# Enumerate Components
joomscan -u http://target.com -ec

# Random Agent
joomscan -u http://target.com -r

# Through Proxy
joomscan -u http://target.com --proxy http://proxy:8080

# Enumerate Installed Modules
joomscan -u http://target.com -em
```

---

## Droopescan (Drupal, WordPress, Joomla, Moodle)

### Was ist Droopescan?

Multi-CMS Scanner (Drupal, WordPress, Joomla, Moodle, Silverstripe).

### Installation

```bash
# pip
pip3 install droopescan

# GitHub
git clone https://github.com/droope/droopescan
cd droopescan
pip3 install -r requirements.txt
```

### Usage

```bash
# Drupal Scan
droopescan scan drupal -u http://target.com

# WordPress Scan
droopescan scan wordpress -u http://target.com

# Joomla Scan
droopescan scan joomla -u http://target.com

# Moodle Scan
droopescan scan moodle -u http://target.com

# Auto-detect CMS
droopescan scan -u http://target.com

# Enumerate Plugins
droopescan scan drupal -u http://target.com --enumerate p

# Enumerate Themes
droopescan scan drupal -u http://target.com --enumerate t

# Enumerate All
droopescan scan drupal -u http://target.com --enumerate p,t,u
```

---

## WhatWeb

### Was ist WhatWeb?

Web Technology Identifier. Erkennt CMS, Frameworks, Server, JavaScript Libraries, etc.

### Installation

```bash
# Kali
sudo apt install whatweb

# GitHub
git clone https://github.com/urbanadventurer/WhatWeb
```

### Usage

```bash
# Simple Scan
whatweb http://target.com

# Verbose
whatweb -v http://target.com

# Aggression Level (0-4)
whatweb --aggression 3 http://target.com
# 1 = Stealthy (default)
# 3 = Aggressive
# 4 = Heavy

# Multiple URLs
whatweb http://target1.com http://target2.com

# From File
whatweb -i targets.txt

# Output Formats
whatweb http://target.com --log-json=output.json
whatweb http://target.com --log-xml=output.xml
whatweb http://target.com --log-brief=output.txt
```

### Use Cases

```bash
# Technology Stack Identification
whatweb -v http://target.com | grep -E "WordPress|Drupal|Joomla|Apache|Nginx|PHP"

# Find Version Numbers
whatweb --aggression 3 http://target.com | grep -i version

# Subnet Scan
whatweb -i <(nmap -p80,443,8080 192.168.1.0/24 -oG - | grep open | awk '{print $2}')
```

---

## Commix (Command Injection)

### Was ist Commix?

Command Injection Exploitation Tool.

### Installation

```bash
# Kali
sudo apt install commix

# GitHub
git clone https://github.com/commixproject/commix
cd commix
python3 commix.py -h
```

### Basic Usage

```bash
# Test URL Parameter
commix --url="http://target.com/page?param=value"

# POST Data
commix --url="http://target.com/page" --data="param=value"

# Cookie Injection
commix --url="http://target.com/" --cookie="user=value"

# Custom Headers
commix --url="http://target.com/" --header="User-Agent: CustomAgent"
```

### Advanced Options

```bash
# Specific Parameter
commix --url="http://target.com/page?id=1&name=test" -p id

# Techniques
commix --url="http://target.com/?param=value" --technique=e
# e = eval-based
# t = time-based
# f = file-based
# b = tempfile-based

# All Techniques
commix --url="http://target.com/?param=value" --technique=etfb

# OS Shell
commix --url="http://target.com/?param=value" --os-shell

# File Read
commix --url="http://target.com/?param=value" --file-read=/etc/passwd

# File Upload
commix --url="http://target.com/?param=value" --file-upload=/local/file --file-dest=/remote/path
```

### With Proxies

```bash
# Through Burp/Proxy
commix --url="http://target.com/?param=value" --proxy=http://127.0.0.1:8080
```

---

## Workflow: CMS Identification → Exploitation

```bash
# Step 1: Identify Technology
whatweb -v http://target.com

# Output: WordPress 5.8.1

# Step 2: Scan for Vulnerabilities
wpscan --url http://target.com --enumerate vp,vt,u --api-token TOKEN

# Output: Vulnerable Plugin found

# Step 3: Searchsploit
searchsploit wordpress plugin-name 5.0

# Step 4: Exploit
# ... use found exploit
```

---

## Tool Matrix

| CMS | Best Tool | Alternative |
|-----|-----------|-------------|
| **WordPress** | WPScan | Droopescan |
| **Joomla** | Joomscan | Droopescan |
| **Drupal** | Droopescan | Manual |
| **Moodle** | Droopescan | Manual |
| **Unknown** | WhatWeb | Nikto |

---

## Quick Reference

### Nikto
```bash
nikto -h http://target.com
nikto -h http://target.com -Tuning 123456789ab
```

### WPScan
```bash
wpscan --url http://target.com --enumerate vp,vt,u --api-token TOKEN
wpscan --url http://target.com --passwords rockyou.txt --usernames admin
```

### WhatWeb
```bash
whatweb -v http://target.com
whatweb --aggression 3 http://target.com
```

### Commix
```bash
commix --url="http://target.com/?param=value"
commix --url="http://target.com/" --data="param=value" --os-shell
```

---

## OSCP Exam Tips

1. **WhatWeb zuerst** - Technology Stack identifizieren
2. **WPScan mit API** - Für WordPress (häufig in OSCP)
3. **Nikto für Directories** - Findet interessante Paths
4. **Droopescan als Universal** - Multi-CMS Support
5. **Searchsploit nach Scan** - CMS Version → Exploits
6. **Commix für Command Injection** - Automated Testing
7. **Manuelle Verification** - Tools zeigen Weg, manuell exploiten
8. **Default Credentials testen** - admin:admin auf WP/Joomla

---

## Resources

- Nikto: https://github.com/sullo/nikto
- WPScan: https://wpscan.com/
- Joomscan: https://github.com/OWASP/joomscan
- Droopescan: https://github.com/droope/droopescan
- WhatWeb: https://github.com/urbanadventurer/WhatWeb
- Commix: https://github.com/commixproject/commix
