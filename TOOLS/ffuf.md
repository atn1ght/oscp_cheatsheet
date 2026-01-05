# ffuf - Fast Web Fuzzer Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Directory & File Fuzzing](#3-directory--file-fuzzing)
4. [Subdomain Enumeration](#4-subdomain-enumeration)
5. [Parameter Fuzzing](#5-parameter-fuzzing)
6. [Virtual Host Discovery](#6-virtual-host-discovery)
7. [Filtering & Matching](#7-filtering--matching)
8. [Authentication & Headers](#8-authentication--headers)
9. [Advanced Techniques](#9-advanced-techniques)
10. [Common OSCP Patterns](#10-common-oscp-patterns)
11. [Troubleshooting](#11-troubleshooting)
12. [Quick Reference](#12-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux (bereits installiert)
ffuf -h

# Manual Installation
go install github.com/ffuf/ffuf@latest

# Verify
ffuf -V
```

### 1.2 Wordlists

```bash
# Common Wordlist Locations
/usr/share/wordlists/dirbuster/
/usr/share/wordlists/dirb/
/usr/share/seclists/Discovery/Web-Content/

# Popular Wordlists
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## 2. Basic Concepts

### 2.1 Basic Syntax

```bash
ffuf -u URL -w WORDLIST

# FUZZ keyword marks injection point
ffuf -u http://example.com/FUZZ -w wordlist.txt
```

### 2.2 Simple Example

```bash
# Directory fuzzing
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Output:
# [Status: 200, Size: 1234, Words: 56, Lines: 78]
# :: URL => http://192.168.1.10/admin
```

### 2.3 Multiple FUZZ Keywords

```bash
# Multiple injection points (FUZZ, FUZZ1, FUZZ2, ...)
ffuf -u http://example.com/FUZZ/FUZZ2 -w wordlist1.txt:FUZZ -w wordlist2.txt:FUZZ2
```

---

## 3. Directory & File Fuzzing

### 3.1 Basic Directory Fuzzing

```bash
# Simple directory fuzzing
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/wordlists/dirb/common.txt

# With extensions
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.txt

# Recursive (1 level deep)
ffuf -u http://192.168.1.10/FUZZ -w wordlist.txt -recursion -recursion-depth 1
```

### 3.2 File Fuzzing

```bash
# Specific file extension
ffuf -u http://192.168.1.10/FUZZ.php -w wordlist.txt

# Multiple extensions
ffuf -u http://192.168.1.10/FUZZ -w wordlist.txt -e .php,.bak,.txt,.old,.zip

# Backup files
ffuf -u http://192.168.1.10/FUZZ -w wordlist.txt -e .bak,.old,.backup,.swp
```

### 3.3 Common Patterns

```bash
# Admin panels
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -mc 200,301,302,403

# Config files
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/web-all.txt \
  -e .conf,.config,.cfg,.ini

# Backups
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .bak,.backup,.old,.zip,.tar.gz
```

---

## 4. Subdomain Enumeration

### 4.1 Basic Subdomain Fuzzing

```bash
# Subdomain enumeration
ffuf -u http://FUZZ.example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# With specific wordlist
ffuf -u http://FUZZ.example.com -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
```

### 4.2 Filter False Positives

```bash
# Filter by size (if wildcard DNS returns same size)
ffuf -u http://FUZZ.example.com -w wordlist.txt -fs 1234

# Filter by response code
ffuf -u http://FUZZ.example.com -w wordlist.txt -mc 200,301,302

# Filter by words count
ffuf -u http://FUZZ.example.com -w wordlist.txt -fw 50
```

---

## 5. Parameter Fuzzing

### 5.1 GET Parameters

```bash
# Fuzz GET parameter names
ffuf -u http://192.168.1.10/page.php?FUZZ=value -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Fuzz parameter values
ffuf -u http://192.168.1.10/page.php?id=FUZZ -w wordlist.txt

# Multiple parameters
ffuf -u http://192.168.1.10/api?user=FUZZ&action=FUZZ2 -w users.txt:FUZZ -w actions.txt:FUZZ2
```

### 5.2 POST Parameters

```bash
# POST data fuzzing
ffuf -u http://192.168.1.10/login -X POST -d "username=admin&password=FUZZ" \
  -w /usr/share/wordlists/rockyou.txt -mc 200,302

# Fuzz POST parameter names
ffuf -u http://192.168.1.10/api -X POST -d "FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -H "Content-Type: application/x-www-form-urlencoded"
```

### 5.3 JSON Fuzzing

```bash
# Fuzz JSON values
ffuf -u http://192.168.1.10/api -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w passwords.txt -mc 200
```

---

## 6. Virtual Host Discovery

### 6.1 Basic VHost Fuzzing

```bash
# Virtual host discovery
ffuf -u http://192.168.1.10 -H "Host: FUZZ.example.com" -w wordlist.txt

# Filter by size (if default vhost returns same size)
ffuf -u http://192.168.1.10 -H "Host: FUZZ.example.com" -w wordlist.txt -fs 1234
```

### 6.2 VHost with IP

```bash
# VHost on IP
ffuf -u http://192.168.1.10 -H "Host: FUZZ" -w vhosts.txt -mc 200,301,302

# Common VHost patterns
ffuf -u http://192.168.1.10 -H "Host: FUZZ.local" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1234
```

---

## 7. Filtering & Matching

### 7.1 Match Codes

```bash
# Match specific status codes
ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200

# Match multiple codes
ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200,301,302,403

# Match all (default)
ffuf -u http://example.com/FUZZ -w wordlist.txt -mc all
```

### 7.2 Filter Codes

```bash
# Filter status codes (exclude)
ffuf -u http://example.com/FUZZ -w wordlist.txt -fc 404

# Filter multiple
ffuf -u http://example.com/FUZZ -w wordlist.txt -fc 404,403,400
```

### 7.3 Size Filtering

```bash
# Filter by response size
ffuf -u http://example.com/FUZZ -w wordlist.txt -fs 1234

# Filter by size range
ffuf -u http://example.com/FUZZ -w wordlist.txt -fs 1234,5678

# Match specific size
ffuf -u http://example.com/FUZZ -w wordlist.txt -ms 4567
```

### 7.4 Word/Line Filtering

```bash
# Filter by word count
ffuf -u http://example.com/FUZZ -w wordlist.txt -fw 50

# Filter by line count
ffuf -u http://example.com/FUZZ -w wordlist.txt -fl 100

# Match word count
ffuf -u http://example.com/FUZZ -w wordlist.txt -mw 10
```

### 7.5 Regex Filtering

```bash
# Filter by regex
ffuf -u http://example.com/FUZZ -w wordlist.txt -fr "error|404"

# Match regex
ffuf -u http://example.com/FUZZ -w wordlist.txt -mr "success|admin"
```

---

## 8. Authentication & Headers

### 8.1 Basic Authentication

```bash
# Basic Auth
ffuf -u http://192.168.1.10/FUZZ -w wordlist.txt \
  -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ="

# Fuzz credentials
ffuf -u http://192.168.1.10/admin -w passwords.txt \
  -H "Authorization: Basic $(echo -n admin:FUZZ | base64)"
```

### 8.2 Custom Headers

```bash
# Custom headers
ffuf -u http://example.com/FUZZ -w wordlist.txt \
  -H "X-Custom-Header: value" \
  -H "User-Agent: Mozilla/5.0"

# Fuzz header values
ffuf -u http://example.com/api -w wordlist.txt \
  -H "X-API-Key: FUZZ"
```

### 8.3 Cookies

```bash
# With cookies
ffuf -u http://example.com/FUZZ -w wordlist.txt \
  -b "session=abc123; user=admin"

# Cookie fuzzing
ffuf -u http://example.com/dashboard -w sessions.txt \
  -b "session=FUZZ"
```

---

## 9. Advanced Techniques

### 9.1 Speed & Performance

```bash
# Threads (default: 40)
ffuf -u http://example.com/FUZZ -w wordlist.txt -t 100

# Rate limiting (requests per second)
ffuf -u http://example.com/FUZZ -w wordlist.txt -rate 50

# Timeout
ffuf -u http://example.com/FUZZ -w wordlist.txt -timeout 10
```

### 9.2 Output Options

```bash
# Save output to file
ffuf -u http://example.com/FUZZ -w wordlist.txt -o results.json

# Output formats: json, ejson, html, md, csv, ecsv
ffuf -u http://example.com/FUZZ -w wordlist.txt -o results.html -of html

# Silent mode (only results)
ffuf -u http://example.com/FUZZ -w wordlist.txt -s

# Verbose mode
ffuf -u http://example.com/FUZZ -w wordlist.txt -v
```

### 9.3 Proxy

```bash
# HTTP Proxy
ffuf -u http://example.com/FUZZ -w wordlist.txt -x http://127.0.0.1:8080

# With Burp Suite
ffuf -u http://example.com/FUZZ -w wordlist.txt -x http://127.0.0.1:8080 -replay-proxy http://127.0.0.1:8080
```

### 9.4 Auto-Calibration

```bash
# Auto-calibrate filtering
ffuf -u http://example.com/FUZZ -w wordlist.txt -ac

# Useful for bypassing WAF responses
ffuf -u http://example.com/FUZZ -w wordlist.txt -ac -mc all
```

### 9.5 Recursion

```bash
# Recursive fuzzing
ffuf -u http://example.com/FUZZ -w wordlist.txt -recursion

# Recursion depth
ffuf -u http://example.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Recursion strategy
ffuf -u http://example.com/FUZZ -w wordlist.txt -recursion -recursion-strategy greedy
```

---

## 10. Common OSCP Patterns

### 10.1 Pattern 1: Directory Discovery

```bash
# Basic directory fuzzing
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403

# With extensions
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -e .php,.html,.txt -mc 200,301,302
```

### 10.2 Pattern 2: File Discovery

```bash
# Common files
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Backup files
ffuf -u http://192.168.1.10/FUZZ -w wordlist.txt -e .bak,.backup,.old,.swp,.zip

# Config files
ffuf -u http://192.168.1.10/FUZZ -w wordlist.txt -e .conf,.config,.cfg,.ini,.xml
```

### 10.3 Pattern 3: Virtual Host Discovery

```bash
# VHost fuzzing
ffuf -u http://192.168.1.10 -H "Host: FUZZ.example.local" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1234

# Common VHost names
ffuf -u http://192.168.1.10 -H "Host: FUZZ" -w <(echo -e "admin\ntest\ndev\napi\ninternal")
```

### 10.4 Pattern 4: Parameter Fuzzing

```bash
# GET parameter discovery
ffuf -u http://192.168.1.10/page.php?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 1234

# POST parameter fuzzing
ffuf -u http://192.168.1.10/login -X POST -d "username=admin&password=FUZZ" -w /usr/share/wordlists/rockyou.txt -mc 200,302 -t 50
```

### 10.5 Pattern 5: API Endpoint Discovery

```bash
# API versioning
ffuf -u http://192.168.1.10/api/FUZZ/users -w <(seq 1 10) -mc 200,301,302

# API endpoints
ffuf -u http://192.168.1.10/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200
```

### 10.6 Pattern 6: Extension Fuzzing

```bash
# Common web extensions
ffuf -u http://192.168.1.10/index.FUZZ -w <(echo -e "php\nhtml\nasp\naspx\njsp\ntxt")

# All extensions on file
ffuf -u http://192.168.1.10/admin.FUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```

### 10.7 Pattern 7: Username Enumeration

```bash
# Username fuzzing
ffuf -u http://192.168.1.10/login -X POST -d "username=FUZZ&password=wrongpass" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -mr "Invalid password" -mc 200
```

### 10.8 Pattern 8: Subdomain Takeover Check

```bash
# Subdomain enumeration
ffuf -u http://FUZZ.example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302 -o subdomains.json
```

---

## 11. Troubleshooting

### 11.1 Too Many Results

```bash
# Problem: Too many false positives
# Solution: Auto-calibration
ffuf -u http://example.com/FUZZ -w wordlist.txt -ac

# Or filter by size
ffuf -u http://example.com/FUZZ -w wordlist.txt -fs 1234

# Or filter by regex
ffuf -u http://example.com/FUZZ -w wordlist.txt -fr "404|error"
```

### 11.2 Rate Limiting / WAF

```bash
# Problem: Getting rate limited
# Solution: Reduce threads and add delay
ffuf -u http://example.com/FUZZ -w wordlist.txt -t 10 -rate 10 -p 0.5-1.0

# Add random User-Agent
ffuf -u http://example.com/FUZZ -w wordlist.txt -H "User-Agent: Mozilla/5.0"
```

### 11.3 SSL/TLS Errors

```bash
# Problem: SSL certificate errors
# Solution: Ignore SSL verification (not in ffuf by default, but can proxy through curl)
```

### 11.4 Performance Issues

```bash
# Problem: Too slow
# Solution: Increase threads
ffuf -u http://example.com/FUZZ -w wordlist.txt -t 200

# Problem: Too fast / getting blocked
# Solution: Rate limiting
ffuf -u http://example.com/FUZZ -w wordlist.txt -rate 50
```

---

## 12. Quick Reference

### 12.1 Essential Options

```bash
# BASIC
ffuf -u URL -w WORDLIST                    # Basic fuzzing
ffuf -u URL/FUZZ -w wordlist.txt           # Directory fuzzing
ffuf -u URL/FUZZ.php -w wordlist.txt       # File fuzzing
ffuf -u URL -H "Host: FUZZ" -w wordlist.txt  # VHost fuzzing

# FILTERING
-mc 200,301,302             # Match codes
-fc 404                     # Filter codes
-fs 1234                    # Filter size
-fw 50                      # Filter words
-fl 100                     # Filter lines
-fr "regex"                 # Filter regex
-mr "regex"                 # Match regex
-ac                         # Auto-calibrate

# OUTPUT
-o file.json                # Output file
-of json                    # Output format (json,html,md,csv)
-s                          # Silent mode
-v                          # Verbose mode

# PERFORMANCE
-t 100                      # Threads (default: 40)
-rate 50                    # Requests per second
-timeout 10                 # Request timeout
-p 0.5-1.0                  # Random delay range

# EXTENSIONS
-e .php,.html,.txt          # Extensions to try

# AUTHENTICATION
-H "Header: value"          # Custom header
-b "cookie=value"           # Cookie
-x http://proxy:8080        # Proxy

# ADVANCED
-recursion                  # Recursive fuzzing
-recursion-depth 2          # Recursion depth
-X POST                     # HTTP method
-d "data"                   # POST data
```

### 12.2 Common Commands

```bash
# Directory fuzzing
ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403

# VHost discovery
ffuf -u http://TARGET -H "Host: FUZZ.example.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1234

# Parameter fuzzing
ffuf -u http://TARGET/page.php?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# POST data fuzzing
ffuf -u http://TARGET/login -X POST -d "user=admin&pass=FUZZ" -w passwords.txt -mc 200,302

# API endpoint fuzzing
ffuf -u http://TARGET/api/FUZZ -w api-endpoints.txt -mc 200

# Backup file discovery
ffuf -u http://TARGET/FUZZ -w wordlist.txt -e .bak,.backup,.old,.swp
```

### 12.3 Wordlist Recommendations

```bash
# Directories (small)
/usr/share/wordlists/dirb/common.txt

# Directories (medium)
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Directories (large)
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Files
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt

# Subdomains
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Parameters
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# API
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

---

## 13. OSCP Tips

**Basic Workflow:**
```bash
# 1. Directory discovery
ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403

# 2. File discovery with extensions
ffuf -u http://TARGET/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak

# 3. VHost discovery
ffuf -u http://TARGET -H "Host: FUZZ.local" -w subdomains.txt -fs 1234
```

**Quick Checks:**
```bash
# Admin panels
ffuf -u http://TARGET/FUZZ -w <(echo -e "admin\nadmin.php\nadministrator\nbackup")

# Backups
ffuf -u http://TARGET/FUZZ -w <(echo -e "backup\nbackup.zip\ndb.sql\ndump.sql")

# Config files
ffuf -u http://TARGET/FUZZ -w <(echo -e "config.php\nconfig.ini\nweb.config\n.env")
```

**Performance:**
- Start with common.txt (fast)
- Use `-ac` for auto-calibration
- Filter false positives with `-fs` or `-fc`
- Increase threads with `-t` on stable targets

---

## 14. Resources

- **ffuf GitHub**: https://github.com/ffuf/ffuf
- **SecLists**: https://github.com/danielmiessler/SecLists
- **HackTricks - ffuf**: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/ffuf

---

## 15. Final Notes

**Für OSCP:**
- ffuf = Fast Directory/File/VHost Fuzzer
- Essential Flags: `-mc`, `-fc`, `-fs`, `-ac`
- Always start with common.txt
- Use auto-calibration (`-ac`) for unknowns
- Filter false positives aggressively
- Combine with `-e` for extensions

**Best Practice:**
1. Start with small wordlist (common.txt)
2. Use `-ac` for auto-calibration
3. Filter false positives (`-fs`, `-fc`)
4. Add extensions (`-e .php,.html,.txt`)
5. Save results (`-o output.json`)
6. Increase threads on stable targets (`-t 100`)
