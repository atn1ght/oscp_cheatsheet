# Feroxbuster - Fast Recursive Content Discovery Tool Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Directory Discovery](#3-directory-discovery)
4. [Recursive Scanning](#4-recursive-scanning)
5. [Filtering & Matching](#5-filtering--matching)
6. [Authentication & Headers](#6-authentication--headers)
7. [Advanced Features](#7-advanced-features)
8. [Common OSCP Patterns](#8-common-oscp-patterns)
9. [Troubleshooting](#9-troubleshooting)
10. [Quick Reference](#10-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux
sudo apt install feroxbuster

# Via cargo (Rust)
cargo install feroxbuster

# Manual download
wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster-x86_64-linux.zip
unzip feroxbuster-x86_64-linux.zip
chmod +x feroxbuster
sudo mv feroxbuster /usr/local/bin/

# Verify
feroxbuster --version
```

### 1.2 Configuration File

```bash
# Config file location
~/.config/feroxbuster/ferox-config.toml

# Example config
[feroxbuster]
wordlist = "/usr/share/wordlists/dirb/common.txt"
threads = 50
timeout = 10
status_codes = [200, 204, 301, 302, 307, 308, 401, 403, 405]
```

### 1.3 Wordlists

```bash
# Same as gobuster/ffuf
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/big.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

---

## 2. Basic Concepts

### 2.1 Basic Syntax

```bash
feroxbuster -u URL -w WORDLIST
```

### 2.2 Simple Example

```bash
# Basic directory fuzzing
feroxbuster -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt

# Output shows:
# 200   GET        123l      456w     7890c http://192.168.1.10/admin
# [l = lines, w = words, c = characters]
```

### 2.3 Key Features

**Feroxbuster's Strengths:**
- **Recursive** - Automatically scans found directories
- **Fast** - Rust-based, very performant
- **Smart** - Auto-filters wildcard responses
- **Flexible** - Many filtering/matching options
- **Interactive** - Real-time stats and controls

---

## 3. Directory Discovery

### 3.1 Basic Directory Fuzzing

```bash
# Simple scan
feroxbuster -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt

# With specific threads
feroxbuster -u http://192.168.1.10 -w wordlist.txt -t 50

# Quiet mode (no banner)
feroxbuster -u http://192.168.1.10 -w wordlist.txt -q

# Silent mode (only URLs)
feroxbuster -u http://192.168.1.10 -w wordlist.txt --silent
```

### 3.2 File Extensions

```bash
# With extensions
feroxbuster -u http://192.168.1.10 -w wordlist.txt -x php,html,txt

# Multiple extensions
feroxbuster -u http://192.168.1.10 -w wordlist.txt -x php,html,txt,asp,aspx,jsp,bak

# Backup files
feroxbuster -u http://192.168.1.10 -w wordlist.txt -x bak,backup,old,~,zip
```

### 3.3 Methods

```bash
# Default: GET
feroxbuster -u http://192.168.1.10 -w wordlist.txt

# Use HEAD requests (faster, less bandwidth)
feroxbuster -u http://192.168.1.10 -w wordlist.txt -m HEAD

# Custom methods
feroxbuster -u http://192.168.1.10 -w wordlist.txt -m POST,PUT,DELETE
```

---

## 4. Recursive Scanning

### 4.1 Basic Recursion

```bash
# Recursive scan (default behavior!)
feroxbuster -u http://192.168.1.10 -w wordlist.txt

# Disable recursion
feroxbuster -u http://192.168.1.10 -w wordlist.txt -n

# Recursion depth
feroxbuster -u http://192.168.1.10 -w wordlist.txt -d 2
```

### 4.2 Recursion Control

```bash
# Limit recursion depth
feroxbuster -u http://192.168.1.10 -w wordlist.txt --depth 3

# Force recursion on specific codes (default: 301, 302, 307, 308)
feroxbuster -u http://192.168.1.10 -w wordlist.txt --force-recursion

# Don't extract links (faster)
feroxbuster -u http://192.168.1.10 -w wordlist.txt --dont-extract-links
```

---

## 5. Filtering & Matching

### 5.1 Status Code Filtering

```bash
# Match specific status codes
feroxbuster -u http://192.168.1.10 -w wordlist.txt -s 200,301,302

# Filter status codes (exclude)
feroxbuster -u http://192.168.1.10 -w wordlist.txt -C 404,403

# Match all codes
feroxbuster -u http://192.168.1.10 -w wordlist.txt -s 100-599
```

### 5.2 Size Filtering

```bash
# Filter by response size
feroxbuster -u http://192.168.1.10 -w wordlist.txt -S 1234

# Multiple sizes
feroxbuster -u http://192.168.1.10 -w wordlist.txt -S 1234,5678

# Size range
feroxbuster -u http://192.168.1.10 -w wordlist.txt -S 1000-2000
```

### 5.3 Word/Line Filtering

```bash
# Filter by word count
feroxbuster -u http://192.168.1.10 -w wordlist.txt -W 50

# Filter by line count
feroxbuster -u http://192.168.1.10 -w wordlist.txt -N 100
```

### 5.4 Regex Filtering

```bash
# Filter by regex
feroxbuster -u http://192.168.1.10 -w wordlist.txt -X "404|error"

# Match regex
feroxbuster -u http://192.168.1.10 -w wordlist.txt --regex "admin|panel"
```

### 5.5 Auto-Filter

```bash
# Auto-filter wildcard responses (default enabled!)
feroxbuster -u http://192.168.1.10 -w wordlist.txt

# Disable auto-filter
feroxbuster -u http://192.168.1.10 -w wordlist.txt --dont-filter
```

---

## 6. Authentication & Headers

### 6.1 Authentication

```bash
# Basic Auth
feroxbuster -u http://192.168.1.10 -w wordlist.txt -U username:password

# Bearer Token
feroxbuster -u http://192.168.1.10 -w wordlist.txt -H "Authorization: Bearer TOKEN"

# API Key
feroxbuster -u http://192.168.1.10 -w wordlist.txt -H "X-API-Key: YOUR_KEY"
```

### 6.2 Headers

```bash
# Custom header
feroxbuster -u http://192.168.1.10 -w wordlist.txt -H "User-Agent: Mozilla/5.0"

# Multiple headers
feroxbuster -u http://192.168.1.10 -w wordlist.txt \
  -H "User-Agent: Mozilla/5.0" \
  -H "X-Custom: value"

# Random User-Agent
feroxbuster -u http://192.168.1.10 -w wordlist.txt -a "Mozilla/5.0"
```

### 6.3 Cookies

```bash
# Cookie
feroxbuster -u http://192.168.1.10 -w wordlist.txt -b "session=abc123"

# Multiple cookies
feroxbuster -u http://192.168.1.10 -w wordlist.txt -b "session=abc123; user=admin"
```

---

## 7. Advanced Features

### 7.1 Output Options

```bash
# Save output to file
feroxbuster -u http://192.168.1.10 -w wordlist.txt -o results.txt

# JSON output
feroxbuster -u http://192.168.1.10 -w wordlist.txt -o results.json --json

# No color
feroxbuster -u http://192.168.1.10 -w wordlist.txt --no-color

# Debug mode
feroxbuster -u http://192.168.1.10 -w wordlist.txt --debug-log debug.txt
```

### 7.2 Performance

```bash
# Threads (default: 50)
feroxbuster -u http://192.168.1.10 -w wordlist.txt -t 100

# Timeout
feroxbuster -u http://192.168.1.10 -w wordlist.txt -T 10

# Rate limiting (requests per second)
feroxbuster -u http://192.168.1.10 -w wordlist.txt --rate-limit 50
```

### 7.3 Proxy

```bash
# HTTP Proxy
feroxbuster -u http://192.168.1.10 -w wordlist.txt -p http://127.0.0.1:8080

# SOCKS5 Proxy
feroxbuster -u http://192.168.1.10 -w wordlist.txt -p socks5://127.0.0.1:1080

# Replay through proxy (for Burp)
feroxbuster -u http://192.168.1.10 -w wordlist.txt --replay-proxy http://127.0.0.1:8080
```

### 7.4 SSL/TLS

```bash
# Ignore certificate errors
feroxbuster -u https://192.168.1.10 -w wordlist.txt -k

# Client certificate
feroxbuster -u https://192.168.1.10 -w wordlist.txt --client-cert cert.pem --client-key key.pem
```

### 7.5 Scan Management

```bash
# Scan from file (multiple URLs)
feroxbuster -w wordlist.txt --stdin < urls.txt

# Resume from state file
feroxbuster --resume-from ferox-http_192_168_1_10-1234567890.state

# Time limit
feroxbuster -u http://192.168.1.10 -w wordlist.txt --time-limit 10m
```

### 7.6 Interactive Controls

```bash
# During scan, press:
# ENTER - Show current stats
# s - Save current state
# q - Quit scan
```

---

## 8. Common OSCP Patterns

### 8.1 Pattern 1: Basic Recursive Scan

```bash
# Fast recursive scan with common.txt
feroxbuster -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -t 50

# Medium scan with extensions
feroxbuster -u http://192.168.1.10 -w /usr/share/wordlists/dirb/big.txt -x php,html,txt -t 50
```

### 8.2 Pattern 2: Deep Recursive Scan

```bash
# Deep recursive scan (max depth 3)
feroxbuster -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -d 3 -t 50

# With extensions and deep recursion
feroxbuster -u http://192.168.1.10 -w wordlist.txt -x php,html,txt,bak -d 3 -t 50
```

### 8.3 Pattern 3: Backup File Discovery

```bash
# Look for backups
feroxbuster -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt \
  -x bak,backup,old,~,zip,tar,tar.gz -t 50

# Specific backup files
feroxbuster -u http://192.168.1.10 -w <(echo -e "backup\nbackup.zip\ndb.sql\ndump.sql\nsite.zip") -t 50
```

### 8.4 Pattern 4: Admin Panel Hunt

```bash
# Admin panels with recursion
feroxbuster -u http://192.168.1.10 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -s 200,204,301,302,307,401,403 -t 50

# Common admin paths
feroxbuster -u http://192.168.1.10 \
  -w <(echo -e "admin\nadmin.php\nadministrator\nbackend\nmanager\ncpanel\nwp-admin") -t 50
```

### 8.5 Pattern 5: API Endpoint Discovery

```bash
# API versioning
feroxbuster -u http://192.168.1.10/api/v -w <(seq 1 10) -t 50

# API endpoints
feroxbuster -u http://192.168.1.10/api -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -t 50
```

### 8.6 Pattern 6: Config File Discovery

```bash
# Configuration files
feroxbuster -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt \
  -x conf,config,cfg,ini,xml,yml,yaml,env -t 50

# Git directory
feroxbuster -u http://192.168.1.10 -w <(echo -e ".git\n.git/config\n.git/HEAD\n.gitignore") -t 50
```

### 8.7 Pattern 7: Technology-Specific Scans

```bash
# PHP application
feroxbuster -u http://192.168.1.10 -w wordlist.txt -x php,inc,phps,phtml -t 50

# ASP.NET application
feroxbuster -u http://192.168.1.10 -w wordlist.txt -x asp,aspx,asmx,ashx,config -t 50

# JSP application
feroxbuster -u http://192.168.1.10 -w wordlist.txt -x jsp,jspx,do,action -t 50

# WordPress
feroxbuster -u http://192.168.1.10 -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt -t 50
```

### 8.8 Pattern 8: Authenticated Scan

```bash
# With cookie (after login)
feroxbuster -u http://192.168.1.10 -w wordlist.txt -b "session=abc123; user=admin" -t 50

# With Bearer token
feroxbuster -u http://192.168.1.10/api -w wordlist.txt -H "Authorization: Bearer TOKEN" -t 50
```

---

## 9. Troubleshooting

### 9.1 Too Many False Positives

```bash
# Problem: Wildcard responses
# Solution: Auto-filter is enabled by default
feroxbuster -u http://192.168.1.10 -w wordlist.txt

# If still issues, filter by size
feroxbuster -u http://192.168.1.10 -w wordlist.txt -S 1234

# Or filter by status code
feroxbuster -u http://192.168.1.10 -w wordlist.txt -C 404,403
```

### 9.2 Rate Limiting / WAF

```bash
# Problem: Getting rate limited
# Solution: Reduce threads and add rate limit
feroxbuster -u http://192.168.1.10 -w wordlist.txt -t 10 --rate-limit 10

# Add delay between requests
feroxbuster -u http://192.168.1.10 -w wordlist.txt --rate-limit 20
```

### 9.3 SSL/TLS Errors

```bash
# Problem: Certificate errors
# Solution: Ignore SSL verification
feroxbuster -u https://192.168.1.10 -w wordlist.txt -k
```

### 9.4 Recursion Too Deep

```bash
# Problem: Scan taking forever (too much recursion)
# Solution: Limit depth
feroxbuster -u http://192.168.1.10 -w wordlist.txt -d 2

# Or disable recursion
feroxbuster -u http://192.168.1.10 -w wordlist.txt -n
```

### 9.5 Performance Issues

```bash
# Problem: Too slow
# Solution: Increase threads
feroxbuster -u http://192.168.1.10 -w wordlist.txt -t 200

# Use HEAD instead of GET (faster)
feroxbuster -u http://192.168.1.10 -w wordlist.txt -m HEAD

# Use smaller wordlist
feroxbuster -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt
```

---

## 10. Quick Reference

### 10.1 Essential Options

```bash
# BASIC
feroxbuster -u URL -w WORDLIST                 # Basic scan
feroxbuster -u URL -w WORDLIST -x php,html     # With extensions
feroxbuster -u URL -w WORDLIST -t 50           # 50 threads
feroxbuster -u URL -w WORDLIST -n              # No recursion
feroxbuster -u URL -w WORDLIST -d 2            # Recursion depth 2
feroxbuster -u URL -w WORDLIST -q              # Quiet mode
feroxbuster -u URL -w WORDLIST --silent        # Silent (only URLs)

# FILTERING
-s 200,301,302              # Match status codes
-C 404                      # Filter status codes
-S 1234                     # Filter size
-W 50                       # Filter words
-N 100                      # Filter lines
-X "regex"                  # Filter regex

# AUTHENTICATION
-U user:pass                # Basic Auth
-H "Authorization: Bearer TOKEN"  # Bearer token
-b "session=abc123"         # Cookie

# OUTPUT
-o file.txt                 # Output file
--json                      # JSON format
--no-color                  # No colors

# PERFORMANCE
-t 100                      # Threads (default: 50)
-T 10                       # Timeout seconds
--rate-limit 50             # Rate limit (req/sec)

# SSL/TLS
-k                          # Ignore SSL errors

# PROXY
-p http://proxy:8080        # HTTP proxy
-p socks5://proxy:1080      # SOCKS5 proxy
--replay-proxy http://127.0.0.1:8080  # Replay proxy (Burp)

# METHODS
-m GET                      # HTTP method (default)
-m HEAD                     # HEAD method (faster)

# HEADERS
-a "Mozilla/5.0"            # User-Agent
-H "Header: value"          # Custom header

# SCAN MANAGEMENT
--stdin                     # Read URLs from stdin
--resume-from STATE         # Resume scan
--time-limit 10m            # Time limit
```

### 10.2 Common Commands

```bash
# Basic recursive scan
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -t 50

# With extensions
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 50

# Deep recursion (depth 3)
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -d 3 -t 50

# Backup files
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x bak,backup,old,~ -t 50

# Config files
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x conf,config,cfg,ini -t 50

# No recursion (like gobuster)
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -n -t 50

# Silent output (only URLs)
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt --silent -o urls.txt

# With proxy (Burp)
feroxbuster -u http://TARGET -w wordlist.txt -p http://127.0.0.1:8080
```

### 10.3 Wordlist Recommendations

```bash
# Small (fast) - 220 words
/usr/share/wordlists/dirb/common.txt

# Medium - 2,000+ words
/usr/share/wordlists/dirb/big.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Large (slow) - 200,000+ words
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# API
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# CMS-specific
/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt
```

---

## 11. OSCP Tips

**Basic Workflow:**
```bash
# 1. Fast recursive scan
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -t 50

# 2. Add extensions based on tech stack
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50

# 3. If time permits, larger wordlist
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirb/big.txt -t 50
```

**Quick Checks:**
```bash
# Admin panels
feroxbuster -u http://TARGET -w <(echo -e "admin\nadmin.php\nadministrator") -t 50

# Backups
feroxbuster -u http://TARGET -w <(echo -e "backup.zip\ndb.sql\ndump.sql") -t 50

# Config files
feroxbuster -u http://TARGET -w <(echo -e ".git/config\n.env\nweb.config") -t 50
```

**Advantages over Gobuster/ffuf:**
- **Auto-recursive** - Finds subdirectories automatically
- **Auto-filter** - Handles wildcard responses smartly
- **Interactive** - Real-time stats (press ENTER)
- **Resume** - Can resume interrupted scans
- **Modern** - Fast (Rust), well-maintained

**When to use:**
- Large sites with many subdirectories
- Want automatic recursion
- Need to resume scans
- Want interactive progress

---

## 12. Resources

- **Feroxbuster GitHub**: https://github.com/epi052/feroxbuster
- **Documentation**: https://epi052.github.io/feroxbuster-docs/
- **SecLists**: https://github.com/danielmiessler/SecLists

---

## 13. Final Notes

**Für OSCP:**
- Feroxbuster = Fast Recursive Directory Fuzzer
- Key Feature: **Automatic Recursion**
- Essential Flags: `-t` (threads), `-x` (extensions), `-d` (depth)
- Auto-filters wildcard responses (smart!)
- Interactive controls (press ENTER for stats)
- Can resume scans (useful for long scans)

**Best Practice:**
1. Start with common.txt and recursion enabled
2. Use 50 threads (`-t 50`)
3. Add extensions based on tech stack (`-x php,html,txt`)
4. Limit recursion depth if needed (`-d 2`)
5. Use `-q` or `--silent` for clean output
6. Press ENTER during scan for real-time stats

**vs Gobuster vs ffuf:**
- **Gobuster**: Simple, stable, no recursion
- **ffuf**: Advanced filtering, auto-calibration, no recursion
- **Feroxbuster**: Auto-recursion, auto-filter, interactive, modern
- **OSCP**: All three work! Feroxbuster best for recursive discovery
