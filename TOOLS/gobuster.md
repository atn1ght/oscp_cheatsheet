# Gobuster - Directory/File Brute-Forcing Tool Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Directory Mode (dir)](#3-directory-mode-dir)
4. [DNS Mode (dns)](#4-dns-mode-dns)
5. [VHost Mode (vhost)](#5-vhost-mode-vhost)
6. [Fuzzing Mode (fuzz)](#6-fuzzing-mode-fuzz)
7. [S3 Bucket Mode (s3)](#7-s3-bucket-mode-s3)
8. [Advanced Options](#8-advanced-options)
9. [Common OSCP Patterns](#9-common-oscp-patterns)
10. [Troubleshooting](#10-troubleshooting)
11. [Quick Reference](#11-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux (bereits installiert)
gobuster version

# Manual Installation
go install github.com/OJ/gobuster/v3@latest

# Verify
gobuster -h
```

### 1.2 Wordlists

```bash
# Common Wordlist Locations
/usr/share/wordlists/dirb/
/usr/share/wordlists/dirbuster/
/usr/share/seclists/Discovery/Web-Content/

# Popular Wordlists
/usr/share/wordlists/dirb/common.txt                                    # Small, fast
/usr/share/wordlists/dirb/big.txt                                       # Medium
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt            # Large
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt  # Quality over quantity
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt      # Subdomains
```

---

## 2. Basic Concepts

### 2.1 Modes

```bash
# Gobuster has 5 main modes:
gobuster dir     # Directory/File enumeration
gobuster dns     # DNS subdomain enumeration
gobuster vhost   # Virtual host enumeration
gobuster fuzz    # Fuzzing (FUZZ keyword)
gobuster s3      # S3 bucket enumeration
```

### 2.2 Basic Syntax

```bash
gobuster <mode> [options]
```

---

## 3. Directory Mode (dir)

### 3.1 Basic Directory Fuzzing

```bash
# Simple directory fuzzing
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt

# With threads
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -t 50

# Quiet mode (only results)
gobuster dir -u http://192.168.1.10 -w wordlist.txt -q
```

### 3.2 File Extensions

```bash
# With specific extensions
gobuster dir -u http://192.168.1.10 -w wordlist.txt -x php,html,txt

# Multiple extensions
gobuster dir -u http://192.168.1.10 -w wordlist.txt -x php,html,txt,asp,aspx,jsp

# Backup files
gobuster dir -u http://192.168.1.10 -w wordlist.txt -x bak,backup,old,~
```

### 3.3 Status Codes

```bash
# Show specific status codes (default: 200,204,301,302,307,401,403)
gobuster dir -u http://192.168.1.10 -w wordlist.txt -s "200,204,301,302,307,401,403"

# Exclude status codes
gobuster dir -u http://192.168.1.10 -w wordlist.txt -b "404,403"

# Show all status codes
gobuster dir -u http://192.168.1.10 -w wordlist.txt -s "100-599"
```

### 3.4 Output

```bash
# Save output to file
gobuster dir -u http://192.168.1.10 -w wordlist.txt -o results.txt

# No color output
gobuster dir -u http://192.168.1.10 -w wordlist.txt --no-color

# Verbose output
gobuster dir -u http://192.168.1.10 -w wordlist.txt -v

# No progress
gobuster dir -u http://192.168.1.10 -w wordlist.txt --no-progress
```

---

## 4. DNS Mode (dns)

### 4.1 Basic DNS Enumeration

```bash
# Subdomain enumeration
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# With threads
gobuster dns -d example.com -w wordlist.txt -t 50

# Show IPs
gobuster dns -d example.com -w wordlist.txt -i
```

### 4.2 Custom DNS Server

```bash
# Use custom DNS server
gobuster dns -d example.com -w wordlist.txt -r 8.8.8.8

# Multiple DNS servers
gobuster dns -d example.com -w wordlist.txt -r 8.8.8.8,1.1.1.1
```

### 4.3 Wildcard Handling

```bash
# Show CNAMEs
gobuster dns -d example.com -w wordlist.txt --show-cname

# Wildcard check
gobuster dns -d example.com -w wordlist.txt --wildcard
```

---

## 5. VHost Mode (vhost)

### 5.1 Basic VHost Fuzzing

```bash
# Virtual host discovery
gobuster vhost -u http://192.168.1.10 -w wordlist.txt

# Append domain
gobuster vhost -u http://192.168.1.10 -w wordlist.txt --domain example.local

# With threads
gobuster vhost -u http://192.168.1.10 -w wordlist.txt -t 50
```

### 5.2 Filter Results

```bash
# Exclude length (filter false positives)
gobuster vhost -u http://192.168.1.10 -w wordlist.txt --exclude-length 1234

# Append domain to wordlist
gobuster vhost -u http://192.168.1.10 -w subdomains.txt --domain example.com --append-domain
```

---

## 6. Fuzzing Mode (fuzz)

### 6.1 Basic Fuzzing

```bash
# Fuzz with FUZZ keyword
gobuster fuzz -u http://192.168.1.10/FUZZ -w wordlist.txt

# Multiple FUZZ points
gobuster fuzz -u http://192.168.1.10/FUZZ/FUZZ2 -w wordlist1.txt,wordlist2.txt

# Exclude length
gobuster fuzz -u http://192.168.1.10/FUZZ -w wordlist.txt --exclude-length 1234
```

---

## 7. S3 Bucket Mode (s3)

### 7.1 S3 Bucket Enumeration

```bash
# S3 bucket discovery
gobuster s3 -w wordlist.txt

# Specific region
gobuster s3 -w wordlist.txt -r us-east-1

# Max files to list
gobuster s3 -w wordlist.txt -m 10
```

---

## 8. Advanced Options

### 8.1 Authentication

```bash
# Basic Auth
gobuster dir -u http://192.168.1.10 -w wordlist.txt -U username -P password

# Cookie
gobuster dir -u http://192.168.1.10 -w wordlist.txt -c "session=abc123"

# Custom headers
gobuster dir -u http://192.168.1.10 -w wordlist.txt -H "Authorization: Bearer TOKEN"
```

### 8.2 Proxy

```bash
# HTTP Proxy
gobuster dir -u http://192.168.1.10 -w wordlist.txt --proxy http://127.0.0.1:8080

# SOCKS5 Proxy
gobuster dir -u http://192.168.1.10 -w wordlist.txt --proxy socks5://127.0.0.1:1080
```

### 8.3 TLS/SSL

```bash
# Ignore certificate errors
gobuster dir -u https://192.168.1.10 -w wordlist.txt -k

# Client certificate
gobuster dir -u https://192.168.1.10 -w wordlist.txt --cert client.crt --key client.key
```

### 8.4 Performance

```bash
# Threads (default: 10)
gobuster dir -u http://192.168.1.10 -w wordlist.txt -t 50

# Timeout
gobuster dir -u http://192.168.1.10 -w wordlist.txt --timeout 10s

# Delay between requests
gobuster dir -u http://192.168.1.10 -w wordlist.txt --delay 100ms
```

### 8.5 User Agent

```bash
# Custom User-Agent
gobuster dir -u http://192.168.1.10 -w wordlist.txt -a "Mozilla/5.0"

# Random User-Agent
gobuster dir -u http://192.168.1.10 -w wordlist.txt --random-agent
```

### 8.6 Follow Redirects

```bash
# Follow redirects
gobuster dir -u http://192.168.1.10 -w wordlist.txt -r

# Expanded mode (show all redirect history)
gobuster dir -u http://192.168.1.10 -w wordlist.txt -e
```

---

## 9. Common OSCP Patterns

### 9.1 Pattern 1: Basic Directory Discovery

```bash
# Fast scan with common.txt
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -t 50 -q

# Medium scan
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/big.txt -t 50 -q

# Large scan (if time permits)
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -q
```

### 9.2 Pattern 2: File Discovery with Extensions

```bash
# PHP application
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50

# ASP.NET application
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -x asp,aspx,config -t 50

# JSP application
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -x jsp,jspx,do -t 50
```

### 9.3 Pattern 3: Backup File Discovery

```bash
# Look for backups
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt \
  -x bak,backup,old,~,zip,tar,tar.gz -t 50

# Common backup patterns
gobuster dir -u http://192.168.1.10 -w <(echo -e "backup\nbackup.zip\ndb.sql\ndump.sql\nsite.zip") -t 50
```

### 9.4 Pattern 4: Admin Panel Discovery

```bash
# Admin panels
gobuster dir -u http://192.168.1.10 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -s "200,204,301,302,307,401,403" -t 50 | grep -i admin

# Common admin paths
gobuster dir -u http://192.168.1.10 \
  -w <(echo -e "admin\nadmin.php\nadministrator\nbackend\nmanager\ncpanel\nwp-admin") -t 50
```

### 9.5 Pattern 5: Virtual Host Discovery

```bash
# VHost fuzzing on single IP
gobuster vhost -u http://192.168.1.10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --domain example.local --append-domain -t 50

# Common VHost names
gobuster vhost -u http://192.168.1.10 -w <(echo -e "admin\ntest\ndev\napi\ninternal") -t 50
```

### 9.6 Pattern 6: DNS Subdomain Enumeration

```bash
# Subdomain discovery
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Show IP addresses
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -i -t 50
```

### 9.7 Pattern 7: API Endpoint Discovery

```bash
# API versioning
gobuster dir -u http://192.168.1.10/api -w <(seq 1 10) -t 50

# API endpoints
gobuster dir -u http://192.168.1.10/api -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -t 50
```

### 9.8 Pattern 8: Config File Discovery

```bash
# Configuration files
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt \
  -x conf,config,cfg,ini,xml,yml,yaml,env -t 50

# .git directory
gobuster dir -u http://192.168.1.10 -w <(echo -e ".git\n.git/config\n.git/HEAD\n.gitignore") -t 50
```

---

## 10. Troubleshooting

### 10.1 Too Slow

```bash
# Problem: Scan too slow
# Solution: Increase threads
gobuster dir -u http://192.168.1.10 -w wordlist.txt -t 100

# Reduce wordlist size
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -t 50
```

### 10.2 Rate Limiting / WAF

```bash
# Problem: Getting rate limited or blocked
# Solution: Add delay
gobuster dir -u http://192.168.1.10 -w wordlist.txt -t 10 --delay 500ms

# Random User-Agent
gobuster dir -u http://192.168.1.10 -w wordlist.txt --random-agent
```

### 10.3 SSL/TLS Errors

```bash
# Problem: Certificate errors
# Solution: Skip certificate verification
gobuster dir -u https://192.168.1.10 -w wordlist.txt -k
```

### 10.4 False Positives

```bash
# Problem: Too many false positives
# Solution: Exclude status codes
gobuster dir -u http://192.168.1.10 -w wordlist.txt -b "404,403,400"

# Or show only specific codes
gobuster dir -u http://192.168.1.10 -w wordlist.txt -s "200,204,301,302"
```

### 10.5 VHost False Positives

```bash
# Problem: VHost scan shows everything
# Solution: Filter by response length
gobuster vhost -u http://192.168.1.10 -w wordlist.txt --exclude-length 1234

# Check baseline first
curl -H "Host: nonexistent.example.com" http://192.168.1.10 -I
# Note the Content-Length, then exclude it
```

---

## 11. Quick Reference

### 11.1 Essential Commands

```bash
# === DIRECTORY MODE ===
gobuster dir -u URL -w WORDLIST                        # Basic dir fuzzing
gobuster dir -u URL -w WORDLIST -x php,html,txt        # With extensions
gobuster dir -u URL -w WORDLIST -t 50                  # 50 threads
gobuster dir -u URL -w WORDLIST -s "200,301,302"       # Specific status codes
gobuster dir -u URL -w WORDLIST -b "404"               # Exclude status codes
gobuster dir -u URL -w WORDLIST -o output.txt          # Save to file
gobuster dir -u URL -w WORDLIST -k                     # Ignore SSL errors
gobuster dir -u URL -w WORDLIST -r                     # Follow redirects
gobuster dir -u URL -w WORDLIST -q                     # Quiet mode

# === DNS MODE ===
gobuster dns -d DOMAIN -w WORDLIST                     # Subdomain enumeration
gobuster dns -d DOMAIN -w WORDLIST -i                  # Show IPs
gobuster dns -d DOMAIN -w WORDLIST -r 8.8.8.8          # Custom DNS server

# === VHOST MODE ===
gobuster vhost -u URL -w WORDLIST                      # VHost discovery
gobuster vhost -u URL -w WORDLIST --domain example.com --append-domain
gobuster vhost -u URL -w WORDLIST --exclude-length 1234

# === AUTHENTICATION ===
gobuster dir -u URL -w WORDLIST -U user -P pass        # Basic Auth
gobuster dir -u URL -w WORDLIST -c "session=abc123"    # Cookie
gobuster dir -u URL -w WORDLIST -H "Authorization: Bearer TOKEN"

# === PROXY ===
gobuster dir -u URL -w WORDLIST --proxy http://127.0.0.1:8080

# === PERFORMANCE ===
gobuster dir -u URL -w WORDLIST -t 100                 # Threads
gobuster dir -u URL -w WORDLIST --timeout 10s          # Timeout
gobuster dir -u URL -w WORDLIST --delay 100ms          # Delay

# === USER AGENT ===
gobuster dir -u URL -w WORDLIST -a "Custom-Agent"      # Custom UA
gobuster dir -u URL -w WORDLIST --random-agent         # Random UA
```

### 11.2 Common Wordlist Paths

```bash
# Small (fast)
/usr/share/wordlists/dirb/common.txt

# Medium
/usr/share/wordlists/dirb/big.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Large (slow)
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Subdomains
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# API
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

### 11.3 One-Liners

```bash
# Quick directory scan
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -t 50 -q

# With common extensions
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50 -q

# VHost discovery
gobuster vhost -u http://TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 50

# Subdomain enumeration
gobuster dns -d TARGET.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Backup files
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x bak,backup,old,~ -t 50
```

---

## 12. OSCP Tips

**Basic Workflow:**
```bash
# 1. Fast scan with common.txt
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -t 50 -q

# 2. Add extensions based on web server
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -t 50 -q

# 3. If time permits, larger wordlist
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/big.txt -t 50 -q
```

**Quick Checks:**
```bash
# Admin panels
gobuster dir -u http://TARGET -w <(echo -e "admin\nadmin.php\nadministrator\nbackup") -t 50

# Backups
gobuster dir -u http://TARGET -w <(echo -e "backup.zip\ndb.sql\ndump.sql\nsite.zip") -t 50

# Common files
gobuster dir -u http://TARGET -w <(echo -e "robots.txt\nsitemap.xml\n.git/config\n.env") -t 50
```

**Performance:**
- Start with common.txt (220 words) - very fast
- Use `-t 50` for 50 threads (good balance)
- Use `-q` for quiet output (only results)
- Add extensions with `-x` based on technology stack
- Save results with `-o` for later review

---

## 13. Resources

- **Gobuster GitHub**: https://github.com/OJ/gobuster
- **SecLists**: https://github.com/danielmiessler/SecLists
- **HackTricks - Gobuster**: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/gobuster

---

## 14. Final Notes

**Für OSCP:**
- Gobuster = Fast Directory/File/VHost Brute-Forcer
- Essential Flags: `-t` (threads), `-x` (extensions), `-q` (quiet)
- Always start with common.txt (fast!)
- Add extensions based on tech stack
- Use VHost mode for multi-site servers
- Save results with `-o`

**Best Practice:**
1. Start with small wordlist (common.txt)
2. Use 50 threads (`-t 50`)
3. Add extensions (`-x php,html,txt`)
4. Quiet mode (`-q`) for clean output
5. Save results (`-o results.txt`)
6. Increase wordlist if needed (big.txt)

**vs ffuf:**
- Gobuster: Simpler syntax, stable, no auto-calibration
- ffuf: More features, auto-calibration, better filtering
- OSCP: Both work fine, use what you're comfortable with!
