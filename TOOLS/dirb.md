# dirb - Web Content Scanner Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Basic Usage](#3-basic-usage)
4. [Wordlists](#4-wordlists)
5. [File Extensions](#5-file-extensions)
6. [Authentication](#6-authentication)
7. [Custom Headers](#7-custom-headers)
8. [Output Options](#8-output-options)
9. [Advanced Options](#9-advanced-options)
10. [Performance Tuning](#10-performance-tuning)
11. [Common OSCP Patterns](#11-common-oscp-patterns)
12. [Troubleshooting](#12-troubleshooting)
13. [Quick Reference](#13-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux (already installed)
dirb

# Debian/Ubuntu
sudo apt install dirb

# Verify installation
which dirb
dirb -h
```

### 1.2 Basic Syntax

```bash
dirb <URL> [WORDLIST] [OPTIONS]
```

---

## 2. Basic Concepts

### 2.1 What is dirb?

**dirb** is a web content scanner that launches dictionary-based attacks against web servers to discover hidden directories and files. It's one of the oldest and most reliable directory brute-forcing tools.

**Key Features:**
- **Built-in wordlists**: Comes with curated wordlists
- **Recursive scanning**: Automatically scans discovered directories
- **Extension support**: Test multiple file extensions
- **Authentication**: Supports Basic/Digest/NTLM auth
- **Custom headers**: Add cookies, User-Agent, etc.

**Compared to alternatives:**
- **dirb**: Older, simpler, built-in wordlists, recursive by default
- **gobuster**: Faster (Go-based), more flexible, no recursion by default
- **ffuf**: Fastest, most flexible, requires more configuration
- **feroxbuster**: Fast, recursive by default, auto-wildcard filtering

### 2.2 How It Works

1. Takes a wordlist of common directory/file names
2. Appends each word to the base URL
3. Makes HTTP request for each URL
4. Identifies valid paths based on response codes
5. Recursively scans discovered directories (by default)

### 2.3 Default Behavior

- **Wordlist**: Uses built-in wordlist if none specified
- **Extensions**: Tests only directories (no file extensions)
- **Recursion**: Enabled by default
- **Speed**: Single-threaded (slow compared to modern tools)
- **Method**: GET requests

---

## 3. Basic Usage

### 3.1 Simple Scan

```bash
# Basic scan with default wordlist
dirb http://192.168.1.10

# Scan with custom wordlist
dirb http://192.168.1.10 /usr/share/wordlists/dirb/common.txt

# Scan HTTPS site (ignore SSL errors)
dirb https://192.168.1.10
```

### 3.2 Output Format

```bash
# Example output:
# -----------------
# DIRB v2.22
# By The Dark Raver
# -----------------
#
# START_TIME: Thu Jan 15 10:00:00 2025
# URL_BASE: http://192.168.1.10/
# WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
#
# -----------------
#
# GENERATED WORDS: 4612
#
# ---- Scanning URL: http://192.168.1.10/ ----
# + http://192.168.1.10/admin (CODE:200|SIZE:1234)
# + http://192.168.1.10/backup (CODE:200|SIZE:5678)
# ==> DIRECTORY: http://192.168.1.10/images/
# + http://192.168.1.10/login.php (CODE:200|SIZE:890)
#
# ---- Entering directory: http://192.168.1.10/images/ ----
# (Recursive scan continues...)
```

### 3.3 Stop Scanning

```bash
# Press Ctrl+C to stop
# dirb will display results found so far
```

---

## 4. Wordlists

### 4.1 Built-in Wordlists

dirb comes with several built-in wordlists in `/usr/share/dirb/wordlists/`:

```bash
# List dirb wordlists
ls -lh /usr/share/dirb/wordlists/

# Common wordlists:
/usr/share/dirb/wordlists/common.txt         # ~4600 entries (default)
/usr/share/dirb/wordlists/big.txt            # ~20,000 entries
/usr/share/dirb/wordlists/small.txt          # ~959 entries
/usr/share/dirb/wordlists/catala.txt         # Catalan words
/usr/share/dirb/wordlists/spanish.txt        # Spanish words
/usr/share/dirb/wordlists/vulns/             # Vulnerability-specific lists
```

### 4.2 Common Wordlists

```bash
# Small wordlist (fast)
dirb http://192.168.1.10 /usr/share/dirb/wordlists/small.txt

# Default (common)
dirb http://192.168.1.10 /usr/share/dirb/wordlists/common.txt

# Large wordlist (thorough)
dirb http://192.168.1.10 /usr/share/dirb/wordlists/big.txt

# SecLists (if installed)
dirb http://192.168.1.10 /usr/share/seclists/Discovery/Web-Content/common.txt
dirb http://192.168.1.10 /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### 4.3 Vulnerability-Specific Wordlists

```bash
# Vulnerability wordlists
ls /usr/share/dirb/wordlists/vulns/

# Examples:
dirb http://192.168.1.10 /usr/share/dirb/wordlists/vulns/apache.txt
dirb http://192.168.1.10 /usr/share/dirb/wordlists/vulns/iis.txt
dirb http://192.168.1.10 /usr/share/dirb/wordlists/vulns/tomcat.txt
dirb http://192.168.1.10 /usr/share/dirb/wordlists/vulns/jboss.txt
dirb http://192.168.1.10 /usr/share/dirb/wordlists/vulns/websphere.txt
```

---

## 5. File Extensions

### 5.1 Add Extensions

```bash
# Test file extensions
dirb http://192.168.1.10 /usr/share/dirb/wordlists/common.txt -X .php

# Multiple extensions
dirb http://192.168.1.10 /usr/share/dirb/wordlists/common.txt -X .php,.html,.txt

# Common combinations:
# PHP applications:
dirb http://192.168.1.10 -X .php,.php3,.php4,.php5,.phps,.phtml

# ASP/ASPX applications:
dirb http://192.168.1.10 -X .asp,.aspx,.asmx,.ashx

# JSP applications:
dirb http://192.168.1.10 -X .jsp,.jspx,.jspa,.do

# General:
dirb http://192.168.1.10 -X .php,.html,.txt,.bak,.old,.zip
```

### 5.2 Extension Examples

```bash
# When you specify -X .php:
# dirb tests:
# http://192.168.1.10/admin      (directory)
# http://192.168.1.10/admin.php  (file with extension)
```

---

## 6. Authentication

### 6.1 HTTP Basic Authentication

```bash
# Basic Auth with username and password
dirb http://192.168.1.10 -u username:password

# Example
dirb http://192.168.1.10/admin -u admin:P@ssw0rd
```

### 6.2 HTTP Digest Authentication

```bash
# Digest Auth (rarely used)
# dirb doesn't have explicit digest support
# Use curl or gobuster instead for digest auth
```

### 6.3 NTLM Authentication

```bash
# NTLM Auth (Windows)
# dirb doesn't support NTLM directly
# Use curl or specialized tools
```

### 6.4 Cookie-Based Authentication

```bash
# Send cookies
dirb http://192.168.1.10 -c "PHPSESSID=abc123; security=low"

# Example with multiple cookies
dirb http://192.168.1.10 -c "session=xyz789; user=admin"
```

---

## 7. Custom Headers

### 7.1 User-Agent

```bash
# Custom User-Agent
dirb http://192.168.1.10 -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Common User-Agents:
dirb http://192.168.1.10 -a "Mozilla/5.0"  # Generic
```

### 7.2 Custom Headers

```bash
# Add custom header
dirb http://192.168.1.10 -H "X-Forwarded-For: 127.0.0.1"

# Multiple headers (not directly supported in dirb)
# Use gobuster or ffuf for multiple custom headers
```

### 7.3 Referer

```bash
# Custom Referer header
dirb http://192.168.1.10 -H "Referer: http://allowed-site.com"
```

---

## 8. Output Options

### 8.1 Save Output to File

```bash
# Save results to file
dirb http://192.168.1.10 -o output.txt

# Save with timestamp
dirb http://192.168.1.10 -o dirb_$(date +%Y%m%d_%H%M%S).txt
```

### 8.2 Silent Mode

```bash
# Silent mode (less verbose)
dirb http://192.168.1.10 -S

# Useful for scripting
```

### 8.3 Fine-Grained Output

```bash
# Show response codes only
dirb http://192.168.1.10 | grep "CODE:"

# Filter for specific codes
dirb http://192.168.1.10 | grep "CODE:200"
```

---

## 9. Advanced Options

### 9.1 Disable Recursion

```bash
# Disable recursive scanning
dirb http://192.168.1.10 -r

# Useful for faster, non-recursive scans
```

### 9.2 Case-Insensitive

```bash
# Case-insensitive search
dirb http://192.168.1.10 -i

# Tests both Admin and admin
```

### 9.3 Ignore Wildcards

```bash
# Don't search in pages with wildcard responses
dirb http://192.168.1.10 -N 404

# Ignore specific response codes
```

### 9.4 Proxy

```bash
# Use HTTP proxy
dirb http://192.168.1.10 -p http://127.0.0.1:8080

# Useful for sending traffic through Burp Suite
dirb http://192.168.1.10 -p http://127.0.0.1:8080 -z 100
```

### 9.5 Delay Between Requests

```bash
# Add delay (milliseconds) between requests
dirb http://192.168.1.10 -z 100

# 100ms delay
# Useful to avoid rate limiting or detection
```

### 9.6 Fine-Tune Scanning

```bash
# Only show specific response codes
dirb http://192.168.1.10 -v

# Don't show warnings
dirb http://192.168.1.10 -w

# Ignore case
dirb http://192.168.1.10 -i
```

---

## 10. Performance Tuning

### 10.1 Speed Considerations

dirb is **single-threaded** and slower than modern alternatives:
- **dirb**: ~1-5 requests/second
- **gobuster**: ~50-200 requests/second
- **ffuf**: ~50-500+ requests/second
- **feroxbuster**: ~50-200 requests/second

### 10.2 Faster Alternatives

```bash
# If speed is critical, use:

# gobuster (faster)
gobuster dir -u http://192.168.1.10 -w /usr/share/dirb/wordlists/common.txt -t 50

# ffuf (fastest)
ffuf -u http://192.168.1.10/FUZZ -w /usr/share/dirb/wordlists/common.txt -t 50

# feroxbuster (fast + recursive)
feroxbuster -u http://192.168.1.10 -w /usr/share/dirb/wordlists/common.txt -t 50
```

### 10.3 When to Use dirb

Use dirb when:
- You want automatic recursion (simplicity)
- Speed is not critical
- You prefer a simple, stable tool
- You're following an older tutorial

Use alternatives when:
- Speed is important (OSCP exam time limit!)
- You need more control (filtering, matching)
- You want modern features (auto-calibration, etc.)

---

## 11. Common OSCP Patterns

### 11.1 Pattern 1: Quick Initial Scan

```bash
# Fast initial scan
dirb http://192.168.1.10 /usr/share/dirb/wordlists/small.txt -o dirb_initial.txt

# Check results
cat dirb_initial.txt | grep "CODE:200\|CODE:301"
```

### 11.2 Pattern 2: Comprehensive Scan

```bash
# Thorough scan with common wordlist
dirb http://192.168.1.10 /usr/share/dirb/wordlists/common.txt -X .php,.html,.txt -o dirb_full.txt

# Or use big wordlist (takes longer)
dirb http://192.168.1.10 /usr/share/dirb/wordlists/big.txt -X .php -o dirb_big.txt
```

### 11.3 Pattern 3: PHP Application

```bash
# PHP application enumeration
dirb http://192.168.1.10 /usr/share/dirb/wordlists/common.txt -X .php,.php3,.php5,.inc,.bak -o dirb_php.txt

# Look for:
# - config.php.bak (backup files)
# - admin.php
# - login.php
# - upload.php
```

### 11.4 Pattern 4: With Authentication

```bash
# Authenticated scan (after login)
dirb http://192.168.1.10/admin -c "PHPSESSID=abc123; security=low" -o dirb_authenticated.txt

# Or with Basic Auth
dirb http://192.168.1.10/admin -u admin:password -o dirb_admin.txt
```

### 11.5 Pattern 5: Through Burp Suite

```bash
# Send requests through Burp (for manual analysis)
dirb http://192.168.1.10 -p http://127.0.0.1:8080 -z 100

# Burp will capture all requests
# Useful for:
# - Manual verification
# - Finding SQL injection, XSS
# - Analyzing responses
```

### 11.6 Pattern 6: Specific Technology

```bash
# Apache server
dirb http://192.168.1.10 /usr/share/dirb/wordlists/vulns/apache.txt -o dirb_apache.txt

# IIS server
dirb http://192.168.1.10 /usr/share/dirb/wordlists/vulns/iis.txt -X .asp,.aspx -o dirb_iis.txt

# Tomcat
dirb http://192.168.1.10 /usr/share/dirb/wordlists/vulns/tomcat.txt -X .jsp -o dirb_tomcat.txt
```

### 11.7 Pattern 7: Backup Files

```bash
# Search for backup files
dirb http://192.168.1.10 /usr/share/dirb/wordlists/common.txt -X .bak,.old,.backup,.txt,.zip -o dirb_backups.txt

# Look for:
# - index.php.bak
# - config.php.old
# - backup.zip
# - database.sql.txt
```

---

## 12. Troubleshooting

### 12.1 Too Slow

```bash
# Problem: dirb is too slow

# Solution 1: Use smaller wordlist
dirb http://192.168.1.10 /usr/share/dirb/wordlists/small.txt

# Solution 2: Disable recursion
dirb http://192.168.1.10 -r

# Solution 3: Use faster tool
gobuster dir -u http://192.168.1.10 -w /usr/share/dirb/wordlists/common.txt -t 50
```

### 12.2 Too Many False Positives

```bash
# Problem: All paths return 200 OK (wildcard responses)

# Solution 1: Manually identify false positive size
# Check a random URL:
curl -I http://192.168.1.10/randomstring123

# Solution 2: Use tool with auto-filtering
ffuf -u http://192.168.1.10/FUZZ -w wordlist.txt -fs 1234  # Filter by size
feroxbuster -u http://192.168.1.10 -w wordlist.txt        # Auto-filters
```

### 12.3 SSL Certificate Errors

```bash
# Problem: SSL certificate verification fails

# dirb automatically ignores SSL errors
# No additional flags needed

# Verify with curl
curl -k https://192.168.1.10
```

### 12.4 Rate Limiting / WAF

```bash
# Problem: Getting blocked by WAF or rate limiting

# Solution 1: Add delay
dirb http://192.168.1.10 -z 500  # 500ms delay

# Solution 2: Change User-Agent
dirb http://192.168.1.10 -a "Mozilla/5.0 (Windows NT 10.0)"

# Solution 3: Use proxy/VPN
# If getting IP banned
```

---

## 13. Quick Reference

### 13.1 Basic Commands

```bash
# BASIC USAGE
dirb <URL>                                  # Default scan
dirb <URL> <WORDLIST>                       # Custom wordlist
dirb <URL> <WORDLIST> -X .ext               # With extensions

# COMMON OPTIONS
-o <file>                                   # Save output
-X .ext1,.ext2                              # Test file extensions
-u user:pass                                # HTTP Basic Auth
-c "cookie1=val1; cookie2=val2"             # Send cookies
-a "User-Agent"                             # Custom User-Agent
-H "Header: value"                          # Custom header
-p http://proxy:port                        # Use proxy
-z <milliseconds>                           # Delay between requests
-r                                          # Disable recursion
-i                                          # Case-insensitive
-S                                          # Silent mode
-w                                          # Don't show warnings
-v                                          # Verbose
```

### 13.2 Common Wordlists

```bash
# DIRB BUILT-IN
/usr/share/dirb/wordlists/small.txt         # ~959 entries (fast)
/usr/share/dirb/wordlists/common.txt        # ~4600 entries (default)
/usr/share/dirb/wordlists/big.txt           # ~20,000 entries (thorough)

# SECLISTS (if installed)
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# TECHNOLOGY-SPECIFIC
/usr/share/dirb/wordlists/vulns/apache.txt
/usr/share/dirb/wordlists/vulns/iis.txt
/usr/share/dirb/wordlists/vulns/tomcat.txt
```

### 13.3 Essential OSCP Commands

```bash
# Quick initial scan
dirb http://192.168.1.10 /usr/share/dirb/wordlists/small.txt

# Comprehensive scan
dirb http://192.168.1.10 /usr/share/dirb/wordlists/common.txt -X .php,.html,.txt -o dirb_out.txt

# PHP application
dirb http://192.168.1.10 -X .php,.bak,.old

# With authentication
dirb http://192.168.1.10 -u admin:password
dirb http://192.168.1.10 -c "PHPSESSID=abc123"

# Through Burp Suite
dirb http://192.168.1.10 -p http://127.0.0.1:8080

# Non-recursive (faster)
dirb http://192.168.1.10 -r
```

### 13.4 File Extensions by Technology

```bash
# PHP
-X .php,.php3,.php4,.php5,.phps,.phtml,.inc

# ASP/ASPX
-X .asp,.aspx,.asmx,.ashx

# JSP
-X .jsp,.jspx,.jspa,.do,.action

# Perl
-X .pl,.cgi

# Backup files
-X .bak,.old,.backup,.txt,.zip,.tar,.gz

# General
-X .php,.html,.txt,.bak,.old
```

---

## 14. Resources

- **dirb Homepage**: https://dirb.sourceforge.net/
- **Kali Tools - dirb**: https://www.kali.org/tools/dirb/
- **Alternative Tools**: gobuster, ffuf, feroxbuster, dirsearch

---

## 15. Final Notes

**Für OSCP:**
- **Simple**: Easy to use, built-in wordlists
- **Recursive**: Automatically scans discovered directories
- **Slower**: Single-threaded, consider alternatives for time-constrained exams
- **Reliable**: Stable, well-tested tool
- **Extensions**: Use `-X` flag to test multiple file extensions

**Best Practices:**
1. Start with small wordlist for quick results
2. Use extensions relevant to the technology (`-X .php` for PHP apps)
3. Save output to file with `-o` flag
4. Disable recursion (`-r`) for faster initial scans
5. Use proxy (`-p`) to send traffic through Burp Suite
6. Add delays (`-z`) if getting rate-limited
7. Consider faster alternatives (gobuster, ffuf) for OSCP time constraints

**When to Use dirb:**
- ✅ You want automatic recursion
- ✅ You prefer simple, straightforward tools
- ✅ Speed is not critical
- ✅ You're comfortable with the classic tool

**When to Use Alternatives:**
- ❌ Speed is important (OSCP exam!)
- ❌ You need advanced filtering (wildcard responses)
- ❌ You want more control over scanning behavior
- ❌ You need modern features (auto-calibration, etc.)

**Common Workflow:**
1. Initial scan: `dirb http://TARGET /usr/share/dirb/wordlists/small.txt`
2. Review results for interesting directories
3. Comprehensive scan: `dirb http://TARGET -X .php,.html,.txt -o output.txt`
4. Manually verify discovered paths
5. Use Burp Suite for detailed analysis of interesting findings

**Remember:** dirb is a reconnaissance tool. Discovery is just the first step - always manually verify and analyze discovered content for potential vulnerabilities!
