# DirBuster - GUI Web Content Scanner Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [GUI Interface](#3-gui-interface)
4. [Basic Scanning](#4-basic-scanning)
5. [Wordlists](#5-wordlists)
6. [File Extensions](#6-file-extensions)
7. [Authentication](#7-authentication)
8. [Advanced Options](#8-advanced-options)
9. [Results Analysis](#9-results-analysis)
10. [Headless Mode (CLI)](#10-headless-mode-cli)
11. [Common OSCP Patterns](#11-common-oscp-patterns)
12. [Troubleshooting](#12-troubleshooting)
13. [Quick Reference](#13-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux (already installed)
dirbuster

# Check if installed
which dirbuster
ls /usr/share/dirbuster/

# Manual installation (if needed)
sudo apt install dirbuster

# Alternative: Use DirBuster JAR directly
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar
```

### 1.2 Launch DirBuster

```bash
# Launch GUI
dirbuster

# Launch with Java (alternative)
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar

# Headless mode (CLI)
dirbuster -H
```

### 1.3 System Requirements

- Java Runtime Environment (JRE)
- Minimum 512MB RAM
- GUI support (X11) for graphical mode

---

## 2. Basic Concepts

### 2.1 What is DirBuster?

**DirBuster** is a multi-threaded Java application designed to brute-force directories and files on web/application servers. It was developed by OWASP but is now **retired/unmaintained**.

**Key Features:**
- **GUI interface**: User-friendly graphical interface
- **Multi-threaded**: Configurable number of threads (faster than dirb)
- **Built-in wordlists**: Comes with OWASP wordlists
- **Recursive scanning**: Optionally scan discovered directories
- **Result tree view**: Visual representation of discovered structure
- **Fuzzing mode**: Can brute-force with character patterns

**Status:**
- ⚠️ **Retired**: No longer actively maintained by OWASP
- ⚠️ **Legacy**: Replaced by modern alternatives (gobuster, ffuf, feroxbuster)
- ✅ **Still functional**: Works fine but consider alternatives

### 2.2 Why Use Alternatives?

**Modern alternatives are better:**
- **gobuster**: Faster (Go-based), CLI-only, actively maintained
- **ffuf**: Fastest, most flexible, extensive filtering options
- **feroxbuster**: Fast (Rust-based), recursive, auto-wildcard detection
- **dirsearch**: Python-based, actively maintained, good features

**When to use DirBuster:**
- Learning/education (understand concepts)
- You prefer GUI over CLI
- Following older tutorials
- Already familiar with it

### 2.3 Comparison with Alternatives

| Tool | Language | Speed | GUI | Maintained | Recursion |
|------|----------|-------|-----|------------|-----------|
| **DirBuster** | Java | Medium | ✅ | ❌ | Optional |
| **gobuster** | Go | Fast | ❌ | ✅ | ❌ |
| **ffuf** | Go | Very Fast | ❌ | ✅ | ❌ |
| **feroxbuster** | Rust | Fast | ❌ | ✅ | ✅ (default) |
| **dirb** | C | Slow | ❌ | ⚠️ | ✅ (default) |

---

## 3. GUI Interface

### 3.1 Main Window

When you launch DirBuster, you'll see:

1. **Target URL** field
2. **Work Method** (Auto Switch, HEAD, GET)
3. **Number of Threads** slider
4. **Wordlist selection**
5. **File extension** input
6. **Start/Stop** buttons
7. **Results pane** (tree view)
8. **Response viewer**

### 3.2 Target Configuration

**Target URL:**
- Enter full URL: `http://192.168.1.10`
- Include port if non-standard: `http://192.168.1.10:8080`
- HTTPS: `https://192.168.1.10`

**Work Method:**
- **Auto Switch**: Try HEAD first, fallback to GET (recommended)
- **HEAD**: Faster, but some servers don't support properly
- **GET**: Slower, but more reliable

### 3.3 Thread Configuration

**Number of Threads:**
- Default: 10 threads
- Range: 1-500+
- Recommended: 20-50 threads for most targets
- Higher threads = faster, but may trigger rate limiting

**Trade-offs:**
- More threads → Faster scanning
- More threads → Higher detection risk
- More threads → May overload target/network

---

## 4. Basic Scanning

### 4.1 Simple Scan (GUI)

1. Launch DirBuster: `dirbuster`
2. Enter target URL: `http://192.168.1.10`
3. Select work method: **Auto Switch (HEAD and GET)**
4. Set threads: **20-50**
5. Choose wordlist:
   - Click "Browse" under "File with list of dirs/files"
   - Navigate to `/usr/share/dirbuster/wordlists/`
   - Select wordlist (e.g., `directory-list-2.3-medium.txt`)
6. (Optional) Enter file extensions: `php,html,txt`
7. Click **Start**

### 4.2 Monitor Progress

**While scanning:**
- Progress bar shows percentage complete
- Results tree updates in real-time
- Response codes displayed: 200, 301, 302, 403, etc.
- Can pause/resume with **Pause** button
- Stop with **Stop** button

### 4.3 Recursive Scanning

**Enable recursion:**
- Check "**Be Recursive**" checkbox
- DirBuster will automatically scan discovered directories
- Can significantly increase scan time

**Recursion depth:**
- No built-in depth limit
- Can result in very long scans
- Monitor progress and stop when needed

---

## 5. Wordlists

### 5.1 Built-in Wordlists

DirBuster includes OWASP wordlists in `/usr/share/dirbuster/wordlists/`:

```bash
# List DirBuster wordlists
ls -lh /usr/share/dirbuster/wordlists/

# Common wordlists:
directory-list-1.0.txt          # ~141,000 entries
directory-list-2.3-small.txt    # ~87,000 entries
directory-list-2.3-medium.txt   # ~220,000 entries (recommended)
directory-list-2.3-big.txt      # ~1.2 million entries
directory-list-lowercase-2.3-small.txt
directory-list-lowercase-2.3-medium.txt
directory-list-lowercase-2.3-big.txt

# Apache-specific
apache-user-enum-1.0.txt
apache-user-enum-2.0.txt
```

### 5.2 Wordlist Selection

**For OSCP:**
- **Quick scan**: `directory-list-2.3-small.txt` (~10-30 min)
- **Standard scan**: `directory-list-2.3-medium.txt` (~30-90 min)
- **Thorough scan**: `directory-list-2.3-big.txt` (hours)

**Alternative wordlists:**
```bash
# SecLists (if installed)
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt

# dirb wordlists (smaller, faster)
/usr/share/dirb/wordlists/common.txt         # ~4600 entries (fast)
/usr/share/dirb/wordlists/big.txt            # ~20,000 entries
```

### 5.3 Custom Wordlists

You can use any custom wordlist:
1. Click "Browse"
2. Navigate to your custom wordlist
3. Select file
4. Start scan

---

## 6. File Extensions

### 6.1 Add Extensions

**In GUI:**
1. Locate "**File extension**" field
2. Enter extensions separated by commas: `php,html,txt`
3. DirBuster will test each word with each extension

**Example:**
- Wordlist entry: `admin`
- Extensions: `php,html`
- Tests:
  - `http://192.168.1.10/admin` (directory)
  - `http://192.168.1.10/admin.php`
  - `http://192.168.1.10/admin.html`

### 6.2 Common Extensions

**By Technology:**

```bash
# PHP applications
php,php3,php4,php5,phps,phtml,inc

# ASP/ASPX applications
asp,aspx,asmx,ashx

# JSP applications
jsp,jspx,jspa,do,action

# Perl
pl,cgi

# General/Backup files
txt,bak,old,backup,zip,tar,gz

# Configuration files
conf,config,xml,json,yml,yaml

# Common combination for OSCP
php,html,txt,bak,old
```

### 6.3 Blank Extensions

**Check "**Use blank extension**" to test:**
- `http://192.168.1.10/admin` (no extension)
- `http://192.168.1.10/admin.php`
- `http://192.168.1.10/admin.html`

---

## 7. Authentication

### 7.1 HTTP Basic Authentication

**In GUI:**
1. Go to **Options** → **Authentication**
2. Select **Basic Authentication**
3. Enter **Username**
4. Enter **Password**
5. Click **OK**
6. Start scan

### 7.2 HTTP Digest Authentication

**In GUI:**
1. Go to **Options** → **Authentication**
2. Select **Digest Authentication**
3. Enter credentials
4. Click **OK**

### 7.3 HTTP NTLM Authentication

**In GUI:**
1. Go to **Options** → **Authentication**
2. Select **NTLM Authentication**
3. Enter **Domain**, **Username**, **Password**
4. Click **OK**

### 7.4 Cookie-Based Authentication

**In GUI:**
1. Go to **Options** → **Advanced Options**
2. Find **HTTP Header to add**
3. Add cookie header:
   ```
   Cookie: PHPSESSID=abc123; security=low
   ```
4. Click **OK**

---

## 8. Advanced Options

### 8.1 Request Options

**In Options menu:**

**Headers:**
- Add custom headers (User-Agent, Referer, etc.)
- Example: `User-Agent: Mozilla/5.0`

**Proxy:**
- Configure HTTP proxy (e.g., Burp Suite)
- Proxy host: `127.0.0.1`
- Proxy port: `8080`

**Timeout:**
- Connection timeout (default: 10000ms)
- Increase if target is slow

### 8.2 Scan Options

**Scan Tuning:**
- **Scan Speed**: Adjust thread count
- **Recursion**: Enable/disable recursive scanning
- **Blank extension**: Test without file extensions
- **Case sensitivity**: Case-insensitive mode (rarely needed)

### 8.3 Response Codes

**Filter response codes:**
- By default, shows all codes
- Focus on interesting codes:
  - **200 OK**: Found
  - **301/302**: Redirect (may indicate protected resources)
  - **403 Forbidden**: Exists but access denied
  - **401 Unauthorized**: Requires authentication

**Hide codes:**
- Right-click response code in results
- Select "Don't show this response code"

---

## 9. Results Analysis

### 9.1 Results Tree

**Tree View:**
- Shows discovered directories/files hierarchically
- Green = Found (200)
- Blue = Redirect (301/302)
- Red = Forbidden (403)
- Yellow = Unauthorized (401)

**Interact with results:**
- Click on entry to see response
- Right-click for options:
  - Copy URL
  - Open in browser
  - Save response
  - Filter response code

### 9.2 Export Results

**Save results:**
1. Click **Report** menu
2. Select **Save Results**
3. Choose format:
   - Text file
   - HTML report
   - CSV

**Result file contains:**
- All discovered paths
- Response codes
- Response sizes
- Timestamps

### 9.3 Analyze Responses

**Response Viewer:**
- Click on discovered path
- View response headers
- View response body
- Identify interesting content

**Look for:**
- Configuration files
- Backup files (`.bak`, `.old`)
- Database files
- Admin panels
- Upload functionality
- API endpoints

---

## 10. Headless Mode (CLI)

### 10.1 Command-Line Interface

DirBuster supports headless (non-GUI) mode:

```bash
# Basic headless scan
dirbuster -H -u http://192.168.1.10 -l /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o output.txt

# With options
dirbuster -H -u http://192.168.1.10 -l wordlist.txt -t 50 -e php,html,txt -o results.txt
```

### 10.2 Headless Options

```bash
# COMMON OPTIONS
-H                      # Headless mode (no GUI)
-u <URL>                # Target URL
-l <wordlist>           # Wordlist file
-o <output>             # Output file
-t <threads>            # Number of threads
-e <extensions>         # File extensions (comma-separated)
-r                      # Recursive scan

# AUTHENTICATION
-U <username>           # Username (Basic Auth)
-P <password>           # Password (Basic Auth)

# ADVANCED
-x <proxy>              # Proxy (e.g., http://127.0.0.1:8080)
-v                      # Verbose output
```

### 10.3 Headless Examples

```bash
# Basic scan
dirbuster -H -u http://192.168.1.10 -l /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -o output.txt

# With extensions
dirbuster -H -u http://192.168.1.10 -l wordlist.txt -e php,html,txt -t 30 -o results.txt

# Recursive scan
dirbuster -H -u http://192.168.1.10 -l wordlist.txt -r -o recursive_results.txt

# With authentication
dirbuster -H -u http://192.168.1.10 -l wordlist.txt -U admin -P password -o authenticated_results.txt

# Through proxy (Burp Suite)
dirbuster -H -u http://192.168.1.10 -l wordlist.txt -x http://127.0.0.1:8080 -o burp_results.txt
```

**Note:** Headless mode is functional but consider using modern alternatives (gobuster, ffuf) for better performance and features.

---

## 11. Common OSCP Patterns

### 11.1 Pattern 1: Standard GUI Scan

```
1. Launch: dirbuster
2. Target: http://192.168.1.10
3. Work Method: Auto Switch (HEAD and GET)
4. Threads: 30
5. Wordlist: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
6. Extensions: php,html,txt
7. Check: "Be Recursive"
8. Start scan
9. Monitor results in real-time
10. Export results when complete
```

### 11.2 Pattern 2: Quick Reconnaissance

```
1. Use smaller wordlist for speed
2. Wordlist: /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
3. Extensions: php (only)
4. Threads: 50
5. Disable recursion (faster initial scan)
6. Review results
7. If needed, run deeper scan on interesting paths
```

### 11.3 Pattern 3: Through Burp Suite

```
1. Start Burp Suite (127.0.0.1:8080)
2. Configure browser to use Burp proxy
3. In DirBuster: Options → Advanced Options
4. Set Proxy: 127.0.0.1:8080
5. Start scan
6. All requests captured in Burp
7. Manually analyze interesting findings in Burp
```

### 11.4 Pattern 4: Authenticated Scan

```
1. Manually login to application in browser
2. Capture session cookie (from browser dev tools)
3. In DirBuster: Options → Advanced Options
4. Add header: Cookie: PHPSESSID=abc123
5. Scan authenticated areas (e.g., /admin, /dashboard)
6. Discover privileged functionality
```

### 11.5 Pattern 5: Technology-Specific Scan

```
# PHP Application
- Extensions: php,php3,php5,inc,bak
- Look for: config.php, admin.php, upload.php

# ASP/ASPX Application
- Extensions: asp,aspx,asmx
- Look for: admin.aspx, login.asp

# Java/JSP Application
- Extensions: jsp,do,action
- Wordlist: /usr/share/dirbuster/wordlists/apache-user-enum-2.0.txt
```

### 11.6 Pattern 6: Backup File Discovery

```
1. Standard scan first
2. Note discovered PHP files (e.g., config.php, login.php)
3. New scan with backup extensions:
   - Extensions: bak,old,backup,txt,zip,tar,gz
4. Look for:
   - config.php.bak
   - index.php.old
   - backup.zip
   - database.sql.txt
```

---

## 12. Troubleshooting

### 12.1 DirBuster Won't Launch

```bash
# Problem: DirBuster doesn't start

# Check Java installation
java -version

# Install Java if missing
sudo apt install default-jre

# Try launching with Java directly
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar

# Check for errors in terminal
```

### 12.2 Too Many False Positives

```bash
# Problem: Everything returns 200 OK (wildcard responses)

# Solution 1: Manually test random URL
curl http://192.168.1.10/randomstring123
# Note the response size

# Solution 2: In results, filter by size
# Right-click results → Sort by size
# Identify common size for false positives
# Ignore those results

# Solution 3: Use modern tool with auto-filtering
feroxbuster -u http://192.168.1.10 -w wordlist.txt
```

### 12.3 Scan Too Slow

```bash
# Problem: Scan taking too long

# Solution 1: Increase threads
# Slide thread count to 50-100

# Solution 2: Use smaller wordlist
# Switch to directory-list-2.3-small.txt

# Solution 3: Disable recursion
# Uncheck "Be Recursive"

# Solution 4: Use faster tool
gobuster dir -u http://192.168.1.10 -w wordlist.txt -t 50
ffuf -u http://192.168.1.10/FUZZ -w wordlist.txt -t 50
```

### 12.4 Getting Rate Limited

```bash
# Problem: Target blocking requests

# Solution 1: Reduce threads
# Lower thread count to 5-10

# Solution 2: Add delay (not directly supported)
# Consider using alternative tool:
ffuf -u http://192.168.1.10/FUZZ -w wordlist.txt -p 0.5  # 0.5 sec delay

# Solution 3: Change User-Agent
# Options → Advanced Options → Add header
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

### 12.5 Java Heap Space Error

```bash
# Problem: "Java heap space" error with large wordlists

# Solution: Increase Java heap size
java -Xmx2048m -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar

# Or use smaller wordlist
```

---

## 13. Quick Reference

### 13.1 GUI Quick Start

```
1. Launch: dirbuster
2. Target URL: http://192.168.1.10
3. Work Method: Auto Switch (HEAD and GET)
4. Threads: 30-50
5. Wordlist: Browse → /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
6. Extensions: php,html,txt (optional)
7. Options:
   - Check "Be Recursive" for deep scan
   - Check "Use blank extension" to test without extensions
8. Start
```

### 13.2 Headless Mode

```bash
# BASIC SYNTAX
dirbuster -H -u <URL> -l <wordlist> -o <output>

# COMMON OPTIONS
-H                              # Headless mode
-u <URL>                        # Target URL
-l <wordlist>                   # Wordlist path
-o <output>                     # Output file
-t <threads>                    # Number of threads
-e <ext1,ext2>                  # File extensions
-r                              # Recursive
-U <user> -P <pass>             # Basic Auth
-x <proxy>                      # Proxy (http://host:port)

# EXAMPLES
dirbuster -H -u http://192.168.1.10 -l /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o output.txt
dirbuster -H -u http://192.168.1.10 -l wordlist.txt -e php,html -t 50 -o results.txt
dirbuster -H -u http://192.168.1.10 -l wordlist.txt -r -o recursive.txt
```

### 13.3 Built-in Wordlists

```bash
# LOCATION
/usr/share/dirbuster/wordlists/

# COMMON LISTS
directory-list-2.3-small.txt        # ~87K entries (fast)
directory-list-2.3-medium.txt       # ~220K entries (recommended)
directory-list-2.3-big.txt          # ~1.2M entries (thorough)
directory-list-lowercase-2.3-medium.txt
apache-user-enum-1.0.txt
apache-user-enum-2.0.txt
```

### 13.4 Response Codes

```
200 OK              Found (interesting!)
301 Moved           Redirect (may be interesting)
302 Found           Redirect
401 Unauthorized    Requires authentication (interesting!)
403 Forbidden       Exists but access denied (interesting!)
404 Not Found       Not found (ignore)
500 Internal Error  Server error (may be interesting)
```

### 13.5 File Extensions by Technology

```
PHP:        php,php3,php4,php5,phps,phtml,inc
ASP/ASPX:   asp,aspx,asmx,ashx
JSP:        jsp,jspx,jspa,do,action
Perl:       pl,cgi
Backup:     bak,old,backup,txt,zip,tar,gz
Config:     conf,config,xml,json,yml,yaml
General:    php,html,txt,bak,old
```

---

## 14. Resources

- **OWASP (Original)**: https://owasp.org/www-community/tools/DirBuster (archived)
- **SourceForge**: https://sourceforge.net/projects/dirbuster/
- **Alternatives**:
  - gobuster: https://github.com/OJ/gobuster
  - ffuf: https://github.com/ffuf/ffuf
  - feroxbuster: https://github.com/epi052/feroxbuster
  - dirsearch: https://github.com/maurosoria/dirsearch

---

## 15. Final Notes

**Für OSCP:**
- ⚠️ **Legacy tool**: DirBuster is retired/unmaintained
- ✅ **Still works**: Functional but consider modern alternatives
- ✅ **GUI**: User-friendly if you prefer graphical interface
- ❌ **Speed**: Slower than modern alternatives (gobuster, ffuf)
- ✅ **Learning**: Good for understanding directory brute-forcing concepts

**Modern Alternative Recommendations:**
1. **gobuster** - Fast, reliable, CLI-only (recommended for OSCP)
2. **ffuf** - Fastest, most flexible, extensive filtering
3. **feroxbuster** - Fast, recursive by default, auto-wildcard filtering
4. **dirsearch** - Python-based, actively maintained, good balance

**Best Practices:**
1. Use medium wordlist for standard scans
2. Add relevant file extensions for target technology
3. Enable recursion for thorough enumeration
4. Export results for offline analysis
5. Verify interesting findings manually
6. Consider using faster alternatives for time-constrained exams

**When to Use DirBuster:**
- Learning/education purposes
- You prefer GUI over CLI
- Following older tutorials that reference it
- Not time-constrained

**When to Use Alternatives:**
- OSCP exam (speed matters!)
- Modern pentesting engagements
- Need advanced filtering/matching
- Want actively maintained tools

**Common Workflow:**
1. Launch DirBuster with medium wordlist and common extensions
2. Start scan and monitor in real-time
3. Identify interesting paths (200, 301, 403)
4. Export results for documentation
5. Manually verify discovered content
6. Use Burp Suite for detailed analysis of findings

**Remember:** DirBuster is just for discovery. Finding directories/files is step one - always manually analyze discovered content for vulnerabilities!
