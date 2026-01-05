# enum4linux-ng - SMB/NetBIOS Enumeration Tool Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Basic Usage](#3-basic-usage)
4. [Authentication](#4-authentication)
5. [Enumeration Modules](#5-enumeration-modules)
6. [Output Formats](#6-output-formats)
7. [Advanced Options](#7-advanced-options)
8. [Common OSCP Patterns](#8-common-oscp-patterns)
9. [Troubleshooting](#9-troubleshooting)
10. [Quick Reference](#10-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux (install if not present)
sudo apt install enum4linux-ng

# Alternative: Install from GitHub
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt

# Verify installation
enum4linux-ng -h
```

### 1.2 Dependencies

```bash
# Required dependencies
sudo apt install smbclient ldapsearch

# Python requirements
pip3 install ldap3 pyyaml impacket
```

### 1.3 Basic Syntax

```bash
enum4linux-ng [options] <target>
```

---

## 2. Basic Concepts

### 2.1 What is enum4linux-ng?

**enum4linux-ng** is a next-generation rewrite of enum4linux (a Linux alternative to Windows enum.exe), written in Python. It's designed to enumerate information from Windows and Samba systems.

**Key Features:**
- **Comprehensive enumeration**: Users, groups, shares, policies, printers
- **Multiple protocols**: SMB, LDAP, RPC
- **Null session support**: Works without credentials on misconfigured systems
- **JSON/YAML output**: Machine-readable formats
- **Colored output**: Easy-to-read terminal display
- **Modern codebase**: Python 3, actively maintained

**vs Original enum4linux:**
- ✅ Faster and more reliable
- ✅ Better output formatting (colors, JSON, YAML)
- ✅ More enumeration modules
- ✅ Better error handling
- ✅ Actively maintained

### 2.2 How It Works

enum4linux-ng uses multiple protocols to gather information:
1. **SMB/CIFS** (port 445): Share enumeration, OS info
2. **RPC** (port 135/445): User/group enumeration, password policy
3. **LDAP** (port 389/636): Domain information, users, groups

### 2.3 What Can Be Enumerated?

- Target information (OS, domain, workgroup)
- RPC/SMB sessions (null session check)
- Domain information (domain name, SID, password policy)
- Users and groups (domain users, local users, groups)
- Shares (network shares and permissions)
- Password policy (complexity, lockout, history)
- Printers
- Group policy information

---

## 3. Basic Usage

### 3.1 Simple Scan

```bash
# Basic enumeration (null session)
enum4linux-ng 192.168.1.10

# Verbose output
enum4linux-ng -v 192.168.1.10

# All enumeration (comprehensive)
enum4linux-ng -A 192.168.1.10
```

### 3.2 Example Output

```bash
# Example output structure:
# ========================================
#  Target Information
# ========================================
# Target: 192.168.1.10
# RID Range: 500-550,1000-1050
# Credentials: guest session
#
# ========================================
#  SMB Dialect Check
# ========================================
# [*] Trying on 445/tcp
#     [+] Supported dialects and settings:
#         SMB 1.0: true
#         SMB 2.02: true
#
# ========================================
#  Domain Information
# ========================================
# Domain: WORKGROUP
# Domain SID: NULL SID
#
# ========================================
#  Users
# ========================================
# user:[Administrator] rid:[0x1f4]
# user:[Guest] rid:[0x1f5]
# user:[john] rid:[0x450]
#
# ... (continues with groups, shares, etc.)
```

---

## 4. Authentication

### 4.1 Null Session (No Credentials)

```bash
# Null session (default)
enum4linux-ng 192.168.1.10

# Explicit null session
enum4linux-ng -u '' -p '' 192.168.1.10
```

### 4.2 With Credentials

```bash
# Username and password
enum4linux-ng -u 'username' -p 'password' 192.168.1.10

# Domain user
enum4linux-ng -u 'DOMAIN\username' -p 'password' 192.168.1.10

# Prompt for password (secure)
enum4linux-ng -u 'username' -p '' 192.168.1.10
# (Will prompt)
```

### 4.3 Pass-the-Hash

```bash
# NTLM hash
enum4linux-ng -u 'username' -H 'NTHASH' 192.168.1.10

# Full LM:NTLM hash
enum4linux-ng -u 'username' -H 'LMHASH:NTHASH' 192.168.1.10
```

---

## 5. Enumeration Modules

### 5.1 Comprehensive Enumeration

```bash
# All enumeration (-A)
enum4linux-ng -A 192.168.1.10

# Equivalent to: -U -G -S -P -O -N -I
```

### 5.2 Specific Modules

```bash
# User enumeration (-U)
enum4linux-ng -U 192.168.1.10

# Group enumeration (-G)
enum4linux-ng -G 192.168.1.10

# Share enumeration (-S)
enum4linux-ng -S 192.168.1.10

# Password policy (-P)
enum4linux-ng -P 192.168.1.10

# OS information (-O)
enum4linux-ng -O 192.168.1.10

# Printer information (-I)
enum4linux-ng -I 192.168.1.10

# RID cycling (-R)
enum4linux-ng -R 192.168.1.10
```

### 5.3 Combined Modules

```bash
# Users and groups
enum4linux-ng -U -G 192.168.1.10

# Users, groups, and shares
enum4linux-ng -U -G -S 192.168.1.10

# Users, password policy, shares
enum4linux-ng -U -P -S 192.168.1.10
```

---

## 6. Output Formats

### 6.1 Terminal Output (Default)

```bash
# Standard colored output
enum4linux-ng 192.168.1.10

# Verbose output
enum4linux-ng -v 192.168.1.10

# Debug output
enum4linux-ng -vv 192.168.1.10
```

### 6.2 JSON Output

```bash
# JSON format
enum4linux-ng -oJ output.json 192.168.1.10

# All enumeration to JSON
enum4linux-ng -A -oJ full_enum.json 192.168.1.10
```

### 6.3 YAML Output

```bash
# YAML format
enum4linux-ng -oY output.yaml 192.168.1.10

# All enumeration to YAML
enum4linux-ng -A -oY full_enum.yaml 192.168.1.10
```

### 6.4 Combined Output

```bash
# Both JSON and terminal
enum4linux-ng -oJ output.json 192.168.1.10

# Both YAML and terminal
enum4linux-ng -oY output.yaml 192.168.1.10
```

---

## 7. Advanced Options

### 7.1 RID Cycling

```bash
# RID cycling (enumerate users via RID brute force)
enum4linux-ng -R 192.168.1.10

# Custom RID range
enum4linux-ng -R -r 500-600,1000-1100 192.168.1.10

# Default range: 500-550,1000-1050
```

### 7.2 Known Usernames

```bash
# Use known usernames file
enum4linux-ng -K users.txt 192.168.1.10

# Example users.txt:
# administrator
# admin
# guest
# john
# jane
```

### 7.3 Timeout Settings

```bash
# Set timeout (seconds)
enum4linux-ng -t 5 192.168.1.10

# Default: 5 seconds
```

### 7.4 Workgroup/Domain

```bash
# Specify workgroup
enum4linux-ng -w WORKGROUP 192.168.1.10

# Specify domain
enum4linux-ng -w DOMAIN 192.168.1.10
```

---

## 8. Common OSCP Patterns

### 8.1 Pattern 1: Initial SMB Enumeration

```bash
# Step 1: Quick check (null session)
enum4linux-ng 192.168.1.10

# Step 2: If null session works, comprehensive enum
enum4linux-ng -A 192.168.1.10 | tee enum4linux_output.txt

# Step 3: Save to JSON for later analysis
enum4linux-ng -A -oJ enum4linux.json 192.168.1.10
```

### 8.2 Pattern 2: Extract Usernames

```bash
# Enumerate users and save to file
enum4linux-ng -U 192.168.1.10 | grep 'user:' | cut -d'[' -f2 | cut -d']' -f1 > users.txt

# Or with RID cycling for more users
enum4linux-ng -R -r 500-1500 192.168.1.10 | grep 'user:' | cut -d'[' -f2 | cut -d']' -f1 > users_full.txt
```

### 8.3 Pattern 3: Password Policy Check

```bash
# CRITICAL: Check before password spray attacks!
enum4linux-ng -P 192.168.1.10

# Look for:
# - Minimum password length
# - Password complexity
# - Lockout threshold (if > 0, be careful!)
# - Lockout duration

# Example output:
# [+] Password Policy:
#     min_password_length: 7
#     password_complexity: enabled
#     lockout_threshold: 5     # DANGER! Only 5 attempts
#     lockout_duration: 30 min
```

### 8.4 Pattern 4: Share Enumeration

```bash
# Enumerate shares
enum4linux-ng -S 192.168.1.10

# Look for:
# - Non-default shares (interesting!)
# - Writable shares
# - Read permissions

# Example finding:
# Share: Backups (READ, WRITE)  # <- Interesting!
```

### 8.5 Pattern 5: With Valid Credentials

```bash
# Enumerate with credentials
enum4linux-ng -u 'john' -p 'Password123!' -A 192.168.1.10 -oJ authenticated_enum.json

# Look for:
# - More users/groups (authenticated access shows more)
# - Domain SID (for Golden Ticket attacks)
# - Privileged group members (Domain Admins, etc.)
```

### 8.6 Pattern 6: Domain Controller Enumeration

```bash
# Enumerate Domain Controller
enum4linux-ng -A 192.168.1.10 | tee dc_enum.txt

# Look for:
# - Domain name
# - Domain SID (S-1-5-21-...)
# - Domain users
# - Domain Admins group members
# - Password policy
# - Trust relationships
```

### 8.7 Pattern 7: Automated Enumeration Script

```bash
#!/bin/bash
TARGET=$1

echo "[+] Starting enum4linux-ng enumeration on $TARGET"

# Null session enumeration
echo "[*] Trying null session..."
enum4linux-ng $TARGET -oJ ${TARGET}_null.json

# Password policy
echo "[*] Checking password policy..."
enum4linux-ng -P $TARGET

# User enumeration with RID cycling
echo "[*] Enumerating users..."
enum4linux-ng -U -R $TARGET | grep 'user:' | cut -d'[' -f2 | cut -d']' -f1 > ${TARGET}_users.txt

echo "[+] Results saved:"
echo "    - JSON: ${TARGET}_null.json"
echo "    - Users: ${TARGET}_users.txt"
```

---

## 9. Troubleshooting

### 9.1 Access Denied

```bash
# Problem: "SMB SessionError: STATUS_ACCESS_DENIED"

# Cause 1: Null session disabled
# Solution: Use valid credentials
enum4linux-ng -u 'username' -p 'password' 192.168.1.10

# Cause 2: Firewall blocking
# Check if port 445 is open
nmap -p445 192.168.1.10
```

### 9.2 Connection Timeout

```bash
# Problem: Connection timeout errors

# Solution 1: Increase timeout
enum4linux-ng -t 10 192.168.1.10

# Solution 2: Check connectivity
ping 192.168.1.10
nmap -p445,139,135 192.168.1.10
```

### 9.3 No Results from Enumeration

```bash
# Problem: Enumeration returns no users/groups

# Cause 1: Null session disabled (modern Windows)
# Solution: Requires valid credentials

# Cause 2: RPC/LDAP disabled
# Try different enumeration methods

# Cause 3: Insufficient privileges
# Use admin credentials if available
```

### 9.4 Module Import Errors

```bash
# Problem: "ModuleNotFoundError: No module named 'ldap3'"

# Solution: Install dependencies
pip3 install ldap3 pyyaml impacket

# Or reinstall
pip3 install -r requirements.txt
```

---

## 10. Quick Reference

### 10.1 Basic Commands

```bash
# BASIC USAGE
enum4linux-ng <target>                          # Basic enumeration
enum4linux-ng -A <target>                       # All enumeration
enum4linux-ng -v <target>                       # Verbose

# AUTHENTICATION
enum4linux-ng -u 'user' -p 'pass' <target>      # With credentials
enum4linux-ng -u 'DOMAIN\user' -p 'pass' <target>  # Domain user
enum4linux-ng -u 'user' -H 'HASH' <target>      # Pass-the-Hash

# MODULES
-A              All enumeration (equivalent to -U -G -S -P -O -N -I)
-U              User enumeration
-G              Group enumeration
-S              Share enumeration
-P              Password policy
-O              OS information
-I              Printer information
-R              RID cycling
-N              LDAP enumeration

# OUTPUT
-oJ <file>      JSON output
-oY <file>      YAML output
-v              Verbose
-vv             Debug

# ADVANCED
-r <range>      RID range (e.g., 500-600,1000-1100)
-K <file>       Known usernames file
-t <seconds>    Timeout
-w <workgroup>  Workgroup/Domain
```

### 10.2 Essential OSCP Commands

```bash
# Quick null session check
enum4linux-ng 192.168.1.10

# Comprehensive enumeration
enum4linux-ng -A 192.168.1.10 | tee enum_output.txt

# Password policy (BEFORE password spray!)
enum4linux-ng -P 192.168.1.10

# User enumeration to file
enum4linux-ng -U -R 192.168.1.10 | grep 'user:' | cut -d'[' -f2 | cut -d']' -f1 > users.txt

# With credentials
enum4linux-ng -u 'admin' -p 'P@ssw0rd' -A 192.168.1.10

# Save to JSON
enum4linux-ng -A -oJ enum4linux.json 192.168.1.10
```

### 10.3 Enumeration Checklist

**Step 1: Null Session Check**
```bash
enum4linux-ng 192.168.1.10
```

**Step 2: Password Policy (CRITICAL!)**
```bash
enum4linux-ng -P 192.168.1.10
# Note lockout threshold!
```

**Step 3: User Enumeration**
```bash
enum4linux-ng -U -R 192.168.1.10 > users.txt
```

**Step 4: Share Enumeration**
```bash
enum4linux-ng -S 192.168.1.10
# Identify writable/readable shares
```

**Step 5: Comprehensive Enum (if time permits)**
```bash
enum4linux-ng -A 192.168.1.10 -oJ full_enum.json
```

### 10.4 Output Parsing

```bash
# Extract usernames
enum4linux-ng -U 192.168.1.10 | grep 'user:' | cut -d'[' -f2 | cut -d']' -f1 > users.txt

# Extract groups
enum4linux-ng -G 192.168.1.10 | grep 'group:' | cut -d'[' -f2 | cut -d']' -f1 > groups.txt

# Extract shares
enum4linux-ng -S 192.168.1.10 | grep 'Sharename:' | awk '{print $2}'

# Check for Domain Admins
enum4linux-ng -G 192.168.1.10 | grep -i "domain admins" -A 5
```

---

## 11. Resources

- **GitHub Repository**: https://github.com/cddmp/enum4linux-ng
- **Original enum4linux**: https://github.com/CiscoCXSecurity/enum4linux
- **HackTricks**: https://book.hacktricks.xyz/pentesting/pentesting-smb

---

## 12. Final Notes

**Für OSCP:**
- **Essential tool**: SMB enumeration is critical for Windows boxes
- **Null session**: Always try first (works on older systems)
- **Password policy**: CHECK BEFORE password attacks to avoid lockout!
- **User list**: Extract for targeted password spray
- **Modern alternative**: Faster and better than original enum4linux

**Best Practices:**
1. Always check password policy before password attacks
2. Extract user list to file for later use
3. Save output to JSON/YAML for offline analysis
4. Check for non-default shares (high-value targets)
5. Note Domain SID for advanced attacks
6. Document all findings for exam report

**Common Workflow:**
1. Check if SMB is open: `nmap -p445 192.168.1.10`
2. Run enum4linux-ng: `enum4linux-ng -A 192.168.1.10 | tee output.txt`
3. Check password policy: Look for lockout threshold
4. Extract users: Save to users.txt for password spray
5. Enumerate shares: Identify interesting shares for smbclient
6. If authenticated: Re-run with credentials for more info

**OSCP Tips:**
- Works on Windows 2000/2003/XP with null sessions
- Modern Windows (2012+) usually blocks null sessions
- Combine with smbclient, rpcclient, CrackMapExec
- Domain Controllers: Check for SYSVOL/NETLOGON shares
- Always document lockout policy in exam report
- JSON output useful for parsing with scripts/tools

**vs Other Tools:**
- **enum4linux-ng** > enum4linux (faster, better output)
- **rpcclient**: More manual, specific RPC queries
- **smbclient**: For file operations, not enumeration
- **CrackMapExec**: For credential validation and lateral movement
- **NetExec**: Modern CrackMapExec alternative

**Remember:** enum4linux-ng is for reconnaissance only. It doesn't exploit - it gathers information for planning your attack strategy. Always combine with other tools for complete picture!
