# smbclient - SMB Client Tool Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Connection & Authentication](#3-connection--authentication)
4. [Share Enumeration](#4-share-enumeration)
5. [File Operations](#5-file-operations)
6. [Directory Operations](#6-directory-operations)
7. [Interactive Commands](#7-interactive-commands)
8. [Non-Interactive Mode](#8-non-interactive-mode)
9. [Advanced Options](#9-advanced-options)
10. [Common OSCP Patterns](#10-common-oscp-patterns)
11. [Troubleshooting](#11-troubleshooting)
12. [Quick Reference](#12-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux (already installed)
smbclient --version

# Debian/Ubuntu
sudo apt install smbclient

# Verify installation
which smbclient
```

### 1.2 Basic Syntax

```bash
# List shares
smbclient -L //TARGET [options]

# Connect to share
smbclient //TARGET/SHARE [options]

# Non-interactive command execution
smbclient //TARGET/SHARE -c "command" [options]
```

---

## 2. Basic Concepts

### 2.1 What is smbclient?

**smbclient** is a command-line SMB/CIFS client from the Samba suite that allows interaction with Windows file shares and printers. It provides an FTP-like interface for accessing SMB shares.

**Key Features:**
- **Share enumeration**: List available shares on target
- **File operations**: Upload/download files
- **Directory browsing**: Navigate share directories
- **Null session support**: Connect without credentials (on misconfigured systems)
- **Interactive mode**: FTP-like shell for share interaction
- **Non-interactive mode**: Execute commands via scripts

**Common Use Cases:**
- Enumerate SMB shares (null session or with credentials)
- Download/upload files to/from shares
- Search for sensitive files in shares
- Test share permissions
- Exfiltrate data

### 2.2 SMB Ports

- **Port 445**: SMB over TCP (modern)
- **Port 139**: SMB over NetBIOS (legacy)

### 2.3 Common Share Names

**Default Windows Shares:**
- `C$` - Administrative share (C: drive) - requires admin
- `ADMIN$` - Windows directory - requires admin
- `IPC$` - Inter-Process Communication - used for enumeration
- `NETLOGON` - Domain logon scripts (Domain Controllers)
- `SYSVOL` - Domain Group Policy files (Domain Controllers)
- Custom shares - User-created shares

---

## 3. Connection & Authentication

### 3.1 Null Session (No Credentials)

```bash
# Null session (anonymous)
smbclient -L //192.168.1.10 -N

# Alternative formats
smbclient -L //192.168.1.10 -U "" -N
smbclient -L //192.168.1.10 --no-pass

# UNC path format
smbclient -L \\\\192.168.1.10 -N
```

### 3.2 Guest Account

```bash
# Guest with no password
smbclient -L //192.168.1.10 -U 'guest' -N

# Guest with password
smbclient -L //192.168.1.10 -U 'guest%password'
```

### 3.3 With Credentials

```bash
# Username and password
smbclient -L //192.168.1.10 -U 'username%password'

# Prompt for password
smbclient -L //192.168.1.10 -U 'username'

# Domain user
smbclient -L //192.168.1.10 -U 'DOMAIN/username%password'
smbclient -L //192.168.1.10 -U 'username%password' -W DOMAIN
```

### 3.4 Pass-the-Hash

```bash
# Pass-the-Hash (SMB authentication)
smbclient -L //192.168.1.10 -U 'username%HASH' --pw-nt-hash

# Example with full hash
smbclient -L //192.168.1.10 -U 'admin%aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' --pw-nt-hash

# Note: Provide full LM:NTLM hash or just NTLM hash
```

---

## 4. Share Enumeration

### 4.1 List Shares

```bash
# List all shares (null session)
smbclient -L //192.168.1.10 -N

# List shares with credentials
smbclient -L //192.168.1.10 -U 'username%password'

# Detailed output
smbclient -L //192.168.1.10 -N -d 3
```

### 4.2 Interpret Share Listing

```bash
# Example output:
#
# Sharename       Type      Comment
# ---------       ----      -------
# ADMIN$          Disk      Remote Admin
# C$              Disk      Default share
# IPC$            IPC       Remote IPC
# Users           Disk      User files
# Backups         Disk      Backup files
#
# Server          Comment
# ------          -------
# FILE-SERVER     Samba Server
#
# Workgroup       Master
# ---------       ------
# WORKGROUP       FILE-SERVER
```

**Share Types:**
- **Disk**: File share (most common)
- **IPC**: Inter-Process Communication (for RPC)
- **Printer**: Printer share

**Interesting Shares:**
- Custom shares (Users, Backups, Shared, Data, etc.)
- Administrative shares (C$, ADMIN$) - if accessible
- SYSVOL, NETLOGON (on Domain Controllers)

### 4.3 Connect to Share

```bash
# Connect to specific share
smbclient //192.168.1.10/Users -N

# With credentials
smbclient //192.168.1.10/Users -U 'username%password'

# Administrative share (requires admin)
smbclient //192.168.1.10/C$ -U 'admin%password'
```

---

## 5. File Operations

### 5.1 Download Files

```bash
# In interactive mode:
smb: \> get filename.txt

# Download to specific path
smb: \> get filename.txt /tmp/filename.txt

# Download all files in directory (recursive)
smb: \> prompt off
smb: \> recurse on
smb: \> mget *

# Non-interactive download
smbclient //192.168.1.10/Users -N -c "get filename.txt"
```

### 5.2 Upload Files

```bash
# Upload file
smb: \> put /tmp/file.txt

# Upload to specific name
smb: \> put /tmp/local.txt remote.txt

# Upload multiple files
smb: \> prompt off
smb: \> mput *.txt

# Non-interactive upload
smbclient //192.168.1.10/Users -N -c "put /tmp/file.txt"
```

### 5.3 Delete Files

```bash
# Delete file
smb: \> del filename.txt

# Delete multiple files
smb: \> prompt off
smb: \> mdel *.txt
```

---

## 6. Directory Operations

### 6.1 Navigate Directories

```bash
# List directory contents
smb: \> ls
smb: \> dir

# Change directory
smb: \> cd folder

# Go up one level
smb: \> cd ..

# Show current directory
smb: \> pwd

# List with details
smb: \> ls -la
```

### 6.2 Create/Remove Directories

```bash
# Create directory
smb: \> mkdir newfolder

# Remove directory
smb: \> rmdir folder

# Remove directory with contents (use mget to backup first)
smb: \> recurse on
smb: \> prompt off
smb: \> mget foldername\*
smb: \> # Then delete files
```

### 6.3 Search for Files

```bash
# Search for specific files
smb: \> ls *.txt
smb: \> ls *password*

# Recursive search (in interactive mode)
smb: \> recurse on
smb: \> ls *.kdbx        # KeePass databases
smb: \> ls *.sql         # SQL dumps
smb: \> ls *password*    # Password files
smb: \> ls *.config      # Config files
```

---

## 7. Interactive Commands

### 7.1 Basic Commands

```bash
# FILE OPERATIONS
ls / dir            List files/directories
get <file>          Download file
put <file>          Upload file
mget <pattern>      Download multiple files
mput <pattern>      Upload multiple files
del <file>          Delete file
mdel <pattern>      Delete multiple files

# DIRECTORY OPERATIONS
cd <dir>            Change directory
pwd                 Print working directory
mkdir <dir>         Create directory
rmdir <dir>         Remove directory

# SETTINGS
prompt              Toggle prompting for mget/mput
recurse             Toggle recursive mode
lowercase           Toggle lowercase filenames

# OTHER
!<cmd>              Execute local shell command
help / ?            Show help
exit / quit         Exit smbclient
```

### 7.2 Useful Options

```bash
# Disable prompting (for mget/mput)
smb: \> prompt off

# Enable recursive operations
smb: \> recurse on

# Show help
smb: \> help
smb: \> ? ls
```

---

## 8. Non-Interactive Mode

### 8.1 Execute Commands

```bash
# Single command
smbclient //192.168.1.10/Users -N -c "ls"

# Multiple commands (semicolon-separated)
smbclient //192.168.1.10/Users -N -c "cd Documents; ls; get file.txt"

# Download file non-interactively
smbclient //192.168.1.10/Users -N -c "get important.txt"

# Upload file non-interactively
smbclient //192.168.1.10/Users -U 'user%pass' -c "put exploit.exe"
```

### 8.2 Recursive Download

```bash
# Download all files recursively
smbclient //192.168.1.10/Users -N -c "prompt off; recurse on; mget *"

# Download specific directory
smbclient //192.168.1.10/Users -N -c "cd folder; prompt off; recurse on; mget *"
```

### 8.3 Scripting

```bash
# Create command file
cat > smb_commands.txt <<EOF
cd Documents
ls
get passwords.txt
exit
EOF

# Execute commands from file
smbclient //192.168.1.10/Users -N < smb_commands.txt

# Or use -c flag
smbclient //192.168.1.10/Users -N -c "$(cat smb_commands.txt)"
```

---

## 9. Advanced Options

### 9.1 Debug/Verbose Output

```bash
# Debug level (0-10, higher = more verbose)
smbclient -L //192.168.1.10 -N -d 3

# Typical levels:
# 0: Minimal output
# 1: Basic info
# 3: Detailed (recommended for troubleshooting)
# 10: Everything (very verbose)
```

### 9.2 Port Specification

```bash
# Connect on non-standard port
smbclient -L //192.168.1.10 -N -p 4445

# Specify port for share connection
smbclient //192.168.1.10/Users -N -p 4445
```

### 9.3 Workgroup/Domain

```bash
# Specify workgroup
smbclient -L //192.168.1.10 -W WORKGROUP -N

# Specify domain
smbclient -L //192.168.1.10 -W DOMAIN -U 'user%pass'
```

### 9.4 Client Name

```bash
# Specify client NetBIOS name
smbclient -L //192.168.1.10 -N -n CLIENTNAME
```

### 9.5 Timeout

```bash
# Set timeout (milliseconds)
smbclient -L //192.168.1.10 -N --timeout=10000
```

---

## 10. Common OSCP Patterns

### 10.1 Pattern 1: Initial Enumeration

```bash
# Step 1: Check if SMB is open
nmap -p445 192.168.1.10

# Step 2: Try null session share enumeration
smbclient -L //192.168.1.10 -N

# Step 3: If null session fails, try guest
smbclient -L //192.168.1.10 -U 'guest' -N

# Step 4: Note interesting shares (non-default)
# Look for: Users, Backups, Shared, Data, etc.
```

### 10.2 Pattern 2: Connect and Explore Share

```bash
# Connect to interesting share
smbclient //192.168.1.10/Users -N

# List contents
smb: \> ls

# Navigate and search for interesting files
smb: \> recurse on
smb: \> ls *.txt
smb: \> ls *password*
smb: \> ls *.config
smb: \> ls *.xml
smb: \> ls *.kdbx       # KeePass
smb: \> ls *.sql        # SQL dumps

# Download interesting files
smb: \> get passwords.txt
smb: \> get config.xml
```

### 10.3 Pattern 3: Recursive Download

```bash
# Download entire share contents
smbclient //192.168.1.10/Backups -N -c "prompt off; recurse on; mget *"

# Download to specific directory
mkdir -p /tmp/smb_loot
cd /tmp/smb_loot
smbclient //192.168.1.10/Backups -N -c "prompt off; recurse on; mget *"

# Then grep for interesting content
grep -r "password" .
grep -r "user" .
```

### 10.4 Pattern 4: With Valid Credentials

```bash
# List shares with credentials
smbclient -L //192.168.1.10 -U 'username%password'

# Try administrative shares
smbclient //192.168.1.10/C$ -U 'admin%password'
smbclient //192.168.1.10/ADMIN$ -U 'admin%password'

# If admin access, can read sensitive files
smb: \> get Windows/System32/config/SAM
smb: \> get Windows/System32/config/SYSTEM
```

### 10.5 Pattern 5: File Upload (for exploits)

```bash
# Upload webshell to web directory
smbclient //192.168.1.10/wwwroot -U 'user%pass' -c "put shell.php"

# Upload exploit
smbclient //192.168.1.10/Users -U 'user%pass' -c "put exploit.exe"

# Upload to writable share
smbclient //192.168.1.10/Public -N -c "put nc.exe"
```

### 10.6 Pattern 6: Search for Credentials

```bash
# Connect to share
smbclient //192.168.1.10/Users -N

# Search for credential-related files
smb: \> recurse on
smb: \> ls *pass*
smb: \> ls *credential*
smb: \> ls *secret*
smb: \> ls *.kdbx       # KeePass databases
smb: \> ls web.config   # ASP.NET config (may contain DB creds)
smb: \> ls *.config
smb: \> ls *.xml
smb: \> ls *.txt

# Download and grep locally
smb: \> prompt off
smb: \> mget *.txt
smb: \> exit
grep -i "password" *.txt
```

### 10.7 Pattern 7: Domain Controller Enumeration

```bash
# Connect to SYSVOL share (Group Policy)
smbclient //192.168.1.10/SYSVOL -U 'DOMAIN/user%pass'

# Look for Group Policy Preferences (GPP) passwords
smb: \> recurse on
smb: \> ls Groups.xml
smb: \> get Policies/*/Machine/Preferences/Groups/Groups.xml

# Connect to NETLOGON share (logon scripts)
smbclient //192.168.1.10/NETLOGON -U 'DOMAIN/user%pass'
smb: \> ls *.bat
smb: \> ls *.ps1
```

---

## 11. Troubleshooting

### 11.1 Connection Refused

```bash
# Problem: "Connection to 192.168.1.10 failed"

# Check 1: Verify SMB port is open
nmap -p445,139 192.168.1.10

# Check 2: Try different port
smbclient -L //192.168.1.10 -N -p 139

# Check 3: Verify target has SMB service
nmap -sV -p445 192.168.1.10
```

### 11.2 Access Denied

```bash
# Problem: "NT_STATUS_ACCESS_DENIED"

# Cause 1: Null session disabled
# Solution: Use valid credentials
smbclient -L //192.168.1.10 -U 'username%password'

# Cause 2: Guest access disabled
# Solution: Find valid credentials

# Cause 3: Share permissions
# Solution: Try different shares or use admin credentials
```

### 11.3 Logon Failure

```bash
# Problem: "NT_STATUS_LOGON_FAILURE"

# Cause: Invalid credentials
# Solutions:
# 1. Verify username/password
# 2. Try different credential formats:
smbclient -L //192.168.1.10 -U 'username%password'
smbclient -L //192.168.1.10 -U 'DOMAIN\username%password'
smbclient -L //192.168.1.10 -U 'username%password' -W DOMAIN

# 3. Check for account lockout
# 4. Verify domain name (if domain user)
```

### 11.4 Protocol Negotiation Failed

```bash
# Problem: "protocol negotiation failed"

# Solution 1: Specify SMB version
smbclient -L //192.168.1.10 -N --option='client min protocol=NT1'
smbclient -L //192.168.1.10 -N --option='client max protocol=SMB3'

# Solution 2: Edit /etc/samba/smb.conf
# Add under [global]:
# client min protocol = NT1
# client max protocol = SMB3

# Solution 3: Use specific protocol
smbclient -L //192.168.1.10 -N -m SMB2
smbclient -L //192.168.1.10 -N -m SMB3
```

### 11.5 Tree Connect Failed

```bash
# Problem: "tree connect failed: NT_STATUS_BAD_NETWORK_NAME"

# Cause: Invalid share name
# Solution: List shares first, verify exact name
smbclient -L //192.168.1.10 -N

# Share names are case-sensitive!
smbclient //192.168.1.10/Users -N      # Correct
smbclient //192.168.1.10/users -N      # May fail
```

---

## 12. Quick Reference

### 12.1 Connection Commands

```bash
# LIST SHARES
smbclient -L //TARGET -N                        # Null session
smbclient -L //TARGET -U 'guest' -N             # Guest
smbclient -L //TARGET -U 'user%pass'            # With credentials
smbclient -L //TARGET -U 'DOMAIN/user%pass'     # Domain user
smbclient -L //TARGET -U 'user%HASH' --pw-nt-hash  # Pass-the-Hash

# CONNECT TO SHARE
smbclient //TARGET/SHARE -N                     # Null session
smbclient //TARGET/SHARE -U 'user%pass'         # With credentials

# NON-INTERACTIVE
smbclient //TARGET/SHARE -N -c "command"        # Execute command
smbclient //TARGET/SHARE -N -c "cmd1; cmd2"     # Multiple commands

# DEBUG
smbclient -L //TARGET -N -d 3                   # Debug level 3
```

### 12.2 Interactive Commands

```bash
# NAVIGATION
ls / dir                List files
cd <dir>                Change directory
pwd                     Print working directory

# FILE OPERATIONS
get <file>              Download file
put <file>              Upload file
mget <pattern>          Download multiple files
mput <pattern>          Upload multiple files
del <file>              Delete file

# SETTINGS
prompt off              Disable prompting
recurse on              Enable recursive operations

# OTHER
!<cmd>                  Execute local shell command
help                    Show help
exit / quit             Exit
```

### 12.3 Common Options

```bash
# AUTHENTICATION
-N                      No password (null/guest)
-U user%pass            Username and password
-W DOMAIN               Workgroup/Domain
--pw-nt-hash            Pass-the-Hash mode

# CONNECTION
-p <port>               Port (default 445)
-m <protocol>           SMB protocol (SMB2, SMB3, NT1)
--timeout=<ms>          Connection timeout

# OUTPUT
-d <level>              Debug level (0-10)
-n <name>               Client NetBIOS name

# COMMANDS
-c "command"            Execute command
-L                      List shares
```

### 12.4 Essential OSCP Commands

```bash
# Enumerate shares (null session)
smbclient -L //192.168.1.10 -N

# Connect and explore
smbclient //192.168.1.10/Users -N

# Recursive file search
smb: \> recurse on
smb: \> ls *pass*

# Download all files
smb: \> prompt off
smb: \> recurse on
smb: \> mget *

# Non-interactive download
smbclient //192.168.1.10/Backups -N -c "prompt off; recurse on; mget *"

# Upload file
smbclient //192.168.1.10/Share -U 'user%pass' -c "put exploit.exe"

# With credentials
smbclient -L //192.168.1.10 -U 'admin%P@ssw0rd'

# Administrative share
smbclient //192.168.1.10/C$ -U 'admin%P@ssw0rd'
```

### 12.5 File Search Patterns

```bash
# CREDENTIALS
ls *pass*
ls *credential*
ls *secret*
ls *.kdbx          # KeePass databases

# CONFIGURATION
ls *.config
ls web.config      # ASP.NET (may have DB creds)
ls *.xml
ls *.ini

# BACKUPS
ls *.bak
ls *.old
ls *.backup
ls backup.*
ls *.sql

# SCRIPTS
ls *.bat
ls *.ps1
ls *.vbs

# DATABASES
ls *.mdb
ls *.accdb
ls *.db
ls *.sqlite
```

---

## 13. Resources

- **Samba Project**: https://www.samba.org/
- **smbclient Man Page**: `man smbclient`
- **HackTricks - SMB**: https://book.hacktricks.xyz/pentesting/pentesting-smb

---

## 14. Final Notes

**Für OSCP:**
- **Essential tool**: SMB enumeration is critical for Windows targets
- **Null sessions**: Always try null session first
- **Share enumeration**: Focus on non-default shares
- **File hunting**: Search for credentials, configs, backups
- **Lateral movement**: Use for file transfer to/from targets

**Best Practices:**
1. Always start with null session (`-N`)
2. List shares before connecting
3. Use recursive search for credential files
4. Download interesting files for offline analysis
5. Check Group Policy (SYSVOL) on Domain Controllers
6. Save all findings for documentation/reporting

**Common Workflow:**
1. Enumerate shares: `smbclient -L //TARGET -N`
2. Identify interesting shares (non-default)
3. Connect to share: `smbclient //TARGET/SHARE -N`
4. Search for files: `recurse on; ls *pass*`
5. Download files: `prompt off; mget *`
6. Analyze locally: `grep -r "password" .`

**OSCP Tips:**
- SMB (port 445) is very common on Windows boxes
- Null sessions work on older systems (2003, XP)
- Modern Windows blocks null sessions by default
- Look for credentials in:
  - config files (web.config, *.ini)
  - scripts (*.bat, *.ps1)
  - backups (*.bak, *.old, *.sql)
  - KeePass databases (*.kdbx)
- SYSVOL/NETLOGON may contain GPP passwords
- Always document share contents for report

**Remember:** smbclient is for reconnaissance and file transfer. Finding files is step one - always analyze their contents for credentials, configurations, and sensitive information!
