# rpcclient - Windows RPC Client Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Connection & Authentication](#3-connection--authentication)
4. [User Enumeration](#4-user-enumeration)
5. [Group Enumeration](#5-group-enumeration)
6. [Domain Enumeration](#6-domain-enumeration)
7. [Share Enumeration](#7-share-enumeration)
8. [Password Policy](#8-password-policy)
9. [Printer Enumeration](#9-printer-enumeration)
10. [SID Enumeration](#10-sid-enumeration)
11. [User Modification](#11-user-modification)
12. [Common OSCP Patterns](#12-common-oscp-patterns)
13. [Troubleshooting](#13-troubleshooting)
14. [Quick Reference](#14-quick-reference)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Kali Linux (already installed)
rpcclient --version

# Debian/Ubuntu
sudo apt install samba-common-bin
```

### 1.2 Basic Syntax

```bash
rpcclient [options] //TARGET
rpcclient [options] TARGET
```

---

## 2. Basic Concepts

### 2.1 What is rpcclient?

**rpcclient** is a tool from the Samba suite for executing MS-RPC (Microsoft Remote Procedure Call) functions against Windows systems. It's used for enumerating users, groups, shares, and other domain information.

**Key Features:**
- **Null session support**: Can work without credentials (on misconfigured systems)
- **User/Group enumeration**: List domain users and groups
- **Share enumeration**: List network shares
- **Password policy**: Query domain password policy
- **SID resolution**: Convert usernames to SIDs and vice versa

**Common Use Cases:**
- Enumerate domain users without credentials (null session)
- Query password policy before password attacks
- Map usernames to SIDs for further attacks
- Identify privileged accounts

### 2.2 RPC Services

rpcclient uses various RPC services:
- **SAMR (Security Account Manager Remote)**: User/group enumeration
- **LSARPC (Local Security Authority RPC)**: Domain info, SID lookups
- **SRVSVC (Server Service)**: Share enumeration
- **NETLOGON**: Domain controller queries

---

## 3. Connection & Authentication

### 3.1 Null Session (No Credentials)

```bash
# Null session (anonymous)
rpcclient -U "" -N 192.168.1.10
rpcclient -U "" 192.168.1.10 -N

# Explicit null user
rpcclient -U "%" 192.168.1.10

# Legacy format
rpcclient -U "" 192.168.1.10 --no-pass
```

### 3.2 With Credentials

```bash
# With username and password
rpcclient -U "username%password" 192.168.1.10

# Prompt for password
rpcclient -U "username" 192.168.1.10

# Domain user
rpcclient -U "DOMAIN/username%password" 192.168.1.10
rpcclient -U "username%password" -W DOMAIN 192.168.1.10
```

### 3.3 Pass-the-Hash

```bash
# Pass-the-Hash
rpcclient -U "username%HASH" --pw-nt-hash 192.168.1.10

# Example
rpcclient -U "admin%aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" --pw-nt-hash 192.168.1.10
```

### 3.4 Interactive Mode

```bash
# Connect and enter interactive shell
rpcclient -U "" -N 192.168.1.10

# You'll see:
rpcclient $>

# Type 'help' for available commands
rpcclient $> help
```

### 3.5 Non-Interactive (Command Execution)

```bash
# Execute single command
rpcclient -U "" -N 192.168.1.10 -c "enumdomusers"

# Execute multiple commands
rpcclient -U "" -N 192.168.1.10 -c "enumdomusers; enumdomgroups"
```

---

## 4. User Enumeration

### 4.1 List Domain Users

```bash
# Enumerate domain users
rpcclient $> enumdomusers

# Output format:
# user:[username] rid:[RID]
# user:[Administrator] rid:[0x1f4]
# user:[Guest] rid:[0x1f5]
# user:[john] rid:[0x450]
```

### 4.2 Query User Info

```bash
# Get user information by RID
rpcclient $> queryuser 0x1f4

# Get user information by username
rpcclient $> queryuser 500    # 500 = 0x1f4 (Administrator)

# Detailed output includes:
# - Username
# - Full name
# - Description
# - Password last set
# - Account expiry
# - Bad password count
# - Logon count
# - Group memberships
```

### 4.3 Query Multiple Users

```bash
# Query all users (bash loop)
for rid in $(rpcclient -U "" -N 192.168.1.10 -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]'); do
    echo "User: $rid"
    rpcclient -U "" -N 192.168.1.10 -c "queryuser $(rpcclient -U "" -N 192.168.1.10 -c "lookupnames $rid" | grep -oP 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+' | cut -d'-' -f8)"
done
```

### 4.4 Display User Info

```bash
# Display user by RID
rpcclient $> queryuser 0x450

# Display user by username (convert first)
rpcclient $> lookupnames john
rpcclient $> queryuser <RID_from_above>

# Query display info (less detailed)
rpcclient $> querydispinfo

# Query display info with index
rpcclient $> querydispinfo 0 100
```

### 4.5 User Aliases

```bash
# Get user aliases (group memberships)
rpcclient $> queryuseraliases builtin 5

# Query user groups
rpcclient $> queryusergroups 0x450
```

---

## 5. Group Enumeration

### 5.1 List Domain Groups

```bash
# Enumerate domain groups
rpcclient $> enumdomgroups

# Output format:
# group:[Domain Admins] rid:[0x200]
# group:[Domain Users] rid:[0x201]
# group:[Domain Guests] rid:[0x202]
```

### 5.2 Query Group Info

```bash
# Query group by RID
rpcclient $> querygroup 0x200

# Query group members
rpcclient $> querygroupmem 0x200

# Output shows member RIDs
# Use queryuser to get member details
```

### 5.3 List Local Groups (Aliases)

```bash
# Enumerate local groups (aliases)
rpcclient $> enumalsgroups builtin
rpcclient $> enumalsgroups domain

# Common groups:
# - Administrators (rid: 0x220)
# - Users (rid: 0x221)
# - Guests (rid: 0x222)
```

### 5.4 Query Alias Members

```bash
# Query alias (local group) members
rpcclient $> queryaliasmem builtin 0x220    # Administrators
rpcclient $> queryaliasmem domain 0x200     # Domain Admins
```

---

## 6. Domain Enumeration

### 6.1 Domain Information

```bash
# Get domain info
rpcclient $> querydominfo

# Output includes:
# - Domain name
# - Server role
# - Number of users
# - Number of groups
# - Domain creation time
# - Password properties
```

### 6.2 Domain SID

```bash
# Get domain SID
rpcclient $> lsaquery

# Output shows domain SID (e.g., S-1-5-21-1234567890-...)
```

### 6.3 Domain Password Policy

```bash
# Query password policy
rpcclient $> getdompwinfo

# Output:
# - Minimum password length
# - Password history length
# - Password complexity
# - Maximum password age
# - Minimum password age
# - Lockout threshold
# - Lockout duration
```

### 6.4 Domain Trust Information

```bash
# Enumerate domain trusts
rpcclient $> dsr_enumtrustdom

# LSA enumerate trusted domains
rpcclient $> lsaenumsid
```

---

## 7. Share Enumeration

### 7.1 List Shares

```bash
# Enumerate network shares
rpcclient $> netshareenum
rpcclient $> netshareenumall

# Output shows:
# - Share name
# - Share type
# - Comment/description
```

### 7.2 Share Information

```bash
# Get share info
rpcclient $> netsharegetinfo sharename

# Example
rpcclient $> netsharegetinfo ADMIN$
rpcclient $> netsharegetinfo C$
rpcclient $> netsharegetinfo IPC$
```

---

## 8. Password Policy

### 8.1 Query Password Policy

```bash
# Get domain password policy
rpcclient $> getdompwinfo

# Example output:
# min_password_length: 7
# password_properties: 0x00000001
# password_history_length: 24
# max_password_age: 49 days
# min_password_age: 1 day
```

### 8.2 Interpret Password Properties

**Password Properties Flags:**
- `0x00000001`: Password complexity enabled
- `0x00000002`: No anonymous connections
- `0x00000004`: Lockout on bad password
- `0x00000008`: Password stored reversible

**Common Values:**
- `0x00000000`: No complexity, no lockout
- `0x00000001`: Complexity enabled, no lockout
- `0x00000005`: Complexity + lockout enabled

### 8.3 Account Lockout Policy

```bash
# Query lockout policy
rpcclient $> getdompwinfo

# Check for:
# - Lockout threshold (e.g., 5 bad attempts)
# - Lockout duration (e.g., 30 minutes)
# - Lockout observation window

# If lockout_threshold = 0, no lockout policy!
```

**IMPORTANT FOR OSCP:**
Always check password policy before password spraying to avoid account lockouts!

---

## 9. Printer Enumeration

### 9.1 List Printers

```bash
# Enumerate printers
rpcclient $> enumprinters

# Get printer info
rpcclient $> getprinter <printer_name>

# Enumerate printer drivers
rpcclient $> enumprinterdrivers
```

---

## 10. SID Enumeration

### 10.1 Username to SID

```bash
# Convert username to SID
rpcclient $> lookupnames username

# Example
rpcclient $> lookupnames Administrator
# Output: Administrator S-1-5-21-...-500 (User: 1)
```

### 10.2 SID to Username

```bash
# Convert SID to username
rpcclient $> lookupsids S-1-5-21-...-500

# Example
rpcclient $> lookupsids S-1-5-21-1234567890-1234567890-1234567890-500
# Output: DOMAIN\Administrator (User: 1)
```

### 10.3 SID Brute Force (RID Cycling)

```bash
# Manually enumerate SIDs by incrementing RID
rpcclient $> lookupsids S-1-5-21-DOMAIN_SID-500
rpcclient $> lookupsids S-1-5-21-DOMAIN_SID-501
rpcclient $> lookupsids S-1-5-21-DOMAIN_SID-502
# ... continue incrementing

# Automated SID enumeration (bash script)
for rid in {500..1100}; do
    rpcclient -U "" -N 192.168.1.10 -c "lookupsids S-1-5-21-DOMAIN_SID-$rid"
done
```

### 10.4 Well-Known SIDs

**Common RIDs:**
- `500`: Administrator
- `501`: Guest
- `502`: KRBTGT (Kerberos TGT account)
- `512`: Domain Admins (group)
- `513`: Domain Users (group)
- `514`: Domain Guests (group)
- `515`: Domain Computers (group)
- `516`: Domain Controllers (group)
- `518`: Schema Admins (group)
- `519`: Enterprise Admins (group)
- `520`: Group Policy Creator Owners
- `1000+`: Regular user accounts

---

## 11. User Modification

### 11.1 Create User (if allowed)

```bash
# Create domain user
rpcclient $> createdomuser username

# Note: Requires admin privileges
```

### 11.2 Delete User (if allowed)

```bash
# Delete domain user
rpcclient $> deletedomuser username

# Note: Requires admin privileges
```

### 11.3 Set User Password (if allowed)

```bash
# Set user password
rpcclient $> setuserinfo2 username 24 'NewPassword123!'

# Note: Requires appropriate privileges
```

---

## 12. Common OSCP Patterns

### 12.1 Pattern 1: Null Session Enumeration

```bash
# Step 1: Test null session
rpcclient -U "" -N 192.168.1.10

# Step 2: Enumerate users
rpcclient $> enumdomusers

# Step 3: Query domain info
rpcclient $> querydominfo

# Step 4: Get password policy
rpcclient $> getdompwinfo

# Step 5: Enumerate groups
rpcclient $> enumdomgroups

# Step 6: Query Domain Admins
rpcclient $> querygroupmem 0x200
```

### 12.2 Pattern 2: Automated User Enumeration

```bash
# One-liner to enumerate users
rpcclient -U "" -N 192.168.1.10 -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' > users.txt

# Get RIDs
rpcclient -U "" -N 192.168.1.10 -c "enumdomusers" | grep -oP 'rid:\[0x[0-9a-f]+\]' | cut -d'[' -f2 | cut -d']' -f1

# Query all users (detailed)
rpcclient -U "" -N 192.168.1.10 -c "querydispinfo" > user_details.txt
```

### 12.3 Pattern 3: Password Policy Check (Pre-Attack)

```bash
# Check password policy before password spray
rpcclient -U "" -N 192.168.1.10 -c "getdompwinfo"

# Look for:
# - Lockout threshold (if > 0, be careful!)
# - Minimum password length
# - Password complexity

# Example output:
# min_password_length: 7
# password_properties: 0x00000001
# lockout_threshold: 5    # DANGER! Only 5 attempts before lockout

# OSCP RULE: If lockout exists, use password spray (1 password, all users)
# NOT brute force (1 user, all passwords)
```

### 12.4 Pattern 4: SID to Username Resolution

```bash
# Get domain SID first
rpcclient -U "" -N 192.168.1.10 -c "lsaquery"
# Output: Domain Sid: S-1-5-21-1234567890-1234567890-1234567890

# Enumerate users via SID (RID cycling)
for rid in {500..1100}; do
    rpcclient -U "" -N 192.168.1.10 -c "lookupsids S-1-5-21-1234567890-1234567890-1234567890-$rid" | grep -v "unknown"
done
```

### 12.5 Pattern 5: Complete Enumeration Script

```bash
#!/bin/bash
TARGET=$1

echo "[+] Enumerating $TARGET via rpcclient"

echo "[*] Domain Info:"
rpcclient -U "" -N $TARGET -c "querydominfo"

echo "[*] Password Policy:"
rpcclient -U "" -N $TARGET -c "getdompwinfo"

echo "[*] Domain Users:"
rpcclient -U "" -N $TARGET -c "enumdomusers" | tee users.txt

echo "[*] Domain Groups:"
rpcclient -U "" -N $TARGET -c "enumdomgroups" | tee groups.txt

echo "[*] Domain Admins Members:"
rpcclient -U "" -N $TARGET -c "querygroupmem 0x200"

echo "[*] Shares:"
rpcclient -U "" -N $TARGET -c "netshareenumall"

echo "[+] Enumeration complete!"
```

### 12.6 Pattern 6: Enum4linux Alternative

```bash
# rpcclient can replace enum4linux for basic enumeration

# Users
rpcclient -U "" -N 192.168.1.10 -c "enumdomusers"

# Groups
rpcclient -U "" -N 192.168.1.10 -c "enumdomgroups"

# Shares
rpcclient -U "" -N 192.168.1.10 -c "netshareenumall"

# Password policy
rpcclient -U "" -N 192.168.1.10 -c "getdompwinfo"

# Domain info
rpcclient -U "" -N 192.168.1.10 -c "querydominfo; lsaquery"
```

### 12.7 Pattern 7: With Credentials

```bash
# If you have valid credentials, use them
rpcclient -U "DOMAIN/username%password" 192.168.1.10

# Query user details
rpcclient $> queryuser 0x1f4

# Query privileged groups
rpcclient $> querygroupmem 0x200    # Domain Admins
rpcclient $> querygroupmem 0x206    # Enterprise Admins

# Enumerate ALL users with details
rpcclient $> querydispinfo
```

---

## 13. Troubleshooting

### 13.1 Access Denied / Connection Refused

```bash
# Problem: "Cannot connect to server. Error was NT_STATUS_ACCESS_DENIED"

# Cause 1: Null sessions disabled
# Solution: Use valid credentials
rpcclient -U "username%password" 192.168.1.10

# Cause 2: SMB signing required
# Solution: Check SMB configuration
```

### 13.2 Null Session Doesn't Work

```bash
# Problem: Null session fails

# Check 1: Verify SMB is open
nmap -p445 192.168.1.10

# Check 2: Try different null session formats
rpcclient -U "" -N 192.168.1.10
rpcclient -U "%" 192.168.1.10
rpcclient -U "" 192.168.1.10 --no-pass

# Check 3: Try with guest account
rpcclient -U "guest%" 192.168.1.10

# Note: Modern Windows versions disable null sessions by default
# Windows Server 2003 and older are more likely to allow null sessions
```

### 13.3 Command Not Found

```bash
# Problem: Command doesn't exist in rpcclient

# Check available commands
rpcclient $> help

# Common typos:
# enumdomusers (correct)
# enumusers (wrong)
```

### 13.4 No Output from Commands

```bash
# Problem: Command runs but returns nothing

# Cause: Insufficient privileges or empty query
# Try different commands or use credentials
```

---

## 14. Quick Reference

### 14.1 Connection Commands

```bash
# NULL SESSION
rpcclient -U "" -N TARGET                           # Null session
rpcclient -U "%" TARGET                             # Null session (alt)
rpcclient -U "" TARGET --no-pass                    # Null session (legacy)

# WITH CREDENTIALS
rpcclient -U "user%pass" TARGET                     # With password
rpcclient -U "user" TARGET                          # Prompt for password
rpcclient -U "DOMAIN/user%pass" TARGET              # Domain user
rpcclient -U "user%HASH" --pw-nt-hash TARGET        # Pass-the-Hash

# NON-INTERACTIVE
rpcclient -U "" -N TARGET -c "command"              # Single command
rpcclient -U "" -N TARGET -c "cmd1; cmd2"           # Multiple commands
```

### 14.2 Enumeration Commands

```bash
# DOMAIN INFORMATION
querydominfo                # Domain information
lsaquery                    # Domain SID
getdompwinfo                # Password policy

# USER ENUMERATION
enumdomusers                # List all domain users
queryuser <RID>             # Query user by RID
querydispinfo               # Display user info (all)
lookupnames <username>      # Username to SID

# GROUP ENUMERATION
enumdomgroups               # List domain groups
querygroup <RID>            # Query group info
querygroupmem <RID>         # Query group members
enumalsgroups builtin       # List builtin groups
enumalsgroups domain        # List domain groups

# SHARE ENUMERATION
netshareenumall             # List all shares
netshareenum                # List shares
netsharegetinfo <share>     # Share details

# SID OPERATIONS
lookupnames <username>      # Username → SID
lookupsids <SID>            # SID → Username

# OTHER
enumprinters                # List printers
dsr_enumtrustdom            # Domain trusts
```

### 14.3 Essential OSCP Commands

```bash
# Quick enumeration
rpcclient -U "" -N 192.168.1.10 -c "enumdomusers"
rpcclient -U "" -N 192.168.1.10 -c "enumdomgroups"
rpcclient -U "" -N 192.168.1.10 -c "getdompwinfo"
rpcclient -U "" -N 192.168.1.10 -c "querydominfo"

# Password policy (IMPORTANT before attacks!)
rpcclient -U "" -N 192.168.1.10 -c "getdompwinfo"

# User list to file
rpcclient -U "" -N 192.168.1.10 -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' > users.txt

# Domain Admins
rpcclient -U "" -N 192.168.1.10 -c "querygroupmem 0x200"

# Domain SID
rpcclient -U "" -N 192.168.1.10 -c "lsaquery"
```

### 14.4 Common RIDs

```bash
# WELL-KNOWN USERS
500  Administrator
501  Guest
502  KRBTGT

# WELL-KNOWN GROUPS
512  Domain Admins
513  Domain Users
514  Domain Guests
515  Domain Computers
516  Domain Controllers
518  Schema Admins
519  Enterprise Admins
520  Group Policy Creator Owners

# LOCAL ALIASES (Builtin)
544  Administrators (0x220)
545  Users (0x221)
546  Guests (0x222)
547  Power Users (0x223)
551  Backup Operators (0x227)
```

---

## 15. Resources

- **Samba Project**: https://www.samba.org/
- **rpcclient Man Page**: `man rpcclient`
- **HackTricks - rpcclient**: https://book.hacktricks.xyz/pentesting/pentesting-smb#rpcclient

---

## 16. Final Notes

**Für OSCP:**
- **Null sessions**: Try null session first on SMB (port 445)
- **Password policy**: ALWAYS check before password attacks
- **User enumeration**: Get user list for targeted attacks
- **RID cycling**: Enumerate users via SID if enumdomusers fails
- **Domain Admins**: Query group 0x200 to identify privileged accounts

**Best Practices:**
1. Always check password policy before password spraying
2. Extract user list to file for later use
3. Check for lockout threshold (avoid account lockouts!)
4. Query Domain Admins group for high-value targets
5. Try null session first, then valid credentials
6. Save enumeration output for offline analysis

**Common Workflow:**
1. Test null session: `rpcclient -U "" -N TARGET`
2. Check password policy: `getdompwinfo`
3. Enumerate users: `enumdomusers` → save to users.txt
4. Query Domain Admins: `querygroupmem 0x200`
5. Get domain info: `querydominfo; lsaquery`
6. If null session fails, try with credentials

**OSCP Tips:**
- rpcclient is essential for SMB enumeration (port 445)
- Works best on older Windows systems (2003, 2008)
- Modern Windows may block null sessions
- Combine with enum4linux, smbclient, crackmapexec
- Always document password policy for exam report

**Remember:** rpcclient is for enumeration only. It doesn't exploit vulnerabilities - it gathers information for planning your attack strategy.
