# FINGER ENUMERATION (Port 79)

## SERVICE OVERVIEW
```
Finger protocol - User information lookup service
- Default port: 79
- Returns information about logged-in users
- Often reveals usernames, real names, login times
- Can be used for user enumeration
- Largely deprecated but still found on older systems
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p79 <IP>                              # Service/Version detection
nc -nv <IP> 79                                  # Manual connection
telnet <IP> 79                                  # Alternative connection
echo "" | nc -nv <IP> 79                        # Empty query
```

## USER ENUMERATION
```bash
# Query specific user
finger <username>@<IP>                          # Query single user
finger root@<IP>                                # Check root user
finger admin@<IP>                               # Check admin user

# Query all logged-in users
finger @<IP>                                    # List all logged-in users
finger 0@<IP>                                   # Alternative syntax

# Multiple users
for user in $(cat users.txt); do finger $user@<IP>; done

# Via netcat
echo "root" | nc -nv <IP> 79                   # Query root
echo "" | nc -nv <IP> 79                        # Query all users
```

## AUTOMATED ENUMERATION
```bash
# Nmap finger script
nmap --script finger -p79 <IP>                  # Basic finger enumeration
nmap --script finger --script-args finger.users={root,admin,user} -p79 <IP>

# finger-user-enum (dedicated tool)
finger-user-enum.pl -U users.txt -t <IP>        # Enumerate users from list
finger-user-enum.pl -u root -t <IP>             # Single user

# Metasploit
msfconsole
use auxiliary/scanner/finger/finger_users
set RHOSTS <IP>
set USERS_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
run
```

## COMMON USERNAMES TO TEST
```bash
# Standard Unix/Linux users
root, admin, administrator, user, guest, test
bin, daemon, sys, sync, mail, operator, nobody
ftp, apache, www-data, mysql, postgres
oracle, tomcat, jenkins

# Check common users
for user in root admin user guest test www-data; do
    echo $user | nc -nv <IP> 79
done
```

## INFORMATION GATHERING
```bash
# Typical information revealed:
# - Username
# - Full name
# - Home directory
# - Shell
# - Last login time
# - Mail status
# - Plan/project file contents

# Extract usernames only
finger @<IP> | grep "Login" | awk '{print $2}'

# Check user's plan file
finger <user>@<IP>                              # May reveal .plan file content
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/finger/finger_users      # User enumeration
set RHOSTS <IP>
set USERS_FILE /path/to/users.txt
run

# Parse results
use auxiliary/gather/finger_enum
```

## VULNERABILITY SCANNING
```bash
# Search for finger exploits
searchsploit finger                             # Search all finger exploits

# Known vulnerabilities
# CVE-1999-0612: Finger reveals system information
# CVE-1999-0197: Finger allows remote user enumeration
```

## NMAP SCRIPTS
```bash
# Finger enumeration script
nmap -p79 --script finger -oA finger_scan <IP>

# With specific users
nmap -p79 --script finger --script-args 'finger.users={root,admin,user,guest,test}' <IP>
```

## POST-ENUMERATION
```bash
# Use discovered usernames for:
# - SSH brute force
# - FTP login attempts
# - SMTP user verification (VRFY command)
# - SMB enumeration
# - Password spraying

# Create username list from finger results
finger @<IP> | grep Login | awk '{print $2}' > users.txt

# Use with other services
hydra -L users.txt -P passwords.txt ssh://<IP>
```

## COMMON MISCONFIGURATIONS
```
☐ Finger service running unnecessarily
☐ Revealing sensitive user information
☐ No access restrictions
☐ Exposing system accounts
☐ Showing last login times (reconnaissance)
☐ Revealing .plan/.project files with sensitive info
☐ Running on internet-facing systems
```

## QUICK WIN CHECKLIST
```
☐ Check if finger is running (port 79 open)
☐ Query all users (finger @<IP>)
☐ Test common usernames (root, admin, etc.)
☐ Extract username list for further attacks
☐ Check for sensitive info in .plan files
☐ Use usernames for SSH/FTP brute force
☐ Search for known finger exploits
```

## ONE-LINER ENUMERATION
```bash
# Quick finger enumeration
nmap -sV -p79 --script finger <IP> && finger @<IP> | tee finger_output.txt

# Batch user enumeration
for user in root admin user guest test www-data nobody; do echo "Testing: $user"; finger $user@<IP>; echo "---"; done
```

## TOOLS
```bash
# finger command (standard)
finger @<IP>                                    # Built-in Unix/Linux

# finger-user-enum.pl (Pentestmonkey)
wget https://pentestmonkey.net/tools/finger-user-enum/finger-user-enum-1.0.pl
chmod +x finger-user-enum-1.0.pl
./finger-user-enum-1.0.pl -U users.txt -t <IP>

# Nmap
nmap --script finger -p79 <IP>

# Metasploit
use auxiliary/scanner/finger/finger_users
```

## SECURITY IMPLICATIONS
```
RISKS:
- Username enumeration (aids brute force attacks)
- Real name disclosure (social engineering)
- Login pattern analysis (identify active users)
- System account exposure
- Home directory disclosure
- Mail status information

RECOMMENDATIONS:
- Disable finger service if not needed
- Restrict access with firewall rules
- Use TCP wrappers (/etc/hosts.allow, /etc/hosts.deny)
- Monitor finger service logs
- Educate users about .plan/.project files
```
