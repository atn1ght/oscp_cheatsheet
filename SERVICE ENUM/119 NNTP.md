# NNTP ENUMERATION (Port 119)

## SERVICE OVERVIEW
```
NNTP (Network News Transfer Protocol) - Usenet newsgroup access
- Default port: 119 (plaintext)
- Secure port: 563 (NNTPS over SSL/TLS)
- Used for reading/posting newsgroup articles
- Can reveal internal documentation, passwords, sensitive info
- Often contains archived company communications
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p119 <IP>                             # Service/Version detection
nc -nv <IP> 119                                 # Manual connection
telnet <IP> 119                                 # Alternative connection
echo "HELP" | nc -nv <IP> 119                   # Get command list
```

## MANUAL ENUMERATION
```bash
# Connect to NNTP server
nc -nv <IP> 119

# Common NNTP commands after connection:
HELP                                            # List available commands
LIST                                            # List all newsgroups
LIST ACTIVE                                     # List active newsgroups
LIST NEWSGROUPS                                 # Newsgroups with descriptions
GROUP <newsgroup>                               # Select newsgroup
ARTICLE <number>                                # Retrieve specific article
HEAD <number>                                   # Get article headers
BODY <number>                                   # Get article body
STAT <number>                                   # Check if article exists
NEXT                                            # Next article
LAST                                            # Previous article
QUIT                                            # Disconnect
```

## NMAP ENUMERATION
```bash
# NNTP scripts
nmap -p119 --script nntp-ntlm-info <IP>         # Get NTLM info
nmap -p119 --script nntp-capabilities <IP>      # List capabilities

# Version detection
nmap -sV -p119,563 <IP>                         # Check both ports
```

## ENUMERATE NEWSGROUPS
```bash
# List all newsgroups
echo "LIST" | nc -nv <IP> 119 | tee newsgroups.txt

# Get newsgroup descriptions
echo "LIST NEWSGROUPS" | nc -nv <IP> 119

# Select and read specific group
echo -e "GROUP <newsgroup_name>\nLIST" | nc -nv <IP> 119
```

## READ ARTICLES
```bash
# Read articles from newsgroup
nc -nv <IP> 119
> GROUP alt.test
> ARTICLE 1                                     # Read first article
> NEXT                                          # Next article
> ARTICLE 100                                   # Specific article number

# Automated article retrieval
for i in {1..100}; do
    echo -e "GROUP <newsgroup>\nARTICLE $i" | nc -nv <IP> 119 >> articles.txt
done
```

## SEARCH FOR SENSITIVE INFORMATION
```bash
# Download all articles and search
echo "LIST" | nc -nv <IP> 119 | grep -i "admin\|secret\|password\|backup\|config"

# Common interesting newsgroups
alt.admin, alt.config, comp.security
microsoft.private, company.internal
test.*, admin.*, dev.*, internal.*

# Search for keywords in articles
for i in {1..1000}; do
    echo -e "ARTICLE $i" | nc -nv <IP> 119
done | grep -i "password\|credential\|secret\|admin"
```

## AUTHENTICATION TESTING
```bash
# Some NNTP servers require authentication
nc -nv <IP> 119
> AUTHINFO USER <username>
> AUTHINFO PASS <password>

# Test common credentials
AUTHINFO USER admin
AUTHINFO PASS admin

AUTHINFO USER news
AUTHINFO PASS news
```

## POSTING MESSAGES (IF ALLOWED)
```bash
# Check if posting is allowed
echo "MODE READER" | nc -nv <IP> 119
echo "POST" | nc -nv <IP> 119

# Post article (if permitted)
nc -nv <IP> 119
> POST
> From: attacker@test.com
> Newsgroups: alt.test
> Subject: Test Post
>
> This is a test message.
> .
> QUIT
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/nntp/nntp_version        # Version detection
use auxiliary/scanner/nntp/nntp_list           # List newsgroups

set RHOSTS <IP>
run
```

## INTERESTING FILES & TOPICS
```bash
# Look for newsgroups containing:
# - Internal documentation
# - Password policies
# - Configuration info
# - Employee communications
# - Technical support threads
# - Admin discussions

# Common valuable newsgroups:
admin.*, administrator.*, company.admin
internal.*, company.internal
dev.*, development.*, engineering.*
security.*, infosec.*
support.*, helpdesk.*
```

## NNTPS (SECURE NNTP) - PORT 563
```bash
# Connect to NNTPS
openssl s_client -connect <IP>:563              # SSL/TLS connection
nmap -sV -p563 --script ssl-enum-ciphers <IP>  # Check SSL/TLS config

# After SSL connection, use normal NNTP commands
> LIST
> GROUP <newsgroup>
```

## COMMON MISCONFIGURATIONS
```
☐ Anonymous access allowed (no authentication)
☐ Sensitive internal newsgroups exposed
☐ Posting allowed without authentication
☐ Archived passwords/credentials in articles
☐ Company internal communications visible
☐ Technical documentation with vuln info
☐ No access restrictions from external networks
☐ Outdated NNTP software with known vulns
```

## VULNERABILITY SCANNING
```bash
# Search for NNTP exploits
searchsploit nntp                               # Search all NNTP exploits
nmap -p119 --script vuln <IP>                   # Generic vuln scan

# Known vulnerabilities:
# CVE-2000-0284: INN NNTP buffer overflow
# CVE-2001-1413: NNTP AUTHINFO USER overflow
# Various buffer overflows in old NNTP servers
```

## QUICK WIN CHECKLIST
```
☐ Check if NNTP is accessible (port 119/563 open)
☐ Test for anonymous access (no auth required)
☐ List all newsgroups (LIST command)
☐ Search for sensitive/internal newsgroups
☐ Read articles looking for credentials
☐ Search for keywords: password, admin, config
☐ Check if posting is allowed
☐ Test default credentials if auth required
☐ Search for known NNTP exploits (older systems)
```

## ONE-LINER ENUMERATION
```bash
# Quick NNTP enumeration
nmap -sV -p119,563 <IP> && echo "LIST" | nc -nv <IP> 119 | tee newsgroups.txt

# List groups and search for interesting ones
echo "LIST NEWSGROUPS" | nc -nv <IP> 119 | grep -i "admin\|internal\|secret\|config\|private"
```

## ADVANCED TECHNIQUES
```bash
# Download entire newsgroup archive
for group in $(echo "LIST" | nc -nv <IP> 119 | awk '{print $1}'); do
    echo "GROUP $group" | nc -nv <IP> 119
    # Download all articles from group
done

# Search for email addresses (social engineering)
echo "LIST" | nc -nv <IP> 119 | nc -nv <IP> 119 > all_articles.txt
grep -Eo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' all_articles.txt | sort -u > emails.txt
```

## TOOLS
```bash
# Netcat (manual interaction)
nc -nv <IP> 119

# Telnet
telnet <IP> 119

# Nmap
nmap --script nntp-* -p119 <IP>

# tin (NNTP newsreader)
tin -r <IP>

# slrn (newsreader)
slrn -h <IP>
```

## SECURITY IMPLICATIONS
```
RISKS:
- Exposure of internal communications
- Password/credential disclosure in articles
- Sensitive technical information leakage
- Employee personal information
- Social engineering intelligence
- Network topology/architecture details

RECOMMENDATIONS:
- Disable NNTP if not needed
- Require authentication for all access
- Use NNTPS (port 563) instead of plain NNTP
- Restrict access to trusted networks only
- Regularly audit newsgroup content
- Implement access controls per newsgroup
- Monitor for sensitive information exposure
```
