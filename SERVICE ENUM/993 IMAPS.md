# IMAPS ENUMERATION (Port 993)

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p993 <IP>                              # Service/Version detection
openssl s_client -connect <IP>:993 -crlf         # Connect with SSL/TLS
openssl s_client -connect <IP>:993 -crlf -quiet  # Quiet mode
nc -nv <IP> 993                                  # Manual banner grab (won't work without TLS)

# Get IMAP capabilities
echo "A001 CAPABILITY" | openssl s_client -connect <IP>:993 -crlf -quiet 2>/dev/null
```

## SSL/TLS CERTIFICATE ENUMERATION
```bash
# Get certificate details
openssl s_client -connect <IP>:993 2>/dev/null | openssl x509 -noout -text
openssl s_client -connect <IP>:993 -showcerts 2>/dev/null

# Certificate subject/issuer
openssl s_client -connect <IP>:993 2>/dev/null | openssl x509 -noout -subject
openssl s_client -connect <IP>:993 2>/dev/null | openssl x509 -noout -issuer

# Check certificate SANs (may reveal email domains)
openssl s_client -connect <IP>:993 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
nmap -p993 --script ssl-cert <IP>
```

## SSL/TLS SECURITY TESTING
```bash
# Cipher suite enumeration
nmap --script ssl-enum-ciphers -p993 <IP>
sslscan <IP>:993
sslyze --regular <IP>:993

# SSL/TLS version testing
openssl s_client -ssl3 -connect <IP>:993         # SSLv3 (should fail)
openssl s_client -tls1 -connect <IP>:993         # TLS 1.0
openssl s_client -tls1_1 -connect <IP>:993       # TLS 1.1
openssl s_client -tls1_2 -connect <IP>:993       # TLS 1.2
openssl s_client -tls1_3 -connect <IP>:993       # TLS 1.3

# Comprehensive SSL/TLS testing
testssl.sh <IP>:993
testssl.sh --vulnerable <IP>:993                 # Vulnerability check
```

## IMAP CAPABILITY ENUMERATION
```bash
# Get server capabilities
echo "A001 CAPABILITY" | openssl s_client -connect <IP>:993 -crlf -quiet 2>/dev/null

# Nmap IMAP capabilities
nmap -p993 --script imap-capabilities <IP>

# Check for NTLM authentication (may leak version info)
nmap -p993 --script imap-ntlm-info <IP>
```

## MANUAL IMAP ENUMERATION
```bash
# Connect and enumerate
openssl s_client -connect <IP>:993 -crlf -quiet
# Then type:
A001 CAPABILITY                                  # List capabilities
A002 LOGIN user password                         # Attempt login
A003 LIST "" "*"                                 # List mailboxes
A004 SELECT INBOX                                # Select inbox
A005 FETCH 1 BODY[TEXT]                          # Fetch first email
A006 LOGOUT                                      # Disconnect

# One-liner IMAP commands
echo "A001 CAPABILITY" | openssl s_client -connect <IP>:993 -crlf -quiet 2>/dev/null
echo "A001 LOGIN user password" | openssl s_client -connect <IP>:993 -crlf -quiet 2>/dev/null
```

## USER ENUMERATION
```bash
# IMAP user enumeration (timing-based)
nmap -p993 --script imap-ntlm-info <IP>          # May leak domain/hostname info

# Manual user enum via timing
for user in $(cat users.txt); do
    echo "A001 LOGIN $user test" | openssl s_client -connect <IP>:993 -crlf -quiet 2>&1
done
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l user@<domain> -P passwords.txt -s 993 <IP> imap
hydra -L users.txt -P passwords.txt -s 993 <IP> imap
hydra -l admin -P rockyou.txt -s 993 -t 4 <IP> imap  # Limit threads

# Medusa
medusa -h <IP> -n 993 -u user@domain.com -P passwords.txt -M imap
medusa -h <IP> -n 993 -U users.txt -P passwords.txt -M imap

# Nmap
nmap -p993 --script imap-brute --script-args userdb=users.txt,passdb=passwords.txt <IP>

# Patator
patator imap_login host=<IP> port=993 user=FILE0 password=FILE1 0=users.txt 1=passwords.txt ssl=1 -x ignore:fgrep='Authentication failed'
```

## DEFAULT CREDENTIALS
```bash
# Common email credentials
admin@<domain>:admin
administrator@<domain>:password
support@<domain>:support
test@<domain>:test
info@<domain>:info

# Test default credentials
echo "A001 LOGIN admin@domain.com admin" | openssl s_client -connect <IP>:993 -crlf -quiet 2>/dev/null
```

## NTLM INFORMATION DISCLOSURE
```bash
# Extract NTLM info (Windows domain, version, hostname)
nmap -p993 --script imap-ntlm-info <IP>

# Manual NTLM authentication request
echo -ne "A001 AUTHENTICATE NTLM\r\n" | openssl s_client -connect <IP>:993 -crlf -quiet
# Server may respond with NTLM challenge containing system info
```

## STARTTLS TESTING (Not typically used on 993)
```bash
# Port 993 is implicit SSL/TLS, but some servers might support STARTTLS
openssl s_client -connect <IP>:993 -starttls imap 2>/dev/null
```

## VULNERABILITY SCANNING
```bash
# SSL/TLS vulnerabilities
nmap -p993 --script ssl-heartbleed <IP>          # Heartbleed
nmap -p993 --script ssl-poodle <IP>              # POODLE
nmap -p993 --script ssl-drown <IP>               # DROWN
testssl.sh --vulnerable <IP>:993                 # All SSL vulnerabilities

# IMAP-specific vulnerabilities
searchsploit imap
nmap -p993 --script vuln <IP>
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/imap/imap_version          # Version detection
use auxiliary/scanner/imap/imap_capabilities     # Capability enumeration
use auxiliary/scanner/ssl/openssl_heartbleed     # Heartbleed
set RPORT 993
```

## POST-EXPLOITATION (After successful login)
```bash
# Connect with credentials
openssl s_client -connect <IP>:993 -crlf -quiet
A001 LOGIN user@domain.com password
A002 LIST "" "*"                                 # List all mailboxes
A003 SELECT INBOX                                # Select inbox
A004 SEARCH ALL                                  # Search all emails
A005 FETCH 1:* (FLAGS)                           # Get all email flags
A006 FETCH 1 BODY[TEXT]                          # Read first email
A007 FETCH 1 BODY[HEADER]                        # Get email headers
A008 LOGOUT

# Automated email download
curl -k "imaps://<IP>:993/INBOX" -u user@domain.com:password
curl -k "imaps://<IP>:993/INBOX;UID=1" -u user@domain.com:password  # Specific email
```

## EMAIL HARVESTING
```bash
# Download all emails with cURL
curl -k "imaps://<IP>:993/INBOX" -u user:password --output emails.txt

# Using openssl + IMAP commands
# Connect and run:
A001 LOGIN user password
A002 SELECT INBOX
A003 SEARCH ALL                                  # Get all email IDs
A004 FETCH 1:100 BODY[TEXT]                      # Fetch first 100 emails
```

## INTERESTING FILES & DATA
```bash
# Look for sensitive information in emails:
# - Passwords in plain text
# - Private keys
# - Configuration files
# - VPN credentials
# - Password reset links
# - Internal system information
# - Meeting notes with sensitive data
```

## COMMON MISCONFIGURATIONS
```
☐ Self-signed certificate                       # Indicates dev/test environment
☐ Weak SSL/TLS configuration                     # SSLv3, TLS 1.0, weak ciphers
☐ Default credentials                            # Easy access
☐ Anonymous/guest access                         # No authentication required
☐ Verbose error messages                         # Information disclosure
☐ NTLM authentication enabled                    # Info leakage
☐ No rate limiting                               # Brute force attacks
☐ Outdated IMAP server                           # Known vulnerabilities
☐ Certificate name mismatch                      # Configuration error
```

## QUICK WIN CHECKLIST
```
☐ Test default credentials (admin, administrator, etc.)
☐ Check SSL/TLS configuration (weak ciphers, old protocols)
☐ Test for Heartbleed (OpenSSL < 1.0.1g)
☐ Extract NTLM information (domain, hostname, version)
☐ Check certificate for SANs (email domains, hostnames)
☐ Brute force with common passwords
☐ Search for known IMAP vulnerabilities
☐ Check for anonymous/guest access
☐ Test for user enumeration
☐ Review certificate validity and chain
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive IMAPS scan
nmap -sV -p993 --script "imap-* and ssl-*" -oA imaps_enum <IP>

# Quick SSL/TLS vulnerability check
testssl.sh --vulnerable <IP>:993

# Quick capability check
echo "A001 CAPABILITY" | openssl s_client -connect <IP>:993 -crlf -quiet 2>/dev/null
```

## ADVANCED TECHNIQUES
```bash
# Check for multiple SSL certificates (SNI)
openssl s_client -connect <IP>:993 -servername mail.<domain>

# Test compression (CRIME vulnerability)
openssl s_client -connect <IP>:993 2>/dev/null | grep Compression

# Session resumption test
openssl s_client -connect <IP>:993 -reconnect 2>/dev/null | grep "Session-ID"

# OCSP stapling
openssl s_client -connect <IP>:993 -status 2>/dev/null | grep -A17 "OCSP"
```
