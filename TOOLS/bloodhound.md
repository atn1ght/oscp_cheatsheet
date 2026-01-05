# BloodHound - Active Directory Attack Path Visualizer

## Was ist BloodHound?

BloodHound ist ein Tool zur Analyse von Active Directory-Umgebungen. Es visualisiert Angriffspfade, Berechtigungen, Gruppen-Memberships und zeigt, wie man von einem kompromittierten Account zu Domain Admin eskalieren kann.

**Komponenten:**
- **SharpHound** - Data Collector (siehe `sharphound.md`)
- **Neo4j** - Graph-Datenbank (siehe `neo4j.md`)
- **BloodHound GUI** - Visualisierungs-Interface

---

## Installation

### Kali Linux
```bash
# BloodHound installieren
sudo apt update
sudo apt install bloodhound

# Neo4j installieren (benötigt)
sudo apt install neo4j

# Python-Version (für Collection)
sudo apt install bloodhound.py
```

### Von GitHub
```bash
# BloodHound GUI
wget https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
chmod +x BloodHound
```

---

## Setup & Start

### 1. Neo4j starten
```bash
# Console-Modus (empfohlen für OSCP)
sudo neo4j console

# Als Service
sudo systemctl start neo4j
sudo systemctl enable neo4j

# Status prüfen
sudo systemctl status neo4j
```

### 2. Neo4j konfigurieren
```bash
# Browser öffnen
http://localhost:7474

# Default-Credentials
Username: neo4j
Password: neo4j

# WICHTIG: Passwort bei erstem Login ändern!
# Neues Passwort setzen (z.B. bloodhound)
```

### 3. BloodHound starten
```bash
# GUI starten
bloodhound

# Oder manuell
./BloodHound --no-sandbox
```

### 4. In BloodHound einloggen
```
Database URL: bolt://localhost:7687
Username: neo4j
Password: <dein_neo4j_passwort>
```

---

## Daten importieren

### JSON-Dateien importieren
```bash
# In BloodHound GUI:
# 1. Klick auf "Upload Data" (rechts oben)
# 2. Wähle alle .json Dateien aus dem SharpHound-Output
# 3. Oder wähle die .zip Datei direkt
```

### Via Command Line (bulk import)
```bash
# Alle JSONs in einem Directory
bloodhound-python -u user -p pass -d corp.local -ns 10.10.10.100 -c All

# JSONs werden erstellt:
# - computers.json
# - users.json
# - groups.json
# - domains.json
# - containers.json

# In BloodHound importieren via GUI
```

---

## BloodHound Interface

### Navigation

**Hamburger Menu (☰) - Links oben:**
- Database Info
- Node Info
- Analysis
- Search
- Settings

**Search Bar:**
- Suche nach Objekten (User, Group, Computer)
- Syntax: `@username`, `name@domain.local`

**Analysis Tab:**
- Vorgefertigte Queries
- Custom Queries

### Wichtige UI-Elemente

**Node-Info (rechts):**
- Klick auf Node zeigt Details
- Tabs: Overview, Node Info, Reachable Computers, etc.

**Graph-Control:**
- Scroll = Zoom
- Drag = Bewegen
- Rechtsklick = Menü
- Doppelklick = Expand

---

## Pre-built Queries (Analysis)

### Domain Information
```
Find all Domain Admins
Find Shortest Paths to Domain Admins
Find Principals with DCSync Rights
```

### Kerberoasting
```
List all Kerberoastable Accounts
Shortest Paths to Kerberoastable Users
```

### AS-REP Roasting
```
List all AS-REP Roastable Users
```

### Privileged Access
```
Find Computers where Domain Users are Local Admin
Find Computers with Unsupported Operating Systems
Shortest Path from Owned Principals
```

### Sessions
```
Find Computers where Domain Admins are logged in
Find Shortest Path to Domain Admin Sessions
```

### Delegations
```
Find Computers with Unconstrained Delegation
Find Users with Constrained Delegation
```

### Passwords
```
Find Users with Password Never Expires
Find Users with Password Not Required
```

---

## Wichtigste Queries für OSCP

### 1. Owned Principals markieren
```
1. Rechtsklick auf User/Computer → "Mark as Owned"
2. Oder search: MATCH (n {owned: true}) RETURN n
```

### 2. Pfad von Owned zu DA
```
Analysis → "Find Shortest Paths from Owned Principals"

# Oder Cypher:
MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p
```

### 3. Kerberoastable Users finden
```
Analysis → "List all Kerberoastable Accounts"

# Oder Cypher:
MATCH (u:User {hasspn:true}) RETURN u
```

### 4. Local Admin Rights finden
```
# Wo ist mein User Admin?
MATCH p=(u:User {name:'USER@CORP.LOCAL'})-[r:AdminTo]->(c:Computer) RETURN p

# Oder via "Outbound Object Control"
Rechtsklick auf User → "Outbound Object Control" → "First Degree Admin Rights"
```

### 5. GenericAll/WriteDacl/WriteOwner finden
```
Analysis → "Shortest Paths to High Value Targets"

# Dangerous Rights:
- GenericAll (Full Control)
- WriteDacl (Change Permissions)
- WriteOwner (Take Ownership)
- ForceChangePassword
```

---

## Custom Cypher Queries

### Cypher-Grundlagen
```cypher
# Einfache Suche
MATCH (n:User) RETURN n LIMIT 10

# Beziehungen
MATCH (u:User)-[r:MemberOf]->(g:Group) RETURN u,r,g

# Pfade
MATCH p=(u:User)-[*1..]->(c:Computer) RETURN p
```

### Nützliche Custom Queries

#### Alle High-Value Targets
```cypher
MATCH (n {highvalue:true}) RETURN n
```

#### Shortest Path von User X zu DA
```cypher
MATCH p=shortestPath((u:User {name:'USER@CORP.LOCAL'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p
```

#### Users mit AdminCount=1 (Protected Users)
```cypher
MATCH (u:User {admincount:true}) RETURN u
```

#### Alle Paths von Kerberoastable zu DA
```cypher
MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p
```

#### Computers mit Unconstrained Delegation
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

#### Users in mehr als X Gruppen
```cypher
MATCH (u:User)
WITH u, size((u)-[:MemberOf]->()) AS groupCount
WHERE groupCount > 10
RETURN u.name, groupCount
ORDER BY groupCount DESC
```

#### Alle Outbound Paths von User
```cypher
MATCH p=(u:User {name:'USER@CORP.LOCAL'})-[r]->(n)
RETURN p
```

#### Computers ohne LAPS
```cypher
MATCH (c:Computer) WHERE c.haslaps = false RETURN c
```

---

## Nodes markieren & annotieren

### Owned Principal markieren
```
Rechtsklick auf Node → "Mark User as Owned"
Rechtsklick auf Node → "Mark Computer as Owned"
```

### High-Value Target markieren
```
Rechtsklick auf Node → "Mark as High Value"
```

### Notizen hinzufügen
```
Rechtsklick auf Node → Node Info → Notes
```

### Markierungen finden
```cypher
# Alle Owned
MATCH (n {owned:true}) RETURN n

# Alle High-Value
MATCH (n {highvalue:true}) RETURN n
```

---

## Angriffspfad-Analyse

### Typische Eskalationspfade

#### 1. GenericAll auf User
```
User A hat GenericAll auf User B
→ Kann Password von User B ändern
→ ForceChangePassword
```

#### 2. GenericAll auf Group
```
User A hat GenericAll auf Group "Domain Admins"
→ Kann sich selbst zur Gruppe hinzufügen
→ Net group / Add-ADGroupMember
```

#### 3. WriteDacl auf Object
```
User A hat WriteDacl auf User B
→ Kann sich selbst GenericAll auf User B geben
→ Dann ForceChangePassword
```

#### 4. WriteOwner
```
User A hat WriteOwner auf Object
→ Ownership übernehmen
→ Dann Permissions ändern
```

#### 5. AddMembers (Group)
```
User A hat AddMembers auf Group
→ Sich selbst zur Gruppe hinzufügen
```

#### 6. ForceChangePassword
```
User A hat ForceChangePassword auf User B
→ Passwort ändern ohne altes zu kennen
```

#### 7. AdminTo (Computer)
```
User A ist Admin auf Computer B
→ PSExec/WMIExec/etc.
→ Lokale SAM dumpen
→ Credentials extrahieren
```

#### 8. CanRDP
```
User A hat CanRDP auf Computer B
→ RDP-Zugriff
→ Credentials extrahieren
```

#### 9. HasSession
```
Domain Admin hat Session auf Computer A
→ Wenn wir Admin auf Computer A sind
→ Mimikatz / Token Impersonation
```

---

## Edge-Types verstehen

### Wichtigste Beziehungen (Edges)

| Edge | Bedeutung | Exploitation |
|------|-----------|--------------|
| **AdminTo** | Lokaler Admin | PSExec, WMI, Remote SAM dump |
| **MemberOf** | Gruppen-Membership | Vererbte Rechte |
| **HasSession** | User ist angemeldet | Credential Theft, Token Impersonation |
| **GenericAll** | Full Control | Alles (siehe Help) |
| **WriteDacl** | Kann Permissions ändern | Add-DomainObjectAcl |
| **WriteOwner** | Kann Owner ändern | Set-DomainObjectOwner |
| **ForceChangePassword** | Kann Passwort ändern | Set-DomainUserPassword |
| **AllExtendedRights** | Alle erweiterten Rechte | User-Force-Change-Password |
| **AddMembers** | Kann Member hinzufügen | Add-DomainGroupMember |
| **CanRDP** | RDP-Rechte | xfreerdp |
| **CanPSRemote** | PSRemoting-Rechte | evil-winrm, Enter-PSSession |
| **ExecuteDCOM** | DCOM Execution | MMC20.Application lateral movement |

### Edge Help (Abuse Info)
```
Rechtsklick auf Edge → Help
→ Zeigt Exploitation-Details
→ Windows / Linux Commands
```

---

## Praktischer OSCP-Workflow

### Phase 1: Initial Collection
```bash
# 1. Credentials bekommen (z.B. via SQL injection, password spray, etc.)

# 2. SharpHound/bloodhound.py ausführen
bloodhound-python -u user -p 'pass' -d corp.local -ns 10.10.10.100 -c All

# 3. Neo4j starten
sudo neo4j console

# 4. BloodHound starten
bloodhound

# 5. Daten importieren
Upload Data → *.json files
```

### Phase 2: Initial Recon
```
# In BloodHound:
1. Analysis → "Find all Domain Admins"
   → Wer sind die Ziele?

2. Analysis → "List all Kerberoastable Accounts"
   → Quick Wins?

3. Analysis → "Find Computers with Unsupported OS"
   → Alte Systeme = einfachere Exploits

4. Search nach deinem User
   → Rechtsklick → Mark as Owned
```

### Phase 3: Path Finding
```
1. Analysis → "Shortest Paths from Owned Principals"
   → Gibt es direkte Pfade zu DA?

2. Rechtsklick auf deinen User → "Outbound Object Control"
   → Was kannst du direkt kontrollieren?

3. Für jeden Hop im Pfad:
   → Rechtsklick auf Edge → Help
   → Anleitung für Exploitation
```

### Phase 4: Exploitation
```
# Beispiel-Pfad:
USER@CORP.LOCAL
  → [MemberOf] → IT-SUPPORT@CORP.LOCAL
  → [GenericAll] → BACKUP-ADMIN@CORP.LOCAL
  → [MemberOf] → BACKUP-OPERATORS@CORP.LOCAL
  → [AdminTo] → DC01.CORP.LOCAL
  → [MemberOf] → DOMAIN ADMINS@CORP.LOCAL

# Umsetzung:
1. USER ist in IT-SUPPORT Gruppe (automatisch)
2. IT-SUPPORT hat GenericAll auf BACKUP-ADMIN
   → ForceChangePassword auf BACKUP-ADMIN
3. BACKUP-ADMIN ist in BACKUP-OPERATORS
4. BACKUP-OPERATORS sind Admin auf DC
   → PSExec/WMI zu DC
5. Domain Admin!
```

---

## Tipps & Tricks

### 1. Pathfinding Settings anpassen
```
Settings → Edge Filtering
→ Deaktiviere unwichtige Edges für klarere Graphs
```

### 2. Custom Queries speichern
```
Raw Query (unten) → Cypher eingeben → Speichern
```

### 3. Export von Graphs
```
Graph anzeigen → Rechtsklick → Export to JSON
```

### 4. Database löschen/neu starten
```bash
# Neo4j stoppen
sudo systemctl stop neo4j

# Datenbank löschen
sudo rm -rf /var/lib/neo4j/data/databases/graph.db
sudo rm -rf /var/lib/neo4j/data/databases/neo4j

# Neu starten
sudo systemctl start neo4j
```

### 5. Mehrere Domains
```
BloodHound unterstützt Multi-Domain/Forest
→ Einfach alle JSONs importieren
→ Trust-Relationships werden angezeigt
```

---

## Häufige Fehler

### "Authentication Failed"
```
→ Neo4j-Passwort falsch
→ Lösung: Neo4j neustarten, Passwort zurücksetzen
```

### "No data found"
```
→ Daten nicht importiert oder Neo4j läuft nicht
→ Lösung: http://localhost:7474 prüfen, Daten re-importieren
```

### Graph ist zu groß/unübersichtlich
```
→ Edge Filtering nutzen
→ Settings → Query Debug Mode → Max Depth limitieren
```

### Import funktioniert nicht
```
→ .zip direkt hochladen statt einzelne .json
→ Oder alle .json zusammen auswählen
```

---

## Advanced Features

### BloodHound API
```bash
# Query via curl
curl -u neo4j:password -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"MATCH (n:User) RETURN n LIMIT 5"}]}' \
  http://localhost:7474/db/data/transaction/commit
```

### Custom Edges hinzufügen
```cypher
# Eigene Beziehung erstellen
MATCH (u:User {name:'USER1@CORP.LOCAL'}), (c:Computer {name:'PC01.CORP.LOCAL'})
CREATE (u)-[:CustomEdge]->(c)
```

### PlumHound (Reporting)
```bash
# Automatische Reports generieren
git clone https://github.com/PlumHound/PlumHound
cd PlumHound
python3 PlumHound.py -x tasks/default.tasks
```

---

## OSCP-spezifische Tipps

1. **DCOnly zuerst** - Schneller Überblick ohne Session-Enum
2. **Owned Principals markieren** - Sofort nach jedem Kompromiss
3. **Kerberoasting prüfen** - Oft schnellster Weg zu privilegiertem Account
4. **ACL-Missconfigurations** - GenericAll/WriteDacl sind Gold
5. **Alte OS-Versionen** - Windows 7/2008 = einfachere Exploits
6. **Session-Enum nur wenn nötig** - Sehr laut, nimmt viel Zeit
7. **LAPS checken** - `haslaps=false` = potentiell schwache lokale Admin-Passwörter
8. **Trust-Relationships** - Bei Multi-Domain-Umgebungen

---

## Quick Reference

| Aktion | Kommando |
|--------|----------|
| Neo4j starten | `sudo neo4j console` |
| BloodHound starten | `bloodhound` |
| Daten importieren | Upload Data → .zip/.json |
| User als Owned markieren | Rechtsklick → Mark as Owned |
| Pfad zu DA | Analysis → Shortest Path from Owned |
| Kerberoastable finden | Analysis → Kerberoastable Accounts |
| Help zu Edge | Rechtsklick auf Edge → Help |
| Custom Query | Raw Query (unten) |
| DB zurücksetzen | `rm -rf /var/lib/neo4j/data/databases/*` |

---

## Weiterführende Ressourcen

- BloodHound Docs: https://bloodhound.readthedocs.io
- Cypher Syntax: https://neo4j.com/docs/cypher-manual
- Attack Primitives: https://posts.specterops.io/
- Custom Queries: https://github.com/hausec/Bloodhound-Custom-Queries
