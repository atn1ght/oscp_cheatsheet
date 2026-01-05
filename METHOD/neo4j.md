# Neo4j - Graph Database für BloodHound

## Was ist Neo4j?

Neo4j ist eine Graph-Datenbank, die von BloodHound zur Speicherung und Analyse von Active Directory-Daten verwendet wird.

**Wichtig:** Neo4j muss laufen, bevor BloodHound gestartet wird!

---

## Installation

### Kali Linux
```bash
# Via apt
sudo apt update
sudo apt install neo4j

# Java benötigt (wird automatisch installiert)
```

### Manuelle Installation
```bash
# Download
wget https://neo4j.com/artifact.php?name=neo4j-community-4.x.x-unix.tar.gz

# Entpacken
tar -xf neo4j-community-4.x.x-unix.tar.gz
cd neo4j-community-4.x.x
```

---

## Neo4j starten & stoppen

### Als Service
```bash
# Starten
sudo systemctl start neo4j

# Stoppen
sudo systemctl stop neo4j

# Status prüfen
sudo systemctl status neo4j

# Auto-Start aktivieren
sudo systemctl enable neo4j
```

### Console-Modus (empfohlen für OSCP)
```bash
# Im Vordergrund starten
sudo neo4j console

# Vorteile:
# - Siehst direkt Logs
# - Einfach zu stoppen (Ctrl+C)
# - Gut für temporäre Nutzung
```

### Manuell (wenn nicht als Service installiert)
```bash
cd /path/to/neo4j
./bin/neo4j start
./bin/neo4j stop
./bin/neo4j status
```

---

## Konfiguration

### Config-Datei
```bash
# Kali default location
sudo nano /etc/neo4j/neo4j.conf

# Oder
sudo nano /usr/share/neo4j/conf/neo4j.conf
```

### Wichtige Settings

#### Remote Access aktivieren
```conf
# Uncomment diese Zeile für remote access:
dbms.default_listen_address=0.0.0.0

# Standard (nur localhost):
# dbms.default_listen_address=127.0.0.1
```

#### Memory Settings anpassen
```conf
# Initial heap size
dbms.memory.heap.initial_size=512m

# Max heap size
dbms.memory.heap.max_size=1G

# Für große Datasets erhöhen:
dbms.memory.heap.max_size=4G
```

---

## Erste Schritte

### 1. Neo4j starten
```bash
sudo neo4j console
```

### 2. Web-Interface öffnen
```
Browser: http://localhost:7474
```

### 3. Erstes Login

**Default-Credentials:**
```
Username: neo4j
Password: neo4j
```

**Passwort ändern (WICHTIG):**
```
Bei erstem Login wirst du aufgefordert, das Passwort zu ändern.
Empfohlen: bloodhound oder ein eigenes Passwort
```

### 4. Verbindung testen
```cypher
# Im Browser-Interface ausführen:
MATCH (n) RETURN n LIMIT 5
```

---

## Ports & Verbindungen

### Standard-Ports

| Port | Protokoll | Verwendung |
|------|-----------|------------|
| **7474** | HTTP | Web-Interface |
| **7473** | HTTPS | Secure Web-Interface |
| **7687** | Bolt | BloodHound Connection |

### Ports prüfen
```bash
# Sind die Ports offen?
sudo netstat -tulpn | grep neo4j

# Oder
sudo ss -tulpn | grep 7474
```

### Firewall-Regeln (falls nötig)
```bash
# UFW
sudo ufw allow 7474/tcp
sudo ufw allow 7687/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 7474 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7687 -j ACCEPT
```

---

## BloodHound Connection

### Connection-Details für BloodHound

```
Database URL: bolt://localhost:7687
Username: neo4j
Password: <dein_passwort>
```

### Alternative URLs
```
# Remote Neo4j
bolt://192.168.1.100:7687

# Mit Authentifizierung in URL
bolt://neo4j:password@localhost:7687
```

---

## Datenbank-Management

### Alle Daten löschen (Fresh Start)
```cypher
# Im Neo4j Browser:
MATCH (n) DETACH DELETE n
```

### Statistiken anzeigen
```cypher
# Anzahl Nodes
MATCH (n) RETURN count(n)

# Nach Type
MATCH (u:User) RETURN count(u)
MATCH (c:Computer) RETURN count(c)
MATCH (g:Group) RETURN count(g)

# Anzahl Relationships
MATCH ()-[r]->() RETURN count(r)
```

### Datenbank-Info
```cypher
# Schema anzeigen
CALL db.schema.visualization()

# Alle Labels
CALL db.labels()

# Alle Relationship-Types
CALL db.relationshipTypes()
```

---

## Backup & Restore

### Datenbank-Pfad
```bash
# Default location
/var/lib/neo4j/data/databases/

# Oder
/usr/share/neo4j/data/databases/
```

### Backup erstellen
```bash
# Neo4j stoppen
sudo systemctl stop neo4j

# Backup
sudo cp -r /var/lib/neo4j/data/databases/neo4j /backup/neo4j-backup-$(date +%Y%m%d)

# Wieder starten
sudo systemctl start neo4j
```

### Restore
```bash
# Neo4j stoppen
sudo systemctl stop neo4j

# Alte DB löschen
sudo rm -rf /var/lib/neo4j/data/databases/neo4j

# Backup wiederherstellen
sudo cp -r /backup/neo4j-backup-YYYYMMDD /var/lib/neo4j/data/databases/neo4j

# Permissions setzen
sudo chown -R neo4j:neo4j /var/lib/neo4j/data

# Starten
sudo systemctl start neo4j
```

### Fresh Install (Alles zurücksetzen)
```bash
# Neo4j stoppen
sudo systemctl stop neo4j

# Alle Daten löschen
sudo rm -rf /var/lib/neo4j/data/databases/*
sudo rm -rf /var/lib/neo4j/data/transactions/*

# Passwort zurücksetzen
sudo rm -f /var/lib/neo4j/data/dbms/auth

# Starten (Passwort wird wieder neo4j/neo4j)
sudo systemctl start neo4j
```

---

## Troubleshooting

### "Neo4j won't start"
```bash
# Logs prüfen
sudo journalctl -u neo4j -f

# Oder
cat /var/log/neo4j/neo4j.log
```

### "Port already in use"
```bash
# Prüfe welcher Prozess Port 7474 nutzt
sudo lsof -i :7474

# Kill falls nötig
sudo kill -9 <PID>
```

### "Authentication failed"
```bash
# Passwort zurücksetzen
sudo systemctl stop neo4j
sudo rm /var/lib/neo4j/data/dbms/auth
sudo systemctl start neo4j

# Neue Credentials: neo4j/neo4j
```

### "Out of Memory"
```bash
# Heap size erhöhen
sudo nano /etc/neo4j/neo4j.conf

# Ändern:
dbms.memory.heap.max_size=4G

# Neu starten
sudo systemctl restart neo4j
```

### "BloodHound can't connect"
```bash
# 1. Ist Neo4j running?
sudo systemctl status neo4j

# 2. Ist Port 7687 offen?
netstat -tulpn | grep 7687

# 3. Credentials korrekt?
# Browser: http://localhost:7474 → Test login

# 4. Firewall?
sudo ufw status
```

### "Browser zeigt nichts an"
```bash
# Cache löschen
# Oder anderen Browser probieren

# Neo4j neu starten
sudo systemctl restart neo4j

# URL direkt öffnen
http://localhost:7474/browser/
```

---

## Performance-Optimierung

### Für große BloodHound-Datasets

#### 1. Heap Size erhöhen
```conf
# /etc/neo4j/neo4j.conf
dbms.memory.heap.initial_size=2G
dbms.memory.heap.max_size=4G
```

#### 2. Page Cache erhöhen
```conf
dbms.memory.pagecache.size=2G
```

#### 3. Query Timeout erhöhen
```conf
dbms.transaction.timeout=300s
```

#### 4. Indizes erstellen
```cypher
# Automatisch von BloodHound gemacht, aber falls nötig:
CREATE INDEX ON :User(name)
CREATE INDEX ON :Computer(name)
CREATE INDEX ON :Group(name)
```

---

## Nützliche Cypher-Queries

### Wartung

#### Anzahl Objekte pro Type
```cypher
MATCH (n)
RETURN labels(n) as Type, count(*) as Count
ORDER BY Count DESC
```

#### Orphaned Nodes finden
```cypher
MATCH (n)
WHERE NOT (n)--()
RETURN n
```

#### Duplicate Nodes finden
```cypher
MATCH (n)
WITH n.name as name, labels(n) as labels, count(*) as count
WHERE count > 1
RETURN name, labels, count
```

#### Alle Relationships nach Type
```cypher
MATCH ()-[r]->()
RETURN type(r) as RelType, count(r) as Count
ORDER BY Count DESC
```

---

## Sicherheit

### Passwort ändern
```cypher
# Im Neo4j Browser als neo4j eingeloggt:
:server change-password

# Oder via Cypher:
CALL dbms.security.changePassword('new_password')
```

### User Management (Enterprise only)
```cypher
# Neuen User erstellen (nur Neo4j Enterprise)
CALL dbms.security.createUser('username', 'password', false)

# User löschen
CALL dbms.security.deleteUser('username')
```

### Auth deaktivieren (NICHT für Produktion!)
```conf
# /etc/neo4j/neo4j.conf
dbms.security.auth_enabled=false
```

---

## OSCP-Workflow

### Setup für BloodHound
```bash
# 1. Neo4j starten
sudo neo4j console

# 2. Browser öffnen: http://localhost:7474
# 3. Login: neo4j / neo4j
# 4. Passwort ändern zu: bloodhound (oder eigenes)
# 5. BloodHound starten
bloodhound

# 6. In BloodHound verbinden:
# URL: bolt://localhost:7687
# User: neo4j
# Pass: bloodhound
```

### Zwischen Labs wechseln
```cypher
# Alte Daten löschen
MATCH (n) DETACH DELETE n

# Neue BloodHound-Daten importieren
# Upload Data → neue .json files
```

### Nach OSCP Exam
```bash
# Neo4j stoppen (Ressourcen freigeben)
sudo systemctl stop neo4j

# Oder ganz deinstallieren
sudo apt remove neo4j
```

---

## Quick Reference

| Kommando | Beschreibung |
|----------|--------------|
| `sudo neo4j console` | Neo4j im Vordergrund starten |
| `sudo systemctl start neo4j` | Als Service starten |
| `sudo systemctl stop neo4j` | Stoppen |
| `http://localhost:7474` | Web-Interface |
| `bolt://localhost:7687` | BloodHound Connection |
| `neo4j / neo4j` | Default-Credentials |
| `MATCH (n) DETACH DELETE n` | Alle Daten löschen |
| `MATCH (n) RETURN count(n)` | Anzahl Nodes |

---

## Credentials (Persönliche Notizen)

**Neo4j:**
```
Passwort: neo4jj
(doppelt j)
```

**BloodHound Admin:**
```
Username: admin
Passwort: wASnesCHEIS353EE!AC
```
