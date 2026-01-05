# Credential Finder - Dokumentation

## Übersicht

Das **Credential Finder Script** ist ein automatisiertes Tool zum Auffinden von Credentials, API-Keys, Tokens und anderen sensiblen Informationen in Dateien und Verzeichnissen.

**WICHTIG:** Nur für autorisierte Security-Tests verwenden! (CTF, HackTheBox, eigene Systeme, Pentests mit schriftlicher Genehmigung)

## Features

### Standard-Suche
- **Passwörter**: Pattern für password, passwd, pwd, pass
- **API Keys**: API-Schlüssel und Secrets
- **Tokens**: Access tokens, Auth tokens, JWT tokens
- **Datenbank-Verbindungen**: MySQL, PostgreSQL, MongoDB, JDBC, MSSQL
- **Cloud-Credentials**: AWS Access Keys und Secret Keys
- **Konfigurationsdateien**: .env, config.php, wp-config.php, settings.py, etc.
- **Private Keys**: RSA, DSA, EC, OpenSSH, PGP
- **SSH-Dateien**: id_rsa, authorized_keys, known_hosts
- **Hardcoded Credentials**: Benutzernamen und Passwörter im Code

### Deep-Scan Modus
Zusätzlich zur Standard-Suche:
- Connection Strings
- Encryption Keys
- Client Secrets
- Base64-kodierte Strings (potentielle Credentials)
- Hash-Werte (MD5, SHA1, SHA256)
- Admin/Root Credentials in JSON

### Sensitive Files
Automatische Suche nach bekannten sensitiven Dateien:
- `.htpasswd`, `.netrc`, `.git-credentials`
- `.dockercfg`, `.npmrc`, `.pypirc`
- `shadow`, `passwd`, `credentials`
- `secrets.yml`, `secret.yml`

## Installation

```bash
# Script ausführbar machen
chmod +x cred-finder.sh
```

## Verwendung

### Basis-Syntax

```bash
./cred-finder.sh [OPTIONS]
```

### Optionen

| Option | Beschreibung |
|--------|-------------|
| `-p, --path PATH` | Zu durchsuchender Pfad (Standard: aktuelles Verzeichnis) |
| `-o, --output DIR` | Ausgabeverzeichnis für Ergebnisse (Standard: cred_findings) |
| `-d, --deep` | Deep-Scan Modus (langsamer aber gründlicher) |
| `-v, --verbose` | Ausführliche Ausgabe |
| `-h, --help` | Hilfe anzeigen |

## Beispiele

### Einfacher Scan im aktuellen Verzeichnis
```bash
./cred-finder.sh
```

### Scan eines spezifischen Pfades
```bash
./cred-finder.sh -p /var/www/html
```

### Deep-Scan mit ausführlicher Ausgabe
```bash
./cred-finder.sh -p /home/user/webapp -d -v
```

### Scan mit benutzerdefiniertem Output-Verzeichnis
```bash
./cred-finder.sh -p /opt/application -o my_findings
```

### Kombination aller Optionen
```bash
./cred-finder.sh --path /var/www --output web_creds --deep --verbose
```

## Output-Struktur

Das Script erstellt folgende Dateien im Output-Verzeichnis:

```
cred_findings/
├── SUMMARY_20231215_143022.txt           # Zusammenfassungsbericht
├── passwords_20231215_143022.txt         # Gefundene Passwörter
├── api_keys_20231215_143022.txt          # API Keys und Secrets
├── secrets_20231215_143022.txt           # Verschiedene Secrets
├── tokens_20231215_143022.txt            # Access und Auth Tokens
├── db_connections_20231215_143022.txt    # Datenbank-Verbindungsstrings
├── aws_creds_20231215_143022.txt         # AWS Credentials
├── env_files_20231215_143022.txt         # Inhalte von .env Dateien
├── config_files_20231215_143022.txt      # Konfigurations-Dateien
├── credential_files_20231215_143022.txt  # Credential-Dateien
├── private_keys_20231215_143022.txt      # Private Keys
├── ssh_keys_20231215_143022.txt          # SSH Keys
├── ssh_files_20231215_143022.txt         # SSH Konfigurationsdateien
├── hardcoded_20231215_143022.txt         # Hardcoded Credentials
├── sensitive_files_20231215_143022.txt   # Sensible Dateien
└── (Deep-Scan Files bei -d Option)
    ├── deep_scan_20231215_143022.txt
    ├── base64_20231215_143022.txt
    └── hashes_20231215_143022.txt
```

## Workflow-Beispiele

### CTF Challenge

```bash
# 1. Nach Übernahme einer Maschine
./cred-finder.sh -p / -d -o ctf_creds

# 2. Summary Report durchsehen
cat cred_findings/SUMMARY_*.txt

# 3. Interessante Findings untersuchen
grep -i "password" cred_findings/passwords_*.txt

# 4. Credentials testen
ssh user@target  # mit gefundenem SSH-Key
mysql -u user -p # mit gefundenem DB-Passwort
```

### Web Application Pentest

```bash
# 1. Webroot durchsuchen
./cred-finder.sh -p /var/www/html -o webapp_creds -v

# 2. .env Dateien prüfen
cat cred_findings/env_files_*.txt

# 3. Database Credentials testen
cat cred_findings/db_connections_*.txt

# 4. API Keys für weitere Tests nutzen
cat cred_findings/api_keys_*.txt
```

### Source Code Audit

```bash
# 1. Repository klonen und scannen
git clone https://github.com/target/repo.git
./cred-finder.sh -p repo/ -d -o source_audit

# 2. Hardcoded Credentials finden
cat cred_findings/hardcoded_*.txt

# 3. Config Files analysieren
cat cred_findings/config_files_*.txt
```

### Post-Exploitation

```bash
# 1. Kompletter System-Scan
./cred-finder.sh -p / -d -o system_creds

# 2. User-Home-Verzeichnisse
./cred-finder.sh -p /home -d -o user_creds

# 3. SSH Keys extrahieren
cat cred_findings/ssh_keys_*.txt

# 4. Gefundene Keys nutzen für Lateral Movement
chmod 600 found_id_rsa
ssh -i found_id_rsa user@other-host
```

## Tipps & Best Practices

### Performance
- **Standard-Scan**: Schnell, für erste Reconnaissance
- **Deep-Scan**: Langsamer aber gründlicher, für vollständige Audits
- Große Verzeichnisse können lange dauern - ggf. Pfad einschränken

### False Positives reduzieren
- Ergebnisse immer manuell verifizieren
- Kommentare und Beispiel-Code werden auch gefunden
- Test-Credentials von echten unterscheiden

### Häufige Fundstellen
```
# Web Applications
/var/www/html/.env
/var/www/html/config.php
/var/www/html/wp-config.php

# User Directories
~/.ssh/id_rsa
~/.aws/credentials
~/.netrc
~/.git-credentials

# Application Configs
/etc/mysql/my.cnf
/etc/shadow
/opt/app/config/
```

### Credentials testen

```bash
# SSH Keys
chmod 600 id_rsa
ssh -i id_rsa user@host

# MySQL
mysql -h host -u user -p'password' database

# PostgreSQL
psql postgresql://user:password@host:5432/database

# AWS CLI
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
aws s3 ls
```

## Integration mit anderen Tools

### Mit LinPEAS kombinieren
```bash
# 1. LinPEAS ausführen
./linpeas.sh > linpeas_output.txt

# 2. Credential Finder ausführen
./cred-finder.sh -d -o creds

# 3. Ergebnisse vergleichen und kombinieren
```

### Mit grep weiter filtern
```bash
# Nur bestimmte Dateitypen
grep -r "password" cred_findings/ | grep ".php"

# Nur spezifische Services
grep -i "mysql\|postgres\|mongodb" cred_findings/db_connections_*.txt

# Case-insensitive Suche
grep -i "admin" cred_findings/hardcoded_*.txt
```

### Output in Pentest-Report einbinden
```bash
# Findings exportieren
cat cred_findings/SUMMARY_*.txt > pentest_report_credentials.txt

# Screenshots von interessanten Findings
cat cred_findings/passwords_*.txt | head -20
```

## Troubleshooting

### Keine Ergebnisse gefunden

```bash
# Verbose Mode aktivieren
./cred-finder.sh -p /path -v

# Deep-Scan versuchen
./cred-finder.sh -p /path -d

# Permissions prüfen
ls -la /path
```

### Permission Denied Fehler

```bash
# Als root ausführen (wenn autorisiert)
sudo ./cred-finder.sh -p /root

# Nur lesbare Verzeichnisse scannen
./cred-finder.sh -p /home/user
```

### Zu viele False Positives

```bash
# Ergebnisse filtern
grep -v "example\|test\|demo" cred_findings/passwords_*.txt

# Nur bestimmte Dateitypen
./cred-finder.sh -p /path | grep -E "\.(php|py|js|env):"
```

## Szenario-basierte Nutzung

### Scenario 1: Initial Access (CTF/HTB)

**Ziel**: Credentials für ersten Zugang finden

```bash
# Web-Directory brute-force + Credential Search
./dirbrute-scanner.sh -u http://target -m advanced
./cred-finder.sh -p downloaded_files/ -d

# Findings analysieren
cat cred_findings/SUMMARY_*.txt
```

### Scenario 2: Privilege Escalation

**Ziel**: Credentials für höhere Privilegien

```bash
# System durchsuchen
./cred-finder.sh -p / -d -o privesc_creds

# Config files prüfen
cat cred_findings/config_files_*.txt

# SUID binaries + creds kombinieren
find / -perm -4000 2>/dev/null
```

### Scenario 3: Lateral Movement

**Ziel**: Credentials für andere Systeme

```bash
# SSH Keys finden
./cred-finder.sh -p /home -o lateral_creds

# Keys extrahieren
cat cred_findings/ssh_keys_*.txt

# Authorized_keys analysieren
cat cred_findings/ssh_files_*.txt
```

### Scenario 4: Data Exfiltration

**Ziel**: Sensible Daten lokalisieren

```bash
# Deep scan
./cred-finder.sh -p /var/www -d -o exfil_data

# API Keys für Cloud Services
cat cred_findings/api_keys_*.txt
cat cred_findings/aws_creds_*.txt

# Database Credentials
cat cred_findings/db_connections_*.txt
```

## Rechtliche Hinweise

⚠️ **NUR FÜR AUTORISIERTE TESTS VERWENDEN!**

**Erlaubt:**
- ✅ Eigene Systeme und Anwendungen
- ✅ CTF Challenges (HackTheBox, TryHackMe, etc.)
- ✅ Pentesting mit schriftlicher Genehmigung
- ✅ Security Audits mit Autorisierung
- ✅ Bildungszwecke in kontrollierten Umgebungen

**NICHT erlaubt:**
- ❌ Unbefugter Zugriff auf fremde Systeme
- ❌ Tests ohne schriftliche Genehmigung
- ❌ Verwendung für illegale Zwecke

## Support & Weiterführende Ressourcen

### Wordlists für Pattern Matching
```bash
# SecLists
/usr/share/seclists/Passwords/

# Custom Patterns erstellen
echo "custom_pattern" >> custom_creds_pattern.txt
grep -f custom_creds_pattern.txt target_files/*
```

### Credential Formats
- **Hash Identifier**: `hash-identifier` oder `hashid`
- **Hash Cracking**: `john`, `hashcat`
- **Password Lists**: `rockyou.txt`, SecLists

### Weiterführende Tools
- **LinPEAS**: Linux Privilege Escalation
- **LaZagne**: Password Recovery Tool
- **Mimikatz**: Windows Credential Extraction
- **secretfinder.py**: JS files credential finder

## Changelog

### v1.0 (Initial Release)
- Pattern-basierte Suche für Credentials
- Support für gängige Config-Dateien
- Deep-Scan Modus
- Summary Report Generation
- Farbige Console-Ausgabe

## Autor & Lizenz

**Zweck**: Educational & Authorized Security Testing
**License**: Nur für legale und autorisierte Verwendung

---

**Happy Hunting! 🎯**
