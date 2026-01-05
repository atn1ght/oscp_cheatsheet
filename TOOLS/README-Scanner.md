# Directory Brute-Force Scanner Suite

Automatisiertes Multi-Tool Testing Framework für Directory & File Enumeration

## 📁 Dateien

- `Directory-Brute-Force-Guide.md` - Komplettes Howto für alle Tools (Obsidian-kompatibel)
- `dirbrute-scanner.sh` - Automatisiertes Scan-Skript
- `README-Scanner.md` - Diese Datei

## 🚀 Quick Start

### 1. Skript ausführbar machen
```bash
chmod +x dirbrute-scanner.sh
```

### 2. Standard Scan
```bash
./dirbrute-scanner.sh -t http://localhost
```

### 3. Advanced Scan
```bash
./dirbrute-scanner.sh -t http://localhost -m advanced
```

### 4. Ultra Deep Scan (dauert sehr lange!)
```bash
./dirbrute-scanner.sh -t http://localhost -m ultra
```

## 📊 Scan Modi Übersicht

| Modus | Wordlists | Einträge | Dauer | Verwendung |
|-------|-----------|----------|-------|------------|
| **Standard** | common.txt, small.txt | ~5.600 | 1-5 Min | Schneller Initial-Scan |
| **Advanced** | big.txt, directory-list-small | ~108K | 10-30 Min | Gründlicher Standard-Test |
| **Ultra** | directory-list-medium, lowercase | ~440K | 1-3 Std | Comprehensive Deep-Dive |
| **All** | Alle oben genannten | ~554K | 2-5 Std | Vollständige Enumeration |

## 🗂️ Wordlist Kategorisierung

### 🟢 Standard Enumeration (Quick & Dirty)

**Zweck:** Schnelle initiale Enumeration, häufigste Pfade

| Wordlist | Pfad | Einträge | Beschreibung |
|----------|------|----------|--------------|
| common.txt | `/usr/share/wordlists/dirb/common.txt` | ~4.614 | Häufigste Directories/Files |
| small.txt | `/usr/share/wordlists/dirb/small.txt` | ~959 | Minimale Liste für Tests |

**Verwendung:**
- Initial Reconnaissance
- Schnelle CTF-Challenges
- Zeitkritische Assessments
- Wenn du nur nach low-hanging fruits suchst

**Beispiel:**
```bash
./dirbrute-scanner.sh -t http://target.com -m standard
```

---

### 🟡 Advanced Enumeration (Thorough)

**Zweck:** Gründliche Enumeration, auch ungewöhnliche Pfade

| Wordlist | Pfad | Einträge | Beschreibung |
|----------|------|----------|--------------|
| big.txt | `/usr/share/wordlists/dirb/big.txt` | ~20.469 | Erweiterte Directory-Liste |
| directory-list-2.3-small | `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` | ~87.650 | DirBuster Small List |
| sensitive_files | `/usr/share/wordlists/metasploit/sensitive_files.txt` | ~1.358 | Sensitive Files (configs, backups, etc.) |

**Verwendung:**
- Standard Pentests
- Nach initial scan noch tiefer graben
- Wenn du mehr Zeit hast
- Professionelle Assessments

**Beispiel:**
```bash
./dirbrute-scanner.sh -t http://target.com -m advanced -T 100
```

---

### 🔴 Ultra Deep Enumeration (Comprehensive)

**Zweck:** Maximale Coverage, keine Steine unberührt lassen

| Wordlist | Pfad | Einträge | Beschreibung |
|----------|------|----------|--------------|
| directory-list-2.3-medium | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | ~220.560 | DirBuster Medium (Most common) |
| directory-list-lowercase-2.3-medium | `/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt` | ~207.629 | Lowercase variants |

**Verwendung:**
- Vollständige Coverage benötigt
- Red Team Engagements
- Wenn alle anderen Methoden fehlschlagen
- Time-unlimited assessments
- Bug Bounty deep dives

**Beispiel:**
```bash
./dirbrute-scanner.sh -t http://target.com -m ultra --tools gobuster,ffuf
```

**⚠️ Warnung:** Kann mehrere Stunden dauern und erzeugt viel Traffic!

---

## 🔧 Weitere Wordlists auf deinem System

### Für Subdomain Enumeration
```bash
/usr/share/wordlists/amass/
├── subdomains-top1mil-5000.txt      # Top 5K subdomains
├── subdomains-top1mil-20000.txt     # Top 20K subdomains
└── subdomains-top1mil-110000.txt    # Top 110K subdomains
```

### Für Password Attacks (NICHT für Directory Scanning)
```bash
/usr/share/wordlists/rockyou.txt            # Famous password list
/usr/share/wordlists/fasttrack.txt          # FastTrack passwords
```

### Für spezifische Anwendungen
```bash
/usr/share/wordlists/metasploit/
├── tomcat_mgr_default_userpass.txt   # Tomcat credentials
├── http_default_pass.txt              # HTTP default passwords
├── sensitive_files.txt                # Sensitive files
└── sensitive_files_win.txt            # Windows sensitive files
```

## 🛠️ Skript Features

### Automatische Tool-Erkennung
Das Skript prüft automatisch, welche Tools installiert sind:
- gobuster
- ffuf
- feroxbuster
- dirb
- dirsearch
- wfuzz

### Flexible Tool-Auswahl
```bash
# Nur gobuster und ffuf verwenden
./dirbrute-scanner.sh -t http://target.com --tools gobuster,ffuf

# Alle Tools verwenden
./dirbrute-scanner.sh -t http://target.com --tools gobuster,ffuf,feroxbuster,dirb,dirsearch,wfuzz
```

### Anpassbare Parameter
```bash
# Mehr Threads für schnellere Scans
./dirbrute-scanner.sh -t http://target.com -T 100

# Spezifische Extensions
./dirbrute-scanner.sh -t http://target.com -e "php,asp,jsp,txt"

# Custom Output Directory
./dirbrute-scanner.sh -t http://target.com -o ./my_results
```

### Automatische Summary-Generierung
Nach jedem Scan wird automatisch ein `SUMMARY.md` erstellt mit:
- Übersicht aller Findings
- Anzahl der Entdeckungen pro Tool
- Liste aller generierten Dateien
- Scan-Konfiguration

## 📂 Output Struktur

```
scan_results_20251212_143022/
├── scan_config.txt              # Scan configuration
├── SUMMARY.md                   # Auto-generated summary
├── common/                      # Results from common.txt
│   ├── gobuster_results.txt
│   ├── ffuf_results.txt
│   ├── ffuf_results.json
│   └── feroxbuster_results.txt
├── big/                         # Results from big.txt
│   ├── gobuster_results.txt
│   ├── ffuf_results.txt
│   └── feroxbuster_results.txt
└── directory-list-2.3-medium/   # Results from medium list
    ├── gobuster_results.txt
    ├── ffuf_results.txt
    └── feroxbuster_results.txt
```

## 💡 Best Practices

### 1. Immer mit Standard beginnen
```bash
# Schneller Überblick verschaffen
./dirbrute-scanner.sh -t http://target.com -m standard
```

### 2. Bei interessanten Findings: Advanced
```bash
# Tiefer graben
./dirbrute-scanner.sh -t http://target.com -m advanced
```

### 3. Nur wenn nötig: Ultra
```bash
# Letzte Resort
./dirbrute-scanner.sh -t http://target.com -m ultra
```

### 4. Rate Limiting beachten
```bash
# Für produktive Systeme: Weniger Threads
./dirbrute-scanner.sh -t http://target.com -T 10
```

### 5. Tool-Kombination
```bash
# Gobuster für Speed, ffuf für Flexibilität
./dirbrute-scanner.sh -t http://target.com --tools gobuster,ffuf
```

## 🎯 Use Cases

### CTF Challenge
```bash
# Schnell und aggressiv
./dirbrute-scanner.sh -t http://ctf.target.com -m standard --tools gobuster -T 100
```

### Professional Pentest
```bash
# Gründlich aber respektvoll
./dirbrute-scanner.sh -t https://client.com -m advanced --tools gobuster,ffuf,feroxbuster -T 20
```

### Bug Bounty
```bash
# Maximum coverage
./dirbrute-scanner.sh -t https://bugbounty.target.com -m ultra --tools gobuster,ffuf -T 50
```

### Eigener Testserver
```bash
# Alle Tools, alle Modi
./dirbrute-scanner.sh -t http://localhost:8080 -m all --tools gobuster,ffuf,feroxbuster,dirb,dirsearch,wfuzz
```

## 🔍 Tool Empfehlungen nach Szenario

| Szenario | Empfohlene Tools | Modus | Threads |
|----------|------------------|-------|---------|
| Schneller Scan | gobuster | standard | 100 |
| Gründlicher Scan | gobuster, ffuf | advanced | 50 |
| CTF | gobuster | standard | 100 |
| Pentest | ffuf, feroxbuster | advanced | 20-50 |
| Bug Bounty | gobuster, ffuf | ultra | 50 |
| Red Team | feroxbuster | ultra | 10-20 |

## 📝 Beispiel-Workflows

### Workflow 1: Standard Pentest
```bash
# 1. Quick Win Scan
./dirbrute-scanner.sh -t http://target.com -m standard --tools gobuster

# 2. Review findings
cat scan_results_*/SUMMARY.md

# 3. Deeper scan auf interessanten Pfaden
./dirbrute-scanner.sh -t http://target.com/admin -m advanced --tools ffuf,feroxbuster
```

### Workflow 2: Bug Bounty
```bash
# 1. Fast initial scan
./dirbrute-scanner.sh -t https://target.com -m standard --tools gobuster -T 100

# 2. Parallel advanced scan
./dirbrute-scanner.sh -t https://target.com -m advanced --tools ffuf,feroxbuster -T 50

# 3. Wenn wenig gefunden: Ultra
./dirbrute-scanner.sh -t https://target.com -m ultra --tools gobuster
```

### Workflow 3: Red Team
```bash
# Langsam und stealth
./dirbrute-scanner.sh -t https://target.com -m advanced --tools feroxbuster -T 5
```

## ⚙️ Weitere Konfiguration

### Custom Wordlist hinzufügen
Editiere `dirbrute-scanner.sh` und füge deine Wordlist hinzu:

```bash
# In der Wordlist-Sektion
declare -a WORDLIST_CUSTOM=(
    "/path/to/your/custom_wordlist.txt"
    "/path/to/another/wordlist.txt"
)
```

### Neue Scan-Modi erstellen
```bash
# Im Script einen neuen Mode hinzufügen
"custom")
    wordlists=("${WORDLIST_CUSTOM[@]}")
    print_header "Running CUSTOM Enumeration"
    ;;
```

## 🐛 Troubleshooting

### Tools nicht gefunden
```bash
# Installiere fehlende Tools
sudo apt update
sudo apt install gobuster ffuf dirb dirsearch

# Feroxbuster manuell installieren
wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb
sudo dpkg -i feroxbuster_amd64.deb
```

### Wordlists nicht gefunden
```bash
# SecLists installieren
sudo apt install seclists

# Oder manuell
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

### Permission Denied
```bash
# Skript ausführbar machen
chmod +x dirbrute-scanner.sh
```

### Scan zu langsam
```bash
# Mehr Threads verwenden
./dirbrute-scanner.sh -t http://target.com -T 200

# Schnellere Tools verwenden
./dirbrute-scanner.sh -t http://target.com --tools gobuster,ffuf
```

## 📚 Weiterführende Ressourcen

- **SecLists:** https://github.com/danielmiessler/SecLists
- **Gobuster:** https://github.com/OJ/gobuster
- **Ffuf:** https://github.com/ffuf/ffuf
- **Feroxbuster:** https://github.com/epi052/feroxbuster

## ⚠️ Legal Disclaimer

**NUR auf eigenen Servern oder mit ausdrücklicher schriftlicher Genehmigung verwenden!**

Unauthorized access to computer systems is illegal. Dieses Tool ist nur für:
- Eigene Systeme
- Autorisierte Penetration Tests
- CTF Challenges
- Bildungszwecke in kontrollierten Umgebungen

## 🏷️ Tags
`#pentesting` `#enumeration` `#reconnaissance` `#directory-scanning` `#bruteforce` `#kali` `#security` `#automation` `#wordlists`
