# Directory & File Brute-Force Testing Guide

> **Wichtig:** Nur auf eigenen Servern oder mit ausdrücklicher Genehmigung verwenden!

## Inhaltsverzeichnis
- [Tools Übersicht](#tools-übersicht)
- [Wordlist Kategorien](#wordlist-kategorien)
- [Tool Howtos](#tool-howtos)
- [Vergleich & Empfehlungen](#vergleich--empfehlungen)

---

## Tools Übersicht

| Tool | Sprache | Speed | Rekursiv | Empfehlung |
|------|---------|-------|----------|------------|
| dirb | C | ⭐⭐ | Ja | Anfänger |
| dirbuster | Java | ⭐⭐ | Ja | GUI-Nutzer |
| gobuster | Go | ⭐⭐⭐⭐⭐ | Nein* | **Beste Performance** |
| ffuf | Go | ⭐⭐⭐⭐⭐ | Ja | **Modernste Features** |
| feroxbuster | Rust | ⭐⭐⭐⭐⭐ | Ja | **Best Balance** |
| wfuzz | Python | ⭐⭐⭐ | Ja | Fuzzing-Spezialist |
| dirsearch | Python | ⭐⭐⭐ | Ja | Python-Fans |

---

## Wordlist Kategorien

### 🟢 Standard Enumeration
**Schnell, für initiale Scans**
- `/usr/share/wordlists/dirb/common.txt` (~4.600 Einträge)
- `/usr/share/wordlists/dirb/small.txt` (~959 Einträge)
- `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` (~87.650 Einträge)

### 🟡 Advanced Enumeration
**Umfangreicher, für gründliche Tests**
- `/usr/share/wordlists/dirb/big.txt` (~20.460 Einträge)
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` (~220.560 Einträge)
- `/usr/share/wordlists/metasploit/sensitive_files.txt`

### 🔴 Ultra Deep Enumeration
**Sehr umfangreich, zeitintensiv**
- `/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt`
- Kombinierte Listen
- Custom wordlists

---

## Tool Howtos

### 1. DIRB

#### Installation
```bash
sudo apt install dirb
```

#### Basic Usage
```bash
# Standard Scan
dirb http://target.com

# Mit spezifischer Wordlist
dirb http://target.com /usr/share/wordlists/dirb/common.txt

# Mit User-Agent
dirb http://target.com /usr/share/wordlists/dirb/big.txt -a "Mozilla/5.0"

# Output in Datei speichern
dirb http://target.com -o results_dirb.txt

# Ignore specific response codes
dirb http://target.com -N 404

# Mit Authentication
dirb http://target.com -u username:password
```

#### Advanced Options
```bash
# Zeige nicht-existierende Seiten NICHT
dirb http://target.com -N 404

# Setze Delay (in Millisekunden)
dirb http://target.com -z 100

# Verwende Cookies
dirb http://target.com -c "COOKIE:value"

# Extensions testen
dirb http://target.com -X .php,.html,.js
```

---

### 2. DirBuster

#### Installation
```bash
sudo apt install dirbuster
```

#### GUI Usage
```bash
# Starten
dirbuster

# Über Terminal starten
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar
```

#### GUI Einstellungen:
1. **Target URL:** http://target.com
2. **Work Method:** Auto Switch (HEAD and GET)
3. **Number of Threads:** 10-50
4. **Select Wordlist:** Browse zu Wordlist
5. **File Extensions:** php,html,txt,js

#### CLI Usage
```bash
# Headless mode
dirbuster -H -u http://target.com -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -r results_dirbuster.txt
```

---

### 3. Gobuster

#### Installation
```bash
sudo apt install gobuster
```

#### Directory Mode
```bash
# Basic Scan
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Mit Extensions
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/big.txt -x php,html,txt,js

# Threads erhöhen (Standard: 10)
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -t 50

# Output speichern
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -o results_gobuster.txt

# Status Codes filtern
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -b 404,403

# Nur spezifische Status Codes zeigen
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -s 200,204,301,302,307,401

# Mit User-Agent
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -a "Mozilla/5.0"

# Keine Fehler anzeigen
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -q

# Mit Timeout
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt --timeout 30s

# HTTPS mit selbst-signiertem Zertifikat
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -k
```

#### DNS Mode
```bash
gobuster dns -d target.com -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt
```

#### VHOST Mode
```bash
gobuster vhost -u http://target.com -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt
```

---

### 4. FFUF

#### Installation
```bash
sudo apt install ffuf
```

#### Basic Directory Fuzzing
```bash
# Standard Scan
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ

# Mit Extensions
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://target.com/FUZZ -e .php,.html,.txt,.js

# Colorized Output
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -c

# Threads/Speed
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -t 100

# Filter by Status Code
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -fc 404

# Filter by Size
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -fs 4242

# Filter by Words
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -fw 97

# Match Status Code
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -mc 200,301,302

# Output formats
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -o results.json -of json
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -o results.html -of html
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -o results.csv -of csv

# Rekursiv
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -recursion -recursion-depth 2
```

#### Advanced Fuzzing
```bash
# Parameter Fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/page?FUZZ=value

# POST Data Fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/login -X POST -d "username=admin&password=FUZZ"

# Header Fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com -H "X-Custom-Header: FUZZ"

# Multiple Wordlists
ffuf -w users.txt:USER -w pass.txt:PASS -u http://target.com/login -X POST -d "username=USER&password=PASS"

# Rate Limiting
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -rate 100
```

---

### 5. Feroxbuster

#### Installation
```bash
sudo apt install feroxbuster
```

#### Basic Usage
```bash
# Standard Scan (automatisch rekursiv!)
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Threads anpassen
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt -t 50

# Tiefe limitieren
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt --depth 2

# Extensions
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js

# Status Codes filtern
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt -C 404,403

# Output speichern
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt -o results_ferox.txt

# Leise (nur Findings)
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt --quiet

# Extrem verbose
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt -vvv

# Mit Timeout
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt --timeout 10

# Insecure SSL
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt -k
```

#### Advanced Features
```bash
# Automatisches Tune (passt sich an)
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt --auto-tune

# Smart Filter (filtert automatisch false positives)
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt --auto-bail

# Resume scan
feroxbuster --resume-from ferox-http_target_com-1234567890.state

# Extrakt Links aus Responses
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt --extract-links

# Rate Limiting
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt --rate-limit 100
```

---

### 6. Wfuzz

#### Installation
```bash
sudo apt install wfuzz
```

#### Basic Usage
```bash
# Standard Directory Scan
wfuzz -w /usr/share/wordlists/dirb/common.txt http://target.com/FUZZ

# Hide 404 responses
wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404 http://target.com/FUZZ

# Hide by size
wfuzz -w /usr/share/wordlists/dirb/common.txt --hs 4242 http://target.com/FUZZ

# Show only specific codes
wfuzz -w /usr/share/wordlists/dirb/common.txt --sc 200,301,302 http://target.com/FUZZ

# Threads
wfuzz -w /usr/share/wordlists/dirb/common.txt -t 50 http://target.com/FUZZ

# Mit Extensions
wfuzz -w /usr/share/wordlists/dirb/common.txt -z list,php-html-txt-js http://target.com/FUZZ.FUZ2Z
```

#### Advanced Fuzzing
```bash
# POST Parameter Fuzzing
wfuzz -w /usr/share/wordlists/dirb/common.txt -d "username=admin&password=FUZZ" http://target.com/login

# Cookie Fuzzing
wfuzz -w /usr/share/wordlists/dirb/common.txt -b "session=FUZZ" http://target.com/

# Header Fuzzing
wfuzz -w /usr/share/wordlists/dirb/common.txt -H "User-Agent: FUZZ" http://target.com/

# Multiple Wordlists
wfuzz -w users.txt -w pass.txt -d "username=FUZZ&password=FUZ2Z" http://target.com/login
```

---

### 7. Dirsearch

#### Installation
```bash
sudo apt install dirsearch
# oder
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
python3 dirsearch.py
```

#### Basic Usage
```bash
# Standard Scan
dirsearch -u http://target.com

# Mit spezifischer Wordlist
dirsearch -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Extensions
dirsearch -u http://target.com -e php,html,js,txt

# Threads
dirsearch -u http://target.com -t 50

# Exclude Status Codes
dirsearch -u http://target.com -x 404,403

# Output
dirsearch -u http://target.com -o results_dirsearch.txt

# Rekursiv
dirsearch -u http://target.com -r

# Rekursive Tiefe
dirsearch -u http://target.com -r --max-recursion-depth=2

# Random User-Agent
dirsearch -u http://target.com --random-agent

# Delay zwischen Requests
dirsearch -u http://target.com --delay 1
```

---

## Vergleich & Empfehlungen

### Speed Ranking
1. **Gobuster** - Am schnellsten für einfache Scans
2. **Ffuf** - Sehr schnell + flexibel
3. **Feroxbuster** - Schnell + smart features
4. **Dirsearch** - Mittel
5. **Wfuzz** - Mittel
6. **Dirb** - Langsam
7. **DirBuster** - Langsam

### Feature Ranking
1. **Ffuf** - Maximale Flexibilität
2. **Feroxbuster** - Best Balance
3. **Wfuzz** - Fuzzing-Spezialist
4. **Gobuster** - Simpel aber effektiv
5. **Dirsearch** - Gute Defaults
6. **Dirb** - Basic
7. **DirBuster** - GUI

### Use Cases

#### Schneller Initial Scan
```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -t 50 -q
```

#### Umfassender Rekursiver Scan
```bash
feroxbuster -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --depth 3
```

#### Fuzzing & Parameter Testing
```bash
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://target.com/FUZZ -recursion
```

#### GUI für Visualisierung
```bash
dirbuster
```

---

## Best Practices

### 1. Immer mit Permission testen!
```bash
# Dokumentiere deine Autorisierung
echo "Pentest authorized by: [Name] on [Date]" > authorization.txt
```

### 2. Rate Limiting beachten
```bash
# Verwende Delays bei produktiven Systemen
feroxbuster -u http://target.com -w wordlist.txt --rate-limit 50
```

### 3. Kombiniere Tools
```bash
# Schneller Scan mit gobuster
gobuster dir -u http://target.com -w common.txt -o quick.txt

# Detaillierter Scan auf gefundenen Pfaden
ffuf -w big.txt -u http://target.com/admin/FUZZ -recursion
```

### 4. Logs speichern
```bash
# Immer Output speichern
feroxbuster -u http://target.com -w wordlist.txt -o results_$(date +%Y%m%d_%H%M%S).txt
```

### 5. False Positives filtern
```bash
# Teste zuerst, welche Status Codes interessant sind
curl -I http://target.com/randomnonexistent123456

# Dann filtere entsprechend
ffuf -w wordlist.txt -u http://target.com/FUZZ -fc 404 -fs 1234
```

---

## Cheat Sheet

### Schnellreferenz

```bash
# Gobuster - Schnell & Simpel
gobuster dir -u TARGET -w WORDLIST -x php,html -t 50 -q

# Ffuf - Flexibel & Powerful
ffuf -w WORDLIST -u TARGET/FUZZ -c -fc 404 -t 100 -recursion

# Feroxbuster - Smart & Rekursiv
feroxbuster -u TARGET -w WORDLIST -x php,html --auto-tune

# Dirb - Klassisch
dirb TARGET WORDLIST -N 404

# Wfuzz - Fuzzing
wfuzz -w WORDLIST --hc 404 -t 50 TARGET/FUZZ
```

---

## Tags
#pentesting #enumeration #reconnaissance #directoryscanning #bruteforce #kali #security
