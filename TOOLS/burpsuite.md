# Burp Suite - Web Application Testing

Burp Suite ist die Standard-Plattform für Web Application Security Testing.

---

## Was ist Burp Suite?

Intercepting Proxy + Web Vulnerability Scanner + Extensive Toolkit für manuelle und automatische Web-Pentests.

**Versionen:**
- **Community Edition** - Kostenlos, limitiert (kein Scanner, throttled Intruder)
- **Professional** - Vollversion mit Scanner ($399/Jahr)
- **Enterprise** - CI/CD Integration

**OSCP Note:** Community Edition reicht vollkommen aus. Scanner ist im OSCP nicht erlaubt.

---

## Installation

### Kali (pre-installed)

```bash
# Community Edition
burpsuite

# Oder direkt über Menü: Applications → Web Application Analysis → burpsuite
```

### Manuelle Installation

```bash
# Download von PortSwigger
wget https://portswigger.net/burp/releases/download?product=community&version=latest&type=Linux

# Ausführbar machen
chmod +x burpsuite_community_linux_*.sh

# Installation
./burpsuite_community_linux_*.sh
```

### Java Version Check

```bash
# Burp benötigt Java
java -version

# Falls nicht installiert
sudo apt install default-jre
```

---

## Basis-Setup

### 1. Proxy Configuration

```
Burp → Proxy → Options
- Proxy Listeners: 127.0.0.1:8080 (default)
- Intercept: On/Off toggle via "Intercept is on/off" button
```

### 2. Browser Setup

**Firefox (empfohlen für Burp):**
```
Preferences → Network Settings → Manual proxy configuration
HTTP Proxy: 127.0.0.1
Port: 8080
☑ Also use this proxy for HTTPS
```

**Oder FoxyProxy Extension:**
```
Add New Proxy
→ Title: Burp
→ IP: 127.0.0.1
→ Port: 8080
→ HTTP + HTTPS
```

### 3. SSL Certificate Installation

```bash
# 1. Mit Browser zu Burp navigieren
http://127.0.0.1:8080

# 2. "CA Certificate" downloaden (burp-ca.der)

# 3. In Firefox importieren
Preferences → Privacy & Security → Certificates → View Certificates
→ Authorities → Import → burp-ca.der
→ ☑ Trust this CA to identify websites
```

---

## Core Features

### Proxy (Interceptor)

```
Proxy → Intercept
- Intercept is on: Requests werden angehalten
- Intercept is off: Requests passieren durch

Actions:
- Forward: Request weitersenden
- Drop: Request verwerfen
- Action → Send to Repeater: In Repeater senden
- Action → Send to Intruder: In Intruder senden
```

**HTTP History:**
```
Proxy → HTTP history
- Zeigt alle Requests/Responses
- Filter: nur bestimmte Hosts, Extensions, Status Codes
- Rechtsklick → Send to...
```

### Repeater (Manual Testing)

```
Repeater Tab:
1. Request modifizieren
2. "Send" klicken
3. Response analysieren
4. Iterieren

Hotkeys:
Ctrl+R: Send to Repeater
Ctrl+Space: Send request
Ctrl+Shift+R: Rename tab
```

**Use Cases:**
```
- SQL Injection Testing
- XSS Payload Testing
- Parameter Tampering
- Authentication Bypass
- IDOR Testing
```

### Intruder (Fuzzing/Brute Force)

**Attack Types:**

```
1. Sniper
   - Single payload set
   - Testet jede Position einzeln
   - Gut für: Parameter Discovery

2. Battering Ram
   - Single payload set
   - Gleicher Payload in alle Positionen
   - Gut für: Credential Stuffing

3. Pitchfork
   - Multiple payload sets (parallel)
   - payload1[0] + payload2[0], payload1[1] + payload2[1]...
   - Gut für: Known credentials testing

4. Cluster Bomb
   - Multiple payload sets (all combinations)
   - Gut für: Username + Password brute force
```

**Workflow:**

```
1. Send Request to Intruder
2. Positions Tab:
   - Clear § markers
   - Add § markers um zu fuzzenden Parameter
   - Beispiel: username=§admin§&password=§pass§

3. Payloads Tab:
   - Payload set 1: Usernames (admin, user, test...)
   - Payload type: Simple list
   - Load: /usr/share/seclists/Usernames/...

4. Options Tab:
   - Grep Match: Success indicators
   - Redirections: Follow redirects

5. Start Attack
6. Analyze Results:
   - Sortiere nach Length, Status, Grep Match
```

**Community Edition Limitation:**
```
⚠️ Throttled to sehr langsam
→ Nutze für größere Fuzzing-Aufgaben: ffuf, wfuzz
```

### Decoder

```
Decoder Tab:
- Encode/Decode:
  - URL
  - HTML
  - Base64
  - ASCII Hex
  - Gzip

- Hash:
  - MD5
  - SHA-1
  - SHA-256

Use Case: Schnelles Encoding/Decoding von Payloads
```

### Comparer

```
Comparer Tab:
- Vergleicht 2 Requests/Responses
- Words: Textvergleich
- Bytes: Binärvergleich

Use Case:
- Unterschiede zwischen Admin vs User Response
- Timing Attack Analysis
```

---

## Praktische Workflows

### Workflow 1: SQL Injection Testing

```
1. Browse normal durch App mit Intercept off
2. Proxy → HTTP History → Finde interessante POST/GET Requests
3. Rechtsklick → Send to Repeater
4. In Repeater:
   - Test: parameter=1' OR '1'='1
   - Test: parameter=1' AND 1=1--
   - Test: parameter=1' UNION SELECT NULL--
5. Analyse Response auf Errors/Unterschiede
6. Falls vuln: Send to Intruder für weitere Enum
```

### Workflow 2: Authentication Bypass

```
1. Capture Login Request
2. Send to Intruder
3. Attack Type: Cluster Bomb
4. Positions:
   username=§admin§&password=§pass§
5. Payloads:
   Set 1: /usr/share/seclists/Usernames/top-usernames-shortlist.txt
   Set 2: /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
6. Options → Grep Match: "Welcome|Dashboard|Logout"
7. Start Attack
8. Sortiere nach Length/Grep → Finde Anomalien
```

### Workflow 3: Directory Discovery via Intruder

```
1. Capture GET / Request
2. Send to Intruder
3. Positions: GET /§admin§ HTTP/1.1
4. Payloads: /usr/share/seclists/Discovery/Web-Content/common.txt
5. Options:
   - Grep Match: nicht "404|Not Found"
   - Redirections: Never
6. Start Attack
7. Filter Status != 404

⚠️ Community Edition sehr langsam
→ Besser: gobuster, ffuf für Directory Brute Force
```

### Workflow 4: Parameter Tampering

```
1. Browse als normaler User
2. Finde Request mit interessanten Parametern:
   GET /profile?user_id=123
3. Send to Repeater
4. Teste IDOR:
   GET /profile?user_id=1
   GET /profile?user_id=2
   GET /profile?user_id=admin
5. Teste HTTP Parameter Pollution:
   GET /profile?user_id=123&user_id=1
6. Teste Type Juggling:
   GET /profile?user_id[]=123
```

---

## Advanced Features

### Match and Replace

```
Proxy → Options → Match and Replace

Use Cases:
1. User-Agent ändern:
   Type: Request header
   Match: ^User-Agent.*$
   Replace: User-Agent: CustomAgent

2. IP Spoofing Headers:
   Type: Request header
   Match: ^$
   Replace: X-Forwarded-For: 127.0.0.1

3. Remove Security Headers:
   Type: Response header
   Match: ^X-Frame-Options:.*$
   Replace: [leer]
```

### Scope

```
Target → Scope → Add

Vorteile:
- Nur In-Scope Requests in History
- Verhindert versehentliche Tests auf Out-of-Scope Hosts

Filter:
Proxy → HTTP history → Filter
☑ Show only in-scope items
```

### Session Handling Rules

```
Project options → Sessions → Session Handling Rules

Use Case: Automatisches Re-Auth
1. Add Rule
2. Scope: Include all URLs
3. Rule Actions:
   - Run macro (erstelle Macro für Login)
4. Macro erstellt automatisch neue Session bei 401/403
```

---

## Extensions (BApp Store)

### Nützliche Extensions für OSCP

```
Extender → BApp Store

1. **Autorize** - Authorization Testing
   - Auto-testet IDOR, Privilege Escalation

2. **Logger++** - Advanced Logging
   - Bessere Log-Ansicht mit Regex Filter

3. **Turbo Intruder** - Schneller Intruder
   - Umgeht Community Edition Throttling (Python-based)

4. **Param Miner** - Parameter Discovery
   - Findet hidden parameters

5. **JSON Beautifier** - JSON Formatter
   - Pretty-print JSON Responses

6. **Active Scan++** - Zusätzliche Checks
   - Nur Pro, aber gute Techniken zum manuellen Nachbauen
```

### Turbo Intruder (wichtig!)

```python
# Umgeht Community Throttling

# Installation:
Extender → BApp Store → Turbo Intruder

# Usage:
Rechtsklick auf Request → Extensions → Turbo Intruder → Send to turbo intruder

# Example Script:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=100,
                           pipeline=False)

    for word in open('/usr/share/wordlists/common.txt'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if '200' in req.response:
        table.add(req)
```

---

## Hotkeys & Shortcuts

```
Global:
Ctrl+Shift+P: Switch to Proxy
Ctrl+Shift+T: Switch to Target
Ctrl+Shift+R: Switch to Repeater
Ctrl+Shift+I: Switch to Intruder

Proxy:
Ctrl+F: Forward
Ctrl+D: Drop
Ctrl+I: Toggle Intercept

Repeater:
Ctrl+Space: Send request
Ctrl+R: Send to Repeater (von anderem Tab)
Ctrl+E: Send to Intruder

General:
Ctrl+F: Search
Ctrl+Shift+F: Find in all tabs
```

---

## Target Sitemap

```
Target → Site map

Features:
- Tree-Ansicht aller discovered Paths
- Rechtsklick → Spider from here (Community: manuell)
- Rechtsklick → Engagement tools
  - Find comments
  - Find scripts
  - Find references

Use Case:
- Übersicht über Application Structure
- Finde versteckte Endpoints
```

---

## Engagement Tools

```
Rechtsklick auf Request/Response → Engagement tools

1. **Find comments**
   - Zeigt alle HTML/JS Comments

2. **Find scripts**
   - Listet alle JS Files

3. **Find references**
   - Zeigt wo Parameter/Values referenziert werden

4. **Discover content**
   - Burp's Content Discovery (brute force)

5. **Schedule task**
   - Nur Pro

6. **Generate CSRF PoC**
   - Erstellt HTML Form für CSRF Testing
```

---

## Burp Collaborator (Pro Feature)

**Alternative für Community: Interact.sh**

```bash
# Interact.sh (kostenlos)
curl -X POST https://interact.sh/register

# Usage in Payloads:
{{random}}.interact.sh
test.{{random}}.oastify.com
```

---

## Project Files

```
Burp → Project → Save project

Dateitypen:
- .burp: Projekt-File (enthält alle Requests/Responses)

Vorteile:
- Resume work später
- Teilen mit Team
- Backup von Testing Session

⚠️ Community: Temporary projects only (kein Save)
→ Workaround: Copy/Paste wichtige Requests in Text-File
```

---

## Filter & Search

### HTTP History Filter

```
Proxy → HTTP history → Filter

Nützliche Filter:
☑ Show only in-scope items
☑ Hide CSS/images/scripts (für cleaner view)
Status code: 200, 301, 302, 403, 500

MIME type:
☑ HTML
☑ Script
☑ JSON
☐ Images (meistens aus)

Search:
- Request: Suche in Requests
- Response: Suche in Responses
- Regex möglich
```

---

## Mobile App Testing

### Android APK via Burp

```bash
# 1. Configure Android Proxy
Settings → WiFi → Long-press → Modify Network
→ Proxy: Manual
→ Hostname: BURP_IP (z.B. 10.10.14.5)
→ Port: 8080

# 2. Install Burp Certificate
http://BURP_IP:8080
→ Download CA Certificate
→ Install as System Certificate (requires root)

# 3. Bypass SSL Pinning
# Use Frida + objection oder Magisk Module
```

---

## Common Issues & Fixes

### Problem: HTTPS nicht sichtbar

```
Lösung:
1. Burp CA Certificate installiert?
   → Siehe SSL Certificate Installation
2. Browser nutzt System Proxy statt Manual?
   → Setze Manual Proxy in Browser
```

### Problem: Keine Requests in History

```
Lösung:
1. Intercept is off?
2. Filter zu restriktiv?
   → Filter → Show all
3. Proxy im Browser korrekt?
   → Check 127.0.0.1:8080
```

### Problem: Connection Timeout

```
Lösung:
1. Burp Proxy läuft?
   → Proxy → Options → Running: Yes
2. Firewall blockiert?
   → sudo ufw allow 8080
```

### Problem: Certificate Error trotz Installation

```
Lösung (Firefox):
1. Alte Burp Certs löschen
   Preferences → Certificates → Authorities
   → Lösche "PortSwigger CA"
2. Neu importieren
3. Firefox restart
```

---

## Burp + ffuf Workflow

```bash
# Burp für manuelle Analysis
# ffuf für schnelles Fuzzing

# 1. In Burp: Request analysieren, Format verstehen
# 2. Request kopieren → Save as request.txt
# 3. ffuf mit Request-File:

ffuf -request request.txt -request-proto http -w wordlist.txt

# Beispiel:
# request.txt:
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=FUZZ&password=admin

# ffuf:
ffuf -request request.txt -request-proto http -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt -mc 200,302
```

---

## Burp CLI (Pro only)

Community hat keine CLI, aber:

```bash
# Headless Burp (nur Pro)
java -jar -Xmx4g burpsuite_pro.jar --project-file=test.burp --unpause-spider-and-scanner

# Community Workaround: Nutze andere Tools für Automation
- ZAP (OWASP) für CLI Scanning
- Nuclei für Automation
- httpx + ffuf für Fuzzing
```

---

## Quick Reference

### Essential Tabs

```
Proxy → Intercept: Request abfangen/modifizieren
Proxy → HTTP history: Alle Requests ansehen
Repeater: Manuelle Request-Wiederholung
Intruder: Fuzzing/Brute Force (langsam in Community)
Decoder: Quick Encode/Decode
```

### Common Actions

```
Send to Repeater: Ctrl+R
Send request (Repeater): Ctrl+Space
Forward (Intercept): Ctrl+F
Toggle Intercept: Ctrl+I
Search: Ctrl+F
```

### Best Workflow for OSCP

```
1. Passive Crawl: Browse mit Intercept off
2. HTTP History: Requests analysieren
3. Repeater: Manuelle Tests (SQLi, XSS, Auth)
4. Decoder: Payloads en/decoden
5. Intruder: Nur für kleine wordlists (Community throttled)
6. External Tools: ffuf, gobuster für größere Fuzzing
```

---

## OSCP Exam Tips

1. **Community Edition reicht** - Kein Scanner/Intruder nötig
2. **Repeater ist Key** - 90% der Arbeit hier
3. **HTTP History durchsuchen** - Oft versteckte Endpoints/Parameters
4. **Intruder vermeiden** - Zu langsam, nutze ffuf/wfuzz
5. **SSL Cert Installation** - Zu Beginn machen!
6. **Match & Replace** - Custom Headers für Bypasses
7. **Save Important Requests** - Copy/Paste in Notes (Community kein Save)
8. **Extensions**: Turbo Intruder für schnelles Fuzzing
9. **Decoder immer offen** - Schnelles Base64/URL en/decode
10. **Scope setzen** - Verhindert versehentliche Out-of-Scope Tests

---

## Alternative: OWASP ZAP

```bash
# Falls Burp Community zu limitiert
sudo apt install zaproxy

# ZAP Vorteile:
- Voll open-source
- Kein Throttling
- Built-in Spider
- Automation möglich

# ZAP Nachteile:
- UI weniger intuitiv als Burp
- Extensions weniger umfangreich
```

---

## Resources

- Burp Suite: https://portswigger.net/burp
- Burp Documentation: https://portswigger.net/burp/documentation
- Web Security Academy: https://portswigger.net/web-security (kostenlose Labs!)
- BApp Store: https://portswigger.net/bappstore
- SecLists: https://github.com/danielmiessler/SecLists (Wordlists für Intruder)
- Interact.sh: https://interact.sh (Burp Collaborator Alternative)
