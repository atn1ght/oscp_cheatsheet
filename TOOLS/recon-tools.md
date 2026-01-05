# Reconnaissance Tools

OSINT & Automated Recon Tools für Information Gathering.

---

## theHarvester

### Was ist theHarvester?

OSINT Tool für Email-Adressen, Subdomains, IPs, URLs aus öffentlichen Quellen.

### Installation

```bash
# Kali (pre-installed)
theHarvester -h

# Oder GitHub
git clone https://github.com/laramies/theHarvester
cd theHarvester
pip3 install -r requirements.txt
```

### Basis-Usage

```bash
# Simple Search
theHarvester -d target.com -b google

# Mit Source Limit
theHarvester -d target.com -b google -l 500

# Alle Sources
theHarvester -d target.com -b all

# Output in File
theHarvester -d target.com -b google -f output
```

### Data Sources (-b)

```bash
# Search Engines
-b google          # Google
-b bing            # Bing
-b yahoo           # Yahoo
-b duckduckgo      # DuckDuckGo
-b baidu           # Baidu

# OSINT/Threat Intel
-b shodan          # Shodan (API Key required)
-b censys          # Censys (API Key required)
-b hunter          # Hunter.io (API Key)
-b securitytrails  # SecurityTrails (API Key)
-b virustotal      # VirusTotal (API Key)
-b threatcrowd     # ThreatCrowd
-b crtsh           # Certificate Transparency Logs

# DNS
-b dnsdumpster     # DNSDumpster

# Social Media
-b linkedin        # LinkedIn
-b twitter         # Twitter

# All Sources
-b all             # Alle verfügbaren Quellen
```

### Erweiterte Optionen

```bash
# DNS Brute Force
theHarvester -d target.com -b google -c

# Verify Hostnames via DNS
theHarvester -d target.com -b google -v

# Screenshot (Selenium required)
theHarvester -d target.com -b google -s

# Virtual Host Detection
theHarvester -d target.com -b google -n

# Shodan Query
theHarvester -d target.com -b shodan -s YOUR_SHODAN_API_KEY

# Limit Results
theHarvester -d target.com -b google -l 100

# Start at specific result
theHarvester -d target.com -b google -l 500 -s 100
```

### API Keys Configuration

```bash
# Config File
nano ~/.theHarvester/api-keys.yaml

# Beispiel:
apikeys:
  shodan: YOUR_SHODAN_KEY
  censys_id: YOUR_CENSYS_ID
  censys_secret: YOUR_CENSYS_SECRET
  hunter: YOUR_HUNTER_KEY
  securitytrails: YOUR_SECURITYTRAILS_KEY
  virustotal: YOUR_VIRUSTOTAL_KEY
```

### Output Formats

```bash
# XML
theHarvester -d target.com -b google -f output -e xml

# JSON
theHarvester -d target.com -b google -f output -e json

# HTML
theHarvester -d target.com -b google -f output -e html
```

### Practical Examples

```bash
# Email Harvesting
theHarvester -d target.com -b google,bing,linkedin -l 500 -f emails

# Subdomain Enumeration
theHarvester -d target.com -b crtsh,dnsdumpster,google -c -v

# IP Gathering
theHarvester -d target.com -b shodan,censys,bing -f ips

# All-in-one Recon
theHarvester -d target.com -b all -c -v -f full_recon
```

---

## AutoRecon

### Was ist AutoRecon?

Automatisiertes Multi-Service Enumeration Tool. Scannt Ports → Enumeriert Services parallel.

### Installation

```bash
# pip3
pip3 install autorecon

# Oder GitHub
git clone https://github.com/Tib3rius/AutoRecon
cd AutoRecon
pip3 install -r requirements.txt
```

### Basis-Usage

```bash
# Single Target
autorecon 192.168.1.100

# Multiple Targets
autorecon 192.168.1.100 192.168.1.101

# CIDR Range
autorecon 192.168.1.0/24

# From File
autorecon -t targets.txt
```

### Output Structure

```
results/
└── 192.168.1.100/
    ├── exploit/        # Exploit suggestions
    ├── loot/           # Found credentials, configs
    ├── report/         # HTML/Markdown reports
    └── scans/          # Raw scan outputs
        ├── _commands.log
        ├── _manual_commands.txt
        ├── tcp_*.txt
        └── udp_*.txt
```

### Important Options

```bash
# Profiling (Schnelligkeit)
autorecon 192.168.1.100 --profile default  # Default
autorecon 192.168.1.100 --profile quick    # Schneller
autorecon 192.168.1.100 --profile full     # Umfassend

# Only TCP
autorecon 192.168.1.100 --only-tcp

# Only UDP
autorecon 192.168.1.100 --only-udp

# Specific Ports
autorecon 192.168.1.100 --ports 80,443,445

# Exclude Ports
autorecon 192.168.1.100 --exclude-ports 25,110

# Nmap Arguments
autorecon 192.168.1.100 --nmap='-sV -sC --script vuln'

# Concurrent Targets
autorecon -t targets.txt --concurrent-targets 5

# Output Directory
autorecon 192.168.1.100 -o /path/to/results

# Verbosity
autorecon 192.168.1.100 -v   # Verbose
autorecon 192.168.1.100 -vv  # Very Verbose
```

### Service Enumeration

AutoRecon führt automatisch aus:

**HTTP/HTTPS:**
- nikto
- gobuster
- whatweb
- wpscan (if WordPress)
- droopescan (if Drupal/Joomla)

**SMB:**
- enum4linux
- smbmap
- smbclient
- nmap smb scripts

**FTP:**
- nmap ftp scripts
- Anonymous login test

**SSH:**
- nmap ssh scripts
- Algorithm enumeration

**DNS:**
- dig
- nslookup
- Zone transfer attempts

**SMTP:**
- smtp-user-enum
- nmap smtp scripts

**SNMP:**
- snmpwalk
- onesixtyone

**SQL:**
- nmap mysql/mssql/oracle scripts

**RDP:**
- nmap rdp scripts

---

## Workflow: OSCP Recon

### Phase 1: Passive Recon

```bash
# 1. OSINT mit theHarvester
theHarvester -d target.com -b all -c -v -f osint_results

# Findings:
# - Email addresses
# - Subdomains
# - Employee names
```

### Phase 2: Active Recon

```bash
# 2. AutoRecon für vollständige Enumeration
autorecon 192.168.1.100 --profile full -o results/

# Läuft automatisch:
# - Port Scan (TCP + UDP)
# - Service Enumeration
# - Vulnerability Scanning
# - Directory Brute Force
# - etc.
```

### Phase 3: Analysis

```bash
# 3. Review AutoRecon Results
cat results/192.168.1.100/scans/_manual_commands.txt

# Manual Commands to run
cat results/192.168.1.100/report/local.txt

# Findings
cat results/192.168.1.100/loot/*
```

---

## AutoRecon vs Manual Scanning

| Aspect | AutoRecon | Manual (nmap, gobuster, etc.) |
|--------|-----------|------------------------------|
| **Speed** | Fast (parallel) | Depends on you |
| **Coverage** | Umfassend | Nur was du runnest |
| **Customization** | Limited | Full control |
| **OSCP Suitability** | Excellent | Standard |
| **Learning** | Less | More |

**OSCP Tipp:** AutoRecon für initiale Recon, dann manuell für deep dive.

---

## Alternative Recon Tools

### subfinder (Subdomain Enum)

```bash
# Installation
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Usage
subfinder -d target.com
subfinder -d target.com -o subdomains.txt
```

### amass (Comprehensive Recon)

```bash
# Installation
sudo apt install amass

# Usage
amass enum -d target.com
amass enum -d target.com -o amass_output.txt
```

### recon-ng (Framework)

```bash
# Kali pre-installed
recon-ng

# Marketplace
marketplace install all

# Basic Recon
workspace create target
db insert domains
modules search
modules load recon/domains-hosts/google_site_web
run
```

---

## Quick Reference

### theHarvester
```bash
# Email + Subdomain Enum
theHarvester -d target.com -b google,bing,crtsh -c -v -f results

# With API Keys
theHarvester -d target.com -b shodan,censys,hunter -f api_results
```

### AutoRecon
```bash
# Full Scan
autorecon 192.168.1.100 --profile full

# Quick Scan (OSCP Exam)
autorecon 192.168.1.0/24 --profile quick --only-tcp

# Results in:
results/192.168.1.100/report/local.txt
results/192.168.1.100/scans/_manual_commands.txt
```

---

## OSCP Exam Tips

### theHarvester
1. **Nicht primär für OSCP** - OSCP ist Active Pentest, nicht OSINT
2. **Nützlich für CTFs** - Subdomain/Email Enum in CTF-like scenarios
3. **API Keys optional** - Free sources (google, bing, crtsh) reichen
4. **Schnelle Subdomain Enum** - crtsh (Certificate Transparency)

### AutoRecon
1. **Erste Recon-Phase** - Startet parallel scanning
2. **Spart Zeit** - Während AutoRecon läuft, anderen Box analysieren
3. **Review _manual_commands.txt** - Zeigt was manuell gemacht werden sollte
4. **Nicht blind vertrauen** - Immer manuell nachprüfen
5. **--profile quick für Exam** - Schneller, fokussierter
6. **Output organisieren** - results/ gut strukturiert für Report
7. **Parallel zu Manual** - AutoRecon ≠ Ersatz für manuelle Skills

---

## Resources

- theHarvester: https://github.com/laramies/theHarvester
- AutoRecon: https://github.com/Tib3rius/AutoRecon
- subfinder: https://github.com/projectdiscovery/subfinder
- amass: https://github.com/OWASP/Amass
- recon-ng: https://github.com/lanmaster53/recon-ng
