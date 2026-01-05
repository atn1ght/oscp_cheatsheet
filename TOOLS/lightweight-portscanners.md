# Lightweight Portscanner - Single Binary Alternativen zu Nmap

## Warum lightweight Scanner?

- **Single Binary** - Einfach zu transferieren
- **Schneller** - Oft schneller als nmap
- **Kleiner Footprint** - Weniger Detection
- **Keine Dependencies** - Statically compiled
- **Cross-Platform** - Windows & Linux

---

## Rustscan - Der schnellste Scanner

### Was ist Rustscan?

Moderner Portscanner in Rust geschrieben. Scannt alle 65535 Ports in < 3 Sekunden, dann übergibt an nmap für Service Detection.

**Vorteile:**
- Extrem schnell
- Integriert mit nmap
- Single Binary
- Cross-Platform

### Installation

```bash
# Kali/Debian
wget https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.1.1_amd64.deb
sudo dpkg -i rustscan_2.1.1_amd64.deb

# Via cargo
cargo install rustscan

# Docker
docker pull rustscan/rustscan
```

### Basis-Usage

```bash
# Quick Scan
rustscan -a 192.168.1.100

# Alle 65535 Ports (default)
rustscan -a 192.168.1.100 --ulimit 5000

# Spezifische Ports
rustscan -a 192.168.1.100 -p 80,443,8080

# Port Range
rustscan -a 192.168.1.100 -p 1-1000

# Multiple Targets
rustscan -a 192.168.1.100,192.168.1.101
```

### Mit nmap Integration

```bash
# Rustscan findet Ports, nmap scannt Services
rustscan -a 192.168.1.100 -- -sV -sC

# Aggressive Scan
rustscan -a 192.168.1.100 -- -A

# Ohne nmap (nur Portfinding)
rustscan -a 192.168.1.100 --no-nmap

# Custom nmap options
rustscan -a 192.168.1.100 -- -sV -O --script vuln
```

### Performance Tuning

```bash
# Batch Size (default 4500)
rustscan -a 192.168.1.100 -b 1000

# Timeout (ms)
rustscan -a 192.168.1.100 -t 500

# Threads (default: auto)
rustscan -a 192.168.1.100 --ulimit 10000

# Schnellster Scan
rustscan -a 192.168.1.100 --ulimit 5000 -b 5000 -t 200
```

### Output

```bash
# JSON Output
rustscan -a 192.168.1.100 --output json > scan.json

# Greppable
rustscan -a 192.168.1.100 | grep "Open"

# In File
rustscan -a 192.168.1.100 > scan.txt
```

---

## Masscan - Schnellster TCP Scanner

### Was ist Masscan?

TCP Port Scanner der schnellste auf dem Markt. Kann das gesamte Internet in ~6 Minuten scannen.

**Vorteile:**
- Extrem schnell
- Asynchrones Design
- Single Binary
- Eigener TCP Stack

**Nachteile:**
- Keine Service Detection
- Nur TCP
- Kann Netzwerke überlasten

### Installation

```bash
# Kali/Debian
sudo apt install masscan

# From source
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install
```

### Basis-Usage

```bash
# Single Host
sudo masscan -p80,443 192.168.1.100

# IP Range
sudo masscan -p80,443 192.168.1.0/24

# Alle Ports
sudo masscan -p1-65535 192.168.1.100

# Top 100 Ports
sudo masscan -p- --top-ports 100 192.168.1.0/24

# Spezifische Ports
sudo masscan -p22,80,443,3389,445 192.168.1.0/24
```

### Rate Control

```bash
# Rate limiten (packets per second)
sudo masscan -p80,443 192.168.1.0/24 --rate 1000

# Maximale Rate (default 100)
sudo masscan -p80,443 192.168.1.0/24 --rate 100000

# Konservativ (für OSCP!)
sudo masscan -p- 192.168.1.100 --rate 500
```

### Output Formats

```bash
# List format
sudo masscan -p80,443 192.168.1.0/24 -oL scan.txt

# XML (nmap-compatible)
sudo masscan -p80,443 192.168.1.0/24 -oX scan.xml

# JSON
sudo masscan -p80,443 192.168.1.0/24 -oJ scan.json

# Grepable
sudo masscan -p80,443 192.168.1.0/24 -oG scan.gnmap

# Binary (resume später)
sudo masscan -p80,443 192.168.1.0/24 -oB scan.bin
```

### Nmap-Style Scan

```bash
# Ähnlich wie nmap -sS
sudo masscan -p80,443 192.168.1.0/24 --rate 1000

# Mit Bannergrab (basic)
sudo masscan -p80,443 192.168.1.0/24 --banners

# Exclude IPs
sudo masscan -p80 192.168.1.0/24 --excludefile exclude.txt

# Include File
sudo masscan -iL targets.txt -p80,443
```

### OSCP-Friendly Scan

```bash
# Konservativer Full-Port Scan
sudo masscan -p1-65535 192.168.1.100 --rate 500 --wait 3 -oL scan.txt

# Dann mit nmap Service Detection
nmap -sV -sC -p $(cat scan.txt | grep "open" | cut -d'/' -f1 | tr '\n' ',') 192.168.1.100
```

---

## Naabu - Lightweight Go Scanner

### Was ist Naabu?

Fast Port Scanner in Go. Projekt Dis covery Tool, optimiert für Geschwindigkeit und Einfachheit.

**Vorteile:**
- Sehr schnell
- Single Binary
- IPv4 + IPv6
- Einfache Syntax
- Cross-Platform

### Installation

```bash
# Via Go
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Binary Download
wget https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_2.1.1_linux_amd64.zip
unzip naabu_*.zip
chmod +x naabu
sudo mv naabu /usr/local/bin/
```

### Basis-Usage

```bash
# Single Host
naabu -host 192.168.1.100

# Top 100 Ports
naabu -host 192.168.1.100 -top-ports 100

# Top 1000 Ports
naabu -host 192.168.1.100 -top-ports 1000

# Alle Ports
naabu -host 192.168.1.100 -p -

# Spezifische Ports
naabu -host 192.168.1.100 -p 80,443,8080
```

### Multiple Targets

```bash
# Hosts von File
naabu -list hosts.txt

# CIDR Range
naabu -host 192.168.1.0/24

# Multiple Hosts
naabu -host 192.168.1.100,192.168.1.101
```

### Output & Integration

```bash
# JSON Output
naabu -host 192.168.1.100 -json -o scan.json

# Nur Ports (für nmap)
naabu -host 192.168.1.100 -silent

# Mit nmap Pipeline
naabu -host 192.168.1.100 -silent | nmap -sV -sC -p- -iL - 192.168.1.100

# CSV Output
naabu -host 192.168.1.100 -csv
```

### Performance

```bash
# Rate Control
naabu -host 192.168.1.100 -rate 1000

# Threads
naabu -host 192.168.1.100 -c 25

# Retries
naabu -host 192.168.1.100 -retries 3

# Timeout
naabu -host 192.168.1.100 -timeout 5000
```

---

## NetCat (nc) - Der klassische Scanner

### Als Portscanner

```bash
# Single Port
nc -zv 192.168.1.100 80

# Port Range
nc -zv 192.168.1.100 1-1000

# Multiple Ports
for port in 22 80 443 445 3389; do nc -zv 192.168.1.100 $port; done

# Quick Scan Script
for port in {1..1000}; do nc -zv -w1 192.168.1.100 $port 2>&1 | grep succeeded; done
```

### UDP Scan

```bash
# UDP Port
nc -zuv 192.168.1.100 161

# UDP Range
nc -zuv 192.168.1.100 1-1000
```

---

## Windows Portscanner

### Test-NetConnection (PowerShell)

```powershell
# Single Port
Test-NetConnection -ComputerName 192.168.1.100 -Port 80

# Multiple Ports
22,80,443,445,3389 | ForEach-Object {Test-NetConnection -ComputerName 192.168.1.100 -Port $_ -InformationLevel Quiet}

# Port Range (Script)
1..1000 | ForEach-Object {
    $result = Test-NetConnection -ComputerName 192.168.1.100 -Port $_ -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($result) { Write-Host "Port $_ is open" }
}
```

### PortQry (Microsoft)

```cmd
# Download
https://www.microsoft.com/en-us/download/details.aspx?id=17148

# Single Port
portqry -n 192.168.1.100 -e 80

# Multiple Ports
portqry -n 192.168.1.100 -r 1:1000

# Specific Protocol
portqry -n 192.168.1.100 -p tcp -e 80
portqry -n 192.168.1.100 -p udp -e 161
```

### TCPing (Windows)

```cmd
# Download
https://www.elifulkerson.com/projects/tcping.php

# Single Port
tcping.exe 192.168.1.100 80

# Continuous
tcping.exe -t 192.168.1.100 80

# Mit Timestamp
tcping.exe -d 192.168.1.100 80
```

---

## Unicornscan - Asynchronous Scanner

### Installation

```bash
sudo apt install unicornscan
```

### Usage

```bash
# TCP SYN Scan
sudo unicornscan -mT 192.168.1.100:1-65535

# UDP Scan
sudo unicornscan -mU 192.168.1.100:1-1000

# Rate Control
sudo unicornscan -mT -r 1000 192.168.1.100:1-65535

# Multiple Targets
sudo unicornscan -mT 192.168.1.0/24:80,443
```

---

## Vergleich der Scanner

| Scanner | Geschwindigkeit | Binary Size | Service Detection | Beste Use-Case |
|---------|----------------|-------------|-------------------|----------------|
| **Rustscan** | ⚡⚡⚡⚡⚡ | ~3MB | Via nmap | OSCP Standard |
| **Masscan** | ⚡⚡⚡⚡⚡ | ~400KB | Nein | Schnelle Recon |
| **Naabu** | ⚡⚡⚡⚡ | ~8MB | Nein | Pipeline mit nmap |
| **Nmap** | ⚡⚡⚡ | ~6MB | Ja | Ausführliche Scans |
| **NC** | ⚡⚡ | ~40KB | Nein | Schnelle Checks |
| **Unicornscan** | ⚡⚡⚡⚡ | ~200KB | Nein | Asynchrone Scans |

---

## Praktische OSCP-Workflows

### Workflow 1: Rustscan → Nmap

```bash
# 1. Quick Port Discovery
rustscan -a 192.168.1.100 --ulimit 5000 > ports.txt

# 2. Extract Ports
cat ports.txt | grep "Open" | cut -d' ' -f2 | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//'

# 3. Detailed nmap Scan
nmap -sV -sC -p22,80,443,445,3389 192.168.1.100 -oA detailed_scan
```

### Workflow 2: Masscan → Nmap

```bash
# 1. Fast All-Port Scan
sudo masscan -p1-65535 192.168.1.100 --rate 500 -oL masscan.txt

# 2. Parse Results
cat masscan.txt | grep "open" | awk '{print $3}' | cut -d'/' -f1 | sort -u | tr '\n' ','

# 3. Service Detection
nmap -sV -sC -p<ports> 192.168.1.100
```

### Workflow 3: Naabu Pipeline

```bash
# Direct Pipeline to nmap
naabu -host 192.168.1.100 -silent -p - | nmap -sV -sC -iL - 192.168.1.100
```

### Workflow 4: Quick Check (nc)

```bash
# Quick Web Check
nc -zv 192.168.1.100 80 && curl -I http://192.168.1.100

# Common Ports
for port in 22 80 443 445 3389; do
    nc -zv -w1 192.168.1.100 $port 2>&1 | grep succeeded && echo "Found: $port"
done
```

---

## Windows-Specific Workflows

### PowerShell Fast Scan

```powershell
# Function für Quick Scan
function Quick-Scan {
    param($IP, $Ports)
    $Ports | ForEach-Object {
        if (Test-NetConnection -ComputerName $IP -Port $_ -InformationLevel Quiet -WarningAction SilentlyContinue) {
            Write-Host "Port $_ open" -ForegroundColor Green
        }
    }
}

# Usage
Quick-Scan -IP "192.168.1.100" -Ports @(22,80,443,445,3389,3306,1433,5985)
```

---

## Stealth Scanning

### Low-Rate Scans

```bash
# Rustscan slow
rustscan -a 192.168.1.100 --ulimit 100 -b 100 -t 5000

# Masscan slow
sudo masscan -p1-65535 192.168.1.100 --rate 100 --wait 5

# Naabu slow
naabu -host 192.168.1.100 -rate 100 -retries 1
```

### IDS/IPS Evasion

```bash
# Fragment Packets (nmap)
nmap -f -sS 192.168.1.100

# Decoy Scan
nmap -D RND:10 192.168.1.100

# Source Port
nmap --source-port 53 192.168.1.100

# Timing (slow)
nmap -T1 192.168.1.100
```

---

## Binary Downloads (for OSCP)

### Rustscan

```bash
# Linux
wget https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.1.1_amd64.deb

# Windows
wget https://github.com/RustScan/RustScan/releases/latest/download/rustscan_windows.exe
```

### Masscan

```bash
# Linux (compile)
git clone https://github.com/robertdavidgraham/masscan
cd masscan && make
sudo cp bin/masscan /opt/tools/

# Windows
wget https://github.com/robertdavidgraham/masscan/releases/download/1.3.2/masscan-binaries.zip
```

### Naabu

```bash
# Linux
wget https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_2.1.1_linux_amd64.zip

# Windows
wget https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_2.1.1_windows_amd64.zip
```

---

## Quick Reference

### Rustscan
```bash
rustscan -a IP --ulimit 5000                    # Fast all-port
rustscan -a IP -- -sV -sC                       # With nmap service detection
rustscan -a IP --no-nmap                        # Port discovery only
```

### Masscan
```bash
sudo masscan -p1-65535 IP --rate 500            # All ports, moderate rate
sudo masscan -p80,443 192.168.1.0/24 --rate 1000  # Subnet scan
sudo masscan -p- IP --banners                   # With banner grab
```

### Naabu
```bash
naabu -host IP -p -                             # All ports
naabu -host IP -top-ports 1000                  # Top 1000
naabu -host IP -silent | nmap -sV -iL -         # Pipeline to nmap
```

### NetCat
```bash
nc -zv IP PORT                                  # Single port
nc -zv IP 1-1000                                # Port range
for p in {1..65535}; do nc -zv IP $p 2>&1 | grep succeeded; done  # All ports
```

---

## OSCP Exam Tips

1. **Rustscan als Standard** - Schnell, zuverlässig, nmap-Integration
2. **Masscan für große Ranges** - Wenn viele IPs gescannt werden müssen
3. **Immer zweimal scannen** - Quick scan, dann detailed nmap
4. **Rate kontrollieren** - `--rate 500` für masscan, kein Netzwerk überlasten
5. **Binary vorbereiten** - Rustscan auf Kali installiert haben
6. **Nmap als Fallback** - Für Service Detection immer nmap nutzen
7. **UDP nicht vergessen** - `sudo nmap -sU --top-ports 20 IP`
8. **Windows: Test-NetConnection** - Native PowerShell, keine Tools nötig

---

## Resources

- Rustscan: https://github.com/RustScan/RustScan
- Masscan: https://github.com/robertdavidgraham/masscan
- Naabu: https://github.com/projectdiscovery/naabu
- HackTricks: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network
