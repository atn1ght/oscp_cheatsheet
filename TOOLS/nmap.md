### Schnellesudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
sudo nmap --script-updatedb
sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124
sudo nmap -p80 --script=http-enum 192.168.50.20
sudo nmap -p80  -sV 192.168.50.20

r Check ob Hosts alive sind

`nmap -sn $target`

➡️ Macht nur einen Ping/ARP-Scan (kein Portscan). Zeigt dir, ob der Host erreichbar ist.

---

### 2. Bekannte Ports scannen (schnell, nur offene zeigen)

`nmap --open $target`

➡️ Standardmäßig scannt Nmap die **1000 bekanntesten TCP-Ports**.  
`--open` zeigt nur Ports, die tatsächlich offen sind.

---

### 3. Alle Ports mit allen Infos

`nmap -p- -A -v $target`

- `-p-` = alle 65535 TCP-Ports
    
- `-A` = OS-Detection, Version, Skripte, Traceroute
    
- `-v` = verbose
    

Falls du es **etwas vorsichtiger** willst (nur Services/Versionen, ohne aggressiv OS-Erkennung & Skripte):

`nmap -p- -sV $target`

---

### 4. UDP-Scan

`nmap -sU -p- -v $target`

➡️ Scannt alle UDP-Ports (dauert sehr lange!).  
Praktischer ist oft ein **Top-20 UDP Scan**:

`nmap -sU --top-ports 20 $target`## 

nmap -p139,445 --script smb-protocols $target    # SMB protocol versions
nmap -p445    --script smb-security-mode $target # Signing required?
nmap -p445    --script smb-os-discovery $target  # OS/hostname/domain
nmap -p445    --script smb-enum-shares $target   # Share list
nmap -p445    --script smb-enum-users $target    # User enumeration
nmap -p445    --script smb-vuln-ms17-010 $target # EternalBlue check

nmap -p 139,445 --script smb-protocols,smb2-security-mode,smb-enum-shares -Pn 192.168.185.145

nmap --script ftp-anon,ftp-brute -p21 192.168.185.145

