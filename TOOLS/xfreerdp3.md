# xfreerdp3 - RDP Client

## Basis-Syntax
```bash
xfreerdp /v:TARGET_IP /u:USERNAME /p:PASSWORD /cert:ignore
```

## Authentifizierung

### Mit Passwort
```bash
xfreerdp /v:IP /u:USERNAME /p:PASSWORD /cert:ignore
xfreerdp /v:IP /u:DOMAIN\\USERNAME /p:PASSWORD /cert:ignore
xfreerdp /v:IP /d:DOMAIN /u:USERNAME /p:PASSWORD /cert:ignore
```

### Mit NTLM-Hash (Pass-the-Hash)
```bash
xfreerdp /v:IP /u:USERNAME /pth:NTLM_HASH /cert:ignore
xfreerdp /v:IP /d:DOMAIN /u:USERNAME /pth:NTLM_HASH /cert:ignore
```

### Restricted Admin Mode (PTH ohne lokale Admin-Rechte)
```bash
xfreerdp /v:IP /u:USERNAME /pth:NTLM_HASH /cert:ignore /restricted-admin
```

### Ohne Credentials (für NLA-Bypass oder Null Session)
```bash
xfreerdp /v:IP /cert:ignore
```

## Display & Performance

### Vollbild
```bash
xfreerdp /v:IP /u:USER /p:PASS /f /cert:ignore
```

### Spezifische Auflösung
```bash
xfreerdp /v:IP /u:USER /p:PASS /size:1920x1080 /cert:ignore
xfreerdp /v:IP /u:USER /p:PASS /w:1920 /h:1080 /cert:ignore
```

### Performance-Optimierung
```bash
# Multimedia/Audio deaktivieren
xfreerdp /v:IP /u:USER /p:PASS /audio-mode:2 /cert:ignore

# Bitmap-Caching
xfreerdp /v:IP /u:USER /p:PASS +bitmap-cache /cert:ignore

# Kompression
xfreerdp /v:IP /u:USER /p:PASS /compression /cert:ignore
```

## File Sharing & Drive Mapping

### Lokales Verzeichnis teilen
```bash
xfreerdp /v:IP /u:USER /p:PASS /drive:share,/local/path /cert:ignore
xfreerdp /v:IP /u:USER /p:PASS /drive:tmp,/tmp /cert:ignore
```

### Clipboard aktivieren
```bash
xfreerdp /v:IP /u:USER /p:PASS +clipboard /cert:ignore
```

### Mehrere Shares
```bash
xfreerdp /v:IP /u:USER /p:PASS /drive:tools,/opt/tools /drive:loot,/tmp/loot +clipboard /cert:ignore
```

## Network & Ports

### Nicht-Standard RDP-Port
```bash
xfreerdp /v:IP:3390 /u:USER /p:PASS /cert:ignore
```

### Über Port-Forward
```bash
xfreerdp /v:127.0.0.1:13389 /u:USER /p:PASS /cert:ignore
```

## Security & Troubleshooting

### Certificate Ignoring (Standard für Pentesting)
```bash
/cert:ignore     # SSL-Zertifikat ignorieren
/cert-ignore     # Alternative Syntax
```

### Network Level Authentication (NLA)
```bash
# NLA deaktivieren (für alte Systeme)
xfreerdp /v:IP /u:USER /p:PASS -sec-nla /cert:ignore

# NLA erzwingen
xfreerdp /v:IP /u:USER /p:PASS +sec-nla /cert:ignore
```

### TLS/Encryption Settings
```bash
# Alle Sicherheitsprotokolle erlauben
xfreerdp /v:IP /u:USER /p:PASS /sec:rdp /cert:ignore
xfreerdp /v:IP /u:USER /p:PASS /sec:tls /cert:ignore
xfreerdp /v:IP /u:USER /p:PASS /sec:nla /cert:ignore
```

### Verbose/Debug Output
```bash
xfreerdp /v:IP /u:USER /p:PASS /cert:ignore /log-level:DEBUG
xfreerdp /v:IP /u:USER /p:PASS /cert:ignore /v
```

## Advanced Features

### Shell statt Desktop
```bash
xfreerdp /v:IP /u:USER /p:PASS /shell:cmd.exe /cert:ignore
xfreerdp /v:IP /u:USER /p:PASS /shell:powershell.exe /cert:ignore
```

### Remote App starten
```bash
xfreerdp /v:IP /u:USER /p:PASS /app:"C:\\Windows\\System32\\cmd.exe" /cert:ignore
```

### Smart Card / Kerberos
```bash
xfreerdp /v:IP /u:USER /cert:ignore /smartcard
```

## Nützliche Kombinationen für Pentesting

### Schneller Connect mit Folder-Share
```bash
xfreerdp /v:IP /u:USER /p:PASS /drive:share,/tmp +clipboard /cert:ignore /compression
```

### Pass-the-Hash mit Drive-Mapping
```bash
xfreerdp /v:IP /d:DOMAIN /u:USER /pth:HASH /drive:loot,/tmp/loot +clipboard /cert:ignore
```

### Stealth-Connect (minimal features)
```bash
xfreerdp /v:IP /u:USER /p:PASS /cert:ignore /audio-mode:2 /compression /size:1024x768
```

### Mehrere Sessions (mit unterschiedlichen Users)
```bash
# Terminal 1
xfreerdp /v:IP /u:user1 /p:pass1 /cert:ignore /size:1280x720

# Terminal 2
xfreerdp /v:IP /u:user2 /p:pass2 /cert:ignore /size:1280x720
```

## Häufige Fehler & Lösungen

### "Certificate verification failed"
```bash
# Lösung: /cert:ignore hinzufügen
```

### "Authentication failure"
```bash
# NLA deaktivieren
xfreerdp /v:IP /u:USER /p:PASS -sec-nla /cert:ignore

# Oder Domain explizit angeben
xfreerdp /v:IP /d:WORKGROUP /u:USER /p:PASS /cert:ignore
```

### "Connection refused" bei Non-Standard Port
```bash
# Port-Syntax prüfen
xfreerdp /v:IP:PORT /u:USER /p:PASS /cert:ignore
```

## Quick Reference - Wichtigste Flags

| Flag | Beschreibung |
|------|-------------|
| `/v:IP` | Target IP/Hostname |
| `/u:USER` | Username |
| `/p:PASS` | Password |
| `/d:DOMAIN` | Domain |
| `/pth:HASH` | Pass-the-Hash (NTLM) |
| `/cert:ignore` | SSL-Zertifikat ignorieren |
| `/drive:NAME,PATH` | Lokales Verzeichnis teilen |
| `+clipboard` | Clipboard-Sharing aktivieren |
| `/f` | Vollbild |
| `/size:WxH` | Auflösung setzen |
| `/shell:PROG` | Alternative Shell starten |
| `-sec-nla` | NLA deaktivieren |
| `/restricted-admin` | Restricted Admin Mode (für PTH) |

## Tipps für OSCP

1. **Immer `/cert:ignore` verwenden** - Keine Zeit für Cert-Validierung im Exam
2. **Drive-Mapping ist Gold** - `/drive:share,/tmp` für schnellen File-Transfer
3. **Pass-the-Hash funktioniert** - Aber `/restricted-admin` kann nötig sein
4. **NLA-Probleme?** - Probiere `-sec-nla` Flag
5. **File-Transfer-Alternative** - Clipboard (`+clipboard`) für kleine Dateien
6. **Multi-Sessions** - Du kannst mehrere RDP-Sessions gleichzeitig offen haben
