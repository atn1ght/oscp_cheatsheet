Analysierte Windows-Authentifizierungsfrage zu runas-Befehl.

Ja, du hast mehrere Optionen um das Passwort direkt mitzugeben:

**Option 1: Mit /savecred (cached credentials)**

cmd

```cmd
runas /user:domain\username /savecred "cmd.exe"
```

- Verwendet gespeicherte Credentials aus dem Credential Manager
- Funktioniert nur wenn Creds vorher gespeichert wurden

**Option 2: Über stdin pipe**

cmd

```cmd
echo password123 | runas /user:domain\username "cmd.exe"
```

**Option 3: PowerShell (besser für scripts)**

powershell

```powershell
$password = ConvertTo-SecureString "password123" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("domain\username", $password)
Start-Process cmd.exe -Credential $credential
```

**Option 4: Batch script mit echo**

batch

```batch
@echo off
echo password123| runas /user:domain\username "cmd.exe"
```

**Wichtig für OSCP:**

- `/savecred` ist oft die praktischste Option wenn die Creds schon cached sind
- PowerShell-Variante ist sauberer für komplexere Scenarios
- Pipe-Methode funktioniert gut in einfachen Fällen