# Active Directory Enumeration

## 1. Domain Information

### PowerShell (Windows)
```powershell
# Domain Info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
Get-ADDomain
(Get-ADDomain).DomainSID

# Domain Controller
Get-ADDomainController
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

# Forest Info
Get-ADForest
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

# Trust Relationships
Get-ADTrust -Filter *
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
```

### CMD / Legacy Commands
```cmd
# Domain Info
echo %USERDNSDOMAIN%
echo %LOGONSERVER%
set | findstr DOMAIN

# Domain Controller
nltest /dclist:domain.local
nltest /dsgetdc:domain.local
```

### Linux Tools
```bash
# LDAP Domain Info
ldapsearch -x -H ldap://10.10.10.10 -s base namingcontexts

# Enumerate Domain
enum4linux -a 10.10.10.10
enum4linux-ng -A 10.10.10.10

# Kerbrute (User enumeration)
kerbrute userenum -d domain.local --dc 10.10.10.10 userlist.txt
```

## 2. User Enumeration

### PowerShell / ActiveDirectory Module
```powershell
# Alle User
Get-ADUser -Filter *
Get-ADUser -Filter * -Properties *
Get-ADUser -Filter * | Select Name,SamAccountName,Enabled

# Spezifischer User
Get-ADUser -Identity john.doe -Properties *
Get-ADUser -Filter "Name -like '*admin*'"

# User nach Gruppe
Get-ADGroupMember "Domain Admins" -Recursive | Select Name,SamAccountName

# Aktive User
Get-ADUser -Filter {Enabled -eq $true}

# User ohne Passwort-Ablauf
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Select Name,PasswordNeverExpires

# User mit gesetztem SPN (Kerberoastable)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# User mit AdminCount=1 (privilegiert)
Get-ADUser -LDAPFilter "(adminCount=1)" -Properties adminCount

# Beschreibung durchsuchen (oft Passwörter!)
Get-ADUser -Filter * -Properties Description | Where {$_.Description -ne $null} | Select Name,Description
```

### CMD / Net Commands
```cmd
# User Info
net user /domain
net user USERNAME /domain
net user john.doe /domain

# Gruppen eines Users
net user john.doe /domain | findstr /i "group"
```

### LDAP Queries
```bash
# Linux - ldapsearch
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' \
  -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName userPrincipalName

# User mit SPN
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' \
  -b "dc=domain,dc=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Beschreibungen
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' \
  -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName description
```

### Windows ohne AD-Module (LDAP)
```powershell
# ADSI Searcher
$searcher = [adsisearcher]"(objectClass=user)"
$searcher.FindAll() | ForEach-Object {$_.Properties}

# Spezifischer User
([adsisearcher]"(samaccountname=john.doe)").FindOne().Properties

# User mit SPN
([adsisearcher]"(&(objectClass=user)(servicePrincipalName=*))").FindAll()
```

## 3. Group Enumeration

### PowerShell
```powershell
# Alle Gruppen
Get-ADGroup -Filter *
Get-ADGroup -Filter * | Select Name,GroupCategory,GroupScope

# Wichtige Gruppen
Get-ADGroup -Filter {Name -like "*admin*"}
Get-ADGroupMember "Domain Admins"
Get-ADGroupMember "Enterprise Admins"
Get-ADGroupMember "Backup Operators"
Get-ADGroupMember "Account Operators"
Get-ADGroupMember "Remote Desktop Users"

# Rekursive Mitglieder
Get-ADGroupMember "Domain Admins" -Recursive

# Gruppen eines Users
Get-ADPrincipalGroupMembership john.doe | Select Name
```

### CMD
```cmd
# Gruppen
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net localgroup Administrators
```

### Linux
```bash
# rpcclient
rpcclient -U "user%password" 10.10.10.10
> enumdomgroups
> querygroupmem 0x200  # RID für Domain Admins

# Impacket
lookupsid.py domain.local/user:password@10.10.10.10
```

## 4. Computer Enumeration

### PowerShell
```powershell
# Alle Computer
Get-ADComputer -Filter *
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter * | Select Name,DNSHostName,OperatingSystem,LastLogonDate

# Server
Get-ADComputer -Filter {OperatingSystem -like "*Server*"}

# Domain Controller
Get-ADComputer -Filter {PrimaryGroupID -eq 516}
Get-ADDomainController -Filter *

# Computer SID
Get-ADComputer -Identity "COMPUTERNAME" -Properties objectSid | Select objectSid
```

### CMD / dsquery
```cmd
# Computer auflisten
dsquery computer
dsquery computer -name "WEB*"

# Computer SID
dsquery computer -name COMPUTERNAME | dsget computer -sid

# Server
dsquery * -filter "(&(objectClass=computer)(operatingSystem=*Server*))"
```

### Linux
```bash
# LDAP Computer Enumeration
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' \
  -b "dc=domain,dc=local" "(objectClass=computer)" cn dNSHostName operatingSystem

# Computer SID
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w 'password' \
  -b "dc=domain,dc=local" "(sAMAccountName=COMPUTERNAME$)" objectSid
```

## 5. Policy Enumeration

### Password Policy
```powershell
# PowerShell
Get-ADDefaultDomainPasswordPolicy
(Get-ADDomain).PasswordPolicy

# CMD
net accounts /domain
```

### Group Policy (GPO)
```powershell
# Alle GPOs
Get-GPO -All
Get-GPO -All | Select DisplayName,GpoStatus,CreationTime

# GPO Report
Get-GPOReport -All -ReportType Html -Path C:\Temp\GPOReport.html

# Angewandte GPOs auf Computer
gpresult /R
gpresult /z > gp_report.txt
```

## 6. Shares & Files

### PowerShell
```powershell
# Shares enumerieren
Get-SmbShare  # Lokal
net view \\COMPUTER /all  # Remote

# Zugriff testen
Test-Path \\dc01\SYSVOL
Test-Path \\dc01\NETLOGON

# Alle Shares im Domain
Get-ADComputer -Filter * | ForEach-Object {Get-SmbShare -CimSession $_.Name -ErrorAction SilentlyContinue}
```

### Impacket (Linux)
```bash
# Shares enumerieren
smbclient -L //10.10.10.10 -U domain/user%password
smbmap -H 10.10.10.10 -u user -p password -d domain
crackmapexec smb 10.10.10.10 -u user -p password --shares

# Rekursiv durchsuchen
smbmap -H 10.10.10.10 -u user -p password -R 'C$'
```

## 7. Kerberos & SPN Enumeration

### Kerberoasting (SPNs finden)
```powershell
# PowerShell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select Name,ServicePrincipalName

# SetSPN
setspn -T domain.local -Q */*

# GetUserSPNs (Impacket - Linux)
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10 -request
```

### ASREPRoasting (Pre-Auth disabled)
```powershell
# PowerShell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Impacket
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 10.10.10.10
GetNPUsers.py domain.local/user:password -dc-ip 10.10.10.10 -request
```

## 8. BloodHound Collection

```powershell
# SharpHound (Windows)
.\SharpHound.exe -c All
.\SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\Temp
.\SharpHound.exe --CollectionMethod All --LdapUsername user --LdapPassword pass

# BloodHound Python (Linux)
bloodhound-python -u user -p password -d domain.local -ns 10.10.10.10 -c All

# Analyse in BloodHound
# - Shortest Path to Domain Admins
# - Find Computers where Domain Users are Local Admin
# - Find Principals with DCSync Rights
```

## 9. Privilege Enumeration

### Local Admin Access
```powershell
# Lokale Admin-Gruppe
net localgroup Administrators

# Remote via WMI
Get-WmiObject -Class Win32_GroupUser -ComputerName SERVER01 | Where-Object {$_.GroupComponent -like "*Administrators*"}

# CrackMapExec
crackmapexec smb 10.10.10.0/24 -u user -p password --local-auth
```

### Constrained & Unconstrained Delegation
```powershell
# Unconstrained Delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,servicePrincipalName

Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Constrained Delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

### DCSync Rights
```powershell
# User mit Replication Rights
Import-Module PowerView.ps1
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | Where-Object {($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll')}
```

## 10. Anonymous / Unauthenticated Enumeration

```bash
# Null Session (Windows)
net use \\10.10.10.10\IPC$ "" /user:""

# Linux - rpcclient
rpcclient -U "" -N 10.10.10.10
> enumdomusers
> enumdomgroups
> querydominfo

# enum4linux
enum4linux -U -G -P 10.10.10.10  # Users, Groups, Password Policy

# LDAP Anonymous Bind
ldapsearch -x -H ldap://10.10.10.10 -b "dc=domain,dc=local"

# SMB Shares
smbclient -N -L //10.10.10.10
crackmapexec smb 10.10.10.10 -u '' -p '' --shares
```

## 11. Credential Hunting

### Saved Credentials
```powershell
# Credential Manager
cmdkey /list
rundll32 keymgr.dll,KRShowKeyMgr

# PowerShell Credentials
Get-StoredCredential
```

### SYSVOL / GPP Passwords
```powershell
# Groups.xml durchsuchen
findstr /S /I cpassword \\domain.local\sysvol\*.xml

# Get-GPPPassword (PowerSploit)
Get-GPPPassword
```

### LAPS (Local Administrator Password Solution)
```powershell
# LAPS Passwörter (wenn berechtigt)
Get-ADComputer -Identity "COMPUTER01" -Properties ms-Mcs-AdmPwd | Select name,ms-Mcs-AdmPwd

# Alle Computer mit LAPS
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where {$_."ms-Mcs-AdmPwd" -ne $null}
```

## 12. Quick Enumeration Scripts

### One-Liner Domain Info
```powershell
# PowerShell Domain Quick Enum
$d=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain(); "Domain: $($d.Name)`nDC: $($d.DomainControllers[0].Name)"; net group "Domain Admins" /domain
```

### User Hunting
```bash
# CrackMapExec - Admin Access finden
crackmapexec smb 10.10.10.0/24 -u user -p password --continue-on-success

# Logged On Users
crackmapexec smb 10.10.10.0/24 -u user -p password --loggedon-users
```

## 13. Tools Overview

```bash
# Windows Native
- net user/group/localgroup
- dsquery/dsget
- nltest
- PowerShell AD Module
- gpresult

# PowerShell Modules/Scripts
- ActiveDirectory Module
- PowerView (PowerSploit)
- SharpHound
- ADRecon

# Linux Tools
- ldapsearch
- enum4linux / enum4linux-ng
- rpcclient
- smbclient / smbmap
- Impacket Suite (GetUserSPNs, GetNPUsers, lookupsid, etc.)
- BloodHound-python
- kerbrute
- CrackMapExec (NetExec)
```