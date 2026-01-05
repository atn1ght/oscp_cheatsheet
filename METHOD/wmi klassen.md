# 📊 WMI / Win32-Klassen für AD-Recon & Pentesting

| Kategorie                | Klasse                              | Was man sieht                                                   | Warum interessant                         |
| ------------------------ | ----------------------------------- | --------------------------------------------------------------- | ----------------------------------------- |
| **System / OS**          | `Win32_OperatingSystem`             | OS-Version, Build, Patchlevel, Uptime                           | Exploit-Wahl (z. B. unpatched PrivEsc)    |
|                          | `Win32_ComputerSystem`              | Hostname, Domain, eingeloggter User                             | Zielidentifikation, User-Tracking         |
|                          | `Win32_BIOS`                        | Seriennummer, BIOS-Version                                      | Fingerprinting, Asset Mgmt                |
|                          | `Win32_QuickFixEngineering`         | Installierte Hotfixes                                           | Patchstand prüfen                         |
| **Benutzer & Sessions**  | `Win32_LoggedOnUser`                | Aktive Sessions, eingeloggte Benutzer                           | Admins auf dem System finden              |
|                          | `Win32_LogonSession`                | Session-IDs, Startzeit, Typ (RDP, Local)                        | Session-Hijacking möglich                 |
|                          | `Win32_UserAccount`                 | Lokale Accounts                                                 | Überblick über lokale User                |
|                          | `Win32_Group` / `Win32_GroupUser`   | Lokale Gruppen + Mitgliedschaften                               | Admins identifizieren                     |
| **Prozesse & Dienste**   | `Win32_Process`                     | Prozesse + Owner                                                | Service Accounts finden                   |
|                          | `Win32_Service`                     | Dienste, inkl. Account, Starttyp, Pfad                          | Kerberoasting-Kandidaten                  |
|                          | `Win32_StartupCommand`              | Autostarts                                                      | Oft Klartext-Passwörter                   |
|                          | `Win32_SystemDriver`                | Treiber-Infos                                                   | Schwache Treiber → LPE                    |
| **Geplante Tasks**       | `Win32_ScheduledJob`                | Geplante Tasks                                                  | Task läuft evtl. als Domain-Admin         |
|                          | `Win32_ScheduledJobFile`            | Zugehörige Dateien                                              | Konfigs + Skripte checken                 |
| **Dateisystem & Shares** | `Win32_Share`                       | SMB-Shares (C$, IPC$, Public, SysVol)                           | Einstiegspunkte                           |
|                          | `CIM_DataFile`                      | Beliebige Dateien abfragen (z. B. `unattend.xml`, `web.config`) | Credential-Discovery                      |
|                          | `Win32_LogicalDisk`                 | Laufwerke, Freigaben                                            | Überblick Speicher & Shares               |
|                          | `Win32_Volume`                      | Volumes inkl. Labels                                            | Daten- und Backup-Speicher finden         |
| **Netzwerk**             | `Win32_NetworkAdapterConfiguration` | IP, Gateway, DNS, DHCP                                          | Netzwerk-Mapping                          |
|                          | `Win32_NTDomain`                    | Domaininformationen                                             | Domain-SID & Policy                       |
|                          | `Win32_PingStatus`                  | Basic Connectivity-Test                                         | Lebt der Host?                            |
|                          | `Win32_NetworkLoginProfile`         | Letzte Logins + User                                            | Oft sensible Accounts sichtbar            |
| **Security-relevant**    | `Win32_PrivilegesStatus`            | Privilegien des aktuellen Users                                 | Prüfen ob `SeDebugPrivilege` etc. aktiv   |
|                          | `Win32_Account`                     | Accounts (Domäne & lokal)                                       | AD-Basisinfos                             |
|                          | `Win32_Audit`                       | Audit-Konfiguration                                             | Logging / Detection-Umgehung              |
| **Hardware**             | `Win32_Processor`                   | CPU-Typ, Kerne                                                  | Fingerprinting, Virtualisierungserkennung |
|                          | `Win32_PhysicalMemory`              | RAM-Größe                                                       | Fingerprinting                            |
|                          | `Win32_BaseBoard`                   | Mainboard Infos                                                 | Hardware-Inventory                        |
|                          | `Win32_VideoController`             | GPU-Infos                                                       | VM vs. Bare-Metal                         |