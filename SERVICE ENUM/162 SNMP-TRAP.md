# SNMP TRAP ENUMERATION (Port 162/UDP)

## SERVICE OVERVIEW
```
SNMP Trap - Asynchronous notifications from SNMP agents
- Port: 162/UDP (trap receiver)
- Port: 161/UDP (SNMP agent - for comparison)
- Sends alerts/notifications from devices to management station
- SNMPv1, SNMPv2c (community-based), SNMPv3 (secure)
- Can reveal network events, device status, security incidents
```

## BASIC DETECTION
```bash
# Nmap scan for SNMP trap port
nmap -sU -p162 <IP>                             # UDP scan port 162
nmap -sU -p161-162 <IP>                         # Scan both SNMP ports

# Check if trap receiver is listening
nc -u <IP> 162                                  # UDP connection test
```

## SNMP TRAP TYPES
```
Trap Types (SNMPv1):
- coldStart (0): Device reinitialized
- warmStart (1): Device restarted
- linkDown (2): Communication link failed
- linkUp (3): Communication link restored
- authenticationFailure (4): Authentication attempt failed
- egpNeighborLoss (5): EGP neighbor down
- enterpriseSpecific (6): Vendor-specific traps

SNMPv2/v3 uses notifications (INFORMs) instead of traps
INFORMs require acknowledgment from receiver
```

## SNMP TRAP LISTENER (RECEIVE TRAPS)
```bash
# Use snmptrapd to listen for traps
snmptrapd -f -Lo -c /etc/snmp/snmptrapd.conf    # Foreground mode

# Simple trap receiver
snmptrapd -f -Le -C -c /etc/snmp/snmptrapd.conf

# Log traps to file
snmptrapd -Lf /var/log/snmptrap.log

# Listen on all interfaces
snmptrapd -Le -f 0.0.0.0:162
```

## CONFIGURE TRAP RECEIVER
```bash
# snmptrapd.conf configuration
cat > /etc/snmp/snmptrapd.conf <<EOF
authCommunity log,execute,net public
disableAuthorization yes
EOF

# Start trap daemon
sudo snmptrapd -f -Lo -c /etc/snmp/snmptrapd.conf

# Or use specific community string
echo "authCommunity log,execute,net <community_string>" > /tmp/snmptrapd.conf
sudo snmptrapd -f -Lo -c /tmp/snmptrapd.conf
```

## SENDING TEST TRAPS
```bash
# Send trap with snmptrap
snmptrap -v 2c -c public <trap_receiver_IP> '' 1.3.6.1.4.1.8072.2.3.0.1 \
  1.3.6.1.4.1.8072.2.3.2.1 i 123456

# SNMPv1 trap
snmptrap -v 1 -c public <trap_receiver_IP> \
  1.3.6.1.4.1.8072.2.3.0.1 <agent_IP> 6 1 '' \
  1.3.6.1.4.1.8072.2.3.2.1 i 123456

# SNMPv2c trap
snmptrap -v 2c -c public <trap_receiver_IP> \
  '' 1.3.6.1.2.1.1.3.0 \
  1.3.6.1.2.1.1.3.0 i 1234
```

## MONITORING TRAPS WITH PYTHON
```bash
# Install pysnmp
pip install pysnmp

# Simple trap receiver script
cat > trap_receiver.py <<'EOF'
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp
from pyasn1.codec.der import decoder
from pysnmp.proto import api

def cbFun(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    while wholeMsg:
        msgVer = int(api.decodeMessageVersion(wholeMsg))
        if msgVer in api.protoModules:
            pMod = api.protoModules[msgVer]
        else:
            print('Unsupported SNMP version %s' % msgVer)
            return
        reqMsg, wholeMsg = decoder.decode(
            wholeMsg, asn1Spec=pMod.Message(),
        )
        print('Notification from %s:%s' % (
            transportDomain, transportAddress
        ))
        print(reqMsg.prettyPrint())
        return wholeMsg

transportDispatcher = AsyncoreDispatcher()
transportDispatcher.registerRecvCbFun(cbFun)
transportDispatcher.registerTransport(
    udp.domainName, udp.UdpSocketTransport().openServerMode(('0.0.0.0', 162))
)
transportDispatcher.jobStarted(1)

try:
    transportDispatcher.runDispatcher()
except:
    transportDispatcher.closeDispatcher()
    raise
EOF

python trap_receiver.py
```

## SNMP TRAP RECONNAISSANCE
```bash
# Set up trap receiver to capture device notifications
# Devices may send traps containing:
# - Device hostnames
# - IP addresses
# - System information
# - Interface status
# - Authentication failures (revealing valid users)
# - Configuration changes

# Monitor for authentication failures
# This reveals:
# - Valid community strings being tested
# - Source IPs attempting SNMP access
# - Potential security monitoring presence
```

## NMAP SCRIPTS
```bash
# SNMP trap detection (limited utility)
nmap -sU -p162 <IP>                             # Port scan

# Focus on SNMP agent (161) instead
nmap -sU -p161 --script snmp-* <IP>             # Comprehensive SNMP enum
```

## TRIGGERING TRAPS FOR RECONNAISSANCE
```bash
# Trigger authentication failure trap
# Try wrong community strings on port 161
for comm in public private manager admin; do
    snmpwalk -v 2c -c $comm <IP> 2>&1 | grep -i "authentication"
done

# This may trigger authenticationFailure traps
# If you're listening on port 162, you'll receive these

# Trigger interface traps
# If you can access SNMP agent, you can trigger linkDown/linkUp
snmpset -v 2c -c private <IP> ifAdminStatus.<interface> i 2  # Down
snmpset -v 2c -c private <IP> ifAdminStatus.<interface> i 1  # Up
```

## METASPLOIT MODULES
```bash
msfconsole

# SNMP enumeration (port 161, not 162 directly)
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS <IP>
set COMMUNITY public
run

# SNMP login scanner
use auxiliary/scanner/snmp/snmp_login
set RHOSTS <IP>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt
run
```

## COMMON MISCONFIGURATIONS
```
☐ Default community strings (public/private)
☐ Trap receiver accepting from any source
☐ SNMPv1/v2c used (no encryption)
☐ Traps revealing sensitive system information
☐ No authentication on trap receiver
☐ Trap messages not logged/monitored
☐ Port 162 exposed to internet
☐ Sensitive data in trap payloads
```

## QUICK WIN CHECKLIST
```
☐ Scan for port 162/UDP (SNMP trap receiver)
☐ Set up trap listener (snmptrapd)
☐ Attempt to send test traps
☐ Trigger authentication failure traps on port 161
☐ Monitor for device traps revealing network topology
☐ Check for default community strings
☐ Correlate with SNMP agent on port 161
☐ Look for sensitive info in trap payloads
```

## ONE-LINER ENUMERATION
```bash
# Quick SNMP trap check
nmap -sU -p162 <IP>

# Set up basic trap receiver
sudo snmptrapd -f -Le -c <(echo "disableAuthorization yes")
```

## SECURITY IMPLICATIONS
```
RISKS:
- Information disclosure via trap messages
- Network topology mapping
- Device/interface enumeration
- Authentication failure monitoring bypass
- Sensitive data in trap payloads (passwords, keys)
- DoS via trap flooding
- Spoofed traps (no authentication in SNMPv1/v2c)

RECOMMENDATIONS:
- Use SNMPv3 with authentication and encryption
- Restrict trap receiver to specific source IPs
- Disable SNMPv1/v2c if possible
- Use strong community strings
- Encrypt trap traffic (SNMPv3)
- Log and monitor all traps
- Limit information in trap payloads
- Implement firewall rules for port 162
```

## ADVANCED TECHNIQUES
```bash
# Trap spoofing (SNMPv1/v2c)
# Send fake traps to manipulate monitoring systems
snmptrap -v 2c -c public <trap_receiver> '' \
  1.3.6.1.6.3.1.1.5.3 \
  1.3.6.1.2.1.2.2.1.8.1 i 2

# Trap flooding (DoS)
while true; do
    snmptrap -v 2c -c public <trap_receiver> '' \
      1.3.6.1.4.1.8072.2.3.0.1 \
      1.3.6.1.4.1.8072.2.3.2.1 i $RANDOM
done

# Capture and replay traps
tcpdump -i eth0 -w snmp_traps.pcap udp port 162
# Analyze with Wireshark, replay with tcpreplay if needed
```

## TOOLS
```bash
# snmptrapd (Net-SNMP)
apt-get install snmp snmptrapd
snmptrapd -f -Lo

# snmptrap (send traps)
snmptrap -v 2c -c public <receiver> '' <OID>

# Python pysnmp
pip install pysnmp

# Wireshark
wireshark -f "udp port 162"                     # Capture SNMP traps

# tcpdump
tcpdump -i eth0 -n udp port 162 -vv -X
```

## INTEGRATION WITH SNMP AGENT (161)
```bash
# Combined SNMP attack
# 1. Enumerate SNMP agent (port 161)
nmap -sU -p161 --script snmp-brute <IP>
onesixtyone -c community.txt <IP>

# 2. Set up trap receiver (port 162)
sudo snmptrapd -f -Le

# 3. Trigger traps via agent manipulation
snmpwalk -v 2c -c public <IP>

# 4. Analyze captured traps for sensitive info
```

## SNMPv3 TRAPS
```bash
# SNMPv3 requires authentication
# Send SNMPv3 trap
snmptrap -v 3 -l authPriv -u <user> -a SHA -A <auth_pass> \
  -x AES -X <priv_pass> <trap_receiver> '' \
  1.3.6.1.4.1.8072.2.3.0.1

# Configure SNMPv3 trap receiver
cat > /etc/snmp/snmptrapd.conf <<EOF
createUser -e 0x8000000001020304 <user> SHA <auth_pass> AES <priv_pass>
authUser log,execute,net <user>
EOF

sudo snmptrapd -f -Lo -c /etc/snmp/snmptrapd.conf
```
