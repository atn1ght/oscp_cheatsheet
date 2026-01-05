# DNS ENUMERATION (Port 53)

## PORT OVERVIEW
```
Port 53 - DNS (TCP/UDP)
UDP 53 - Standard DNS queries
TCP 53 - Zone transfers, large responses
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p53 <IP>                              # Service/Version detection
nmap -sU -p53 <IP>                              # UDP scan
dig @<IP> version.bind CHAOS TXT                # BIND version query
dig @<IP> version.bind CH TXT                   # Alternative version query
host -t txt version.bind <IP>                   # Host command
```

## BASIC DNS QUERIES
```bash
# Query DNS server
dig @<IP> <domain>                              # Query A record
dig @<IP> <domain> ANY                          # All records
host <domain> <IP>                              # Host command
nslookup <domain> <IP>                          # Nslookup

# Specific record types
dig @<IP> <domain> A                            # IPv4 address
dig @<IP> <domain> AAAA                         # IPv6 address
dig @<IP> <domain> MX                           # Mail servers
dig @<IP> <domain> NS                           # Name servers
dig @<IP> <domain> TXT                          # TXT records
dig @<IP> <domain> SOA                          # Start of Authority
dig @<IP> <domain> PTR                          # Reverse DNS
```

## ZONE TRANSFER (AXFR)
```bash
# Attempt zone transfer (full DNS database dump)
dig @<IP> <domain> AXFR                         # Full zone transfer
dig @<IP> <domain> AXFR +short                  # Short output
host -l <domain> <IP>                           # Host command
nslookup -type=AXFR <domain> <IP>               # Nslookup

# Automated zone transfer
dnsrecon -d <domain> -t axfr -n <IP>            # DNSRecon
fierce --domain <domain> --dns-servers <IP>    # Fierce
dnsenum <domain> --dnsserver <IP>               # DNSEnum
```

## SUBDOMAIN ENUMERATION
```bash
# Brute force subdomains
dnsrecon -d <domain> -D /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt -n <IP>
dnsenum --dnsserver <IP> -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt <domain>
fierce --domain <domain> --wordlist subdomains.txt --dns-servers <IP>

# Fast subdomain bruteforce
gobuster dns -d <domain> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r <IP>:53
amass enum -d <domain> -src                     # Comprehensive enumeration

# Passive subdomain discovery
subfinder -d <domain>                           # Fast passive discovery
assetfinder --subs-only <domain>                # Passive discovery
```

## REVERSE DNS LOOKUP
```bash
# Reverse DNS (PTR records)
dig @<IP> -x <TARGET_IP>                        # Query PTR record
host <TARGET_IP> <IP>                           # Host command

# Reverse DNS zone transfer
dig @<IP> <reversed_IP>.in-addr.arpa AXFR       # e.g., 1.168.192.in-addr.arpa
```

## NMAP DNS ENUMERATION
```bash
nmap --script "dns-*" -p53 <IP>                 # All DNS scripts
nmap --script dns-zone-transfer -p53 <IP> --script-args dns-zone-transfer.domain=<domain>
nmap --script dns-brute -p53 <IP> --script-args dns-brute.domain=<domain>
nmap --script dns-srv-enum -p53 <IP> --script-args dns-srv-enum.domain=<domain>
nmap --script dns-nsid -p53 <IP>                # Name Server ID
nmap --script dns-recursion -p53 <IP>           # Test for recursive queries
nmap --script dns-cache-snoop -p53 <IP> --script-args 'dns-cache-snoop.domains={google.com,facebook.com}'
```

## DNS RECONNAISSANCE TOOLS
```bash
# DNSRecon (comprehensive)
dnsrecon -d <domain> -n <IP>                    # Standard enumeration
dnsrecon -d <domain> -t axfr -n <IP>            # Zone transfer
dnsrecon -d <domain> -t brt -D wordlist.txt -n <IP>  # Brute force
dnsrecon -r <IP_RANGE> -n <IP>                  # Reverse lookup range

# DNSEnum
dnsenum <domain> --dnsserver <IP>               # Standard enumeration
dnsenum <domain> --threads 5 --dnsserver <IP>   # Multi-threaded

# Fierce
fierce --domain <domain> --dns-servers <IP>     # Enumerate DNS
fierce --domain <domain> --subdomains hosts.txt # Custom wordlist

# Host
host -t ns <domain> <IP>                        # Name servers
host -t mx <domain> <IP>                        # Mail servers
host -l <domain> <IP>                           # Zone transfer attempt
```

## DNS CACHE SNOOPING
```bash
# Check if specific domains are cached (information disclosure)
nmap --script dns-cache-snoop -p53 <IP> --script-args 'dns-cache-snoop.domains={internal.local,vpn.company.com}'

# Manual cache snooping
dig @<IP> <target_domain> +norecurse            # Non-recursive query
# If answer returned, domain is cached
```

## DNS RECURSION TESTING
```bash
# Test if DNS server allows recursive queries
dig @<IP> google.com                            # Should resolve if recursive
nmap --script dns-recursion -p53 <IP>           # Nmap script

# Recursive queries = DNS amplification attack possible
# Recursive queries can leak internal domains
```

## DNS TUNNELING DETECTION
```bash
# DNS can be used for data exfiltration and C2 communication
# Look for suspicious patterns:
# - High volume of TXT queries
# - Long subdomain names (encoded data)
# - Unusual query patterns

# Tools for DNS tunneling
iodine                                          # DNS tunneling client
dnscat2                                         # DNS C2 channel
```

## SRV RECORD ENUMERATION
```bash
# SRV records reveal services in domain
dig @<IP> _ldap._tcp.<domain> SRV               # LDAP servers
dig @<IP> _kerberos._tcp.<domain> SRV           # Kerberos servers
dig @<IP> _sip._tcp.<domain> SRV                # SIP servers
dig @<IP> _xmpp-server._tcp.<domain> SRV        # XMPP servers

# Nmap SRV enumeration
nmap --script dns-srv-enum -p53 <IP> --script-args dns-srv-enum.domain=<domain>
```

## DNSSEC VALIDATION
```bash
# Check if DNSSEC is enabled
dig @<IP> <domain> +dnssec                      # DNSSEC query
dig @<IP> <domain> DNSKEY                       # DNSSEC keys
dig @<IP> <domain> DS                           # Delegation Signer

# Test DNSSEC validation
delv @<IP> <domain>                             # DNSSEC validation tool
```

## DNS AMPLIFICATION ATTACK (TESTING)
```bash
# DNS amplification uses DNS servers for DDoS
# Test if server is vulnerable (allows recursive queries)
dig @<IP> google.com                            # Should not resolve if configured properly

# ANY query returns large response (good for amplification)
dig @<IP> <domain> ANY                          # Large response

# Don't actually perform attacks, just test configuration
```

## COMMON MISCONFIGURATIONS
```
☐ Zone transfer allowed from any IP (AXFR)
☐ Recursive queries enabled for external IPs
☐ DNS server exposed to internet
☐ No rate limiting (DNS amplification)
☐ DNSSEC not enabled
☐ Outdated BIND version (known CVEs)
☐ Internal IP addresses in DNS records
☐ Weak TSIG keys
☐ Cache poisoning possible
☐ Version information disclosure
```

## DNS VULNERABILITIES
```bash
# DNS Cache Poisoning (CVE-2008-1447 - Dan Kaminsky)
# DNS Amplification attacks
# DNS Tunneling for C2

# Check BIND version for known CVEs
searchsploit bind                               # Search exploits
```

## ACTIVE DIRECTORY DNS ENUMERATION
```bash
# Enumerate AD via DNS
dig @<DC_IP> _ldap._tcp.dc._msdcs.<domain> SRV  # Domain Controllers
dig @<DC_IP> _kerberos._tcp.<domain> SRV        # Kerberos servers
dig @<DC_IP> _gc._tcp.<domain> SRV              # Global Catalog servers
dig @<DC_IP> _ldap._tcp.<domain> SRV            # LDAP servers

# Enumerate all DC-related SRV records
for srv in _gc _kerberos _kpasswd _ldap; do
  dig @<DC_IP> ${srv}._tcp.<domain> SRV
done
```

## METASPLOIT DNS MODULES
```bash
msfconsole
use auxiliary/gather/dns_info                   # DNS information gathering
use auxiliary/gather/dns_reverse_lookup         # Reverse DNS
use auxiliary/gather/dns_srv_enum               # SRV record enumeration
use auxiliary/gather/dns_bruteforce             # Subdomain brute force
use auxiliary/server/dns/spoofing               # DNS spoofing (MITM)
```

## QUICK WIN CHECKLIST
```
☐ Attempt zone transfer (AXFR)
☐ Enumerate subdomains (brute force)
☐ Check for recursive queries
☐ Extract DNS version (BIND)
☐ Enumerate SRV records (AD services)
☐ Test for DNS cache snooping
☐ Reverse DNS lookup for IP ranges
☐ Check DNSSEC configuration
☐ Look for internal IP disclosure
☐ Test for ANY query response (amplification)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick DNS enumeration
dig @<IP> <domain> ANY && \
dig @<IP> <domain> AXFR && \
dnsrecon -d <domain> -n <IP> && \
nmap --script dns-zone-transfer,dns-recursion -p53 <IP>

# Comprehensive subdomain enumeration
dnsrecon -d <domain> -D /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt -n <IP>
```

## ADVANCED TECHNIQUES
```bash
# DNS wildcard detection
dig @<IP> randomstring123456.<domain>           # Check if wildcard exists

# DNS load balancing detection
for i in {1..10}; do dig @<IP> <domain> +short; done  # Multiple queries

# IPv6 enumeration
dig @<IP> <domain> AAAA                         # IPv6 addresses
dig @<IP> ipv6.<domain> AAAA                    # Common IPv6 subdomain
```

## POST-EXPLOITATION (AFTER DNS ACCESS)
```bash
# After compromising DNS server:
1. Enumerate all domains and subdomains (zone transfer)
2. Identify internal IP addresses and networks
3. Map infrastructure (web servers, mail servers, DCs)
4. DNS hijacking (redirect traffic to attacker)
5. DNS cache poisoning
6. DNS tunneling for C2/exfiltration
7. Enumerate AD infrastructure (if internal DNS)
8. Identify hidden services via SRV records
```
