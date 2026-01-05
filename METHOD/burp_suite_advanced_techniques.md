# Burp Suite Advanced Techniques Guide

## Table of Contents
1. [Burp Suite Setup & Configuration](#burp-suite-setup--configuration)
2. [Proxy Advanced Techniques](#proxy-advanced-techniques)
3. [Repeater Mastery](#repeater-mastery)
4. [Intruder Deep Dive](#intruder-deep-dive)
5. [Decoder & Comparer](#decoder--comparer)
6. [Sequencer Analysis](#sequencer-analysis)
7. [Scanner & Active Scanning](#scanner--active-scanning)
8. [Extensions & BApps](#extensions--bapps)
9. [Collaborator Usage](#collaborator-usage)
10. [Advanced Workflows](#advanced-workflows)
11. [OSCP-Specific Techniques](#oscp-specific-techniques)

---

## Burp Suite Setup & Configuration

### Optimal Settings for Pentesting

#### Proxy Listener Configuration
```
Proxy → Options → Proxy Listeners

1. Add listener: 127.0.0.1:8080 (default)
2. Add listener: 0.0.0.0:8080 (for external devices)
3. Enable "Support invisible proxying"
4. Certificate: Generate per-host certificates
```

#### Browser Configuration (Firefox)
```
1. Install FoxyProxy extension
2. Add proxy: 127.0.0.1:8080
3. Import Burp CA certificate:
   - Export from Burp: http://burpsuite
   - Firefox → Settings → Certificates → Import
   - Trust for websites
```

#### Scope Configuration
```
Target → Scope → Add

Include:
- Target domain and subdomains
- API endpoints
- Related domains

Exclude:
- CDNs (cloudflare, akamai)
- Analytics (google-analytics, hotjar)
- Ads networks
```

#### Display Settings
```
User Options → Display

- HTTP message display: Show line numbers
- Character sets: UTF-8
- HTML rendering: Disabled (for manual analysis)
```

### Project Configuration

#### Save Project
```
Burp → Project → Save project as
- Save regularly during assessment
- Use descriptive names: target_date.burp
```

#### Project Options
```
Connections:
- Upstream proxy (if needed)
- SOCKS proxy (for Tor, etc.)
- Platform authentication (NTLM, etc.)

Sessions:
- Session handling rules
- Cookie jar
- Macros for multi-step auth
```

---

## Proxy Advanced Techniques

### Intercept Rules

#### Conditional Interception
```
Proxy → Options → Intercept Client Requests

Enable interception based on:
- URL contains specific path: /admin, /api
- File extension: .php, .aspx, .jsp
- Parameter name: id, user, token
- Headers: Authorization, Cookie

Example: Only intercept POST to /login
- Match: Method = POST
- Match: URL contains /login
```

#### Automatic Modifications
```
Proxy → Options → Match and Replace

Add rules:
1. Replace User-Agent:
   Type: Request header
   Match: ^User-Agent.*$
   Replace: User-Agent: Custom-Agent/1.0

2. Add custom header:
   Type: Request header
   Match: ^Host.*$
   Replace: $0\r\nX-Custom-Header: value

3. Remove security headers:
   Type: Response header
   Match: ^Content-Security-Policy.*$
   Replace: (empty)
```

### Response Modification

#### CORS Bypass
```
Match and Replace:
Type: Response header
Match: ^Access-Control-Allow-Origin.*$
Replace: Access-Control-Allow-Origin: *

Type: Response header
Match: ^$
Replace: Access-Control-Allow-Credentials: true
```

#### Force HTTPS Downgrade (Testing)
```
Type: Response header
Match: ^Strict-Transport-Security.*$
Replace: (empty)
```

### History Filtering

#### Advanced Filters
```
Proxy → HTTP history → Filter

Show only:
- Status code: 200-299, 400-499
- MIME type: HTML, JSON, Script
- Parameters: Has parameters
- Search term: password, api, admin

Negative filters:
- Hide extensions: .jpg, .css, .js, .woff
- Hide status: 304
- Hide MIME: image
```

### Request Interception Workflow

```
1. Browse target with intercept OFF
2. Review HTTP history
3. Find interesting requests
4. Right-click → "Do intercept" → "This request"
5. Configure conditional intercept rules
6. Enable intercept
7. Repeat request (Ctrl+R in history)
8. Modify in real-time
```

---

## Repeater Mastery

### Navigation & Shortcuts

#### Essential Shortcuts
```
Ctrl + Space     : Send request
Ctrl + R         : Send to Repeater (from any tool)
Ctrl + I         : Send to Intruder
Ctrl + Shift + R : Rename tab
Ctrl + W         : Close tab
Ctrl + E         : Edit in external editor
Ctrl + U         : URL decode selection
Ctrl + Shift + U : URL encode key characters
```

### Request Manipulation

#### Parameter Tampering
```
Original:
GET /user?id=123&role=user HTTP/1.1

Test variations:
1. id=124 (IDOR)
2. id=1' OR '1'='1 (SQLi)
3. id=../../../etc/passwd (Path traversal)
4. role=admin (Privilege escalation)
5. id[]=123 (Array injection)
6. id=123&id=456 (Parameter pollution)
```

#### Header Manipulation
```
Test headers:
- X-Forwarded-For: 127.0.0.1
- X-Original-URL: /admin
- X-Rewrite-URL: /admin
- X-Custom-IP-Authorization: 127.0.0.1
- X-Forwarded-Host: attacker.com
- Host: localhost
```

#### Method Tampering
```
GET /admin HTTP/1.1    → 403 Forbidden

Try:
POST /admin HTTP/1.1   → 200 OK
PUT /admin HTTP/1.1
DELETE /admin HTTP/1.1
OPTIONS /admin HTTP/1.1
HEAD /admin HTTP/1.1
```

### Repeater Tabs Organization

#### Tab Naming Strategy
```
Right-click tab → Rename

Examples:
- "Login - SQLi test"
- "User API - IDOR"
- "Upload - File bypass"
- "Admin - Auth bypass"

Color coding:
- Green: Success/exploit found
- Red: Blocked/failed
- Orange: Testing in progress
```

### Response Analysis

#### Compare Responses
```
1. Send request multiple times with variations
2. Right-click response → "Show response in browser"
3. Compare tab → Select two requests
4. View differences highlighted

Useful for:
- Time-based blind SQLi (response time)
- Boolean-based SQLi (response length)
- Authentication bypass attempts
```

#### Render Response
```
Right-click response → Show response in browser

Options:
- In current browser session (with cookies)
- In original session (proxy through Burp)

Useful for:
- Preview XSS payloads
- Test CSRF tokens
- View rendered JavaScript
```

---

## Intruder Deep Dive

### Attack Types

#### 1. Sniper (Single Position)
```
Use case: Test single parameter
Positions: 1
Payloads: All payloads to one position

Example - Password brute force:
POST /login HTTP/1.1

username=admin&password=§§

Payload: rockyou.txt
Result: Each password tried with username=admin
```

#### 2. Battering Ram (All Positions Same Payload)
```
Use case: Same value in multiple positions
Positions: Multiple
Payloads: Same payload to all

Example - SQL injection in multiple params:
GET /search?q=§§&category=§§

Payload: ' OR '1'='1
Result: Both positions get same payload
```

#### 3. Pitchfork (Iterate Together)
```
Use case: Credential stuffing, paired values
Positions: Multiple
Payloads: Different list per position, iterate together

Example - User:Pass pairs:
POST /login HTTP/1.1

username=§user1§&password=§pass1§

Payload set 1: admin, user, root
Payload set 2: admin123, user123, root123

Result:
- admin:admin123
- user:user123
- root:root123
```

#### 4. Cluster Bomb (All Combinations)
```
Use case: Brute force all combinations
Positions: Multiple
Payloads: All combinations tested

Example - Full brute force:
POST /login HTTP/1.1

username=§user§&password=§pass§

Payload set 1: admin, user
Payload set 2: pass1, pass2

Result:
- admin:pass1
- admin:pass2
- user:pass1
- user:pass2
```

### Payload Types

#### Simple List
```
Payloads → Payload type: Simple list

Add manually or load from file:
- /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
- /usr/share/wordlists/rockyou.txt
- Custom wordlists
```

#### Numbers
```
Payloads → Payload type: Numbers

Configuration:
Type: Sequential
From: 1
To: 10000
Step: 1
Format: Decimal

Use for: IDOR, sequential ID enumeration
```

#### Character Substitution
```
Payloads → Payload type: Character substitution

Base word: password

Substitutions:
a → @, 4
e → 3
i → 1, !
o → 0
s → $, 5

Results: p@ssw0rd, pa$$word, p4ssw0rd
```

#### Case Modification
```
Payloads → Payload type: Case modification

Options:
- No change
- To lowercase
- To uppercase
- To Propername
- To ProperName

Base: password
Results: password, PASSWORD, Password
```

#### Recursive Grep
```
Payloads → Payload type: Recursive grep

Extract values from responses to use in next requests

Example - CSRF token chaining:
1. Extract: <input name="csrf" value="(.+?)">
2. Use extracted value in next request
```

#### Username Generator
```
Payloads → Payload type: Username generator

Input: john.smith@company.com

Outputs:
- john.smith
- jsmith
- smithj
- john_smith
- j.smith
```

### Payload Processing

#### Encoding
```
Payload Processing → Add → Encode

URL-encode:
- All characters
- Key characters only

Base64 encode
HTML encode
```

#### Prefix/Suffix
```
Payload Processing → Add → Add prefix/suffix

Example - SQL injection:
Prefix: '
Payload: OR 1=1--
Suffix: --

Result: 'OR 1=1----
```

#### Match/Replace
```
Payload Processing → Add → Match/replace

Example - Remove spaces:
Match: \s
Replace: (empty)

payload with spaces → payloadwithspaces
```

### Grep - Match

#### Identify Successful Login
```
Options → Grep - Match

Add strings to identify success:
- "Welcome back"
- "Dashboard"
- "Logout"
- "Account settings"

Use to filter results:
- Requests with matches = successful auth
```

#### Error-Based Detection
```
Grep - Match patterns:
- "SQL syntax error"
- "mysql_fetch"
- "ORA-01"
- "Microsoft OLE DB"
- "Exception"

Identify vulnerable parameters
```

### Grep - Extract

#### Extract Dynamic Tokens
```
Options → Grep - Extract

Add item:
- Extract from: Response body
- Match: <input name="csrf" value="(.+?)">
- Capture group: 1

View extracted values in results table
```

#### Extract Session IDs
```
Match: Set-Cookie: session=(.+?);

Monitor session changes across requests
```

### Resource Pool

#### Rate Limiting
```
Options → Resource pool

Create new pool:
- Maximum concurrent requests: 1
- Delay between requests: 1000ms

Use for:
- Avoid account lockout
- Bypass rate limiting
- Slow enumeration
```

### Redirections

#### Follow Redirections
```
Options → Redirections

- Always: Follow all
- Never: Stop at first response
- On-site only: Follow same domain

Useful for:
- Testing authentication flows
- SSRF with redirects
```

---

## Decoder & Comparer

### Decoder

#### Encoding Chains
```
Decoder → Input text

Chain multiple encodings:
1. Start: <script>alert(1)</script>
2. URL encode: %3Cscript%3Ealert%281%29%3C%2Fscript%3E
3. Base64: JTNDc2NyaXB0JTNFYWxlcnQlMjgxJTI5JTNDJTJGc2NyaXB0JTNF
4. URL encode again: JTNDc2NyaXB0...

Test double/triple encoding bypasses
```

#### Hash Identification
```
Decoder → Hash → Identify

Paste hash, Burp identifies:
- MD5
- SHA1
- SHA256
- NTLM
- bcrypt
```

#### Smart Decode
```
Decoder → Smart decode

Automatically tries multiple decodings:
- URL decode
- HTML decode
- Base64
- Hex
- Gzip

Useful for obfuscated parameters
```

### Comparer

#### Response Comparison
```
Comparer → Load 2 responses

Compare:
- Words: Highlight different words
- Bytes: Highlight different bytes

Use cases:
- Blind SQLi (length differences)
- Time-based testing
- Authentication bypass attempts
- Before/after exploit comparison
```

#### Request Comparison
```
Load 2 requests

Identify differences in:
- Parameters
- Headers
- Body content

Useful for:
- Session comparison
- Privilege level differences
```

---

## Sequencer Analysis

### Token Strength Analysis

#### Session Token Analysis
```
1. Find session token in response
2. Right-click → "Send to Sequencer"
3. Configure token location
4. Start live capture (collect 100+ samples)
5. Analyze randomness

Sequencer tests:
- Character-level analysis
- Bit-level analysis
- Spectral analysis
```

#### CSRF Token Analysis
```
Capture CSRF tokens from multiple requests

Check:
- Randomness quality
- Predictability
- Reuse possibility

Results:
- Effective entropy
- Reliability assessment
```

---

## Scanner & Active Scanning

### Scan Configuration

#### Scan Speed
```
Scanner → Options → Active scanning engine

Fast:
- Concurrent requests: 10
- Per-host: 4
- Retry: 2

Slow (stealth):
- Concurrent requests: 1
- Per-host: 1
- Retry: 1
```

#### Scan Accuracy
```
Scanner → Options → Active scanning areas

Normal: All checks
Light: Common vulns only
```

### Custom Scan Insertion Points

#### Define Insertion Points
```
Scanner → Scan insertion points

Include:
- URL path segments
- Parameter values
- Parameter names
- Headers
- Cookies
- Body (JSON/XML)

Exclude:
- Static values
- Tokens/CSRFs
```

### Passive Scanning

#### Automatic Detection
```
Scanner continuously checks for:
- Missing security headers
- Sensitive data exposure
- Input validation issues
- Cookie security issues

No requests sent - analyzes proxy traffic
```

---

## Extensions & BApps

### Essential Extensions

#### 1. Autorize (Authorization Testing)
```
BApp Store → Autorize

Features:
- Test for authorization flaws
- Compare low-priv vs high-priv responses
- Automatic IDOR detection

Setup:
1. Configure low-privilege user token
2. Browse as high-privilege user
3. Autorize replays with low-priv token
4. Highlights authorization issues
```

#### 2. Logger++ (Enhanced Logging)
```
Features:
- Advanced filtering
- Export to CSV
- Grep on all fields
- Custom columns

Use for:
- Comprehensive request tracking
- Export for reporting
- Advanced analysis
```

#### 3. Turbo Intruder (Fast Fuzzing)
```
Features:
- Much faster than Intruder
- Python scripting
- Race condition testing
- High concurrency

Example - Race condition:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=10,
                          requestsPerConnection=1)

    for i in range(100):
        engine.queue(target.req)
```

#### 4. JWT Editor
```
Features:
- Parse JWT tokens
- Modify header/payload
- Sign with custom keys
- None algorithm attack

Workflow:
1. Capture request with JWT
2. JWT Editor → Parse token
3. Modify payload (change role, user)
4. Sign/resign
5. Send modified request
```

#### 5. Upload Scanner
```
Features:
- Test file upload bypasses
- Magic byte manipulation
- Extension testing
- MIME type testing

Automatic tests:
- Double extensions
- Null byte injection
- Content-Type bypass
- Polyglot files
```

#### 6. Retire.js
```
Features:
- Scan JavaScript libraries
- Identify outdated libraries
- Known vulnerabilities

Automatic detection of vulnerable JS
```

#### 7. Active Scan++
```
Features:
- Additional scan checks
- Edge case vulnerabilities
- CORS misconfigurations
- Host header attacks
```

#### 8. Param Miner
```
Features:
- Discover hidden parameters
- Cache poisoning detection
- Header discovery

Useful for:
- API fuzzing
- Finding hidden functionality
```

#### 9. Error Message Checks
```
Features:
- Detect verbose errors
- Stack traces
- Debug information

Highlights:
- PHP errors
- Java exceptions
- .NET errors
```

### Extension Development Basics

#### Simple Extension (Python)
```python
from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Custom Extension")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Process requests/responses
        if messageIsRequest:
            request = messageInfo.getRequest()
            # Modify request
        else:
            response = messageInfo.getResponse()
            # Analyze response
```

---

## Collaborator Usage

### OAST Testing (Out-of-Band Application Security Testing)

#### Collaborator Basics
```
Burp Collaborator:
- Generates unique subdomain
- Captures DNS/HTTP/HTTPS interactions
- Detects blind vulnerabilities

Generated: abc123.burpcollaborator.net
```

#### Testing Blind SSRF
```
Payload in vulnerable parameter:
http://abc123.burpcollaborator.net

Check Collaborator:
- DNS lookup received
- HTTP request received
- Confirms blind SSRF
```

#### Blind XXE Detection
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://abc123.burpcollaborator.net">
]>
<root>&xxe;</root>

Collaborator receives HTTP request → XXE confirmed
```

#### Blind Command Injection
```bash
; nslookup abc123.burpcollaborator.net
; curl http://abc123.burpcollaborator.net

DNS/HTTP interaction → Command injection confirmed
```

---

## Advanced Workflows

### Workflow 1: Complete SQLi Testing

```
1. Proxy → Find DB query parameter
2. Send to Repeater (Ctrl+R)
3. Test basic SQLi: ' OR '1'='1
4. If vulnerable, send to Intruder
5. Intruder → Load SQLi payloads
6. Grep - Match: "SQL syntax"
7. Run attack
8. Identify successful payloads
9. Repeater → Refine exploit
10. Extract data
```

### Workflow 2: Authentication Bypass

```
1. Proxy → Capture login request
2. Repeater → Test default creds
3. Intruder → Username enumeration
   - Payload: usernames
   - Grep: "User not found" vs "Invalid password"
4. Intruder → Password spray
   - Attack type: Pitchfork
   - Payload 1: Valid users
   - Payload 2: Common passwords
   - Resource pool: 1 req/sec (avoid lockout)
5. Grep - Match: "Welcome" or "Dashboard"
```

### Workflow 3: API Fuzzing

```
1. Proxy → Capture API requests
2. Identify API endpoints
3. Repeater → Test each endpoint
4. Intruder → Fuzz parameters
   - Numbers for IDs
   - Simple list for values
5. Compare → Find differences
6. Scanner → Active scan API
7. Extensions → Param Miner for hidden params
```

### Workflow 4: JWT Testing

```
1. Proxy → Capture JWT in request
2. Extensions → JWT Editor
3. Decode token
4. Repeater → Test modifications:
   - Change role
   - Change user ID
   - Algorithm None attack
   - Weak secret brute force
5. Intruder → Test signature bypass
```

---

## OSCP-Specific Techniques

### Quick Wins with Burp

#### 1. Directory Brute Force
```
Intruder → Sniper
Position: GET /§§ HTTP/1.1
Payload: /usr/share/seclists/Discovery/Web-Content/common.txt
Grep - Match: 200, 301, 302
Filter: Show only matches
```

#### 2. IDOR Testing
```
Repeater:
GET /user/profile?id=123

Test: 1, 2, 100, admin, 0, -1
Compare responses
Look for info disclosure
```

#### 3. File Upload Bypass
```
Intruder → Pitchfork
Content-Disposition: filename="§shell§.§php§"

Payload 1: shell, test, upload
Payload 2: php, php5, phtml, phar

Grep - Match: "Upload successful"
```

#### 4. Parameter Pollution
```
Repeater:
GET /admin?role=user

Test:
?role=user&role=admin
?role=admin&role=user
?role[]=admin
```

### Time-Saving Tips

```
1. Use Target → Site map for overview
2. Set scope early (avoid noise)
3. Organize Repeater tabs (rename/color)
4. Use Comparer for blind testing
5. Export Intruder results for analysis
6. Take screenshots of exploits for report
7. Use Logger++ for complete history
8. Save project regularly
```

---

## Quick Reference

### Shortcuts
```
Ctrl + R     : Send to Repeater
Ctrl + I     : Send to Intruder
Ctrl + Space : Send request (Repeater)
Ctrl + F     : Search
Ctrl + Shift + F : Search all (Site map)
```

### Common Tests
```
SQLi: ' OR '1'='1
XSS: <script>alert(1)</script>
LFI: ../../../../etc/passwd
Command Injection: ; whoami
```

---

**Remember**: Burp Suite is the most powerful web application testing tool. Master it for OSCP and beyond!
