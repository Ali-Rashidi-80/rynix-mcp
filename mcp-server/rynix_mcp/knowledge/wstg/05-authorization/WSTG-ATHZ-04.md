---
id: WSTG-ATHZ-04
title: Testing for Insecure Direct Object References
category: Authorization
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
---

# WSTG-ATHZ-04: Testing for Insecure Direct Object References

## Summary

Insecure Direct Object References (IDOR) occur when an application uses user-controllable input to directly access objects such as database records, files, or API resources without proper authorization checks. This test focuses specifically on API endpoints and object-level authorization, verifying that users cannot access or manipulate objects belonging to other users simply by changing identifier values in requests.

## Test Objectives

- Identify API endpoints that reference objects by user-controllable identifiers
- Test if changing object IDs allows unauthorized access to other users' resources
- Verify that object-level authorization is enforced consistently across all CRUD operations
- Test for IDOR in both REST and GraphQL API endpoints

## Prerequisites

- At least two test accounts at the same privilege level (User A and User B)
- An admin account for testing vertical IDOR
- Knowledge of object IDs belonging to each test account
- Docker pentest container capturing traffic from all test accounts

## Test Steps

### Step 1: Enumerate API Endpoints with Object References

**CLI Actions:**
1. Use `curl` to review all captured API requests while browsing as User A
2. Use `curl` with pattern `/(api|v[0-9])/.*/(\\d+|[a-f0-9-]{36}|[a-zA-Z0-9]{20,})` to identify REST endpoints with object IDs
3. Catalog all endpoints that contain identifiers:
   - Path parameters: `/api/users/123/orders/456`
   - Query parameters: `/api/documents?id=789`
   - Request body fields: `{"user_id": 123, "order_id": 456}`
4. Use `curl` with pattern `(id|user_id|account_id|order_id|doc_id|file_id|record_id)` to find parameterized references

### Step 2: Test Horizontal IDOR on GET Endpoints

**CLI Actions:**
1. Log in as User A and access User A's resources to note the object IDs
2. Use `save to manual-review file` with a request to User A's resource
3. Use `curl` to replace User A's object ID with User B's ID:
   ``
   GET /api/users/USER_B_ID/profile HTTP/1.1
   Host: target.com
   Authorization: Bearer <user_a_token>
   ``
4. Test each identified endpoint systematically:
   ``
   GET /api/orders/OTHER_USER_ORDER_ID HTTP/1.1
   GET /api/documents/OTHER_USER_DOC_ID HTTP/1.1
   GET /api/messages/OTHER_USER_MSG_ID HTTP/1.1
   ``
5. Compare response codes and content - a 200 response with another user's data confirms IDOR

### Step 3: Test Horizontal IDOR on Write Operations

**CLI Actions:**
1. Capture a PUT/PATCH request that modifies User A's own resource
2. Use `curl` to change the target ID to User B's resource:
   ``
   PUT /api/users/USER_B_ID/profile HTTP/1.1
   Host: target.com
   Authorization: Bearer <user_a_token>
   Content-Type: application/json

   {"name":"Hacked","email":"hacked@example.com"}
   ``
3. Test DELETE operations on other users' resources:
   ``
   DELETE /api/orders/OTHER_USER_ORDER_ID HTTP/1.1
   Host: target.com
   Authorization: Bearer <user_a_token>
   ``
4. Test POST operations that create resources tied to other users:
   ``
   POST /api/users/USER_B_ID/orders HTTP/1.1
   Host: target.com
   Authorization: Bearer <user_a_token>
   Content-Type: application/json

   {"item":"test","quantity":1}
   ``

### Step 4: Test ID Enumeration and Predictability

**CLI Actions:**
1. If IDs are sequential integers, use `fuzz-cli` with a numeric range payload to enumerate objects:
   - Set the ID position as the payload marker
   - Use a sequential number range (e.g., 1-1000)
   - Analyze responses for varying content lengths indicating valid objects
2. If IDs are UUIDs, check if they are leaked elsewhere:
   - Use `curl` with pattern `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}` to find UUIDs in responses
3. Check if IDs are encoded - use `base64 -d` on any base64-looking identifiers to reveal underlying patterns

### Step 5: Test IDOR in Request Body Parameters

**CLI Actions:**
1. Capture requests where object ownership is specified in the body
2. Use `curl` to modify body-level ID references:
   ``
   POST /api/transfer HTTP/1.1
   Host: target.com
   Authorization: Bearer <user_a_token>
   Content-Type: application/json

   {"from_account":"USER_B_ACCOUNT","to_account":"USER_A_ACCOUNT","amount":100}
   ``
3. Test modifying `user_id`, `owner_id`, `account_id` fields in POST/PUT bodies
4. Test if the API trusts client-supplied user identifiers over the authenticated session

### Step 6: Test IDOR via GraphQL

**CLI Actions:**
1. Use `curl` with pattern `graphql|query\s*\{|mutation\s*\{` to identify GraphQL endpoints
2. Use `curl` to query another user's objects via GraphQL:
   ``
   POST /graphql HTTP/1.1
   Host: target.com
   Authorization: Bearer <user_a_token>
   Content-Type: application/json

   {"query":"{ user(id: \"USER_B_ID\") { name email orders { id total } } }"}
   ``
3. Test mutations that modify other users' data:
   ``
   {"query":"mutation { updateUser(id: \"USER_B_ID\", input: { name: \"Hacked\" }) { id name } }"}
   ``

### Step 7: Test IDOR with Different ID Formats

**CLI Actions:**
1. Use `curl` to test various ID format transformations:
   - Integer overflow: use very large numbers
   - Negative IDs: `-1`, `-100`
   - Floating point: `1.0`, `1.1`
   - String coercion: `"123"` vs `123`
2. Use `curl --data-urlencode` to encode IDs when testing path-based IDOR
3. Test with `null`, `undefined`, `0`, empty string, and array values:
   ``
   GET /api/users/0/profile HTTP/1.1
   GET /api/users/null/profile HTTP/1.1
   ``

## Payloads

### ID Enumeration Values
```
0
1
-1
99999999
null
undefined
(empty)
true
false
```

### ID Format Variations
```
123
"123"
123.0
0x7B
1e2
[123]
{"id":123}
```

### Common Object Reference Parameters
```
id
user_id
userId
account_id
accountId
order_id
orderId
doc_id
document_id
file_id
record_id
invoice_id
payment_id
msg_id
message_id
```

## Detection Criteria

A finding should be logged when:
- Changing an object ID in a GET request returns another user's data
- Modifying an object ID in a PUT/PATCH request alters another user's resource
- Deleting another user's resource succeeds by changing the ID
- Enumerating sequential IDs reveals valid objects belonging to other users
- GraphQL queries return data for objects not owned by the authenticated user
- Body-level user ID fields allow acting on behalf of another user

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| IDOR allows reading other users' PII or financial data | High |
| IDOR allows modifying other users' data | Critical |
| IDOR allows deleting other users' resources | Critical |
| IDOR on admin-only objects from a regular user session | Critical |
| IDOR reveals non-sensitive data (e.g., public usernames) | Low |
| ID enumeration reveals object existence but no data | Low |
| IDOR on non-sensitive, non-modifiable metadata | Informational |

## Remediation

- Implement object-level authorization checks on every API endpoint
- Verify that the authenticated user owns or has permission to access the requested object
- Use indirect references or mapping tables instead of exposing direct database IDs
- Prefer UUIDs over sequential integer IDs to reduce enumeration risk
- Implement rate limiting on endpoints to slow down enumeration attacks
- For GraphQL, enforce authorization in resolvers, not just at the query level
- Use a centralized authorization middleware or policy engine
- Log and monitor for suspicious patterns of ID enumeration

## References

- [OWASP Testing Guide - IDOR](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP API Security Top 10 - BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

## Rynix workflow

1. `scope_check` and `register_scope` for the target host.
2. `get_wstg_test` for this test ID — read objectives.
3. Execute probes via `http_probe` / `compare_role_response` / `run_idor_matrix`.
4. `track_wstg_test` with status and evidence path.
5. `record_finding` only when verified with probe evidence.

## Evidence requirements

- Request/response snippet or `compare_role_response` diff.
- Session ID on all tool calls.
- No unverified claims in `export_report`.
## ASVS mapping

- V4 Access Control — horizontal and vertical privilege checks.
- V13 API — object-level authorization on every endpoint.

## CWE references

- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control

## Rynix tooling

- Primary tools: ``run_idor_matrix``, ``compare_role_response``, ``rbac_matrix``, ``check_access``

## Test focus

- Mandatory cross-role comparison on every object ID parameter.
- Document 403 vs 404 behavior — both can indicate IDOR signals.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

