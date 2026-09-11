---
id: WSTG-BUSL-02
title: Test Ability to Forge Requests
category: Business Logic
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests
---

# WSTG-BUSL-02: Test Ability to Forge Requests

## Summary

Request forgery vulnerabilities occur when an application fails to verify the authenticity and integrity of incoming requests. Attackers can manipulate hidden fields, tamper with request parameters, modify cookies, replay captured requests with alterations, or add unexpected parameters to change application behavior. If the server blindly trusts request data without proper validation and integrity checks, attackers can perform unauthorized actions.

## Test Objectives

- Manipulate hidden form fields and observe server behavior
- Tamper with request parameters to alter business logic
- Replay modified requests to test server-side validation
- Add unexpected parameters to trigger mass assignment or parameter pollution
- Test if CSRF tokens and request integrity mechanisms are enforced

## Prerequisites

- Target application is accessible through Docker pentest container
- Normal application workflows have been captured in proxy history
- User accounts are available for testing authenticated functionality

## Test Steps

### Step 1: Capture and Analyze Normal Request Flow

**CLI Actions:**
Use `curl` to review captured requests from normal application usage. Identify:

- Hidden form fields (price, user_id, role, state, step)
- Session-related parameters
- CSRF tokens and their validation
- Parameters that control business logic (amounts, permissions, statuses)

### Step 2: Manipulate Hidden Fields

**CLI Actions:**
Use `save to manual-review file` with a captured request and modify hidden field values:

```
POST /purchase HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

product_id=1&quantity=1&price=9.99&currency=USD&user_id=1001
```

Modify to:

```
POST /purchase HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

product_id=1&quantity=1&price=0.01&currency=USD&user_id=1002
```

Test modifying: `price`, `total`, `discount`, `user_id`, `role`, `status`, `account_type`.

### Step 3: Test Parameter Tampering

**CLI Actions:**
Use `curl` to modify parameters that control business logic:

```
POST /api/order/update HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"order_id": 12345, "status": "approved", "amount": 0.01}
```

```
POST /api/user/update HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"user_id": 1001, "role": "admin", "email_verified": true}
```

Use `curl --data-urlencode` to properly encode special characters in parameter values when testing URL-encoded requests.

### Step 4: Test Request Replay with Modifications

**CLI Actions:**
Use `curl` to find a completed transaction request. Use `save to manual-review file` to replay it with modifications:

1. Replay the exact same request (test idempotency)
2. Replay with modified amounts
3. Replay with a different user's session token
4. Replay with an expired timestamp but valid signature

### Step 5: Test HTTP Parameter Pollution

**CLI Actions:**
Use `curl` to send duplicate parameters:

```
POST /transfer HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

amount=100&to_account=attacker&amount=1
```

```
GET /api/user?id=1001&id=1002 HTTP/1.1
Host: target.com
```

Different web frameworks handle duplicate parameters differently:
- First occurrence wins (e.g., ASP.NET)
- Last occurrence wins (e.g., PHP, Apache)
- Comma-concatenated (e.g., some Java frameworks)

### Step 6: Test Mass Assignment / Object Injection

**CLI Actions:**
Use `curl` to add extra parameters not present in the original form:

```
POST /api/user/register HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "newuser", "password": "pass123", "email": "new@test.com", "role": "admin", "is_admin": true, "account_type": "premium"}
```

```
PUT /api/profile HTTP/1.1
Host: target.com
Content-Type: application/json

{"name": "Test User", "email": "test@test.com", "balance": 999999, "verified": true}
```

### Step 7: Test CSRF Token Validation

**CLI Actions:**
Use `save to manual-review file` to test CSRF protection:

1. Remove the CSRF token entirely and send the request
2. Use an empty CSRF token value
3. Use a CSRF token from a different session
4. Use a previously used (expired) CSRF token
5. Modify one character of a valid CSRF token

```
POST /transfer HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

amount=100&to_account=attacker&csrf_token=
```

Use `rynix_plugin_run('template-scan')` to check if template-scan has identified CSRF or parameter tampering issues.

## Payloads

### Hidden Field Manipulation Values
```
# Price manipulation
price=0
price=0.01
price=-1
price=0.001

# Role escalation
role=admin
role=administrator
is_admin=true
is_admin=1
privilege=superuser
account_type=premium
user_type=staff

# Status manipulation
status=approved
status=completed
status=verified
approved=true
verified=true
```

### Parameter Pollution Patterns
```
# Duplicate parameters
param=value1&param=value2
param[]=value1&param[]=value2
param=value1,value2

# Array injection
id[]=1&id[]=2
items[0]=A&items[1]=B

# Object injection (JSON)
{"role": "admin"}
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
```

### CSRF Token Bypass Values
```
(empty string)
null
undefined
0
true
AAAA (short token)
<valid_token_with_one_char_changed>
<token_from_different_session>
```

## Detection Criteria

A finding should be logged when:
- Hidden field modifications change server behavior (e.g., price accepted as submitted)
- Parameter tampering allows unauthorized state changes
- Mass assignment adds unintended attributes (role, permissions, balance)
- CSRF tokens are not validated or can be bypassed
- Request replay with modifications succeeds
- HTTP parameter pollution causes inconsistent processing

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Price or payment amount can be manipulated in requests | High |
| Mass assignment allows privilege escalation to admin | High |
| CSRF protection absent on state-changing operations | High |
| User ID manipulation allows accessing other users' data | High |
| Parameter tampering changes order status or approval state | Medium |
| CSRF token validated but can be reused across sessions | Medium |
| HTTP parameter pollution causes different behavior | Medium |
| Hidden fields can be modified but changes are logged and reversed | Low |
| Request replay detected but not fully prevented | Low |
| All hidden fields validated and integrity-checked server-side | Not a finding |

## Remediation

- Never trust client-supplied values for security-critical fields (price, role, user ID)
- Recalculate all derived values server-side (totals, taxes, discounts)
- Implement anti-CSRF tokens on all state-changing requests
- Use object allowlisting to prevent mass assignment (only accept expected fields)
- Sign or MAC request parameters to detect tampering
- Implement request deduplication to prevent replay attacks
- Use the principle of least privilege: derive user identity from session, not request parameters
- Log and alert on requests with unexpected or modified parameters
- Use a consistent parameter parsing strategy to prevent HTTP parameter pollution

## References

- [OWASP Testing Guide - Test Ability to Forge Requests](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests)
- [CWE-472: External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

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

- V11 Business Logic — workflow integrity and limit enforcement.
- V4 Access Control — state transitions require proper authorization.

## CWE references

- CWE-840: Business Logic Errors
- CWE-362: Race Condition

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test price/quantity manipulation and workflow step skipping.
- Parallel requests for race windows on limits and balances.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

