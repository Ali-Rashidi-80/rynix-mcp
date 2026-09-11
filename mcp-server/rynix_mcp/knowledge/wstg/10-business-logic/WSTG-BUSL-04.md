---
id: WSTG-BUSL-04
title: Test for Process Timing
category: Business Logic
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing
---

# WSTG-BUSL-04: Test for Process Timing

## Summary

Process timing vulnerabilities arise when an application fails to properly handle concurrent requests or time-dependent operations. Race conditions occur when multiple requests modify shared resources simultaneously, and the outcome depends on the precise timing of execution. Time-of-check-to-time-of-use (TOCTOU) flaws happen when there is a gap between verifying a condition and acting on it, allowing an attacker to change the state in between. These vulnerabilities can lead to double-spending, bypassing limits, and data corruption.

## Test Objectives

- Identify race conditions in critical operations (payments, transfers, voting)
- Test for TOCTOU vulnerabilities in multi-step processes
- Assess concurrent request handling for shared resources
- Determine if locking mechanisms are properly implemented

## Prerequisites

- Target application is accessible through Docker pentest container
- Critical business operations have been identified (financial transactions, account modifications)
- Ability to send multiple simultaneous requests

## Test Steps

### Step 1: Identify Race Condition Targets

**CLI Actions:**
Use `curl` to identify operations that modify shared state:

- Balance transfers or payments
- Coupon or voucher redemption
- Voting or rating submissions
- Account balance checks followed by withdrawals
- Inventory decrements on purchase
- Concurrent file or resource modifications

### Step 2: Test Double-Spend via Concurrent Requests

**CLI Actions:**
Use `save to manual-review file` to prepare the race condition test. Capture a single transaction request:

```
POST /api/transfer HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"from_account": "A", "to_account": "B", "amount": 100}
```

Use `fuzz-cli` configured for concurrent execution:
1. Set payload type to Null payloads with 10-20 iterations
2. Configure maximum concurrent threads (use parallel http_probe batch if available)
3. All requests send simultaneously to the same endpoint with the same parameters

Compare results: if the balance was 100 and you sent 10 transfer requests for 100 each, check if more than one succeeded.

### Step 3: Test TOCTOU in Multi-Step Processes

**CLI Actions:**
Identify processes where a check happens in one request and the action in a subsequent request:

Step A - Check balance:
```
GET /api/account/balance HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

Step B - Execute transfer:
```
POST /api/transfer HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"amount": 100}
```

Use `curl` to execute Step A, then rapidly send Step B multiple times using `fuzz-cli` before the balance is updated.

### Step 4: Test Coupon/Voucher Race Condition

**CLI Actions:**
Use `save to manual-review file` with a coupon redemption request:

```
POST /api/redeem HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"coupon_code": "DISCOUNT50"}
```

Use `fuzz-cli` to send this request multiple times simultaneously. Check if the single-use coupon was applied more than once.

### Step 5: Test Concurrent Account Modifications

**CLI Actions:**
Use `curl` to send concurrent modification requests from two sessions:

Session 1:
```
PUT /api/profile HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <user1_token>

{"email": "user1_new@test.com"}
```

Session 2 (simultaneous):
```
PUT /api/profile HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <user1_token>

{"email": "user1_other@test.com"}
```

Check for data corruption, lost updates, or inconsistent state.

### Step 6: Analyze Timing Differences

**CLI Actions:**
Use `curl` to measure response times for different operations and look for timing-based information leaks:

```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "valid_user", "password": "wrong_password"}
```

```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "nonexistent_user", "password": "wrong_password"}
```

Compare response times - significant differences may indicate the application processes valid vs. invalid usernames differently (user enumeration via timing).

Use `rynix_plugin_run('template-scan')` to check for timing-related findings.

## Payloads

### Concurrent Request Patterns
```
# Same request repeated N times simultaneously
# N = 5, 10, 20, 50

# Same coupon redeemed simultaneously
POST /redeem {"code": "SINGLE_USE_CODE"} x 10

# Same transfer executed simultaneously
POST /transfer {"amount": 100} x 10

# Same vote submitted simultaneously
POST /vote {"option": "A"} x 10
```

### TOCTOU Exploitation Sequences
```
# Pattern: Check then Act
1. GET /balance -> returns 100
2. POST /withdraw {"amount": 100} (sent 5x simultaneously)

# Pattern: Validate then Process
1. GET /coupon/validate?code=X -> returns valid
2. POST /coupon/apply {"code": "X"} (sent 5x simultaneously)

# Pattern: Reserve then Confirm
1. POST /cart/add {"item": "limited_item"}
2. POST /checkout (sent 3x simultaneously from different sessions)
```

### Timing Attack Payloads
```
# User enumeration via timing
valid_username + wrong_password
invalid_username + wrong_password

# Compare response times (ms)
# Significant difference > 50ms indicates different code paths
```

## Detection Criteria

A finding should be logged when:
- Concurrent requests cause a single-use resource to be consumed multiple times
- Balance or inventory goes negative due to race conditions
- TOCTOU gap allows bypassing validation checks
- Concurrent modifications result in data corruption or lost updates
- Timing differences reveal information about internal processing
- No locking or serialization is applied to critical shared resource operations

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Race condition allows double-spending of financial resources | High |
| TOCTOU allows bypassing balance or inventory checks | High |
| Concurrent requests bypass single-use restrictions (coupons, votes) | Medium |
| Race condition causes data corruption in user profiles | Medium |
| Timing side-channel enables user enumeration | Medium |
| Concurrent requests handled correctly but cause degraded performance | Low |
| Minor timing differences with no exploitable information leak | Informational |
| Proper locking and serialization on all critical operations | Not a finding |

## Remediation

- Implement database-level locking (pessimistic or optimistic) for critical operations
- Use transactions with appropriate isolation levels (SERIALIZABLE for critical sections)
- Implement idempotency keys to prevent duplicate processing of the same request
- Use atomic operations (compare-and-swap, database constraints) instead of check-then-act patterns
- Apply rate limiting to sensitive endpoints
- Use distributed locks (Redis, Zookeeper) for multi-server environments
- Ensure constant-time comparison for authentication to prevent timing side-channels
- Implement queue-based processing for operations requiring strict ordering
- Add unique constraints at the database level to prevent duplicate entries

## References

- [OWASP Testing Guide - Test for Process Timing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing)
- [CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)

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

