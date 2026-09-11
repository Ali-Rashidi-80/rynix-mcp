---
id: WSTG-BUSL-01
title: Test Business Logic Data Validation
category: Business Logic
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation
---

# WSTG-BUSL-01: Test Business Logic Data Validation

## Summary

Business logic data validation flaws occur when the application relies solely on client-side validation or fails to enforce server-side business rules on input data. Attackers can bypass client-side checks by intercepting and modifying requests, submitting values outside expected ranges, or providing data in unexpected formats. This can lead to financial loss, data corruption, privilege escalation, or circumvention of business constraints.

## Test Objectives

- Identify client-side validation that is not enforced server-side
- Submit data outside expected boundaries and ranges
- Test negative values, zero values, and extreme values
- Bypass data type restrictions by manipulating request parameters
- Test for missing server-side validation of business rules

## Prerequisites

- Target application is accessible through Docker pentest container
- Application forms and input points have been identified
- Understanding of the application's business rules and expected data constraints

## Test Steps

### Step 1: Identify Client-Side Validation Controls

**CLI Actions:**
Use `curl` to fetch forms and pages with input fields:

```
GET /order/create HTTP/1.1
Host: target.com
```

Analyze HTML responses for client-side validation:
- `maxlength`, `min`, `max`, `pattern` attributes on input fields
- JavaScript validation functions
- Disabled or hidden form fields
- Dropdown menus and radio buttons that restrict choices

### Step 2: Bypass Client-Side Validation with Modified Requests

**CLI Actions:**
Use `save to manual-review file` to capture a valid form submission, then modify values to bypass client-side restrictions:

```
POST /order/create HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

quantity=99999&price=0.01&product_id=1&discount_code=FAKE
```

Test each field with:
- Values exceeding `maxlength`
- Values below `min` or above `max`
- Values violating `pattern` restrictions
- Characters not allowed by client-side filters

### Step 3: Test Boundary Values

**CLI Actions:**
Use `curl` to submit boundary and edge-case values:

```
POST /transfer HTTP/1.1
Host: target.com
Content-Type: application/json

{"amount": 0}
```

```
POST /transfer HTTP/1.1
Host: target.com
Content-Type: application/json

{"amount": -100}
```

```
POST /transfer HTTP/1.1
Host: target.com
Content-Type: application/json

{"amount": 999999999999}
```

```
POST /transfer HTTP/1.1
Host: target.com
Content-Type: application/json

{"amount": 0.001}
```

Use `save to manual-review file` to iterate through boundary values for each numeric field.

### Step 4: Test Data Type Manipulation

**CLI Actions:**
Use `curl` to submit unexpected data types:

```
POST /api/order HTTP/1.1
Host: target.com
Content-Type: application/json

{"quantity": "abc", "price": true, "product_id": null}
```

```
POST /api/order HTTP/1.1
Host: target.com
Content-Type: application/json

{"quantity": [1,2,3], "price": {"amount": 0}, "product_id": -1}
```

Test what happens when:
- String is sent where number is expected
- Array is sent where scalar is expected
- Object is sent where string is expected
- Null is sent for required fields

### Step 5: Test Hidden and Read-Only Field Manipulation

**CLI Actions:**
Use `curl` to modify hidden fields and read-only values:

```
POST /checkout HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

item_id=1&quantity=1&price=0.01&total=0.01&currency=USD&role=admin
```

Add parameters that may be accepted but not present in the form:
- `role`, `is_admin`, `user_type`, `privilege_level`
- `price`, `total`, `discount`, `tax`
- `user_id`, `account_id`, `owner_id`

### Step 6: Test Business Rule Violations

**CLI Actions:**
Use `curl` to test business-specific constraints:

```
POST /booking HTTP/1.1
Host: target.com
Content-Type: application/json

{"check_in": "2020-01-01", "check_out": "2019-12-31"}
```

Test scenarios:
- End date before start date
- Booking in the past
- Overlapping reservations
- Exceeding maximum allowed quantities
- Using expired promotions

Use `rynix_plugin_run('template-scan')` to check if template-scan has identified parameter manipulation vulnerabilities.

## Payloads

### Numeric Boundary Values
```
0
-1
-0.01
0.001
0.00
1
100
999999999
9999999999999999
-999999999
2147483647    (INT_MAX)
2147483648    (INT_MAX + 1)
-2147483648   (INT_MIN)
-2147483649   (INT_MIN - 1)
1e308         (near DOUBLE_MAX)
NaN
Infinity
-Infinity
```

### String Boundary Values
```
(empty string)
(single space)
(8000+ character string)
null
undefined
true
false
0
```

### Type Confusion Values
```
[]
{}
[null]
{"key": "value"}
true
false
0
""
```

### Hidden Parameter Names to Test
```
role
admin
is_admin
user_type
privilege
access_level
price
total
discount
tax
user_id
account_id
debug
test
internal
```

## Detection Criteria

A finding should be logged when:
- Server accepts values outside defined business rules (negative prices, impossible dates)
- Client-side validation is not enforced server-side
- Hidden field manipulation changes application behavior (price, role, permissions)
- Integer overflow or underflow causes unexpected behavior
- Null or empty values bypass required field validation
- Data type confusion causes errors or unexpected processing

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Price or financial value manipulation accepted by server | High |
| Role or privilege escalation via hidden parameter manipulation | High |
| Negative quantities or amounts processed, causing financial loss | High |
| Business rule bypass allowing unauthorized actions | Medium |
| Boundary values cause application errors but no direct exploitation | Medium |
| Client-side-only validation on non-sensitive fields | Low |
| Type confusion causes verbose errors but no business impact | Low |
| All client-side validation properly enforced server-side | Not a finding |

## Remediation

- Implement server-side validation for all input fields, mirroring and exceeding client-side rules
- Validate data types, ranges, formats, and business rules on the server
- Use allowlists for expected values rather than denylists
- Implement proper type checking before processing input
- Never trust hidden fields or client-side calculated values (recalculate server-side)
- Enforce minimum and maximum value constraints in the business logic layer
- Log and alert on submissions that violate business rules (may indicate attack)
- Use parameterized database queries to prevent type confusion at the data layer

## References

- [OWASP Testing Guide - Business Logic Data Validation](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

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

