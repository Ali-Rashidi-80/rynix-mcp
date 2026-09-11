---
id: WSTG-BUSL-06
title: Testing for the Circumvention of Work Flows
category: Business Logic
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows
---

# WSTG-BUSL-06: Testing for the Circumvention of Work Flows

## Summary

Many applications implement multi-step workflows where each step must be completed in sequence: registration requires email verification before account activation, checkout requires cart review before payment, and loan applications require identity verification before approval. If the application does not enforce step ordering server-side, attackers can skip intermediate steps (like validation, payment, or approval) by directly accessing later steps in the process.

## Test Objectives

- Identify multi-step processes and their expected sequence
- Test if intermediate steps can be skipped by directly accessing later steps
- Verify that state is properly tracked and validated server-side
- Test if completed steps can be revisited and modified after proceeding

## Prerequisites

- Target application is accessible through Docker pentest container
- Multi-step workflows have been identified (checkout, registration, wizards)
- Valid session with access to the workflow

## Test Steps

### Step 1: Map the Complete Workflow

**CLI Actions:**
Use `curl` to capture the full multi-step workflow. Document each step:

Example checkout workflow:
1. `GET /cart` - View cart
2. `POST /checkout/shipping` - Enter shipping details
3. `POST /checkout/payment` - Enter payment details
4. `POST /checkout/review` - Review order
5. `POST /checkout/confirm` - Confirm and place order

Note the URLs, parameters, and any state tokens passed between steps.

### Step 2: Skip Intermediate Steps

**CLI Actions:**
Use `curl` to access later steps directly without completing earlier ones:

Skip shipping and payment, go directly to confirmation:
```
POST /checkout/confirm HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"order_id": "ORD001"}
```

Skip email verification and access authenticated features:
```
GET /dashboard HTTP/1.1
Host: target.com
Cookie: session=<session_from_registration>
```

Skip payment step and go to order completion:
```
POST /checkout/complete HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"order_id": "ORD001", "status": "paid"}
```

### Step 3: Modify Step Sequence

**CLI Actions:**
Use `save to manual-review file` to test out-of-order step execution:

1. Complete Step 1, skip Step 2, complete Step 3
2. Complete Step 3 first, then Step 1
3. Complete Step 1, complete Step 3, then try Step 2

```
POST /checkout/review HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"shipping_address": "modified_address", "step": 3}
```

### Step 4: Modify Data After Validation Step

**CLI Actions:**
Use `curl` to go back and modify data after it has been validated:

1. Complete Steps 1-3 (including validation)
2. Go back to Step 1 and modify critical data (price, quantity)
3. Proceed directly to the final confirmation step

```
POST /checkout/shipping HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"address": "new_address", "order_id": "ORD001"}
```

Then immediately:
```
POST /checkout/confirm HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"order_id": "ORD001"}
```

Check if the modified data is used without re-validation.

### Step 5: Manipulate Workflow State Parameters

**CLI Actions:**
Use `curl` to tamper with state-tracking parameters:

```
POST /checkout/confirm HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

step=5&state=confirmed&validated=true&payment_complete=true
```

```
POST /application/approve HTTP/1.1
Host: target.com
Content-Type: application/json

{"application_id": "APP001", "current_step": "final_review", "all_checks_passed": true}
```

Use `curl --data-urlencode` to properly encode parameters when needed.

### Step 6: Test Parallel Workflow Instances

**CLI Actions:**
Use `curl` to start two workflow instances and mix their steps:

Instance A: Start checkout, reach payment step
Instance B: Start checkout with different items/prices

Use the state token from Instance A's payment step with Instance B's cart:

```
POST /checkout/confirm HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"session_state": "<state_from_instance_A>", "cart_id": "<cart_from_instance_B>"}
```

Use `rynix_plugin_run('template-scan')` to check for workflow-related findings.

## Payloads

### Step Skipping URLs
```
# Direct access to final steps
/checkout/confirm
/checkout/complete
/order/place
/application/approve
/registration/activate
/wizard/finish
/process/finalize

# Step parameter manipulation
step=final
step=99
step=-1
current_step=complete
workflow_state=approved
```

### State Parameter Manipulation
```
validated=true
verified=true
payment_complete=true
approved=true
step_completed=all
checks_passed=true
email_verified=true
identity_confirmed=true
```

### Workflow Bypass Patterns
```
# Skip verification
Register -> (skip email verify) -> Login -> Dashboard

# Skip payment
Cart -> Shipping -> (skip payment) -> Confirm -> Order placed

# Skip approval
Submit application -> (skip review) -> Approved

# Skip identity check
Login -> (skip MFA) -> Access protected resource
```

## Detection Criteria

A finding should be logged when:
- Final workflow steps are accessible without completing intermediate steps
- Skipping steps results in completing an action (order placed, account activated) without required validation
- State parameters can be manipulated to indicate completed steps
- Data modified after a validation step is used without re-validation
- Mixing state between parallel workflow instances succeeds
- Multi-step processes do not enforce server-side step ordering

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Payment step can be skipped in checkout process | High |
| Identity verification can be bypassed in onboarding | High |
| Approval workflow steps can be skipped to self-approve | High |
| Email verification can be skipped for account activation | Medium |
| Cart items/prices can be modified after review step | Medium |
| Workflow state parameters can be manipulated to advance steps | Medium |
| Steps can be revisited but data is re-validated | Low |
| Out-of-order access detected and rejected by server | Not a finding |

## Remediation

- Track workflow state server-side using session data, not client-supplied parameters
- Validate at each step that all previous steps have been completed and validated
- Re-validate all data at the final step, not just data from the current step
- Use cryptographically signed state tokens that cannot be forged
- Implement step-locking: once a step is passed, previous steps cannot be modified
- Invalidate workflow state if data changes require re-validation
- Set timeouts on incomplete workflows to prevent indefinite state manipulation
- Log and alert on out-of-order step access attempts
- Use database transactions to ensure workflow atomicity

## References

- [OWASP Testing Guide - Circumvention of Work Flows](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows)
- [CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
- [CWE-372: Incomplete Internal State Distinction](https://cwe.mitre.org/data/definitions/372.html)

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

