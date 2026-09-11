---
id: WSTG-BUSL-10
title: Test Payment Functionality
category: Business Logic
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test_Payment_Functionality
---

# WSTG-BUSL-10: Test Payment Functionality

## Summary

Payment functionality is a critical business logic area where vulnerabilities can directly result in financial loss. Common issues include price manipulation in client-side requests, negative quantity exploitation, currency confusion, race conditions in payment processing, coupon stacking abuse, and insufficient validation of payment callbacks from payment gateways. Testing payment logic requires careful verification that all financial calculations and validations occur server-side.

## Test Objectives

- Test for price manipulation in purchase requests
- Attempt negative quantity or negative amount exploitation
- Test currency confusion and conversion manipulation
- Identify race conditions in payment processing
- Verify payment gateway callback/webhook validation
- Test coupon and discount stacking logic

## Prerequisites

- Target application has payment/checkout functionality
- Docker pentest container capturing traffic
- Test payment credentials or sandbox environment available
- Understanding of the payment flow (direct processing vs. gateway redirect)

## Test Steps

### Step 1: Map the Payment Flow

**CLI Actions:**
Use `curl` to capture the complete payment flow from cart to confirmation. Document:

1. Cart creation and item addition
2. Price calculation (where does it occur?)
3. Discount/coupon application
4. Payment submission to gateway
5. Payment callback/webhook handling
6. Order confirmation

Identify which values are client-supplied vs. server-calculated.

### Step 2: Test Price Manipulation

**CLI Actions:**
Use `save to manual-review file` with the checkout request. Modify price-related parameters:

```
POST /api/checkout HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"items": [{"id": 1, "quantity": 1, "price": 0.01}], "total": 0.01}
```

```
POST /api/checkout HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

product_id=1&quantity=1&unit_price=0.01&subtotal=0.01&tax=0&total=0.01
```

Modify: `price`, `unit_price`, `subtotal`, `total`, `tax`, `shipping_cost`, `discount_amount`.

### Step 3: Test Negative Quantity and Amount

**CLI Actions:**
Use `curl` to submit negative values:

```
POST /api/cart/add HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"product_id": 1, "quantity": -1}
```

```
POST /api/checkout HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"items": [{"id": 1, "quantity": -5, "price": 99.99}], "total": -499.95}
```

Check if negative quantities create a credit to the account. Also test:
- Negative shipping costs
- Negative tax values
- Zero-value transactions

### Step 4: Test Currency Confusion

**CLI Actions:**
Use `curl` to manipulate currency parameters:

```
POST /api/checkout HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"total": 100.00, "currency": "IDR"}
```

```
POST /api/checkout HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"total": 100.00, "currency": "JPY"}
```

Test if changing the currency from USD to a weaker currency (IDR, VND) allows paying a fraction of the actual price.

### Step 5: Test Race Conditions in Payment

**CLI Actions:**
Use `fuzz-cli` to exploit race conditions in payment processing:

1. Apply a single-use coupon and simultaneously submit multiple checkout requests:

```
POST /api/checkout HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"cart_id": "CART001", "coupon": "50OFF", "payment_method": "card"}
```

Send 10 simultaneous requests. Check if the coupon is applied to multiple orders.

2. Test double-spend: submit payment twice simultaneously for the same cart.

### Step 6: Test Coupon and Discount Stacking

**CLI Actions:**
Use `curl` to test applying multiple coupons:

```
POST /api/cart/apply-coupon HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"coupon_code": "SAVE20"}
```

Then immediately:
```
POST /api/cart/apply-coupon HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"coupon_code": "WELCOME10"}
```

Test:
- Multiple coupon application
- Coupon applied after manual discount
- Coupon applied to already-sale items
- Same coupon applied twice

### Step 7: Test Payment Gateway Callback Manipulation

**CLI Actions:**
Use `curl` to forge payment gateway callbacks:

```
POST /api/payment/callback HTTP/1.1
Host: target.com
Content-Type: application/json

{"transaction_id": "TXN001", "status": "success", "amount": 0.01, "order_id": "ORD001"}
```

```
POST /api/payment/webhook HTTP/1.1
Host: target.com
Content-Type: application/json

{"event": "payment.success", "data": {"id": "ORD001", "paid": true}}
```

Check if the callback:
- Validates the signature/HMAC from the payment gateway
- Verifies the payment amount matches the order total
- Accepts callbacks from any source IP

### Step 8: Test Order Modification After Payment

**CLI Actions:**
Use `curl` to modify an order after payment confirmation:

```
PUT /api/order/ORD001 HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"items": [{"id": 999, "quantity": 10}], "shipping_address": "new_address"}
```

Check if items or quantities can be changed after payment is completed.

Use `rynix_plugin_run('template-scan')` to check for payment-related findings.

## Payloads

### Price Manipulation Values
```
0
0.00
0.01
-1
-99.99
-0.01
1
0.001
999999999
NaN
Infinity
null
```

### Quantity Manipulation Values
```
0
-1
-100
0.5
99999999
2147483647
-2147483648
NaN
```

### Currency Codes (low-value for manipulation)
```
IDR    (Indonesian Rupiah)
VND    (Vietnamese Dong)
IRR    (Iranian Rial)
KRW    (South Korean Won)
JPY    (Japanese Yen)
CLP    (Chilean Peso)
```

### Coupon Stacking Patterns
```
# Apply same coupon twice
SAVE20, SAVE20

# Apply multiple different coupons
SAVE20, WELCOME10, FREESHIP

# Apply percentage + fixed discount
50PERCENT, MINUS50

# Exceed 100% discount
SAVE50, SAVE50, SAVE50
```

### Payment Callback Forgery
```
{"status": "success", "amount": 0.01}
{"status": "completed", "verified": true}
{"event": "charge.succeeded", "paid": true}
```

## Detection Criteria

A finding should be logged when:
- Client-supplied prices are used for payment processing
- Negative quantities or amounts create credits or free orders
- Currency manipulation allows paying in weaker currency
- Race conditions allow double-use of single-use coupons or discounts
- Multiple coupons stack beyond intended limits
- Payment gateway callbacks are not properly validated (signature, amount, source)
- Orders can be modified after payment confirmation
- Zero-value transactions bypass payment entirely

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Price manipulation allows purchasing items for arbitrary low prices | Critical |
| Negative quantities create account credits | Critical |
| Payment gateway callbacks accepted without signature validation | Critical |
| Currency confusion allows paying in wrong currency at face value | High |
| Race condition allows double-spending coupons for significant discounts | High |
| Order modification after payment changes items delivered | High |
| Coupon stacking exceeds 100% discount (free items) | Medium |
| Zero-value transactions processed without payment | Medium |
| Race condition exists but financial impact is minimal | Medium |
| Minor rounding errors in price calculation | Low |
| All prices server-calculated, callbacks validated, no race conditions | Not a finding |

## Remediation

- Calculate all prices, totals, taxes, and discounts server-side only
- Never trust client-supplied financial values
- Validate that payment amounts match order totals before order confirmation
- Verify payment gateway callback signatures (HMAC, webhook secret)
- Restrict payment callback endpoints to gateway IP addresses
- Use database-level constraints to prevent negative quantities and amounts
- Implement atomic transactions for payment processing to prevent race conditions
- Enforce coupon rules server-side: single use, non-stackable, expiration dates
- Lock orders after payment confirmation to prevent modification
- Implement idempotency keys for payment operations
- Log all payment anomalies for fraud detection
- Validate currency codes against expected values

## References

- [OWASP Testing Guide - Test Payment Functionality](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test_Payment_Functionality)
- [CWE-472: External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
- [CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

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

