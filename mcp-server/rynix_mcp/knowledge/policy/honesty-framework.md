# Anti-Hallucination Honesty Framework

**This section is MANDATORY for all testing and exploitation agents.**

## Core Rules

1. **No exploit = no finding.** If you cannot demonstrate the vulnerability with actual evidence (request + response showing exploitation), do NOT log it as EXPLOITED.

2. **Distinguish observation from proof.**
   - "The parameter reflects input" is an OBSERVATION (potential)
   - "JavaScript executed in the browser" is PROOF (exploited)
   - "The SQL error message appeared" is an OBSERVATION (potential)
   - "I extracted the admin password hash" is PROOF (exploited)

3. **Never claim impact you didn't demonstrate.**
   - BAD: "This allows session hijacking" (without actually hijacking a session)
   - GOOD: "Reflected XSS confirmed — `document.cookie` accessible, demonstrating session theft risk"
   - BEST: "Reflected XSS confirmed — extracted session cookie value `abc123` via `document.cookie`"

4. **Report what you actually saw, not what you expected.**
   - If the payload was reflected but encoded: say "reflected but HTML-encoded — NOT exploitable in this context"
   - If sql-injection-cli found nothing: say "sql-injection-cli returned no injection points" — do NOT claim "the endpoint is not vulnerable to SQLi" (it may need manual testing)
   - If a tool timed out: say "tool timed out" — do NOT say "no vulnerabilities found"

5. **Use the three-tier classification honestly.**
   - **EXPLOITED**: You have L3+ proof. The vulnerability was actually demonstrated.
   - **POTENTIAL**: You have L1-L2 evidence. The vulnerability likely exists but exploitation was blocked (CSP, WAF, encoding).
   - **FALSE_POSITIVE**: After exhaustive bypass attempts (meeting exhaustion thresholds), the security control holds. This is NOT a finding.

## Forbidden Phrases

Never use these phrases in findings or test notes without the required evidence:

| Forbidden Phrase | Required Evidence |
|-----------------|-------------------|
| "JavaScript execution confirmed" | Actual JS output (alert fired, DOM changed, cookie accessed) |
| "Data extracted from database" | Actual data shown in response |
| "Command execution achieved" | Actual command output (id, whoami, hostname) |
| "Full RCE achieved" | Actual OS command output |
| "Session hijacked" | Actual session token captured and reused |
| "Authentication bypassed" | Access to protected resource without valid credentials |
| "File contents retrieved" | Actual file content in response |
| "Internal network accessed" | Actual internal service response data |

## When Uncertain

If you're not sure whether something is exploitable:

1. Log it as **POTENTIAL** with clear evidence of what you observed
2. Document what prevented full exploitation (WAF? CSP? encoding?)
3. Document what bypass techniques you attempted
4. Let the exploitation agent or Final Judge make the determination

**Honesty is more valuable than a long finding list.** A report with 3 confirmed vulnerabilities is better than one with 10 unverified claims.
