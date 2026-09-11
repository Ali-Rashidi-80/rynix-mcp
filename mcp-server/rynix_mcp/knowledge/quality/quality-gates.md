# Quality Gates Reference

Read this file when performing quality review at phase transitions.
The Quality Reviewer subagent should read this file and apply it to the current engagement context.

## Anti-Patterns to Catch

These are common mistakes that reduce pentest quality. Flag any you see:

1. **Premature N/A marking**: Marking tests as "not_applicable" when they could be tested with a different approach. Example: marking IDOR as N/A because "no API endpoints" when there ARE URL parameters with IDs.

2. **Copy-paste notes**: Multiple tests with identical or near-identical notes suggests the tester is not actually running the test steps.

3. **No endpoints listed**: A "completed" test with no endpoints_tested was likely rubber-stamped without actual testing.

4. **Skipping without alternatives**: Skipping a test without considering alternative approaches. Example: skipping hydra because "might lock out users" — try with a single known-bad password first to detect lockout.

5. **Zero findings in high-risk areas**: If Phase 4 (input validation) completes with zero findings on an application with user input, something is wrong. Either the testing was superficial or the application is genuinely well-hardened (which should be noted explicitly).

6. **Tool-only testing**: Running sql-injection-cli but not doing manual SQLi testing. Tools miss context-specific injection points. Always do manual testing first.

7. **Ignoring conditional tests**: SHOULD-priority tests with met conditions are being silently skipped instead of tracked as "skipped" with a reason.

8. **Broken auth = give up**: If OAuth/authentication is broken, do NOT give up. Try alternative grants, direct token endpoints, JWT manipulation, API key access, etc. See Phase 2 brainstorming.

9. **Shallow CSRF testing**: Checking for CSRF tokens but not actually testing if they're validated. A present-but-not-validated token is worse than no token (false sense of security).

10. **Single payload testing**: Trying one XSS payload and moving on. Different contexts need different payloads. Try at least 3 context-appropriate payloads before marking as not vulnerable.

11. **Auth failure cascade**: Authentication fails and >50% of tests are marked N/A without exhausting all auth alternatives (password grant, client_credentials, PKCE script, headless browser, manual token from user). The correct response to auth failure is escalation, not capitulation. See `templates/cross-domain-auth-guide.md` for the mandatory escalation procedure.

12. **N/A instead of skipped**: Using `not_applicable` when the correct status is `skipped`. A test is N/A only when the **feature being tested does not exist** (e.g., no file upload = BUSL-08 N/A). A test is `skipped` when the feature **exists but cannot be tested** (e.g., auth failure prevents IDOR testing on an endpoint that has IDs).

13. **Missing register_scope()**: Creating manual text files or notes instead of calling `register_scope()` MCP tool. All domains must be registered via the tool for proper report generation and finding grouping.

14. **Tool results not ingested**: Background CLI tools completed but their output was never read or incorporated. Every tool launched in background MUST have its output file read and findings integrated into the endpoint map and logged findings.

15. **Quality Reviewer never spawned**: Phase gate check called but Quality Reviewer subagent not spawned at the phase transition. The reviewer is mandatory at every phase transition — it catches gaps the automated gates miss.

16. **Skipping Final Judge review**: Generating the report and presenting it to the user without running the Final Judge. The Judge is a zero-context agent that catches issues in-session reviewers miss due to shared context bias. Most common finds: N/A cascades from auth failure, tools marked "run" but output never ingested, endpoints in the map that were never tested, and finding severity inconsistencies.

17. **Primary-domain-only testing**: In multi-domain engagements, testing only the primary domain and marking tests N/A because "the primary is a static SPA" — while ignoring API gateways, auth providers, and backend services that have server-side processing. EVERY in-scope domain is an independent attack surface. N/A must be justified per-domain, not just for the primary.

18. **Empty tool output counted as "run"**: A tool that produces empty output files, has proxy issues, or shows "may have had issues" in notes is NOT a successful run. Re-run the tool, investigate the issue, or run it against a different domain. Tools with genuinely no findings should note "Tool ran successfully against X endpoints, no vulnerabilities found" — not just "output file empty".

19. **Finding duplication**: The same underlying vulnerability logged as 3+ separate findings under different WSTG test IDs. Example: CORS misconfiguration logged under CONF-13, CLNT-07, and SESS-09. Consolidate into ONE finding and reference all test IDs. Missing headers logged under CONF-07, CONF-12, CONF-14, and CLNT-09. Consolidate per domain.

20. **Simultaneous phase gate checks**: Calling phase_gate_check() for multiple phases within seconds of each other (e.g., phases 3, 4, 5 all checked at the same timestamp). This indicates the phases were batched/rushed rather than properly executed with testing, review, and Quality Reviewer between each.

21. **Missing chaining analysis**: Finding multiple related vulnerabilities but not analyzing how they combine. No lockout + No MFA = critical credential attack chain. CORS + No CSP + Clickjacking = cross-origin exploit chain. Open redirect + Cookie injection = auth token theft. Each combination must be explicitly evaluated and noted in findings.

22. **TLS findings not logged**: testssl.sh reports Grade A- or below (missing TLS 1.3, weak ciphers, forward secrecy gaps) but no finding is logged. Any testssl.sh result below A+ should be reviewed for findings.

23. **Missing Quality Reviewer between phases**: Phase gate checks present but no Quality Reviewer subagent spawned between them. The Quality Reviewer is mandatory at every phase transition — it catches gaps the automated gates miss. Skipping it is a process failure.


## Phase 0: Application Discovery & Mapping

### Quality Checklist
- [ ] Pre-flight connectivity check completed
- [ ] All 10 Tier 1 tools launched (nmap, web-crawler, fuzz-cli, http-probe-cli, template-scan, tech-fingerprint-cli, gau, nikto, feroxbuster, wapiti)
- [ ] track_probe_step called for each launched tool
- [ ] Homepage HTML parsed for links, forms, scripts, meta tags, comments
- [ ] robots.txt, sitemap.xml, security.txt, crossdomain.xml checked
- [ ] Recursive crawling done to depth 2-3
- [ ] JavaScript files analyzed for API endpoints
- [ ] Tech stack identified from headers/cookies/error pages
- [ ] Tech-specific wordlist loaded for fuzz-cli
- [ ] Tool results ingested (web-crawler, fuzz-cli, gau, http-probe-cli, tech-fingerprint-cli, template-scan) — empty outputs investigated
- [ ] **Tool output quality verified**: no tools with empty output counted as "run" without investigation
- [ ] Complete endpoint map built and presented to user
- [ ] **Endpoint map organized per domain** with server-side processing capability noted per domain
- [ ] Per-endpoint test matrix constructed **with endpoints from ALL in-scope domains**
- [ ] If login redirects to external domain: cross-domain auth detected and documented
- [ ] All in-scope domains registered with `register_scope()`
- [ ] Cookie jar created and tested with valid session (if cross-domain auth)
- [ ] **Discovery tools run against ALL in-scope domains** (not just primary) — at minimum: fuzz-cli, template-scan per domain

### Brainstorming Prompts
- Are there any subdomains? Check DNS records, certificate transparency logs (crt.sh).
- Did you find API documentation endpoints? (/swagger, /api-docs, /graphql, /openapi.json, /redoc)
- Are there WebSocket endpoints? Check for ws:// or wss:// in JS files.
- Check common admin paths that fuzz-cli might miss: /admin, /manager, /administrator, /wp-admin, /phpmyadmin, /adminer, /debug, /_debug
- Look for development/staging indicators: X-Debug headers, verbose errors, test accounts in comments.
- Are there CDN or WAF indicators? (Cloudflare, Akamai, AWS WAF) This affects payload delivery strategy.
- Check for API versioning (/api/v1/, /api/v2/) — old versions may lack security controls.
- Did nmap reveal any non-standard ports? 8080, 8443, 3000, 9090, 4443?


## Phase 1: Information Gathering

### Quality Checklist
- [ ] All 7 MUST INFO tests completed (01-07)
- [ ] SHOULD tests tracked (completed, skipped, or N/A with reason)
- [ ] template-scan results reviewed for prioritization
- [ ] Search engine dorking attempted (site:, filetype:, inurl:)
- [ ] Web server fingerprinted (type, version if possible)
- [ ] All entry points identified and documented
- [ ] Execution paths mapped (authentication flows, navigation flows)

### Brainstorming Prompts
- Check Wayback Machine (web.archive.org) for old versions of the site that may reveal removed endpoints, old tech stack, or sensitive files.
- Search GitHub/GitLab for the target domain — leaked credentials, config files, or source code.
- Check certificate transparency logs (crt.sh) for subdomain enumeration.
- Try common API paths: /api, /rest, /graphql, /v1, /v2
- Search for the target in Shodan/Censys for exposed services.
- Check for email addresses in WHOIS data or on the website for social engineering targets.

### Common Missed Opportunities
- Dismissing "Informational" findings — version disclosure and technology fingerprinting are valid findings that aid reconnaissance.
- Not checking for HTTP vs HTTPS — does the site serve on port 80? Is there a redirect? Is it vulnerable to MITM during redirect?
- Missing comment analysis — HTML comments often contain developer notes, internal URLs, credentials, or TODO items.


## Phase 2: Configuration & Deployment Testing

### Quality Checklist
- [ ] All 11 MUST CONF tests completed (01-07, 11-14)
- [ ] SHOULD tests tracked (08, 09, 10 — at minimum as N/A with reason)
- [ ] cors-probe via http_probe (or tracked as skipped with reason)
- [ ] Security headers checked on EVERY domain/subdomain, not just one
- [ ] HTTP methods tested (OPTIONS, TRACE, PUT, DELETE, PATCH)
- [ ] Backup/unreferenced files searched with tech-specific extensions
- [ ] CORS tested with multiple origins (evil.com, null, subdomain)
- [ ] CSP analyzed for bypasses, not just presence

### Brainstorming Prompts
- Is the CSP actually effective? Check for unsafe-inline, unsafe-eval, wildcard sources, data: URIs. Use csp-evaluator.withgoogle.com
- CORS: test with subdomain origins (sub.target.com), null origin, and HTTP vs HTTPS protocol switch.
- Did you test for TRACE method? If enabled, it can be chained with XSS for cross-site tracing (XST) to steal HttpOnly cookies.
- Check for exposed .git directory: /.git/HEAD, /.git/config
- Check for exposed environment files: /.env, /config.yml, /application.properties
- Are there debug endpoints? /debug, /actuator, /health, /metrics, /env, /configprops, /trace, /dump
- Test for HTTP request smuggling if behind a reverse proxy/CDN.

### Alternative Approaches When Blocked
- **OAuth callback broken?** Try:
  1. Direct token endpoint: POST /token with grant_type=client_credentials
  2. Password grant: POST /token with grant_type=password&username=X&password=Y
  3. Implicit grant: Change response_type=token in auth URL
  4. Device code flow: POST /devicecode
  5. Look for API keys in JavaScript files as alternative auth
  6. Try accessing API endpoints directly with a crafted JWT
  7. Check the OIDC well-known config for all supported grant_types
- **WAF blocking payloads?** Try:
  1. Case alternation: `<ScRiPt>` vs `<script>`
  2. Double encoding: `%253Cscript%253E`
  3. Alternative encodings: UTF-7, UTF-16, null bytes
  4. Comment injection: `<!--><script>alert(1)</script>`
  5. Use non-standard HTTP methods to bypass method-based WAF rules
- **Rate limited?** Try:
  1. X-Forwarded-For header rotation
  2. Different IP via proxy chains
  3. Slower request rate with jitter
  4. Different User-Agent strings


## Phase 3: Identity, Authentication, Authorization & Session Testing

### Quality Checklist
- [ ] All ATHN MUST tests tracked (01-04, 07, 11)
- [ ] All ATHZ MUST tests tracked (01-04)
- [ ] All SESS MUST tests tracked (01-05, 09)
- [ ] IDNT tests tracked (at minimum as N/A if no identity management)
- [ ] hydra tracked (run, skipped, or N/A with reason)
- [ ] jwt_tool tracked (run, skipped, or N/A with reason)
- [ ] CSRF tested on EVERY state-changing endpoint, not just one
- [ ] IDOR tested with at least 3 alternate IDs per endpoint
- [ ] Session cookie attributes checked (HttpOnly, Secure, SameSite, Path)
- [ ] Session fixation tested (set token before auth, check if it persists)
- [ ] If SSO/OIDC: well-known configuration retrieved and analyzed
- [ ] If SSO: all supported grant types tested (password, client_credentials, device_code, implicit)
- [ ] If SSO: token exchange endpoint tested directly
- [ ] Cross-domain cookie scope analyzed (auth cookies not leaking to app domain or vice versa)
- [ ] If auth failed: Authentication Failure Escalation Procedure followed (all 6 levels attempted)
- [ ] Quality Reviewer subagent spawned and at least 2 suggestions acted on
- [ ] IDNT-04 (account enumeration) tested on login form even without auth

### Brainstorming Prompts
- JWT: Did you test alg:none? RS256->HS256 confusion? Key extraction from /jwks endpoint? JWT with expired timestamps?
- Can you register a new user? If so, test horizontal privilege escalation by accessing resources belonging to other users.
- Password reset: can you enumerate users by comparing reset request timing or response differences?
- Session: after logout, is the old session token still valid?
- IDOR: try negative IDs (-1), zero (0), very large numbers (999999999), UUIDs from other contexts, and string values where integers are expected.
- Check if API endpoints enforce the same auth as web endpoints (common gap).
- Test for mass assignment: can you set admin=true or role=admin when creating/updating your user profile?
- Test concurrent sessions — can the same user log in twice? Does the first session get invalidated?

### Common Missed Opportunities
- Testing CSRF only on the login form — test it on ALL state-changing endpoints (profile update, password change, settings, data modification).
- Not testing horizontal privilege escalation — only testing vertical.
- Not checking if session tokens change after login (session fixation).
- Not testing concurrent sessions.


## Phase 4: Input Validation Testing

### Quality Checklist
- [ ] At least 4 of 6 core tests actually COMPLETED (not just N/A) — gate enforced
- [ ] **Multi-domain check**: Core INPV tests evaluated against ALL in-scope domains with server-side processing, not just the primary domain
- [ ] **N/A justification**: Each N/A test has per-domain justification confirming no domain has applicable endpoints
- [ ] Every endpoint in the test matrix tested for applicable vuln classes
- [ ] CLI tools launched against ALL domains with server-side endpoints (sql-injection-cli, dalfox, commix, sstimap, crlfuzz, smuggler)
- [ ] track_probe_step called for each Phase 4 tool with per-domain notes
- [ ] Tool results ingested and verified manually (empty outputs investigated and re-run)
- [ ] Subagents used for parallel testing of different vuln classes
- [ ] Each parameter tested, not just the first one in each endpoint
- [ ] Both GET and POST parameter locations tested
- [ ] Filter bypass attempted where initial payloads were blocked
- [ ] Vulnerability chaining reviewed for all findings (see chaining analysis mandate)
- [ ] If >50% tests N/A: auth failure escalation completed (all 6 levels attempted)
- [ ] Quality Reviewer subagent spawned and at least 2 suggestions acted on
- [ ] Unauthenticated endpoints tested for input validation even if auth failed
- [ ] Pipelined execution followed: exploitation queues created, validated, and processed
- [ ] Deliverables saved (xss_analysis, sqli_analysis, ssrf_ssti_analysis)

### Brainstorming Prompts
- Did you test SECOND-ORDER injection? Payload stored in one endpoint, triggered from another (e.g., username stored in profile, displayed in admin panel without sanitization).
- HTTP parameter pollution: send same param twice. Does the app use first, last, or both? This bypasses WAFs.
- Did you test headers as injection points? Host, Referer, X-Forwarded-For, User-Agent, Accept-Language.
- For file upload: test .svg (XSS), .html (XSS), .php/.jsp/.aspx (RCE), .xml (XXE), polyglot files (GIFAR).
- Test for prototype pollution if the backend is Node.js: `__proto__[isAdmin]=true`
- Check for SSTI in error pages, PDF generators, and email templates — not just search results.
- SSRF: test DNS rebinding, IPv6 (::1), decimal IP, cloud metadata (169.254.169.254), redirect chains.
- Test CRLF injection in any endpoint that sets headers based on input (especially redirect URLs and cookie values).

### Common Missed Opportunities
- Only testing the search parameter and missing injection in: User-Agent, Referer, Cookie values, Accept-Language, X-Forwarded-For.
- Missing blind SSRF because you only checked for reflected responses.
- Not testing file path traversal with null bytes (%00) on older systems.
- Missing out-of-band (OOB) techniques for blind injection.
- Not testing for Mass Assignment on API endpoints that accept JSON bodies.


## Phase 5: Error Handling, Cryptography, Business Logic, Client-Side & API

### Quality Checklist
- [ ] ERRH-01 and ERRH-02 completed (always testable)
- [ ] CRYP-01 completed (TLS testing via testssl.sh)
- [ ] BUSL-01, BUSL-02, BUSL-06 completed (minimum business logic tests)
- [ ] CLNT-01, CLNT-02, CLNT-07, CLNT-09, CLNT-13 completed (MUST client tests)
- [ ] testssl.sh tracked (run, skipped, or N/A)
- [ ] graphql-cop tracked (run or N/A)
- [ ] websocat tracked (run or N/A)
- [ ] All SHOULD tests either completed or tracked as N/A with reason
- [ ] Vulnerability chaining review performed across ALL findings
- [ ] Quality Reviewer subagent spawned for final review
- [ ] ERRH and CLNT tests completed (these are always testable without auth)

### Brainstorming Prompts
- Clickjacking: is X-Frame-Options set? If CSP frame-ancestors is used, does it allow framing from attacker-controlled domains?
- Open redirect: test with //evil.com, \/evil.com, /\evil.com, and protocol-relative URLs. Also test redirect parameters in login flow.
- DOM XSS: look for document.location, document.referrer, document.URL, window.name as sources, and innerHTML, eval(), document.write() as sinks.
- Check for WebSocket origin validation — can you connect from evil.com?
- localStorage: does the app store JWT tokens in localStorage? This makes them accessible to XSS attacks (unlike HttpOnly cookies).
- Business logic: can you change item prices? Apply discount codes multiple times? Skip steps in multi-step workflows? Access resources after subscription expires?
- TLS: check for TLS 1.0/1.1 support, weak cipher suites, expired certificates, missing certificate pinning.
- If GraphQL: test introspection, batching attacks, deep query DoS, field-level authorization bypass.


## Phase 6: Coverage Verification & Reporting

### Quality Checklist
- [ ] get_coverage() called and reviewed
- [ ] get_tool_coverage() called and reviewed
- [ ] All required categories have >0% coverage
- [ ] Overall test coverage >= 40%
- [ ] All mandatory tools tracked
- [ ] All conditional tools tracked as N/A (if condition not met)
- [ ] **Finding deduplication completed**: same root cause + same domain = one finding (see CLAUDE.md Rule 6)
- [ ] **Vulnerability chaining analysis completed** (see CLAUDE.md Rule 8): explicit list of finding combinations evaluated
- [ ] All phase gate checks passed (no FAIL results)
- [ ] **Tool output quality verified**: no tools marked "run" with empty output or proxy issues
- [ ] **Quality Reviewer spawned at every phase transition** (Phases 0-5)

### Final Review Questions
- Are there any findings that should be upgraded in severity due to chaining potential?
- Are there any "Informational" findings that should be "Low" because they aid exploitation of other vulnerabilities?
- Did you check for findings from CLI tools that you haven't logged yet?
- Is the endpoint test matrix fully populated (every cell tested, N/A, or skipped with reason)?
- Are there endpoints discovered late in testing that were not tested for all vulnerability classes?
- **Were ALL in-scope domains tested** (not just the primary)?
- **Are there duplicate findings** that should be consolidated? (same CORS issue logged 3 times, same missing headers logged 4 times)
- **Did testssl.sh findings get logged?** (Grade A- or below = at least an Informational finding)
- **Were Phase 4 tools run against all domains with server-side processing?**


## Phase 7: Final Judge Review & Remediation

### Quality Checklist
- [ ] Final Judge agent spawned with ZERO session context
- [ ] Final Judge prompt contained NO information about testing difficulties or decisions
- [ ] `get_judge_data()` called by the Judge to retrieve full analysis packet
- [ ] Report file (`engagements/{eid}/report.md`) read by the Judge
- [ ] Anti-patterns from this file (quality-gates.md) checked by the Judge
- [ ] Raw tracking data (`server/data/tracking/{eid}.json`) inspected for quality indicators
- [ ] Verdict received (PASS, FAIL, or CONDITIONAL_PASS)
- [ ] If FAIL: ALL critical actions executed
- [ ] If CONDITIONAL_PASS: ALL HIGH and MEDIUM recommended actions executed
- [ ] `track_judge_review()` called with verdict and action counts
- [ ] Report regenerated if any changes were made during remediation
- [ ] Final Judge section appears in the regenerated report

### Final Judge Analytical Checklist (for the Judge agent itself)
- [ ] Coverage integrity verified (no rubber-stamped tests, no ghost completions)
- [ ] N/A cascade analysis completed (auth failure root cause identified if present)
- [ ] Finding quality assessed (evidence completeness, severity consistency, chaining)
- [ ] Tool utilization verified (run tools had output ingested, skipped tools have genuine reasons)
- [ ] Missed attack surface identified (endpoints in map but not in test tracking)

### Common Issues the Final Judge Catches
1. **Auth failure cascade marked as N/A instead of skipped** — 15+ tests marked N/A because OAuth login failed, but unauthenticated endpoints were never tested for input validation
2. **Tool output not ingested** — template-scan, sql-injection-cli, or dalfox run in background but output files never read; findings_count stays at 0
3. **Severity inconsistency** — Missing HSTS on the main portal rated as Low, but the same issue on a subdomain rated as Medium
4. **Endpoint map orphans** — Endpoints discovered during Phase 0 crawling that never appear in any test's endpoints_tested
5. **Rubber-stamped tests** — Multiple tests with identical 10-word notes and no endpoints, suggesting they were tracked without actual testing
6. **Missing chaining** — XSS found on a page with no CSP, but severity not upgraded; SQLi found but no attempt to extract credentials
7. **Conditional tools wrongly marked N/A** — jwt_tool marked N/A but the tracking data shows JWT tokens in session cookies
8. **Primary-domain-only testing** — Multi-domain engagement but all INPV tests show only the primary domain in endpoints_tested. API gateways, auth providers, and backend services with server-side processing were never tested for input validation.
9. **Finding duplication** — Same CORS vulnerability logged under 3 different WSTG test IDs (CONF-13, CLNT-07, SESS-09). Same missing headers logged under 4 test IDs. Report has 21 findings but only ~14 unique issues.
10. **Empty tool output accepted** — 5 tools produced empty output files but were counted as "run". Effective tool coverage is 22%, not 41%.
11. **Simultaneous phase gates** — Phases 3, 4, 5 all gate-checked within 1 second, indicating they were batched rather than properly executed with Quality Reviewer between each.
12. **testssl.sh findings not logged** — Grade A- with missing TLS 1.3 and forward secrecy gaps but no finding created.
