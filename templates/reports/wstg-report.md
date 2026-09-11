# Penetration Test Report

| Field | Value |
|-------|-------|
| **Target** | {target} |
| **Engagement ID** | {engagement_id} |
| **Tester** | {tester} |
| **Date** | {date} |
| **Methodology** | OWASP WSTG v4.2 |

## Executive Summary

A penetration test was conducted against **{target}** following the OWASP Web Security Testing Guide (WSTG) methodology. This report documents all identified security findings with their severity, evidence, and remediation guidance.

### Finding Summary

| Severity | Count |
|----------|-------|
| Critical | {critical_count} |
| High | {high_count} |
| Medium | {medium_count} |
| Low | {low_count} |
| Informational | {info_count} |

## Scope

- **Target Application**: {target}
- **Testing Type**: Web Application Penetration Test
- **Methodology**: OWASP Web Security Testing Guide (WSTG) v4.2
- **Testing Period**: {date}

## Methodology

Testing was performed using the following WSTG categories:

1. Information Gathering (WSTG-INFO)
2. Configuration and Deployment Management (WSTG-CONF)
3. Identity Management (WSTG-IDNT)
4. Authentication (WSTG-ATHN)
5. Authorization (WSTG-ATHZ)
6. Session Management (WSTG-SESS)
7. Input Validation (WSTG-INPV)
8. Error Handling (WSTG-ERRH)
9. Cryptography (WSTG-CRYP)
10. Client-Side (WSTG-CLNT)

## Test Coverage

### Coverage Summary

| Category | Code | Completed | Skipped | N/A | Not Attempted | Coverage |
|----------|------|-----------|---------|-----|---------------|----------|
| Information Gathering | INFO | - | - | - | - | -% |
| Configuration | CONF | - | - | - | - | -% |
| Identity Management | IDNT | - | - | - | - | -% |
| Authentication | ATHN | - | - | - | - | -% |
| Authorization | ATHZ | - | - | - | - | -% |
| Session Management | SESS | - | - | - | - | -% |
| Input Validation | INPV | - | - | - | - | -% |
| Error Handling | ERRH | - | - | - | - | -% |
| Cryptography | CRYP | - | - | - | - | -% |
| Business Logic | BUSL | - | - | - | - | -% |
| Client-Side | CLNT | - | - | - | - | -% |
| API Testing | APIT | - | - | - | - | -% |
| **Overall** | | | | | | **-%** |

### Skipped Tests (with reasons)

<!-- Skipped tests with documented reasons are inserted here by generate_report -->

### Tests Not Attempted

<!-- List of test IDs that were not executed during this engagement -->

## Detailed Findings

<!-- Findings are inserted here by the generate_report tool, sorted by severity -->

## Recommendations

### Immediate Actions (Critical/High)
- Address all Critical and High findings immediately
- Prioritize findings that allow unauthorized access or data exposure

### Short-Term (Medium)
- Remediate Medium findings within the next sprint/release cycle
- Review and harden configurations

### Long-Term (Low/Informational)
- Address Low findings as part of ongoing security improvements
- Consider Informational findings for defense-in-depth hardening

---

*Report generated using Rynix MCP with OWASP WSTG methodology.*
