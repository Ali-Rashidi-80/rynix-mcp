# OWASP Static Audit Prompt

Use this prompt for **read-only** pre-release API security passes inside Cursor (auditor mode — no code writes).

## Scope

```
Audit security without any write:
Scope: all routes under {API_ROOT}
Checklist: OWASP Top 10 web (A01–A10)
For each finding provide:
- severity: critical/high/medium/low + rationale
- evidence: exact file:line
- exploit sketch (no full malicious payload)
- minimal remediation diff suggestion
Output: single table + 3-line executive summary (subagent-friendly)
```

## Workflow

1. Run `analyze_repo` + `high_risk_surfaces` with the target profile.
2. Cross-check live behavior with `scope_check` → `http_probe` / `compare_role_response` when authorized.
3. Record verified issues via `record_finding`; export with `export_report` (markdown + JSON + SARIF).

## Notes

- Prefer mirror/staging (`127.0.0.1`) until production scope is explicitly approved.
- Static hints (secrets, taint sinks) are triage signals — confirm before escalating severity.
