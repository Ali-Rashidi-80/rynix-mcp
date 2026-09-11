# Rynix CWE Honesty Matrix

Pattern-based static analysis and MCP probes — **not** a full taint analysis or autonomous exploit engine.

| CWE | Status | Rynix coverage |
|-----|--------|----------------|
| CWE-639 IDOR/BOLA | Implemented (probe) | `compare_role_response`, static `{id}` scoring |
| CWE-285 BFLA | Partial | `rbac_matrix`, `require_roles` detection |
| CWE-287 Auth | Partial | `auth_login`, missing Depends detection |
| CWE-798 Secrets | Implemented (static) | `secret_hits` in `analyze_repo` scan (pattern-based, not taint) |
| CWE-89 SQLi | Deferred | knowledge base only |
| CWE-79 XSS | Deferred | knowledge base only |
| CWE-918 SSRF | Deferred | active probe path validation only |

Cursor/Antigravity agent provides reasoning; Rynix provides evidence-class tools.
