# Rynix MCP Design (v1)

Rynix is a **local-first security MCP host**: Cursor (Rāy) reasons; Rynix tools execute scoped probes, static analysis, and evidence export without external LLM API keys.

## Layers

| Layer | Role |
| --- | --- |
| `rynix-scan` (Rust) | Repo static analysis: routes, RBAC hints, secrets, taint sinks |
| `rynix-mcp` (Python) | MCP server, session store, probes, plugins, SARIF/report export |
| Knowledge | Bundled WSTG + technique + vuln-class playbooks |
| Profiles | Stack-specific scan/probe config (`profiles/*.toml`) |

## Tool groups (24)

- **Static (8):** analyze, routes, RBAC, risk surfaces, brief, profiles, health, openapi stub
- **Active (9):** scope, probes, auth, access compare, findings, export, stealth gate, IDOR matrix
- **Knowledge (2):** technique guide, WSTG test (+ `search_knowledge` helper in library)
- **Plugins (3):** list, health, `rynix_plugin_run`
- **Playbook (1):** `agent_engagement_playbook`
- **IDOR matrix (1):** `run_idor_matrix`

## Integration patterns

1. **Default-deny scope** — `scope_check` before any live probe; repo `rynix.scope.toml` gates `allow_live`.
2. **Session evidence** — findings, audit log, and artifacts keyed by `session_id`.
3. **Plugin sidecars** — template-scan/wstg/engagement/agent-guides merge into the same session + SARIF export.
4. **Bundled assets** — wheel ships `profiles/`, `plugins/`, `schemas/`, `templates/` under `rynix_mcp/_assets/`.

## MCP client config

Use dedicated venv interpreter (not `uv run` on Windows reconnect). See `cursor.windows.json` / `cursor.posix.json`.

## Verification

```powershell
.\scripts\build.ps1
python scripts\final_verify.py
```
