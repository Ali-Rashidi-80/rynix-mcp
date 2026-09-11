# Rynix MCP v2 — agent-native (no external LLM)

## Core principle

**Host agent (Cursor) = brain. Rynix MCP = hands + knowledge + evidence.**

No `AGENT_GUIDES_LLM`, no `LLM_API_KEY`, no agent-guides subprocess by default.

| Item | Status |
|------|--------|
| Agent-native playbooks | **Done** — `agent_playbook.py`, `agent_engagement_playbook` tool |
| 75 agent-guides skill guides in MCP | **Done** — `vuln-classes/` |
| tree-sitter taint | **Done** — `rynix-core/src/taint.rs` |
| mcpsec scan | **Done** — optional G4 |
| Stealth gate probes | **Done** |
| Production IDOR via `http_session` gate cookies | **Done** |
| 8-role `probe_user_resolver` (admin API) | **Done** |
| `unlock_stealth_gate` MCP tool | **Done** |
| agent-orchestrator / browser-debug | Backlog |
| Subprocess agent-guides+LLM | **Intentionally not used** — see `docs/AGENT_NATIVE.md` |

## Usage (Cursor agent)

```
agent_engagement_playbook(scan_mode="standard", target_url="http://127.0.0.1:8001", repo_path="...")
rynix_plugin_run("agent-guides", options='{"action":"playbook","scan_mode":"deep"}')
get_technique_guide("idor")
```
