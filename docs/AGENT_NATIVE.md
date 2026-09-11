# Agent-native architecture

Rynix MCP is designed to **ride on the host agent** (Cursor, Anti-gravity, Claude Desktop, etc.) — not to spawn a second LLM.

## Principle

| Layer | Responsibility |
|-------|----------------|
| **Host agent** | Reasoning, chaining, PoC design, judgment, orchestration |
| **Rynix MCP** | Tools, static scan, live probes, knowledge (75 agent-guides skills), SARIF, evidence |

**No `AGENT_GUIDES_LLM`, no `LLM_API_KEY`, no Docker sandbox required** for the default path.

## agent-guides integration

agent-guides OSS skills are **ported into** `mcp-server/rynix_mcp/knowledge/vuln-classes/` (75 guides).

The `agent-guides` plugin does **not** run agent-guides subprocess. It provides:

- `action: health` — skills pack status
- `action: playbook` — structured MCP tool sequence for the host agent
- `action: guide` — single vuln-class guide
- `action: skills` — list available guides

Legacy `action: scan` is an alias for `playbook` (never subprocess).

## Primary MCP tools

```
agent_engagement_playbook(scan_mode="standard", target_url=..., repo_path=..., session_id=...)
get_technique_guide("idor")
run_idor_matrix(...)
compare_role_response(...)
export_report(...)
```

## Scan modes

| Mode | Use when |
|------|----------|
| `quick` | Time-boxed; static + IDOR matrix |
| `standard` | Full static + live matrix + optional template-scan |
| `deep` | Exhaustive static + all live probes + WSTG refs |

## For IDE agents

1. Call `agent_engagement_playbook` at engagement start.
2. Execute each phase's `tools` using MCP.
3. Call `get_technique_guide` when you need agent-guides methodology depth.
4. Use **your own** reasoning to chain findings — MCP records evidence.
