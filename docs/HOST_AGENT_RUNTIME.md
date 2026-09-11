# Host-agent runtime contract — Cursor/IDE agent is the reasoning engine.

## Architecture

| Plugin | Host agent responsibility | MCP supplies |
|--------|---------------------------|--------------|
| `agent-guides` | Read technique guides, plan exploit steps | `get_technique_guide`, `http_probe`, `record_finding` |
| `pipeline-runner` | Advance recon→analyze→exploit→report | `track_probe_step`, `save_engagement_context` |
| `cyber-range` | Execute bench scenarios | `track_probe_step`, session scoring |
| `whitebox-scan` | Validate static queue targets | `analyze_repo`, `http_probe`, SARIF export |
| `agent-orchestrator` | Multi-role specialist flows | `agent_engagement_playbook` |
| `browser-debug` | Headless browser validation | Playbook steps + `track_probe_step` |
| `engagement` | Scope guard + verifier | `register_scope`, `scope_check` |

## Rules

1. **No external LLM API** — reasoning runs in the host agent (Cursor).
2. **Evidence required** — every finding needs `http_probe` or `compare_role_response` evidence before `record_finding(verified=True)`.
3. **Session continuity** — pass `session_id` on all probe and finding calls.
4. **Stage tracking** — call `track_wstg_test` and `track_probe_step` per playbook stage.

## Playbook execution

```text
agent_engagement_playbook(scan_mode="standard")
  → for each step: run listed MCP tools
  → track_probe_step(name, status, evidence)
  → record_finding only after probe evidence
export_report(include_unverified=False)
```

## Docker sidecar (optional)

When `RYNIX_TOOLS_CONTAINER=1`, WSTG runner may invoke `docker exec rynix-tools` with generic tool names (`rynix-http-probe`, `rynix-fuzz`, `rynix-sqli-probe`).

## Verification

```powershell
python scripts/verify_no_external_llm.py
python scripts/verify_runtime_parity.py
```
