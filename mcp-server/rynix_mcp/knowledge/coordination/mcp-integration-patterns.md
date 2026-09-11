# MCP Integration Patterns (summary)

Adapted from newline knowledge — practical patterns for wiring Rynix (and other MCP servers) into agent hosts.

## Primitives

MCP servers expose **tools** (callable actions), **resources** (readable context), and **prompts** (templates). Rynix v1 focuses on tools + bundled knowledge; treat each tool call as a state-changing action requiring scope checks.

## Four team patterns

1. **Capability scoping** — one server/domain per task (e.g. Rynix for security, separate DB read replica server).
2. **Read/write separation** — static analysis vs live probes; deny writes in engagement YAML.
3. **Least-surface allowlist** — enable named tools only (`health_check`, `analyze_repo`, …) instead of wildcard MCP trust.
4. **Version & audit pinning** — commit `mcp.json` / Cursor config; review tool list changes like dependency bumps.

## Policy matrix

| Pattern | Risk | When |
| --- | --- | --- |
| Per-tool allowlist | Lowest | Production / shared workspaces |
| Per-server allowlist | Medium | Trusted internal servers with tests |
| Global wildcard | High | Personal dev only |
| disabledTools list | Medium | Block a few dangerous tools on otherwise trusted servers |

## Rynix-specific guardrails

- Call `scope_check` before probes; set `allow_live=true` only with repo scope permission.
- Pass `session_id` through probe → finding → export for traceability.
- Optional plugins (agent-orchestrator, browser-debug) stay **disabled** until Docker stacks are intentionally started.

## Default posture

Assume **Ask / default-deny** for tools that hit the network. Approve scoped sessions explicitly rather than enabling `mcp(*)`.
