---
title: GenAI and LLM Application Security (2026)
category: custom
owasp_ref: https://owasp.org/www-project-top-10-for-large-language-model-applications/
---

# GenAI / LLM Security — 2026 Testing Notes

Rynix tests GenAI surfaces with **deterministic probes** (`http_probe`, `record_finding`) — no external LLM API keys in the MCP runtime (host-agent only).

## OWASP LLM Top 10 mapping (2025–2026)

| Risk | Rynix probe approach |
|------|---------------------|
| LLM01 Prompt injection | Send system/user delimiter payloads via chat/completion endpoints; compare role responses |
| LLM02 Sensitive disclosure | Probe for training/config leakage in responses; check error messages |
| LLM03 Supply chain | `analyze_repo` for pinned model deps, API keys in env samples |
| LLM04 Model DoS | Rate-limit headers, oversized context, token exhaustion (safe bounds only) |
| LLM05 Improper output handling | XSS/HTML in streamed responses; markdown render sinks |
| LLM06 Excessive agency | Tool/MCP action endpoints without auth; IDOR on agent sessions |
| LLM07 System prompt leak | Indirect extraction prompts; multi-turn coaxing |
| LLM08 Vector/embedding weakness | Poisoning via uploaded docs if RAG ingest exposed |
| LLM09 Misinformation | Out of pentest scope unless business logic requires |
| LLM10 Unbounded consumption | Billing/quota bypass via parallel `http_probe` batch |

## High-value endpoints

```
POST /api/chat /api/completion /api/ai /api/assistant
POST /v1/chat/completions  (OpenAI-compatible proxies)
WebSocket /ws/chat /stream
```

## Rynix workflow

1. `get_technique_guide` → `web-llm-attacks`
2. `analyze_repo` — search for LangChain, LlamaIndex, OpenAI SDK imports
3. `http_probe` indirect injection payloads (safe, no exfil to third parties)
4. `compare_role_response` — same prompt as user A vs user B (data leak)
5. `record_finding` with request/response hash only — redact tokens

## Evidence requirements

- Reproducible prompt/response pair proving boundary violation
- No live calls to vendor LLM APIs from Rynix MCP (host agent may reason locally)
- Map finding to OWASP LLM ID in `export_report`

## CWE / ASVS

- CWE-77: Command injection via tool routing
- CWE-200: Information exposure in model output
- ASVS V14 Configuration — secrets not in client bundles
- ASVS V4 Access Control — per-user chat history isolation
