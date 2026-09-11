# Agent Role System

All subagents are spawned from role templates. Each template defines the agent's identity, allowed/restricted tools, input/output contracts, and anti-patterns.

## Available Roles

| Role | Template | Purpose | Phases |
|------|----------|---------|--------|
| **Scout** | `scout.md` | Reconnaissance, mapping, no attack payloads | 0, 1, code analysis (architecture) |
| **Analyzer** | `analyzer.md` | Vulnerability discovery with canary payloads, queue building | 2, 3, 4 (analysis), 5, code analysis (taint) |
| **Exploiter** | `exploiter.md` | Exploitation proof, finding logging | 4 (exploitation) |
| **Reporter** | `reporter.md` | Quality review, gap analysis, chaining | Phase transitions (QA), post-report (Judge) |

## Role Selection Guide

| Task | Role |
|------|------|
| Phase 0 discovery, crawling, tool ingestion | Scout |
| Phase 1 INFO tests | Scout |
| Phase 2 CONF tests | Analyzer |
| Phase 3 ATHN/ATHZ/SESS tests | Analyzer |
| Phase 4 analysis wave (per vuln class) | Analyzer |
| Phase 4 exploitation wave (per vuln class) | Exploiter |
| Phase 5 ERRH/CRYP/BUSL/CLNT/APIT tests | Analyzer |
| Quality Reviewer at phase transitions | Reporter (mode: quality_reviewer) |
| Final Judge post-report | Reporter (mode: final_judge) |
| Source code: architecture, entry points, security patterns | Scout |
| Source code: taint analysis, sink tracing | Analyzer |

## How to Construct Prompts from Templates

1. **Select role template** based on the task (see table above)
2. **Read the template**: `templates/agent-roles/{role}.md`
3. **Fill all `{placeholder}` variables** listed in the template's Prompt Variables section
4. **Append shared mandates** (already in the template's Section 9, but verify anti-loop safeguard is present)
5. **Append engagement rules**: Include output of `get_engagement_rules(engagement_id)`
6. **Spawn**: `Task(prompt=..., subagent_type="general-purpose", max_turns=...)`

## max_turns by Role

| Role | Context | max_turns |
|------|---------|-----------|
| Scout | Phase 0 discovery | 75 |
| Scout | Phase 1 INFO | 50 |
| Analyzer | Phase 2 CONF | 60 |
| Analyzer | Phase 3 ATHN/ATHZ/SESS | 75 |
| Analyzer | Phase 4 analysis (per vuln class) | 75 |
| Exploiter | Phase 4 exploitation (per vuln class) | 75 |
| Analyzer | Phase 5 mixed | 75 |
| Reporter | Quality Reviewer | 30 |
| Reporter | Final Judge | 50 |
| Scout | Source code (architecture) | 60 |
| Analyzer | Source code (taint analysis) | 75 |

## Template Section Structure

Every role template follows the same 10 sections:

1. **Role Identity** — who you are, one-sentence mission
2. **Purpose & Boundaries** — what you do and don't do
3. **Allowed Tools** — primary + supporting, with one-line rationale each
4. **Restricted Tools** — explicit denylist with explanations
5. **Input Contract** — what you receive from orchestrator/upstream agents
6. **Output Contract** — what you must produce before finishing
7. **Workflow Steps** — numbered procedure, references detail templates
8. **Anti-Patterns** — role-specific mistakes to avoid
9. **Shared Mandates** — honesty framework, classification, reproducibility, scope rules, anti-loop safeguard
10. **Prompt Variables** — `{placeholder}` list with descriptions
