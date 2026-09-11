#!/usr/bin/env python3

"""Final verification gate: all 12 DoD gates + pytest + cargo."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp-server"
VENV_PY_WIN = MCP / ".venv" / "Scripts" / "python.exe"
VENV_PY_POSIX = MCP / ".venv" / "bin" / "python"


def _python() -> str:
    venv_env = os.environ.get("VIRTUAL_ENV")
    if venv_env:
        v_win = Path(venv_env) / "Scripts" / "python.exe"
        v_posix = Path(venv_env) / "bin" / "python"
        if v_win.is_file():
            return str(v_win)
        if v_posix.is_file():
            return str(v_posix)
    if VENV_PY_WIN.is_file():
        return str(VENV_PY_WIN)
    if VENV_PY_POSIX.is_file():
        return str(VENV_PY_POSIX)
    return str(Path(sys.executable))


def run(cmd: list[str], cwd: Path | None = None) -> int:
    proc = subprocess.run(cmd, cwd=str(cwd or ROOT))

    return proc.returncode


def main() -> int:
    py = _python()

    gates = [
        ("align-knowledge", [py, str(ROOT / "scripts" / "align_knowledge_tools.py")]),
        ("scrub-knowledge-brands", [py, str(ROOT / "scripts" / "scrub_knowledge_brands.py")]),
        ("gate-1-zero-brands", [py, str(ROOT / "scripts" / "verify_zero_brands.py")]),
        ("gate-2-private-leaks", [py, str(ROOT / "scripts" / "verify_no_private_leaks.py")]),
        ("scrub-publish-leaks", [py, str(ROOT / "scripts" / "scrub_publish_leaks.py")]),
        ("gate-2b-github-publish", [py, str(ROOT / "scripts" / "verify_github_publish_ready.py")]),
        ("gate-3-no-external-llm", [py, str(ROOT / "scripts" / "verify_no_external_llm.py")]),
        ("gate-4-mcp-self-audit", [py, str(ROOT / "scripts" / "mcp_self_audit.py")]),
        ("gate-5-knowledge-manifest", [py, str(ROOT / "scripts" / "sync_knowledge_manifest.py")]),
        (
            "gate-5-knowledge-manifest-audit",
            [py, str(ROOT / "scripts" / "knowledge_manifest_audit.py")],
        ),
        ("enrich-knowledge", [py, str(ROOT / "scripts" / "enrich_knowledge.py")]),
        ("generate-framework-guides", [py, str(ROOT / "scripts" / "generate_framework_guides.py")]),
        ("enrich-wstg-deep", [py, str(ROOT / "scripts" / "enrich_wstg_deep.py")]),
        ("enrich-genai", [py, str(ROOT / "scripts" / "enrich_genai_knowledge.py")]),
        (
            "gate-5b-knowledge-enrichment",
            [py, str(ROOT / "scripts" / "verify_knowledge_enrichment.py")],
        ),
        ("gate-6-knowledge-xref", [py, str(ROOT / "scripts" / "verify_knowledge_tool_xref.py")]),
        (
            "gate-7-knowledge-alignment",
            [py, str(ROOT / "scripts" / "verify_knowledge_mcp_alignment.py")],
        ),
        ("gate-8-golden-jury", [py, str(ROOT / "scripts" / "golden_engagement_jury.py")]),
        ("gate-9-tool-inventory", [py, str(ROOT / "scripts" / "mcp_tool_inventory_audit.py")]),
        (
            "gate-10-example-law-firm",
            [py, str(ROOT / "scripts" / "verify_gate10_example_law_firm.py")],
        ),
        ("gate-11-runtime-parity", [py, str(ROOT / "scripts" / "verify_runtime_parity.py")]),
        ("generate-rynix-tools", [py, str(ROOT / "scripts" / "generate_rynix_tools_bin.py")]),
        ("gate-11b-rynix-tools", [py, str(ROOT / "scripts" / "verify_rynix_tools_manifest.py")]),
        (
            "expand-tier1-frameworks",
            [py, str(ROOT / "scripts" / "expand_tier1_framework_deepdives.py")],
        ),
        ("gate-12-multistack", [py, str(ROOT / "scripts" / "verify_multistack_coverage.py")]),
        ("gate-12b-dm-scope", [py, str(ROOT / "scripts" / "verify_dm_scope.py")]),
        ("gate-10b-live-smoke-optional", [py, str(ROOT / "scripts" / "run_live_smoke_ci.py")]),
        ("scrub-legacy-tooling", [py, str(ROOT / "scripts" / "scrub_autopentest.py")]),
        ("pytest", [py, "-m", "pytest", "-q"], ROOT / "mcp-server"),
        ("contract", [py, str(ROOT / "scripts" / "run_contract.py")]),
        ("rust", ["cargo", "test", "-q"], ROOT / "rynix-core"),
    ]

    failed: list[str] = []

    for name, cmd, *rest in gates:
        cwd = rest[0] if rest else ROOT

        code = run(cmd, cwd)

        status = "PASS" if code == 0 else "FAIL"

        print(f"[{status}] {name}")

        if code != 0:
            failed.append(name)

    if failed:
        print(f"final_verify failed: {', '.join(failed)}", file=sys.stderr)

        return 1

    print("final_verify: all gates passed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
