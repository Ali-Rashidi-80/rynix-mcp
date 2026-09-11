"""WSTG manifest gate — required canonical IDs exist in knowledge."""

import json
from pathlib import Path

from rynix_mcp.knowledge import KNOWLEDGE_ROOT


def test_wstg_manifest_ids_present():
    manifest = json.loads(
        (Path(__file__).parent / "wstg_manifest.json").read_text(encoding="utf-8")
    )
    wstg_dir = KNOWLEDGE_ROOT / "wstg"
    present = {p.stem.upper() for p in wstg_dir.rglob("WSTG-*.md")}
    missing = [tid for tid in manifest["required_ids"] if tid not in present]
    assert not missing, f"missing WSTG docs: {missing}"
