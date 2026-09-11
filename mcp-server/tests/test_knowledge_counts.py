"""Knowledge catalog structural gates (WSTG, technique, vuln classes)."""

import hashlib
from collections import defaultdict

from rynix_mcp.knowledge import (
    KNOWLEDGE_ROOT,
    get_technique_guide,
    list_vuln_classes,
    search_knowledge,
    techniques_topic_count,
    wstg_test_count,
)


def test_wstg_at_least_109():
    assert wstg_test_count() >= 109


def test_wstg_files_have_canonical_ids():
    wstg_dir = KNOWLEDGE_ROOT / "wstg"
    ids = {p.stem.upper() for p in wstg_dir.rglob("WSTG-*.md")}
    assert "WSTG-APIT-01" in ids
    assert "WSTG-ATHZ-01" in ids
    assert all(i.startswith("WSTG-") for i in ids)


def test_techniques_topics():
    assert techniques_topic_count() >= 25


def test_vuln_class_catalog_has_core_guides():
    classes = set(list_vuln_classes())
    for required in ("idor", "authentication-jwt", "mass-assignment", "open-redirect"):
        assert required in classes


def test_no_duplicate_kb_content():
    """R-47 — no byte-identical markdown files in knowledge tree."""
    by_hash: dict[str, list[str]] = defaultdict(list)
    for path in KNOWLEDGE_ROOT.rglob("*.md"):
        digest = hashlib.md5(path.read_bytes()).hexdigest()
        by_hash[digest].append(str(path.relative_to(KNOWLEDGE_ROOT)))
    dups = {h: paths for h, paths in by_hash.items() if len(paths) > 1}
    assert not dups, f"duplicate KB content: {dups}"


def test_no_duplicate_flat_techniques_stems():
    """Flat vuln-class stems must not shadow techniques topics."""
    ps = KNOWLEDGE_ROOT / "techniques"
    vuln_dir = KNOWLEDGE_ROOT / "vuln-classes"
    overlap = {
        p.stem
        for p in vuln_dir.glob("*.md")
        if "--" not in p.stem and (ps / f"{p.stem}.md").is_file()
    }
    assert not overlap, f"duplicate flat vuln-classes vs techniques: {sorted(overlap)}"


def test_get_technique_guide_prefers_techniques():
    guide = get_technique_guide("sql-injection")
    assert "error" not in guide
    assert guide["source"].startswith("knowledge/techniques/")


def test_search_knowledge_finds_idor():
    result = search_knowledge("IDOR")
    assert result["count"] >= 1
    assert any("idor" in m["path"].lower() or "IDOR" in m["title"] for m in result["matches"])
