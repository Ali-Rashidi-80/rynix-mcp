from rynix_mcp.knowledge import KNOWLEDGE_ROOT


def test_all_wstg_have_rynix_workflow():
    wstg_dir = KNOWLEDGE_ROOT / "wstg"
    missing = []
    for path in wstg_dir.rglob("WSTG-*.md"):
        text = path.read_text(encoding="utf-8")
        if "## Rynix workflow" not in text:
            missing.append(path.name)
        if "## Evidence requirements" not in text:
            missing.append(f"{path.name}:evidence")
    assert not missing, f"missing workflow sections: {missing[:5]}"
