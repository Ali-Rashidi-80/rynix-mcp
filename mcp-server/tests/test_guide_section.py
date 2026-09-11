"""R-48 — get_guide_section extracts markdown headings."""

from rynix_mcp.knowledge import get_guide_section, get_technique_guide


def test_get_guide_section_returns_heading_block():
    full = get_technique_guide("idor")
    assert "error" not in full
    section = get_guide_section("idor", full["title"])
    assert "error" not in section
    assert section["heading"]
    assert section["content"].startswith("#")
    assert "truncated" in section


def test_get_guide_section_missing_heading():
    result = get_guide_section("idor", "zzzz-nonexistent-section-zzzz")
    assert "error" in result
    assert result["error"]["code"] == "SECTION_NOT_FOUND"
