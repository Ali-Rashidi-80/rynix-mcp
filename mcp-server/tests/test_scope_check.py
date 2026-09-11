"""_require_scope must resolve profiles without NameError."""

from rynix_mcp.server import scope_check


def test_scope_check_loads_profile():
    r = scope_check("http://127.0.0.1:8001", "example-law-firm")
    assert r.get("allowed") is True
    assert "127.0.0.1" in r.get("matched_rule", "")
