"""MCP list_profiles tool must work at runtime."""

from rynix_mcp.server import list_profiles


def test_mcp_list_profiles_tool():
    result = list_profiles()
    assert "profiles" in result
    names = {p["name"] for p in result["profiles"]}
    assert "example-law-firm" in names
    assert "generic-fastapi-react" in names
