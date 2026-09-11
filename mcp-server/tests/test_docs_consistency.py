"""R-61 — README / self-audit / server tool surface must stay aligned."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
SERVER = ROOT / "mcp-server" / "rynix_mcp" / "server.py"
SELF_AUDIT = ROOT / "scripts" / "mcp_self_audit.py"


def test_readme_tool_count_matches_server():
    readme = README.read_text(encoding="utf-8")
    server = SERVER.read_text(encoding="utf-8")
    mcp_tools = re.findall(r"@mcp\.tool\(\)", server)
    readme_match = re.search(r"MCP tools \((\d+)\)", readme)
    assert readme_match, "README missing 'MCP tools (N)' heading"
    assert len(mcp_tools) == int(readme_match.group(1)), (
        f"server has {len(mcp_tools)} @mcp.tool() but README says {readme_match.group(1)}"
    )


def test_self_audit_min_tool_count_not_above_server():
    server = SERVER.read_text(encoding="utf-8")
    audit = SELF_AUDIT.read_text(encoding="utf-8")
    mcp_tools = len(re.findall(r"@mcp\.tool\(\)", server))
    min_match = re.search(r"MIN_TOOL_COUNT\s*=\s*(\d+)", audit)
    assert min_match
    assert int(min_match.group(1)) <= mcp_tools


def test_example_law_firm_profile_has_risk_section():
    profile = (ROOT / "profiles" / "example-law-firm.toml").read_text(encoding="utf-8")
    assert "[risk]" in profile
    assert "list_probe_paths" in profile
    assert "discovery_roles" in profile


def test_readme_avoids_stale_marketing_counts():
    readme = README.read_text(encoding="utf-8")
    assert "75+" not in readme
    assert "51 stacks" not in readme.lower()
