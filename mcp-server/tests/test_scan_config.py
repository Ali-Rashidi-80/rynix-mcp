"""Profile → ScanConfig mapping for Rust scanner."""

from rynix_mcp.config import PROFILES_DIR
from rynix_mcp.profiles import load_profile
from rynix_mcp.scan_config import scan_config_from_profile


def test_example_law_firm_scan_config_includes_stealth_prefixes():
    prof = load_profile("example-law-firm", PROFILES_DIR)
    cfg = scan_config_from_profile(prof)
    assert "/api/v1/auth" in cfg["stealth_public_prefixes"]
    assert "purge" in cfg["risk_keywords_high"]
    assert "check_case_access" in cfg["auth_markers"]
