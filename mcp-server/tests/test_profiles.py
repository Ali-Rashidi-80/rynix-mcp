from rynix_mcp.config import PROFILES_DIR
from rynix_mcp.profiles import list_profiles, load_profile


def test_list_profiles_includes_example_law_firm():
    names = {p["name"] for p in list_profiles(PROFILES_DIR)}
    assert "example-law-firm" in names
    assert "generic-fastapi-react" in names


def test_load_example_law_firm_auth():
    prof = load_profile("example-law-firm", PROFILES_DIR)
    auth = prof.get("auth", {})
    assert auth.get("login_path") == "/api/v1/auth/login"
    assert "application/x-www-form-urlencoded" in auth.get("content_type", "")


def test_profile_shape_rejects_bad_scope():
    import pytest
    from rynix_mcp.profiles import _validate_profile_shape

    with pytest.raises(ValueError, match="allow_hosts"):
        _validate_profile_shape({"name": "x", "scope": {"allow_hosts": "bad"}})
