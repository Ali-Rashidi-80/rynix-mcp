from rynix_mcp.scanner import scope_allowed


def test_scope_localhost_allowed():
    profile = {"scope": {"allow_hosts": ["localhost"]}}
    ok, reason = scope_allowed("http://localhost:8000", profile, "")
    assert ok
    assert "localhost" in reason


def test_scope_unknown_blocked():
    profile = {"scope": {"allow_hosts": ["localhost"]}}
    ok, _ = scope_allowed("https://evil.example.com", profile, "")
    assert not ok


def test_scope_ipv6_loopback_allowed():
    profile = {"scope": {"allow_hosts": ["::1"]}}
    ok, reason = scope_allowed("http://[::1]:8001", profile, "")
    assert ok
    assert "::1" in reason or "matched" in reason


def test_scope_invalid_cidr_fail_closed():
    profile = {"scope": {"allow_hosts": ["localhost"], "allow_cidrs": ["not-a-cidr"]}}
    ok, reason = scope_allowed("https://10.0.0.5", profile, "")
    assert not ok
    assert "fail-closed" in reason


def test_json_overlap():
    from rynix_mcp.session import json_field_overlap

    a = '{"id": 1, "name": "x"}'
    b = '{"id": 2, "name": "y"}'
    assert json_field_overlap(a, b) == 1.0
