"""Tests for profile-driven IDOR/RBAC heuristics (R-69)."""

from rynix_mcp.profile_risk import load_risk_profile


def test_load_risk_profile_defaults():
    risk = load_risk_profile({})
    assert risk.has_object_id_in_path("/api/v1/cases/42")
    assert not risk.has_object_id_in_path("/api/v1/cases/")
    assert risk.is_collection_list_path("/api/v1/cases/")
    assert risk.role_trust_level("ceo") > risk.role_trust_level("client")


def test_load_risk_profile_from_toml_section():
    prof = {
        "risk": {
            "office_roles": ["ceo"],
            "assigned_roles": ["client"],
            "discovery_roles": ["ceo"],
            "list_probe_paths": [{"method": "GET", "path": "/api/v1/foo/"}],
        }
    }
    risk = load_risk_profile(prof)
    assert risk.office_roles == frozenset({"ceo"})
    assert risk.list_probe_paths == [("GET", "/api/v1/foo/")]


def test_expected_assignment_scoped_rbac_office_pair():
    risk = load_risk_profile({})
    assert risk.expected_assignment_scoped_rbac("/api/v1/cases/", "secretary", "ceo")
    assert not risk.expected_assignment_scoped_rbac("/api/v1/cases/1", "client", "intern")
