"""Tests for admin API probe user resolver."""

from unittest.mock import MagicMock, patch

from rynix_mcp.probe_accounts import _ROLE_ENV_MAP
from rynix_mcp.probe_user_resolver import missing_roles, resolve_via_admin_api


def _clear_probe_user_env(monkeypatch) -> None:
    monkeypatch.delenv("RYNIX_PROBE_ACCOUNTS_FILE", raising=False)
    for role in _ROLE_ENV_MAP:
        user_env = _ROLE_ENV_MAP[role][0]
        monkeypatch.delenv(user_env, raising=False)


def test_missing_roles_from_env(monkeypatch):
    _clear_probe_user_env(monkeypatch)
    monkeypatch.setenv("RYNIX_PROBE_USER_CLIENT", "c1")
    monkeypatch.setenv("RYNIX_PROBE_USER_CEO", "ceo1")
    missing = missing_roles(("client", "ceo", "psychologist"), session_id="missing-env-test")
    assert "psychologist" in missing
    assert "client" not in missing


@patch("rynix_mcp.server.auth_login", return_value={"token_preview": "...abcd"})
@patch("rynix_mcp.http_session.request")
def test_resolve_psychologist_via_admin(mock_request, _mock_login, monkeypatch):
    _clear_probe_user_env(monkeypatch)
    monkeypatch.setenv("RYNIX_PROBE_PASSWORD", "x")
    monkeypatch.setenv("RYNIX_PROBE_USER_ADMIN", "admin1")
    from rynix_mcp.session import STORE

    STORE.get("resolve-test").tokens["admin"] = "admin-token"
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"items": [{"username": "psych-user-1", "role": "PSYCHOLOGIST"}]}
    mock_request.return_value = resp

    result = resolve_via_admin_api(
        "https://api.example.com", session_id="resolve-test", roles=("psychologist",)
    )
    assert result["resolved"].get("psychologist") == "psych-user-1"
    assert STORE.get("resolve-test").probe_usernames.get("psychologist") == "psych-user-1"
