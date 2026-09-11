"""Tests for env-driven probe account loading."""

import json

from rynix_mcp.probe_accounts import load_probe_accounts, missing_credentials_message


def test_load_from_per_role_env(monkeypatch):
    monkeypatch.delenv("RYNIX_PROBE_ACCOUNTS_FILE", raising=False)
    monkeypatch.setenv("RYNIX_PROBE_USER_CLIENT", "c1")
    monkeypatch.setenv("RYNIX_PROBE_USER_LAWYER", "l1")
    accounts = load_probe_accounts(session_id="probe-env-test")
    assert accounts["client"] == ("c1", "RYNIX_PROBE_PASSWORD")
    assert accounts["lawyer"] == ("l1", "RYNIX_PROBE_PASSWORD")


def test_load_from_accounts_file(tmp_path, monkeypatch):
    path = tmp_path / "accounts.json"
    path.write_text(
        json.dumps({"ceo": {"username": "ceo1", "password_env": "RYNIX_PROBE_PASSWORD_CEO"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("RYNIX_PROBE_ACCOUNTS_FILE", str(path))
    accounts = load_probe_accounts()
    assert accounts["ceo"] == ("ceo1", "RYNIX_PROBE_PASSWORD_CEO")


def test_missing_credentials_message_empty():
    assert "RYNIX_PROBE_USER" in missing_credentials_message({})
