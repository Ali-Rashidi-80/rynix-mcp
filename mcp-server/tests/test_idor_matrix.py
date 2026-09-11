"""run_idor_matrix MCP tool and library."""

from unittest.mock import patch

from rynix_mcp.idor_matrix import run_idor_matrix
from rynix_mcp.session import STORE


def _fake_login(
    base_url, username, password, profile=None, role_label=None, session_id=None, **kwargs
):
    session = STORE.get(session_id)
    session.tokens[role_label or username] = f"token-{role_label}"
    return {"token_preview": "...abcd", "role_label": role_label}


@patch("rynix_mcp.http_session.ensure_stealth_gate", return_value=True)
@patch("rynix_mcp.server.export_report", return_value={"json_path": "/tmp/f.json"})
@patch("rynix_mcp.server.compare_role_response")
@patch("rynix_mcp.server.auth_login", side_effect=_fake_login)
@patch("rynix_mcp.server.scope_check", return_value={"allowed": True})
def test_idor_matrix_runs_comparisons(mock_scope, mock_login, mock_compare, mock_export, _gate):
    mock_compare.return_value = {"verdict": "no_signal", "idor_likely": False, "diff": {}}

    with patch.dict(
        "os.environ",
        {
            "RYNIX_PROBE_PASSWORD": "x",
            "RYNIX_PROBE_PASSWORD_CEO": "y",
            "RYNIX_PROBE_USER_CLIENT": "client-user",
            "RYNIX_PROBE_USER_LAWYER": "lawyer-user",
        },
    ):
        result = run_idor_matrix(
            "http://127.0.0.1:8001",
            roles=["client", "lawyer"],
            session_id="test-matrix",
        )

    assert "error" not in result
    assert result["comparisons"] > 0
    assert mock_compare.called
    assert mock_export.called


def test_idor_matrix_requires_password_env():
    with patch.dict("os.environ", {}, clear=True):
        result = run_idor_matrix("http://127.0.0.1:8001")
    assert result["error"]["code"] == "MISSING_CREDENTIALS"
