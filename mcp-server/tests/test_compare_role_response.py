"""Tests for compare_role_response IDOR algorithm (httpx mocked)."""

from unittest.mock import MagicMock, patch

import httpx
from rynix_mcp.server import compare_role_response


def _mock_response(status: int, body: str) -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    r.text = body
    return r


@patch("rynix_mcp.server._require_live_probe", return_value=(True, ""))
@patch("rynix_mcp.server._require_scope", return_value=(True, "localhost"))
@patch("rynix_mcp.http_session.request")
def test_idor_likely_when_both_200_same_body(mock_request, _scope, _live):
    body = '{"id": 1, "title": "case"}'
    mock_request.side_effect = [
        _mock_response(200, body),
        _mock_response(200, body),
    ]
    result = compare_role_response(
        base_url="http://localhost:8000",
        path="/api/v1/cases/1",
        method="GET",
        token_a="a",
        token_b="b",
        profile="generic-fastapi-react",
        role_a="client",
        role_b="lawyer",
        allow_live=True,
    )
    assert result["idor_likely"] is True
    assert result["verdict"] == "idor_likely"


@patch("rynix_mcp.server._require_live_probe", return_value=(True, ""))
@patch("rynix_mcp.server._require_scope", return_value=(True, "localhost"))
@patch("rynix_mcp.http_session.request")
def test_no_idor_when_client_403_lawyer_200(mock_request, _scope, _live):
    """403 vs 200 is expected RBAC — must NOT flag as IDOR."""
    mock_request.side_effect = [
        _mock_response(403, '{"detail":"forbidden"}'),
        _mock_response(200, '{"id": 1}'),
    ]
    result = compare_role_response(
        base_url="http://localhost:8000",
        path="/api/v1/cases/1",
        method="GET",
        token_a="client",
        token_b="lawyer",
        profile="generic-fastapi-react",
        allow_live=True,
    )
    assert result["idor_likely"] is False
    assert result["verdict"] == "no_signal"


@patch("rynix_mcp.server._require_live_probe", return_value=(True, ""))
@patch("rynix_mcp.server._require_scope", return_value=(True, "localhost"))
@patch("rynix_mcp.http_session.request")
def test_no_idor_on_identical_empty_lists(mock_request, _scope, _live):
    mock_request.side_effect = [
        _mock_response(200, "[]"),
        _mock_response(200, "[]"),
    ]
    result = compare_role_response(
        base_url="http://localhost:8000",
        path="/api/v1/cases/",
        method="GET",
        token_a="client",
        token_b="lawyer",
        profile="generic-fastapi-react",
        allow_live=True,
    )
    assert result["idor_likely"] is False
    assert result["verdict"] == "no_signal"


@patch("rynix_mcp.server._require_live_probe", return_value=(True, ""))
@patch("rynix_mcp.server._require_scope", return_value=(True, "localhost"))
@patch("rynix_mcp.http_session.request")
def test_office_roles_same_cases_list_not_idor(mock_request, _scope, _live):
    body = '[{"id": 1, "title": "case"}]'
    mock_request.side_effect = [
        _mock_response(200, body),
        _mock_response(200, body),
    ]
    result = compare_role_response(
        base_url="http://localhost:8000",
        path="/api/v1/cases/",
        method="GET",
        token_a="a",
        token_b="b",
        profile="example-law-firm",
        role_a="secretary",
        role_b="ceo",
        allow_live=True,
    )
    assert result["idor_likely"] is False
    assert result["verdict"] == "expected_rbac_scope"


@patch("rynix_mcp.server._require_live_probe", return_value=(True, ""))
@patch("rynix_mcp.server._require_scope", return_value=(True, "localhost"))
@patch("rynix_mcp.http_session.request")
def test_privilege_inversion_when_a_200_b_403(mock_request, _scope, _live):
    mock_request.side_effect = [
        _mock_response(200, '{"id": 1}'),
        _mock_response(403, '{"detail":"forbidden"}'),
    ]
    result = compare_role_response(
        base_url="http://localhost:8000",
        path="/api/v1/system/docker/containers",
        method="GET",
        token_a="intern",
        token_b="admin",
        profile="generic-fastapi-react",
        role_a="intern",
        role_b="admin",
        allow_live=True,
    )
    assert result["idor_likely"] is True
    assert result["verdict"] == "privilege_inversion_suspect"
