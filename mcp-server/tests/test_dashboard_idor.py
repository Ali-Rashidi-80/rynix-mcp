"""Overlap-only with different hashes must not flag IDOR (role-scoped dashboards)."""

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
def test_same_schema_different_values_not_idor(mock_request, _scope, _live):
    mock_request.side_effect = [
        _mock_response(200, '{"total_cases": 1, "pending": 0}'),
        _mock_response(200, '{"total_cases": 5, "pending": 2}'),
    ]
    result = compare_role_response(
        base_url="http://localhost:8000",
        path="/api/v1/dashboard/summary",
        method="GET",
        token_a="a",
        token_b="b",
        profile="example-law-firm",
        role_a="intern",
        role_b="lawyer",
        allow_live=True,
    )
    assert result["idor_likely"] is False
    assert result["verdict"] == "no_signal"
    assert result["diff"]["field_overlap"] == 1.0
