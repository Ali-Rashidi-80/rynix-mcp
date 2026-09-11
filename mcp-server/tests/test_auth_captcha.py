"""Tests for auth captcha solver."""

from rynix_mcp.auth_captcha import (
    fetch_captcha_fields,
    response_needs_captcha,
    solve_math_prompt,
)

_CAPTCHA = {
    "path": "/api/v1/auth/captcha",
    "markers": ["کد امنیتی", "captcha", "CAPTCHA"],
    "required_status": 400,
}


def test_solve_math_prompt_addition():
    assert solve_math_prompt("12 + 7 = ?") == "19"


def test_solve_math_prompt_subtraction():
    assert solve_math_prompt("9 − 4 = ?") == "5"


def test_response_needs_captcha():
    assert response_needs_captcha(400, '{"message":"کد امنیتی الزامی است."}', _CAPTCHA)
    assert not response_needs_captcha(401, "unauthorized", _CAPTCHA)


def test_fetch_captcha_fields_parses_challenge():
    from unittest.mock import MagicMock, patch

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "captcha_id": "abc",
        "prompt_en": "3 + 5 = ?",
        "disabled": "false",
    }
    with patch("rynix_mcp.http_session.request", return_value=resp):
        fields = fetch_captcha_fields(
            "https://api.example.com", _CAPTCHA, session_id="captcha-test"
        )
    assert fields == {"captcha_id": "abc", "captcha_answer": "8"}
