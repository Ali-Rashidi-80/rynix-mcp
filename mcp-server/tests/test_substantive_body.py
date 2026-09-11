"""Empty paginated list bodies must not trigger IDOR."""

from rynix_mcp.server import _substantive_response_body


def test_empty_paginated_wrapper_not_substantive():
    assert _substantive_response_body('{"items": [], "total": 0}') is False
    assert _substantive_response_body('{"cases": [], "count": 0}') is False


def test_non_empty_list_is_substantive():
    assert _substantive_response_body('[{"id": 1}]') is True
    assert _substantive_response_body('{"items": [{"id": 1}], "total": 1}') is True
