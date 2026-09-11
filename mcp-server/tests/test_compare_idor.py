from rynix_mcp.session import json_field_overlap


def test_idor_likely_same_body():
    body = '{"id": 1, "name": "secret", "role": "client"}'
    assert json_field_overlap(body, body) == 1.0


def test_idor_no_overlap_different_keys():
    a = '{"id": 1}'
    b = '{"other": 2}'
    assert json_field_overlap(a, b) == 0.0


def test_idor_partial_overlap():
    a = '{"id": 1, "name": "x", "email": "a@b.c"}'
    b = '{"id": 2, "name": "y", "email": "d@e.f"}'
    assert json_field_overlap(a, b) == 1.0
