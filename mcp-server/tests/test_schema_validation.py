"""Validate scan-result JSON against bundled schema using jsonschema."""

import json

import jsonschema
from rynix_mcp.config import ROOT


def test_scan_result_validates_against_schema():
    schema = json.loads((ROOT / "schemas" / "scan-result.schema.json").read_text(encoding="utf-8"))
    sample = json.loads(
        (ROOT / "tests" / "golden" / "example-law-firm-scan.json").read_text(encoding="utf-8-sig")
    )
    jsonschema.validate(instance=sample, schema=schema)


def test_profile_schema_validates_example_law_firm():
    import tomllib

    schema = json.loads((ROOT / "schemas" / "profile.schema.json").read_text(encoding="utf-8"))
    profile_path = ROOT / "profiles" / "example-law-firm.toml"
    data = tomllib.loads(profile_path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=data, schema=schema)
