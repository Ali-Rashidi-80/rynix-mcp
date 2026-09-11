from rynix_mcp.sarif import export_sarif
from rynix_mcp.session import Finding


def test_sarif_schema_and_rule_id():
    findings = [
        Finding(
            id="1",
            severity="high",
            title="IDOR on cases endpoint",
            endpoint="GET /api/v1/cases/1",
            evidence="token overlap",
            verified=True,
        )
    ]
    doc = export_sarif(findings, "test-session")
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "RYNIX-API1-IDOR"
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["original_severity"] == "high"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Rynix"
