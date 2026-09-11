"""template-scan plugin records findings into session."""

from rynix_mcp.plugins import _record_plugin_findings
from rynix_mcp.session import STORE


def test_record_plugin_findings():
    rows = [
        {
            "template_id": "test-cve",
            "name": "Test CVE",
            "severity": "high",
            "matched_at": "https://example.com",
        }
    ]
    ids = _record_plugin_findings(rows, "template-scan-test", "template-scan")
    session = STORE.get("template-scan-test")
    assert len(ids) == 1
    assert len(session.findings) == 1
    assert session.findings[0].source_plugin == "template-scan"
