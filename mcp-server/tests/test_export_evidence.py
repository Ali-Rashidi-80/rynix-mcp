"""export_report writes evidence/ when session has compare artifacts."""

import tempfile
from pathlib import Path

from rynix_mcp.config import ROOT
from rynix_mcp.server import compare_role_response, export_report, record_finding

_PENTEST_OUTPUT = ROOT / "pentest_output"


def test_export_includes_evidence_dir():
    _PENTEST_OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=_PENTEST_OUTPUT) as tmp:
        record_finding(
            severity="high",
            title="Verified IDOR",
            endpoint="/api/v1/cases/1",
            evidence="dual-token",
            verified=True,
            session_id="ev-test",
        )
        compare_role_response(
            base_url="http://127.0.0.1:1",
            path="/api/v1/cases/1",
            method="GET",
            token_a="a",
            token_b="b",
            profile="generic-fastapi-react",
            session_id="ev-test",
        )
        # compare may fail scope/live — evidence only added on success path
        # Force evidence for export test
        from rynix_mcp.session import STORE

        STORE.get("ev-test").add_evidence("req-001.txt", '{"verdict":"no_signal"}')

        paths = export_report(tmp, session_id="ev-test", formats="json")
        evidence_dir = Path(tmp) / "evidence"
        assert evidence_dir.is_dir()
        assert list(evidence_dir.glob("*.txt"))
        assert "json_path" in paths
