"""export_report must not leak unverified findings when include_unverified=False."""

import json
import tempfile
from pathlib import Path

from rynix_mcp.config import ROOT
from rynix_mcp.path_safety import resolve_export_output_dir
from rynix_mcp.server import export_report, record_finding

_PENTEST_OUTPUT = ROOT / "pentest_output"


def test_export_verified_only_excludes_unverified():
    _PENTEST_OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=_PENTEST_OUTPUT) as tmp:
        record_finding(
            severity="high",
            title="Verified",
            endpoint="/a",
            evidence="proof",
            verified=True,
            session_id="verified-only",
        )
        record_finding(
            severity="high",
            title="Unverified",
            endpoint="/b",
            evidence="guess",
            verified=False,
            session_id="verified-only",
        )
        paths = export_report(
            output_dir=tmp,
            session_id="verified-only",
            formats="json",
            include_unverified=False,
        )
        data = json.loads(Path(paths["json_path"]).read_text(encoding="utf-8"))
        findings = data["findings"] if isinstance(data, dict) else data
        assert len(findings) == 1
        assert findings[0]["title"] == "Verified"


def test_export_html_format():
    _PENTEST_OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=_PENTEST_OUTPUT) as tmp:
        record_finding(
            severity="medium",
            title="HTML finding",
            endpoint="/x",
            evidence="proof",
            verified=True,
            session_id="html-export",
        )
        paths = export_report(
            output_dir=tmp,
            session_id="html-export",
            formats="html",
            include_unverified=False,
        )
        html = Path(paths["html_path"]).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "HTML finding" in html


def test_export_rejects_path_outside_pentest_output(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    record_finding(
        severity="low",
        title="x",
        endpoint="/",
        evidence="y",
        verified=True,
        session_id="path-guard",
    )
    try:
        export_report(output_dir=str(outside), session_id="path-guard", formats="json")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "pentest_output" in str(exc).lower()


def test_export_rejects_null_byte_in_output_dir():
    record_finding(
        severity="low",
        title="x",
        endpoint="/",
        evidence="y",
        verified=True,
        session_id="null-guard",
    )
    try:
        export_report(output_dir="mcpsec_test\x00/evil", session_id="null-guard", formats="json")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_export_relative_dir_under_pentest_output():
    rel = "pytest-relative-export"
    resolved = resolve_export_output_dir(rel)
    assert str(resolved).replace("\\", "/").endswith(f"pentest_output/{rel}")


def test_export_html_and_markdown_escapes_xss():
    _PENTEST_OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=_PENTEST_OUTPUT) as tmp:
        record_finding(
            severity="high",
            title="<script>alert('xss')</script>",
            endpoint="/api/<img src=x onerror=alert(1)>",
            evidence="payload: <svg/onload=alert(1)> & 'quotes'",
            verified=True,
            session_id="xss-test-session",
        )
        paths = export_report(
            output_dir=tmp,
            session_id="xss-test-session",
            formats="html,markdown",
            include_unverified=False,
        )
        html_content = Path(paths["html_path"]).read_text(encoding="utf-8")
        assert "<script>" not in html_content
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_content
        assert "<img" not in html_content
        assert "&lt;img src=x onerror=alert(1)&gt;" in html_content
        assert "<svg" not in html_content

        md_content = Path(paths["markdown_path"]).read_text(encoding="utf-8")
        assert "Session: xss-test-session" in md_content
        assert paths["html_path"]
        assert paths["markdown_path"]
