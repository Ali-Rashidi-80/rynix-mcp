from __future__ import annotations

from typing import Any

from rynix_mcp.session import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

RULES = [
    {
        "id": "RYNIX-API1-IDOR",
        "name": "Broken Object Level Authorization",
        "shortDescription": {"text": "Potential IDOR/BOLA across roles"},
        "properties": {"security-severity": "8.0"},
    },
    {
        "id": "RYNIX-API2-AUTH",
        "name": "Broken Authentication",
        "shortDescription": {"text": "Authentication weakness"},
        "properties": {"security-severity": "7.5"},
    },
    {
        "id": "RYNIX-API5-BFLA",
        "name": "Broken Function Level Authorization",
        "shortDescription": {"text": "RBAC/BFLA issue"},
        "properties": {"security-severity": "7.0"},
    },
    {
        "id": "RYNIX-STATIC-RISK",
        "name": "High Risk Surface",
        "shortDescription": {"text": "Static high-risk endpoint or pattern"},
        "properties": {"security-severity": "6.0"},
    },
    {
        "id": "RYNIX-STEALTH-BYPASS",
        "name": "Stealth Gate vs Auth Mismatch",
        "shortDescription": {"text": "Public stealth prefix but handler requires auth"},
        "properties": {"security-severity": "5.0"},
    },
    {
        "id": "RYNIX-STATIC-SECRET",
        "name": "Secret Pattern",
        "shortDescription": {"text": "Potential hardcoded secret"},
        "properties": {"security-severity": "9.0"},
    },
]


def severity_to_level(severity: str) -> str:
    s = severity.lower()
    if s in ("critical", "high"):
        return "error"
    if s == "medium":
        return "warning"
    return "note"


def export_sarif(findings: list[Finding], session_id: str) -> dict[str, Any]:
    results = []
    for f in findings:
        rule_id = "RYNIX-STATIC-RISK"
        title_lower = f.title.lower()
        if "idor" in title_lower or "bola" in title_lower:
            rule_id = "RYNIX-API1-IDOR"
        elif "auth" in title_lower:
            rule_id = "RYNIX-API2-AUTH"
        elif "rbac" in title_lower or "bfla" in title_lower:
            rule_id = "RYNIX-API5-BFLA"
        elif "stealth" in title_lower:
            rule_id = "RYNIX-STEALTH-BYPASS"

        results.append(
            {
                "ruleId": rule_id,
                "level": severity_to_level(f.severity),
                "message": {"text": f"{f.title}: {f.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.endpoint},
                        }
                    }
                ],
                "properties": {
                    "owasp": "API1:2023" if rule_id == "RYNIX-API1-IDOR" else "API2:2023",
                    "original_severity": f.severity,
                    "source_plugin": f.source_plugin,
                    "session_id": session_id,
                    "verified": f.verified,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Rynix",
                        "version": "0.1.0",
                        "rules": RULES,
                    }
                },
                "results": results,
            }
        ],
    }
