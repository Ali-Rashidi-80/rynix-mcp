from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from rynix_mcp.browser_debug_delegate import browser_debug_delegate
from rynix_mcp.config import PLUGINS_DIR
from rynix_mcp.engagement_delegate import engagement_delegate
from rynix_mcp.guides_delegate import guides_delegate
from rynix_mcp.options_util import parse_options
from rynix_mcp.orchestrator_delegate import orchestrator_delegate
from rynix_mcp.sarif_import import merge_sarif_file
from rynix_mcp.session import STORE, Finding, new_finding_id
from rynix_mcp.template_scan import resolve_template_scan_bin, run_template_scan
from rynix_mcp.wstg_runner import run_wstg_suite

ALLOWED_BINARIES = frozenset({"template-scan", "npx", "uv", "rynix-scan"})


def _load_toml(path: Path) -> dict[str, Any] | None:
    import tomllib

    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
        return None


def list_plugin_manifests() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not PLUGINS_DIR.is_dir():
        return out
    for path in sorted(PLUGINS_DIR.glob("*.toml")):
        data = _load_toml(path)
        if not data:
            continue
        out.append(
            {
                "id": data.get("id", path.stem),
                "display_name": data.get("display_name", path.stem),
                "phase": data.get("phase", ""),
                "enabled": bool(data.get("enabled", False)),
                "mcp_tool": data.get("mcp_tool", ""),
            }
        )
    return out


def load_manifest(plugin_id: str) -> dict[str, Any] | None:
    if not plugin_id or "/" in plugin_id or "\\" in plugin_id or ".." in plugin_id:
        return None
    path = PLUGINS_DIR / f"{plugin_id}.toml"
    if not path.is_file():
        return None
    data = _load_toml(path)
    if not data:
        return None
    data["id"] = data.get("id", plugin_id)
    return data


def _validate_binary(binary: str) -> bool:
    return binary in ALLOWED_BINARIES


def plugin_health_check(plugin_id: str) -> dict[str, Any]:
    manifest = load_manifest(plugin_id)
    if not manifest:
        return {
            "error": {
                "code": "NOT_FOUND",
                "message": f"Plugin {plugin_id} not found",
                "retryable": False,
            }
        }

    binary = manifest.get("binary", "")
    if binary and not _validate_binary(binary):
        return {
            "error": {
                "code": "BINARY_DENIED",
                "message": f"Binary {binary} not in allowlist",
                "retryable": False,
            }
        }

    ok = True
    details: dict[str, Any] = {"plugin_id": plugin_id, "enabled": manifest.get("enabled", False)}

    if binary == "template-scan":
        resolved = resolve_template_scan_bin()
        details["binary"] = binary
        details["binary_found"] = resolved is not None
        details["binary_path"] = resolved
        if manifest.get("enabled") and not resolved:
            ok = False
            details["reason"] = (
                "template scanner not found — set RYNIX_TEMPLATE_SCAN_BIN or bin/template-scan"
            )
        if resolved:
            try:
                proc = subprocess.run(
                    [resolved, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False,
                )
                details["version_output"] = (proc.stdout or proc.stderr or "")[:200].strip()
            except Exception as exc:
                details["version_error"] = str(exc)
    elif binary:
        resolved = shutil.which(binary)
        details["binary"] = binary
        details["binary_found"] = resolved is not None
        details["binary_path"] = resolved
        if manifest.get("enabled") and not resolved:
            ok = False
            details["reason"] = f"{binary} not found on PATH"

    return {"ok": ok, **details}


def _record_plugin_findings(
    rows: list[dict[str, Any]], session_id: str | None, plugin_id: str
) -> list[str]:
    session = STORE.get(session_id)
    ids: list[str] = []
    for row in rows:
        fid = new_finding_id()
        sev = str(row.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        session.findings.append(
            Finding(
                id=fid,
                severity=sev,
                title=str(row.get("name") or row.get("template_id") or "plugin finding"),
                endpoint=str(row.get("matched_at") or ""),
                evidence=json.dumps(row, ensure_ascii=False)[:800],
                verified=False,
                source_plugin=plugin_id,
            )
        )
        ids.append(fid)
    if ids:
        session.audit_log("plugin_findings", {"plugin_id": plugin_id, "count": len(ids)})
    return ids


def run_wstg_checklist(category: str | None = None) -> dict[str, Any]:
    wstg_dir = Path(__file__).resolve().parent / "knowledge" / "wstg"
    if not wstg_dir.is_dir():
        return {
            "error": {"code": "KB_MISSING", "message": "WSTG knowledge missing", "retryable": False}
        }

    tests: list[dict[str, str]] = []
    for path in sorted(wstg_dir.rglob("WSTG-*.md")):
        rel = path.relative_to(wstg_dir)
        if category and category not in str(rel):
            continue
        tests.append({"test_id": path.stem.upper(), "path": rel.as_posix()})

    return {
        "plugin_id": "wstg",
        "category_filter": category,
        "count": len(tests),
        "tests": tests,
    }


def rynix_plugin_run(
    plugin_id: str,
    target_url: str | None = None,
    options: Any = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    manifest = load_manifest(plugin_id)
    if not manifest:
        return {
            "error": {
                "code": "NOT_FOUND",
                "message": f"Unknown plugin {plugin_id}",
                "retryable": False,
            }
        }

    tool = manifest.get("mcp_tool", "")
    opts = parse_options(options)

    if not manifest.get("enabled", False):
        action = str(opts.get("action", "health"))
        if plugin_id != "agent-orchestrator" or action != "health":
            return {
                "error": {
                    "code": "PLUGIN_DISABLED",
                    "message": f"{plugin_id} is disabled by manifest",
                    "retryable": False,
                }
            }

    if plugin_id == "template-scan" or tool == "plugin_template_scan":
        if not target_url:
            return {
                "error": {
                    "code": "MISSING_ARG",
                    "message": "target_url required for template-scan",
                    "retryable": False,
                }
            }
        return run_template_scan(
            target_url,
            templates=opts.get("templates", "http/cves/"),
            tags=opts.get("tags", ""),
            session_id=session_id,
        )

    if plugin_id == "wstg" or tool == "plugin_wstg_checklist":
        action = opts.get("action", "list")
        if action == "run":
            if not target_url:
                return {
                    "error": {
                        "code": "MISSING_ARG",
                        "message": "target_url required for wstg action=run",
                        "retryable": False,
                    }
                }
            return run_wstg_suite(
                target_url,
                repo_path=opts.get("repo_path"),
                frontend_url=opts.get("frontend_url"),
                idor_summary=opts.get("idor_summary"),
            )
        return run_wstg_checklist(opts.get("category"))

    if plugin_id == "engagement" or tool == "plugin_engagement_delegate":
        if "raw" in opts and "action" not in opts and "engagement_path" not in opts:
            opts = {"engagement_path": opts["raw"]}
        action = opts.get("action", "validate")
        return engagement_delegate(
            action=action,
            engagement_path=opts.get("engagement_path") or target_url,
            url=opts.get("url") or target_url,
            output_dir=opts.get("output_dir"),
            session_id=session_id,
            profile=opts.get("profile"),
        )

    if plugin_id == "sarif-import" or tool == "plugin_sarif_import":
        from rynix_mcp.path_safety import safe_sarif_input_path

        sarif_path = target_url
        if options:
            sarif_path = opts.get("sarif_path", sarif_path)
            if isinstance(options, str) and not sarif_path:
                sarif_path = options
        if not sarif_path:
            return {
                "error": {
                    "code": "MISSING_ARG",
                    "message": "options JSON {sarif_path: ...} required for sarif-import",
                    "retryable": False,
                }
            }
        try:
            resolved = safe_sarif_input_path(str(sarif_path))
        except ValueError as exc:
            return {
                "error": {
                    "code": "INVALID_PATH",
                    "message": str(exc),
                    "retryable": False,
                }
            }
        return merge_sarif_file(str(resolved), session_id=session_id, source_plugin="sarif-import")

    if plugin_id == "agent-guides" or tool == "plugin_agent_guides":
        if "raw" in opts and "action" not in opts:
            opts = {"action": opts["raw"]}
        profile_name = opts.get("profile")
        return guides_delegate(
            action=str(opts.get("action", "playbook")),
            target_url=opts.get("url") or target_url,
            session_id=session_id,
            scan_mode=str(opts.get("scan_mode", "standard")),
            repo_path=opts.get("repo_path"),
            profile=str(profile_name) if profile_name else None,
            vuln_class=opts.get("vuln_class"),
        )

    if plugin_id == "agent-orchestrator" or tool == "plugin_agent_orchestrator":
        action = str(opts.get("action", "health"))
        if not manifest.get("enabled", False) and action != "health":
            return {
                "error": {
                    "code": "PLUGIN_DISABLED",
                    "message": "agent-orchestrator disabled in manifest",
                    "retryable": False,
                }
            }
        return orchestrator_delegate(
            action=action,
            target_url=opts.get("url") or target_url,
            engagement_path=opts.get("engagement_path"),
        )

    if plugin_id == "browser-debug" or tool == "plugin_browser_debug":
        if not manifest.get("enabled", False):
            return {
                "error": {
                    "code": "PLUGIN_DISABLED",
                    "message": "browser-debug disabled in manifest",
                    "retryable": False,
                }
            }
        return browser_debug_delegate(
            action=str(opts.get("action", "health")),
            target_url=opts.get("url") or target_url,
        )

    # Phase L plugins — routed when manifests exist
    if plugin_id == "pipeline-runner":
        from rynix_mcp.pipeline_delegate import pipeline_delegate

        return pipeline_delegate(
            action=str(opts.get("action", "status")), session_id=session_id, opts=opts
        )

    if plugin_id == "cyber-range":
        from rynix_mcp.cyber_range_delegate import cyber_range_delegate

        return cyber_range_delegate(action=str(opts.get("action", "list_scenarios")), opts=opts)

    if plugin_id == "whitebox-scan":
        from rynix_mcp.whitebox_delegate import whitebox_delegate

        return whitebox_delegate(
            action=str(opts.get("action", "queue_from_repo")),
            session_id=session_id,
            repo_path=opts.get("repo_path"),
            opts=opts,
        )

    if manifest.get("never_default") and not manifest.get("enabled", False):
        return {
            "error": {
                "code": "PLUGIN_DISABLED",
                "message": f"Plugin {plugin_id} is optional; set enabled=true in manifest",
                "retryable": False,
            }
        }

    return {
        "error": {
            "code": "UNSUPPORTED",
            "message": f"Plugin {plugin_id} has no runner (manifest tool={tool})",
            "retryable": False,
        }
    }
