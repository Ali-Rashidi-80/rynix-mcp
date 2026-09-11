"""Static cloud/K8s/AWS/Azure posture probe for repo + deployment artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

K8S_MARKERS = ("apiVersion:", "kind:", "kubernetes", "helm", "kustomize", "namespace:")
AWS_MARKERS = ("aws_", "amazonaws.com", "s3://", "arn:aws:", "eks.", "elasticache")
AZURE_MARKERS = ("azurerm", "azure", "microsoft.com", "blob.core.windows.net", "aks")
DOCKER_MARKERS = ("docker-compose", "services:", "image:")


def _scan_file(path: Path) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {"k8s": [], "aws": [], "azure": [], "docker": []}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return hits
    rel = path.as_posix()
    if any(m in text for m in K8S_MARKERS):
        hits["k8s"].append(rel)
    if any(m in text for m in AWS_MARKERS):
        hits["aws"].append(rel)
    if any(m in text for m in AZURE_MARKERS):
        hits["azure"].append(rel)
    if any(m in text for m in DOCKER_MARKERS):
        hits["docker"].append(rel)
    return hits


def run_cloud_probe(repo_path: str | None) -> dict[str, Any]:
    if not repo_path:
        return {"pass": False, "scope": "none", "note": "no repo_path"}

    root = Path(repo_path)
    if not root.is_dir():
        return {"pass": False, "scope": "unknown", "error": "repo missing"}

    aggregate: dict[str, list[str]] = {"k8s": [], "aws": [], "azure": [], "docker": []}
    patterns = (
        "**/*.yaml",
        "**/*.yml",
        "**/*.tf",
        "**/*.tfvars",
        "**/Dockerfile*",
        "**/*.toml",
        "**/*.env*",
    )
    scanned = 0
    for pattern in patterns:
        for path in root.glob(pattern):
            if any(skip in path.parts for skip in (".git", "node_modules", ".venv", "__pycache__")):
                continue
            scanned += 1
            row = _scan_file(path)
            for key, vals in row.items():
                aggregate[key].extend(vals[:5])

    for key in aggregate:
        aggregate[key] = sorted(set(aggregate[key]))[:20]

    k8s_live = len(aggregate["k8s"]) > 0
    aws_live = len(aggregate["aws"]) > 0
    azure_live = len(aggregate["azure"]) > 0
    docker_live = len(aggregate["docker"]) > 0
    any_markers = k8s_live or aws_live or azure_live or docker_live

    if k8s_live:
        scope = "kubernetes"
    elif aws_live:
        scope = "aws"
    elif azure_live:
        scope = "azure"
    elif docker_live:
        scope = "docker-compose"
    else:
        scope = "none"

    return {
        "pass": True,
        "scope": scope,
        "files_scanned": scanned,
        "markers": aggregate,
        "k8s_deployed": k8s_live,
        "aws_references": aws_live,
        "azure_references": azure_live,
        "live_cloud_probe": False,
        "note": "Static artifact scan only — no live K8s/AWS/Azure API calls",
        "recommendations": _recommendations(scope, aggregate) if any_markers else [],
    }


def _recommendations(scope: str, markers: dict[str, list[str]]) -> list[str]:
    recs: list[str] = []
    if scope == "docker-compose":
        recs.append("WSTG cloud tests: N/A for live API — verify compose secrets not committed")
    if markers.get("aws"):
        recs.append("Review AWS refs in: " + ", ".join(markers["aws"][:3]))
    if markers.get("azure"):
        recs.append("Review Azure refs in: " + ", ".join(markers["azure"][:3]))
    if markers.get("k8s"):
        recs.append("K8s manifests found — run cluster RBAC review separately if deployed")
    return recs
