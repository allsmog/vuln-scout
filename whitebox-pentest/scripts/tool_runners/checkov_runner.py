"""Checkov tool runner for Infrastructure as Code scanning.

Scans Terraform, CloudFormation, Kubernetes manifests, Dockerfiles, and
Helm charts for security misconfigurations.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")

name = "checkov"

_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high",
    "MEDIUM": "medium", "LOW": "low", "INFO": "info",
}


def is_available() -> bool:
    return shutil.which("checkov") is not None


def supported_languages() -> set[str]:
    return set()  # IaC scanner, not language-specific


def run(target: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Run Checkov and return normalized findings."""
    if not is_available():
        log.warning("checkov not installed, skipping")
        return []

    cmd = ["checkov", "-d", target, "--output", "json", "--quiet", "--compact"]

    log.info("Running checkov IaC scan")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        log.warning("checkov execution failed")
        return []

    # Checkov returns exit code 1 when findings exist.
    # Empty stdout or non-JSON output means nothing to scan.
    stdout = result.stdout.strip()
    if not stdout or stdout == "[]" or not stdout.startswith(("{", "[")):
        log.info("checkov: no IaC files to scan (empty output)")
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        log.warning("Failed to parse checkov output: %s", stdout[:200])
        return []

    return _normalize_findings(data, target)


def _normalize_findings(data: Any, target: str) -> list[dict[str, Any]]:
    """Convert Checkov JSON output to VulnScout finding format."""
    findings: list[dict[str, Any]] = []
    root = Path(target).resolve()

    # Checkov output can be a list of framework results or a single object
    results_list = data if isinstance(data, list) else [data]

    for framework_result in results_list:
        if not isinstance(framework_result, dict):
            continue

        for check in framework_result.get("results", {}).get("failed_checks", []):
            check_id = check.get("check_id", "")
            check_name = check.get("check_result", {}).get("name", check.get("name", check_id))
            file_path = check.get("file_path", "unknown")
            file_line = check.get("file_line_range", [0, 0])
            line = file_line[0] if file_line else 0
            severity = _SEVERITY_MAP.get(
                check.get("severity", check.get("check_result", {}).get("severity", "MEDIUM")),
                "medium",
            )
            guideline = check.get("guideline", "")

            # Make path relative
            try:
                rel_path = str(Path(file_path).relative_to(root))
            except ValueError:
                rel_path = file_path.lstrip("/")

            # Map common Checkov IDs to vulnerability types
            vuln_type = _map_check_type(check_id, check_name)

            findings.append({
                "id": "",
                "stable_key": "",
                "kind": "finding",
                "severity": severity,
                "type": vuln_type,
                "title": f"{check_id}: {check_name}"[:200],
                "file": rel_path,
                "line": line,
                "verdict": "unverified",
                "confidence": "high",
                "source_tool": "checkov",
                "message": f"{check_name}. {guideline}"[:300] if guideline else check_name,
                "rule_id": check_id,
                "evidence": [{
                    "type": "iac-check",
                    "label": check_id,
                    "path": rel_path,
                    "line": line,
                    "excerpt": f"Check: {check_id}\nResource: {check.get('resource', 'unknown')}",
                }],
            })

    log.info("checkov returned %d findings", len(findings))
    return findings


def _map_check_type(check_id: str, check_name: str) -> str:
    """Map Checkov check IDs/names to VulnScout vulnerability types."""
    name_lower = check_name.lower()
    if any(w in name_lower for w in ("encryption", "encrypt", "tls", "ssl", "kms")):
        return "security-misconfiguration"
    if any(w in name_lower for w in ("public", "exposed", "open", "ingress")):
        return "security-misconfiguration"
    if any(w in name_lower for w in ("secret", "credential", "password", "key")):
        return "hardcoded-secret"
    if any(w in name_lower for w in ("privileged", "root", "admin", "rbac", "iam")):
        return "security-misconfiguration"
    if any(w in name_lower for w in ("logging", "audit", "monitor")):
        return "logging-failure"
    return "iac-misconfiguration"
