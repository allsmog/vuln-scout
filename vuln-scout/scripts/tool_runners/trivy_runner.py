"""Trivy tool runner for container and filesystem vulnerability scanning."""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")

name = "trivy"

# Map Trivy severity to VulnScout severity
_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high",
    "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info",
}


def is_available() -> bool:
    return shutil.which("trivy") is not None


def supported_languages() -> set[str]:
    return {"javascript", "typescript", "python", "go", "java", "ruby", "php", "rust"}


def run(target: str, scan_type: str = "fs", **kwargs: Any) -> list[dict[str, Any]]:
    """Run Trivy and return normalized findings.

    Args:
        target: Directory or container image to scan.
        scan_type: "fs" for filesystem, "image" for container image.
    """
    if not is_available():
        log.warning("trivy not installed, skipping")
        return []

    cmd = ["trivy", scan_type, "--format", "json", "--scanners", "vuln,secret",
           "--severity", "CRITICAL,HIGH,MEDIUM", target]

    log.info("Running trivy %s scan", scan_type)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        log.warning("trivy execution failed")
        return []

    if result.returncode not in (0, 1):
        log.warning("trivy error (exit %d): %s", result.returncode, result.stderr[:200])
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        log.warning("Failed to parse trivy output")
        return []

    return _normalize_findings(data)


def _normalize_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert Trivy JSON output to VulnScout finding format."""
    findings: list[dict[str, Any]] = []

    for result in data.get("Results", []):
        target_file = result.get("Target", "unknown")

        for vuln in result.get("Vulnerabilities", []):
            severity = _SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "info")
            cve_id = vuln.get("VulnerabilityID", "")
            pkg_name = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")

            title = f"{cve_id}: {pkg_name} {installed}"
            if fixed:
                title += f" (fix: {fixed})"

            findings.append({
                "id": "",
                "stable_key": "",
                "kind": "finding" if fixed else "hotspot",
                "severity": severity,
                "type": "vulnerable-dependency",
                "title": title,
                "file": target_file,
                "line": 0,
                "verdict": "unverified",
                "confidence": "high",
                "source_tool": "trivy",
                "message": vuln.get("Description", vuln.get("Title", cve_id))[:300],
                "cwe": "",
                "rule_id": cve_id,
                "evidence": [{
                    "type": "dependency-vuln",
                    "label": f"{pkg_name}@{installed}",
                    "path": target_file,
                    "line": 0,
                    "excerpt": f"Package: {pkg_name}\nInstalled: {installed}\nFixed: {fixed or 'N/A'}\nCVE: {cve_id}",
                }],
            })

        for secret in result.get("Secrets", []):
            findings.append({
                "id": "",
                "stable_key": "",
                "kind": "finding",
                "severity": "high",
                "type": "hardcoded-secret",
                "title": f"Secret found: {secret.get('Category', 'unknown')}",
                "file": target_file,
                "line": secret.get("StartLine", 0),
                "verdict": "unverified",
                "confidence": "high",
                "source_tool": "trivy",
                "message": f"Exposed {secret.get('Category', 'secret')} in {target_file}",
                "evidence": [{
                    "type": "secret",
                    "label": secret.get("Category", "secret"),
                    "path": target_file,
                    "line": secret.get("StartLine", 0),
                    "excerpt": secret.get("Match", "")[:100],
                }],
            })

    log.info("trivy returned %d findings", len(findings))
    return findings
