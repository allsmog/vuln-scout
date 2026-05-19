#!/usr/bin/env python3
"""Generate a CI-friendly VulnScout evidence bundle."""
from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from artifact_utils import dump_json, stable_key_for, to_sarif


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def input_digest(path: str | Path) -> str:
    """Return a SHA-256 digest for the source artifact."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _unsuppressed_findings(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        finding for finding in artifact.get("findings", [])
        if finding.get("kind") == "finding" and not finding.get("suppressed")
    ]


def _vex_state(finding: dict[str, Any]) -> str:
    if finding.get("dynamic_verified") or finding.get("verdict") == "verified":
        return "affected"
    if finding.get("verdict") == "false_positive":
        return "not_affected"
    return "under_investigation"


def _cwe_numbers(finding: dict[str, Any]) -> list[int]:
    cwe = finding.get("cwe")
    if not cwe:
        return []
    values = cwe if isinstance(cwe, list) else [cwe]
    numbers: list[int] = []
    for value in values:
        digits = "".join(ch for ch in str(value) if ch.isdigit())
        if digits:
            numbers.append(int(digits))
    return numbers


def _evidence_summary(finding: dict[str, Any]) -> str:
    parts = []
    for evidence in finding.get("evidence", [])[:5]:
        label = evidence.get("label") or evidence.get("type") or "evidence"
        path = evidence.get("path") or finding.get("file") or ""
        line = evidence.get("line") or 0
        excerpt = str(evidence.get("excerpt", "")).strip().replace("\n", " ")
        parts.append(f"{label} at {path}:{line}: {excerpt[:160]}")
    return " | ".join(parts)


def build_vex(artifact: dict[str, Any], generated_at: str | None = None) -> dict[str, Any]:
    """Build a compact CycloneDX-style VEX document from a findings artifact."""
    generated_at = generated_at or _utc_now()
    project_path = artifact.get("project_path", "")
    project_name = Path(project_path).name if project_path else "unknown-project"

    vulnerabilities = []
    for finding in _unsuppressed_findings(artifact):
        stable_key = stable_key_for(finding)
        vulnerability: dict[str, Any] = {
            "id": stable_key,
            "source": {"name": "VulnScout"},
            "description": finding.get("message", finding.get("title", "")),
            "analysis": {
                "state": _vex_state(finding),
                "detail": _evidence_summary(finding),
            },
            "affects": [{"ref": project_name}],
            "properties": [
                {"name": "vuln-scout:id", "value": str(finding.get("id", ""))},
                {"name": "vuln-scout:type", "value": str(finding.get("type", ""))},
                {"name": "vuln-scout:severity", "value": str(finding.get("severity", ""))},
                {"name": "vuln-scout:verdict", "value": str(finding.get("verdict", ""))},
                {"name": "vuln-scout:file", "value": str(finding.get("file", ""))},
                {"name": "vuln-scout:line", "value": str(finding.get("line", 0))},
            ],
        }
        cwes = _cwe_numbers(finding)
        if cwes:
            vulnerability["cwes"] = cwes
        if finding.get("cvss_score") is not None:
            vulnerability["ratings"] = [{
                "method": "CVSSv31",
                "score": finding.get("cvss_score"),
                "vector": finding.get("cvss_vector", ""),
                "severity": finding.get("severity", ""),
            }]
        vulnerabilities.append(vulnerability)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "component": {
                "type": "application",
                "name": project_name,
                "bom-ref": project_name,
            },
            "tools": [{"vendor": "VulnScout", "name": "vuln-scout"}],
        },
        "vulnerabilities": vulnerabilities,
    }


def build_attestation(
    artifact: dict[str, Any],
    source_digest: str,
    suppressions: dict[str, str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build bundle metadata that is easy to audit in CI."""
    generated_at = generated_at or _utc_now()
    suppressions = suppressions or {}
    applied = [
        stable_key_for(finding)
        for finding in artifact.get("findings", [])
        if finding.get("suppressed")
    ]
    return {
        "attestation_type": "vuln-scout.evidence-bundle",
        "generated_at": generated_at,
        "source_artifact_sha256": source_digest,
        "schema_version": artifact.get("schema_version"),
        "scan_id": artifact.get("scan_id"),
        "project_path": artifact.get("project_path"),
        "scan_profile": artifact.get("scan_profile"),
        "source_tool": artifact.get("source_tool"),
        "summary": artifact.get("summary", {}),
        "tool_status": artifact.get("tool_status", {}),
        "suppressions": {
            "provided": len(suppressions),
            "applied": len(applied),
            "applied_keys": sorted(applied),
        },
        "bundle_files": [
            "findings.json",
            "findings.sarif",
            "vex.json",
            "attestation.json",
            "README.md",
        ],
    }


def _readme(artifact: dict[str, Any], generated_at: str) -> str:
    summary = artifact.get("summary", {})
    return "\n".join([
        "# VulnScout Evidence Bundle",
        "",
        f"Generated: {generated_at}",
        f"Scan ID: {artifact.get('scan_id', '')}",
        f"Project: {artifact.get('project_path', '')}",
        "",
        "## Contents",
        "",
        "- `findings.json` - Validated VulnScout findings artifact after suppressions.",
        "- `findings.sarif` - SARIF 2.1.0 output for code scanning integrations.",
        "- `vex.json` - CycloneDX-style exploitability statements for reportable findings.",
        "- `attestation.json` - Tool status, counts, suppressions, and input artifact digest.",
        "",
        "## Summary",
        "",
        f"- Findings: {summary.get('total_findings', 0)}",
        f"- Hotspots: {summary.get('total_hotspots', 0)}",
        f"- Critical: {summary.get('critical', 0)}",
        f"- High: {summary.get('high', 0)}",
        f"- Medium: {summary.get('medium', 0)}",
        f"- Low: {summary.get('low', 0)}",
        f"- Info: {summary.get('info', 0)}",
        "",
    ])


def generate(
    artifact: dict[str, Any],
    output_dir: str | Path,
    source_digest: str,
    suppressions: dict[str, str] | None = None,
) -> dict[str, Path]:
    """Write the evidence bundle and return created file paths."""
    output_path = Path(output_dir)
    if output_path.exists() and not output_path.is_dir():
        raise ValueError(f"bundle output must be a directory: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)

    generated_at = _utc_now()
    normalized_artifact = copy.deepcopy(artifact)
    vex = build_vex(normalized_artifact, generated_at)
    attestation = build_attestation(normalized_artifact, source_digest, suppressions, generated_at)

    paths = {
        "findings": output_path / "findings.json",
        "sarif": output_path / "findings.sarif",
        "vex": output_path / "vex.json",
        "attestation": output_path / "attestation.json",
        "readme": output_path / "README.md",
    }
    dump_json(normalized_artifact, paths["findings"])
    dump_json(to_sarif(normalized_artifact), paths["sarif"])
    dump_json(vex, paths["vex"])
    dump_json(attestation, paths["attestation"])
    paths["readme"].write_text(_readme(normalized_artifact, generated_at))
    return paths
