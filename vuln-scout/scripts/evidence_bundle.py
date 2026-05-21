#!/usr/bin/env python3
"""Generate a CI-friendly VulnScout evidence bundle."""
from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from artifact_utils import dump_json, stable_key_for, to_sarif
from html_report import generate as generate_html


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
    exploitability = (finding.get("trust_metadata") or {}).get("exploitability_status")
    if exploitability == "confirmed":
        return "affected"
    if exploitability in ("blocked_by_control", "unreachable"):
        return "not_affected"
    if exploitability in ("plausible", "requires_auth"):
        return "under_investigation"
    if finding.get("dynamic_verified") or finding.get("verdict") == "verified":
        return "affected"
    if finding.get("verdict") == "false_positive":
        return "not_affected"
    return "under_investigation"


def _vex_justification(finding: dict[str, Any]) -> str | None:
    exploitability = (finding.get("trust_metadata") or {}).get("exploitability_status")
    if exploitability == "blocked_by_control":
        return "protected_by_mitigating_control"
    if exploitability == "unreachable":
        return "code_not_reachable"
    if exploitability == "requires_auth":
        return "requires_environment"
    return None


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
        state = _vex_state(finding)
        justification = _vex_justification(finding)
        trust = finding.get("trust_metadata") or {}
        confidence_reason = str(trust.get("confidence_reason", ""))
        evidence_summary = _evidence_summary(finding)
        analysis = {
            "state": state,
            "detail": "; ".join([confidence_reason, evidence_summary]).strip("; "),
            "response": [],
        }
        if state == "not_affected" and justification:
            analysis["justification"] = justification
        vulnerability: dict[str, Any] = {
            "id": stable_key,
            "source": {"name": "VulnScout"},
            "description": finding.get("message", finding.get("title", "")),
            "analysis": analysis,
            "affects": [{"ref": project_name}],
            "properties": [
                {"name": "vuln-scout:id", "value": str(finding.get("id", ""))},
                {"name": "vuln-scout:type", "value": str(finding.get("type", ""))},
                {"name": "vuln-scout:severity", "value": str(finding.get("severity", ""))},
                {"name": "vuln-scout:verdict", "value": str(finding.get("verdict", ""))},
                {"name": "vuln-scout:file", "value": str(finding.get("file", ""))},
                {"name": "vuln-scout:line", "value": str(finding.get("line", 0))},
                {"name": "vuln-scout:provenance", "value": str((trust.get("provenance") or {}).get("origin", ""))},
                {"name": "vuln-scout:fp_risk", "value": str((trust.get("false_positive_risk") or {}).get("level", ""))},
                {"name": "vuln-scout:exploitability_status", "value": str(trust.get("exploitability_status", ""))},
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
    provenance_counts: dict[str, int] = {}
    fp_risk_counts: dict[str, int] = {}
    inferred_trust_metadata = 0
    for finding in artifact.get("findings", []):
        trust = finding.get("trust_metadata") or {}
        provenance = str((trust.get("provenance") or {}).get("origin", "unknown"))
        fp_risk = str((trust.get("false_positive_risk") or {}).get("level", "unknown"))
        if trust.get("inferred_from_legacy_artifact"):
            inferred_trust_metadata += 1
        provenance_counts[provenance] = provenance_counts.get(provenance, 0) + 1
        fp_risk_counts[fp_risk] = fp_risk_counts.get(fp_risk, 0) + 1
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
        "trust_model_summary": {
            "provenance": dict(sorted(provenance_counts.items())),
            "fp_risk": dict(sorted(fp_risk_counts.items())),
            "inferred_from_legacy_artifact": inferred_trust_metadata,
        },
        "bundle_files": [
            "findings.json",
            "findings.sarif",
            "vex.json",
            "attestation.json",
            "report.html",
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
        "- `report.html` - Self-contained human-readable HTML report.",
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
        "## Trust Model",
        "",
        "Findings may include trust metadata for provenance, false-positive risk, exploitability status, and confidence rationale.",
        "VEX states prefer this trust metadata when present.",
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
        "html": output_path / "report.html",
        "readme": output_path / "README.md",
    }
    dump_json(normalized_artifact, paths["findings"])
    dump_json(to_sarif(normalized_artifact), paths["sarif"])
    dump_json(vex, paths["vex"])
    dump_json(attestation, paths["attestation"])
    paths["html"].write_text(generate_html(normalized_artifact) + "\n")
    paths["readme"].write_text(_readme(normalized_artifact, generated_at))
    return paths
