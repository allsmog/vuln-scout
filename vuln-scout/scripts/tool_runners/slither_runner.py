"""Slither tool runner for Solidity smart contract analysis.

Slither is the standard static analyzer for Solidity, detecting reentrancy,
access control, integer overflow, and dozens of other smart contract
vulnerability patterns with higher precision than generic Semgrep rules.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")

name = "slither"

# Map Slither detector impact to VulnScout severity
_IMPACT_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}

# Map Slither confidence to VulnScout confidence
_CONFIDENCE_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
}

# Map Slither detector names to VulnScout vulnerability types
_TYPE_MAP: dict[str, str] = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    "uninitialized-state": "access-control",
    "uninitialized-local": "access-control",
    "arbitrary-send-eth": "access-control",
    "arbitrary-send-erc20": "access-control",
    "controlled-delegatecall": "delegatecall",
    "delegatecall-loop": "delegatecall",
    "suicidal": "access-control",
    "unprotected-upgrade": "access-control",
    "tx-origin": "access-control",
    "unchecked-transfer": "reentrancy",
    "unchecked-lowlevel": "reentrancy",
    "unchecked-send": "reentrancy",
    "weak-prng": "insecure-randomness",
    "integer-overflow": "integer-overflow",
    "integer-underflow": "integer-overflow",
    "divide-before-multiply": "integer-overflow",
    "locked-ether": "access-control",
    "shadowing-state": "access-control",
    "shadowing-local": "access-control",
    "timestamp": "insecure-randomness",
    "assembly": "code-injection",
    "erc20-interface": "security-misconfiguration",
    "erc721-interface": "security-misconfiguration",
    "incorrect-equality": "integer-overflow",
    "tautology": "security-misconfiguration",
    "boolean-cst": "security-misconfiguration",
}


def is_available() -> bool:
    return shutil.which("slither") is not None


def supported_languages() -> set[str]:
    return {"solidity"}


def run(target: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Run Slither and return normalized findings.

    Args:
        target: Directory containing Solidity files, or a specific .sol file.
    """
    if not is_available():
        log.warning("slither not installed, skipping")
        return []

    target_path = Path(target).resolve()

    # Check if there are any .sol files
    if target_path.is_dir():
        sol_files = list(target_path.rglob("*.sol"))
        if not sol_files:
            log.info("slither: no .sol files found, skipping")
            return []

    cmd = [
        "slither", str(target_path),
        "--json", "-",  # Output JSON to stdout
        "--no-fail",    # Don't fail on compilation errors
    ]

    log.info("Running slither on %s", target_path)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        log.warning("slither timed out (300s)")
        return []
    except FileNotFoundError:
        log.warning("slither binary not found")
        return []

    # Slither outputs JSON to stdout when --json - is used
    stdout = result.stdout.strip()
    if not stdout:
        # Try stderr -- some versions output JSON there
        stdout = result.stderr.strip()

    if not stdout or not stdout.startswith("{"):
        log.info("slither: no JSON output (compilation issues or no findings)")
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        log.warning("Failed to parse slither JSON output")
        return []

    return _normalize_findings(data, target_path)


def _normalize_findings(data: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    """Convert Slither JSON output to VulnScout finding format."""
    findings: list[dict[str, Any]] = []

    if not data.get("success"):
        log.warning("slither reported compilation errors")

    for detector_result in data.get("results", {}).get("detectors", []):
        impact = detector_result.get("impact", "Medium")
        confidence = detector_result.get("confidence", "Medium")
        check = detector_result.get("check", "unknown")
        description = detector_result.get("description", "")

        severity = _IMPACT_MAP.get(impact, "medium")
        vuln_confidence = _CONFIDENCE_MAP.get(confidence, "medium")
        vuln_type = _TYPE_MAP.get(check, check)

        # Extract file and line from elements
        elements = detector_result.get("elements", [])
        file_path = "unknown"
        line_number = 0
        evidence: list[dict[str, Any]] = []

        for element in elements:
            source_mapping = element.get("source_mapping", {})
            elem_file = source_mapping.get("filename_relative", "")
            elem_line = source_mapping.get("lines", [0])[0] if source_mapping.get("lines") else 0

            if file_path == "unknown" and elem_file:
                file_path = elem_file
                line_number = elem_line

            # Build evidence from each element
            elem_type = element.get("type", "")
            elem_name = element.get("name", "")
            snippet = element.get("source_mapping", {}).get("filename_relative", "")

            evidence.append({
                "type": "slither-element",
                "label": f"{elem_type}: {elem_name}" if elem_name else elem_type,
                "path": elem_file or file_path,
                "line": elem_line,
                "excerpt": description[:200] if not evidence else f"{elem_type} {elem_name}",
            })

        if not evidence:
            evidence.append({
                "type": "slither-detector",
                "label": check,
                "path": file_path,
                "line": line_number,
                "excerpt": description[:200],
            })

        # Determine kind: high-impact verified patterns are findings
        kind = "finding" if impact in ("High", "Medium") and confidence == "High" else "hotspot"

        findings.append({
            "id": "",
            "stable_key": "",
            "kind": kind,
            "severity": severity,
            "type": vuln_type,
            "title": f"Slither: {check} ({impact} impact)",
            "file": file_path,
            "line": line_number,
            "verdict": "unverified",
            "confidence": vuln_confidence,
            "source_tool": "slither",
            "message": description[:300],
            "rule_id": f"slither/{check}",
            "evidence": evidence,
        })

    log.info("slither returned %d findings", len(findings))
    return findings
