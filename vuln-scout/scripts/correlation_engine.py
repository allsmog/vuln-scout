#!/usr/bin/env python3
"""Cross-tool finding correlation and confidence cascade.

Implements the three-phase confidence cascade:
  Phase 1: Fast triage (Semgrep) -- already done by the tool runner.
  Phase 2: Targeted deep analysis (Joern queries from Semgrep findings).
  Phase 3: Cross-tool correlation (this module).

The correlation engine compares findings from multiple tools at the same
code location and adjusts confidence based on corroboration.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("vuln-scout")

# Corroboration thresholds
MULTI_TOOL_CONFIDENCE = "high"         # 2+ tools agree → high confidence
SINGLE_TOOL_VERIFIED_CONFIDENCE = "high"  # 1 tool + CPG verified
SINGLE_TOOL_UNVERIFIED_CONFIDENCE = "medium"  # 1 tool, no CPG


def correlate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Adjust confidence based on cross-tool corroboration.

    Findings at the same (file, line, type) from different tools get boosted
    confidence.  Findings from only one tool without verification get lower
    confidence.

    This runs AFTER deduplication (which merges same stable_key), so we
    check the ``source_tool`` field -- ``"multi"`` means multiple tools
    agreed on this location.
    """
    boosted = 0
    lowered = 0

    for f in findings:
        # Already verified by CPG -- trust the verdict
        if f.get("verdict") in ("verified", "false_positive"):
            continue

        tool = f.get("source_tool", "")
        current_confidence = f.get("confidence", "medium")

        if tool == "multi":
            # Multiple tools agree → boost to high confidence
            if current_confidence != "high" and current_confidence != "verified":
                f["confidence"] = MULTI_TOOL_CONFIDENCE
                boosted += 1

        elif f.get("verdict") == "unverified" and f.get("kind") == "finding":
            # Single tool, unverified finding -- keep medium but flag
            if current_confidence == "high":
                f["confidence"] = SINGLE_TOOL_UNVERIFIED_CONFIDENCE
                lowered += 1

    if boosted or lowered:
        log.info("Correlation: boosted %d findings, lowered %d", boosted, lowered)

    return findings


def generate_targeted_joern_params(
    semgrep_findings: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Generate parameters for targeted Joern queries based on Semgrep findings.

    For each Semgrep finding, extract the sink location and vulnerability type
    so that Joern can run a focused dataflow trace instead of scanning the
    entire CPG.

    Returns:
        List of dicts with keys: file, line, type, sink_excerpt, rule_id.
        Each entry represents a target for a focused Joern verification query.
    """
    targets: list[dict[str, str]] = []
    seen = set()

    for f in semgrep_findings:
        if f.get("source_tool") != "semgrep":
            continue
        if f.get("verdict") != "unverified":
            continue

        key = (f.get("file", ""), f.get("line", 0), f.get("type", ""))
        if key in seen:
            continue
        seen.add(key)

        # Extract a brief code excerpt for targeted Joern focus
        excerpt = ""
        for ev in f.get("evidence", []):
            if ev.get("excerpt"):
                excerpt = ev["excerpt"][:100]
                break

        targets.append({
            "file": str(f.get("file", "")),
            "line": str(f.get("line", 0)),
            "type": str(f.get("type", "")),
            "sink_excerpt": excerpt,
            "rule_id": str(f.get("rule_id", "")),
        })

    log.info("Generated %d targeted Joern query parameters from Semgrep findings", len(targets))
    return targets


# Mapping from vuln type to Joern verify script name
VULN_TYPE_TO_JOERN_SCRIPT: dict[str, str] = {
    "sql-injection": "verify-sqli.sc",
    "command-injection": "verify-cmdi.sc",
    "xss": "verify-xss.sc",
    "path-traversal": "verify-path.sc",
    "ssrf": "verify-ssrf.sc",
    "ssti": "verify-ssti.sc",
    "xxe": "verify-xxe.sc",
    "deserialization": "verify-deser.sc",
    "ldap-injection": "verify-ldap.sc",
    "insecure-randomness": "verify-randomness.sc",
}


def select_joern_script(vuln_type: str) -> str:
    """Return the appropriate Joern verification script for a vulnerability type."""
    return VULN_TYPE_TO_JOERN_SCRIPT.get(vuln_type, "verify-generic.sc")
