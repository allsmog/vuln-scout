#!/usr/bin/env python3
"""Migrate VulnScout findings artifacts to schema v1.2.0."""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any


TARGET_SCHEMA_VERSION = "1.2.0"


def _first_sentence(value: str | None, max_chars: int) -> str:
    text = " ".join(str(value or "").split())
    if not text:
        return ""
    match = re.match(r"(.+?[.!?])(?:\s|$)", text)
    sentence = match.group(1) if match else text
    return sentence[:max_chars].rstrip()


def _contributors(finding: dict[str, Any]) -> list[str]:
    contributors = ["deterministic_tool"]
    if finding.get("claude_analysis"):
        contributors.append("llm_analysis")
    if finding.get("dynamic_verified"):
        contributors.append("dynamic_verified")
    return contributors


def _provenance(finding: dict[str, Any]) -> dict[str, Any]:
    claude_analysis = finding.get("claude_analysis")
    verification_level = int(finding.get("verification_level") or 0)

    if claude_analysis and verification_level >= 3:
        origin = "mixed"
    elif claude_analysis:
        origin = "llm_analysis"
    elif finding.get("dynamic_verified"):
        origin = "dynamic_verified"
    else:
        origin = "deterministic_tool"

    tool = "claude" if claude_analysis else str(finding.get("source_tool", "unknown"))
    return {
        "origin": origin,
        "tool": tool,
        "contributors": _contributors(finding),
    }


def _exploitability_status(finding: dict[str, Any]) -> str:
    claude_analysis = finding.get("claude_analysis") or {}
    fp_indicator = str(finding.get("fp_indicator", "")).lower()

    if claude_analysis.get("exploitable") is True or finding.get("dynamic_verified"):
        return "confirmed"
    if finding.get("verdict") == "false_positive" and re.search(r"sanitize|control", fp_indicator):
        return "blocked_by_control"
    if finding.get("verdict") == "false_positive" and re.search(r"unreachable|dead", fp_indicator):
        return "unreachable"
    if finding.get("verdict") == "needs_review":
        return "plausible"
    return "unknown"


def _false_positive_risk(finding: dict[str, Any]) -> dict[str, str]:
    fp_indicator = str(finding.get("fp_indicator", "")).strip()
    claude_analysis = finding.get("claude_analysis") or {}

    if fp_indicator:
        level = "high"
    elif finding.get("verdict") == "verified" and finding.get("confidence") in ("verified", "high"):
        level = "low"
    elif finding.get("verdict") == "needs_review":
        level = "medium"
    elif finding.get("confidence") == "low":
        level = "high"
    else:
        level = "unknown"

    reason = fp_indicator or _first_sentence(claude_analysis.get("reasoning"), 200)
    result = {"level": level}
    if reason:
        result["reason"] = reason
    return result


def build_trust_metadata(finding: dict[str, Any]) -> dict[str, Any]:
    claude_analysis = finding.get("claude_analysis") or {}
    source_tool = str(finding.get("source_tool", "unknown"))
    verification_level = int(finding.get("verification_level") or 0)
    confidence_reason = _first_sentence(claude_analysis.get("reasoning"), 280)
    if not confidence_reason:
        confidence_reason = f"Derived from {source_tool} at L{verification_level}"

    return {
        "provenance": _provenance(finding),
        "exploitability_status": _exploitability_status(finding),
        "false_positive_risk": _false_positive_risk(finding),
        "confidence_reason": confidence_reason,
    }


def migrate_to_1_2_0(artifact: dict[str, Any]) -> dict[str, Any]:
    if (
        artifact.get("schema_version") == TARGET_SCHEMA_VERSION
        and all("trust_metadata" in finding for finding in artifact.get("findings", []))
    ):
        return artifact

    migrated = copy.deepcopy(artifact)
    migrated["schema_version"] = TARGET_SCHEMA_VERSION
    for finding in migrated.get("findings", []):
        finding.setdefault("trust_metadata", build_trust_metadata(finding))
    return migrated


def _dump(artifact: dict[str, Any]) -> str:
    return json.dumps(artifact, indent=2, sort_keys=True) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Migrate VulnScout findings artifact to schema v1.2.0.")
    parser.add_argument("artifact", help="Path to findings.json")
    parser.add_argument("--in-place", action="store_true", help="Rewrite the artifact in place")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    path = Path(args.artifact)
    artifact = json.loads(path.read_text())
    migrated = migrate_to_1_2_0(artifact)
    already_current = migrated is artifact

    if args.in_place:
        if already_current:
            print("already at 1.2.0")
            return 0
        path.write_text(_dump(migrated))
        print(f"migrated {path} to 1.2.0")
        return 0

    if already_current:
        print("already at 1.2.0", file=sys.stderr)
    sys.stdout.write(_dump(migrated))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
