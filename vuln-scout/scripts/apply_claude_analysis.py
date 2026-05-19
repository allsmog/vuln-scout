#!/usr/bin/env python3
"""Apply Claude analysis results back to findings.json.

Reads .claude/findings.json and .claude/claude-analysis-results.json,
parses each response, updates verdicts/confidence/evidence, recalculates
summary and verification levels, and writes the updated findings.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure sibling imports work.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tool_runners.claude_analyzer import parse_analysis_response, apply_analysis
from artifact_utils import (
    summarize_findings,
    apply_verification_levels,
    dump_json,
)


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: apply_claude_analysis.py <findings.json> <results.json>", file=sys.stderr)
        return 1

    findings_path = Path(sys.argv[1])
    results_path = Path(sys.argv[2])

    if not findings_path.exists():
        print(f"Findings not found: {findings_path}", file=sys.stderr)
        return 1
    if not results_path.exists():
        print(f"Results not found: {results_path}", file=sys.stderr)
        return 1

    artifact = json.loads(findings_path.read_text())
    results = json.loads(results_path.read_text())

    # Index findings by ID for fast lookup
    findings_by_id: dict[str, dict] = {}
    for f in artifact.get("findings", []):
        findings_by_id[f.get("id", "")] = f

    applied = 0
    failed = 0
    for result in results:
        finding_id = result.get("finding_id", "")
        response_text = result.get("response_text", "")

        if not finding_id or not response_text:
            continue

        finding = findings_by_id.get(finding_id)
        if not finding:
            print(f"  Finding {finding_id} not found, skipping", file=sys.stderr)
            failed += 1
            continue

        analysis = parse_analysis_response(response_text)
        if not analysis:
            print(f"  Could not parse response for {finding_id}, skipping", file=sys.stderr)
            failed += 1
            continue

        apply_analysis(finding, analysis)
        applied += 1

    # Recalculate verification levels and summary
    findings = artifact.get("findings", [])
    apply_verification_levels(findings)
    artifact["summary"] = summarize_findings(findings)

    # Write updated artifact
    dump_json(artifact, str(findings_path))
    print(f"Applied {applied} Claude analyses ({failed} failed) -> {findings_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
