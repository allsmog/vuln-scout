#!/usr/bin/env python3
"""Prepare a batch of findings for Claude semantic analysis.

Reads .claude/findings.json, selects up to 20 unresolved findings,
builds structured analysis prompts, and writes the batch to
.claude/claude-analysis-batch.json for the command layer to process.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure sibling imports work.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tool_runners.claude_analyzer import prepare_analysis_batch
from artifact_utils import load_artifact


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: prepare_claude_batch.py <findings.json> [--output batch.json]", file=sys.stderr)
        return 1

    findings_path = sys.argv[1]
    output_path = ".claude/claude-analysis-batch.json"
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_path = sys.argv[idx + 1]

    artifact = load_artifact(findings_path)
    project_root = artifact.get("project_path", ".")
    entry_points = artifact.get("entry_points")

    batch = prepare_analysis_batch(
        artifact.get("findings", []),
        project_root,
        entry_points,
    )

    if not batch:
        print("No findings need Claude analysis.", file=sys.stderr)
        return 0

    # Write batch (strip the full finding object to keep prompts lean)
    output = []
    for item in batch:
        output.append({
            "finding_id": item["finding_id"],
            "prompt": item["prompt"],
        })

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(output, indent=2))
    print(f"Prepared {len(output)} findings for Claude analysis -> {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
