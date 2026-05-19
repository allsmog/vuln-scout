#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from artifact_utils import apply_suppressions, dump_json, load_artifact, parse_suppressions, to_sarif, validate_findings_artifact


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert VulnScout findings.json into SARIF.")
    parser.add_argument("input", help="Path to findings.json")
    parser.add_argument("-o", "--output", help="Output SARIF file. Defaults to stdout.")
    parser.add_argument(
        "--suppressions",
        help="Optional suppression file in .vuln-scout-ignore format.",
    )
    args = parser.parse_args()

    artifact = load_artifact(args.input)
    suppressions = parse_suppressions(args.suppressions)
    if suppressions:
        artifact = apply_suppressions(artifact, suppressions)

    errors = validate_findings_artifact(artifact)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    sarif = to_sarif(artifact)
    if args.output:
        dump_json(sarif, args.output)
    else:
        json.dump(sarif, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
