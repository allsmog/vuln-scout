#!/usr/bin/env python3
"""Render a VulnScout findings artifact into JSON, SARIF, Markdown, or HTML."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from artifact_utils import (
    SEVERITY_PRIORITY,
    apply_suppressions,
    dump_json,
    load_artifact,
    parse_suppressions,
    to_sarif,
    validate_findings_artifact,
)
from evidence_bundle import generate as generate_bundle, input_digest
from html_report import generate as generate_html
from markdown_report import generate as generate_markdown


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a VulnScout findings artifact.")
    parser.add_argument(
        "input",
        nargs="?",
        default=".claude/findings.json",
        help="Path to findings.json (default: .claude/findings.json)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file. Defaults to stdout for all formats.",
    )
    parser.add_argument(
        "--format",
        choices=["md", "json", "sarif", "html", "bundle"],
        default="md",
        help="Output format (default: md)",
    )
    parser.add_argument(
        "--suppressions",
        help="Optional suppression file in .vuln-scout-ignore format.",
    )
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITY_PRIORITY.keys()),
        help="Exit 2 when unsuppressed findings exist at or above this severity.",
    )
    return parser


def _render_content(artifact: dict, fmt: str) -> tuple[str | dict, bool]:
    if fmt == "json":
        return artifact, True
    if fmt == "sarif":
        return to_sarif(artifact), True
    if fmt == "html":
        return generate_html(artifact), False
    return generate_markdown(artifact), False


def _write_output(payload: str | dict, is_json: bool, output_path: str | None) -> None:
    if output_path:
        if is_json:
            dump_json(payload, output_path)
        else:
            Path(output_path).write_text(f"{payload}\n")
        return

    if is_json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(f"{payload}\n")


def _exit_code_for_fail_on(summary: dict[str, int], fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = SEVERITY_PRIORITY.get(fail_on, 0)
    for severity, priority in SEVERITY_PRIORITY.items():
        if priority >= threshold and summary.get(severity, 0) > 0:
            return 2
    return 0


def main() -> int:
    parser = build_arg_parser()
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

    if args.format == "bundle":
        if not args.output:
            print("error: --output is required when --format bundle", file=sys.stderr)
            return 1
        try:
            generate_bundle(
                artifact,
                args.output,
                input_digest(args.input),
                suppressions,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return _exit_code_for_fail_on(artifact["summary"], args.fail_on)

    payload, is_json = _render_content(artifact, args.format)
    _write_output(payload, is_json, args.output)
    return _exit_code_for_fail_on(artifact["summary"], args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
