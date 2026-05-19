#!/usr/bin/env python3
"""CLI wrapper for security mutation testing.

Finds security controls, temporarily weakens them, and checks if the
scanning pipeline detects the resulting vulnerability.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_mutator import find_mutations, mutation_report

log = logging.getLogger("vuln-scout")


def main() -> int:
    parser = argparse.ArgumentParser(description="Security mutation testing")
    parser.add_argument("path", nargs="?", default=".", help="Target directory")
    parser.add_argument("--dry-run", action="store_true", help="List mutations without testing")
    parser.add_argument("--format", choices=["json", "md"], default="md")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)

    # Find all possible mutations
    mutations = find_mutations(args.path)
    report = mutation_report(mutations)

    if args.dry_run:
        if args.format == "json":
            output = json.dumps(report, indent=2)
        else:
            output = _format_report_md(report)
        if args.output:
            Path(args.output).write_text(output)
        else:
            print(output)
        return 0

    # Test each mutation (apply -> scan -> check -> revert)
    detected = 0
    tested = 0
    results = []

    for mutation in mutations:
        file_path = Path(args.path) / mutation.file
        if not file_path.is_file():
            continue

        try:
            original_content = file_path.read_text()
        except OSError:
            continue

        # Apply mutation
        lines = original_content.splitlines()
        if mutation.line - 1 >= len(lines):
            continue

        lines[mutation.line - 1] = mutation.mutated
        mutated_content = "\n".join(lines) + "\n"

        try:
            file_path.write_text(mutated_content)
            tested += 1

            # Quick scan of the mutated file
            orchestrator = Path(__file__).resolve().parent / "scan_orchestrator.py"
            result = subprocess.run(
                [sys.executable, str(orchestrator), args.path,
                 "--tools", "semgrep", "--format", "json", "--output", "/dev/null"],
                capture_output=True, text=True, timeout=60,
            )

            # Check if the mutation was caught (any findings at the mutation location)
            was_detected = False
            try:
                scan_data = json.loads(result.stdout) if result.stdout.strip().startswith("{") else {}
                for f in scan_data.get("findings", []):
                    if f.get("file", "").endswith(mutation.file) and f.get("line") == mutation.line:
                        was_detected = True
                        break
            except (json.JSONDecodeError, KeyError):
                pass

            if was_detected:
                detected += 1

            results.append({
                "file": mutation.file,
                "line": mutation.line,
                "type": mutation.mutation_type,
                "detected": was_detected,
            })
        finally:
            # Always revert
            file_path.write_text(original_content)

    kill_rate = detected / tested if tested > 0 else 0
    summary = {
        "total_mutations": len(mutations),
        "tested": tested,
        "detected": detected,
        "undetected": tested - detected,
        "kill_rate": round(kill_rate, 3),
        "results": results,
    }

    if args.format == "json":
        output = json.dumps(summary, indent=2)
    else:
        output = f"# Security Mutation Testing Results\n\n"
        output += f"- **Total mutations found**: {len(mutations)}\n"
        output += f"- **Tested**: {tested}\n"
        output += f"- **Detected**: {detected}\n"
        output += f"- **Undetected (gaps)**: {tested - detected}\n"
        output += f"- **Kill rate**: {kill_rate:.1%}\n"

    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)

    return 0


def _format_report_md(report: dict) -> str:
    lines = [
        "# Security Mutation Report (Dry Run)",
        "",
        f"**Total mutations found**: {report['total_mutations']}",
        "",
        "| File | Line | Type | Description |",
        "|------|------|------|-------------|",
    ]
    for m in report.get("mutations", []):
        lines.append(f"| {m['file']} | {m['line']} | {m['type']} | {m['description']} |")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
