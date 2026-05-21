#!/usr/bin/env python3
"""CLI wrapper for differential security analysis.

Scans two git refs and computes a security diff showing new/fixed/changed
findings and a regression score.
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_mutator import diff_security, diff_to_dict
from artifact_utils import load_artifact

log = logging.getLogger("vuln-scout")


def _render_markdown(result: dict[str, object]) -> str:
    details = result.get("details", {})
    changed = details.get("changed", [])
    lines = [
        "# VulnScout Security Diff",
        "",
        "## Summary",
        f"- New findings: {result.get('new_findings', 0)}",
        f"- Fixed findings: {result.get('fixed_findings', 0)}",
        f"- Changed findings: {result.get('changed_findings', 0)}",
        f"- Regression score: {result.get('regression_score', 0):+}",
        "",
    ]

    def append_bucket(title: str, entries: list[dict[str, object]]) -> None:
        lines.append(f"## {title}")
        if not entries:
            lines.append("- None")
            lines.append("")
            return
        for entry in entries:
            severity = entry.get("severity", "info")
            finding_type = entry.get("type", "unknown")
            file_path = entry.get("file", "?")
            finding_id = entry.get("id", "?")
            lines.append(f"- `{finding_id}` `{severity}` `{finding_type}` in `{file_path}`")
        lines.append("")

    append_bucket("New Findings", details.get("new", []))
    append_bucket("Fixed Findings", details.get("fixed", []))

    lines.append("## Changed Findings")
    if not changed:
        lines.append("- None")
    else:
        for item in changed:
            finding = item.get("finding", {})
            finding_id = finding.get("id", "?")
            file_path = finding.get("file", "?")
            changes = item.get("changes", {})
            change_parts: list[str] = []
            if "severity" in changes:
                severity = changes["severity"]
                change_parts.append(f"severity {severity.get('old')} -> {severity.get('new')}")
            if "verdict" in changes:
                verdict = changes["verdict"]
                change_parts.append(f"verdict {verdict.get('old')} -> {verdict.get('new')}")
            if "kind" in changes:
                kind = changes["kind"]
                change_parts.append(f"kind {kind.get('old')} -> {kind.get('new')}")
            lines.append(f"- `{finding_id}` in `{file_path}`: {', '.join(change_parts)}")
    lines.append("")

    lines.append("## Endpoint Changes")
    new_endpoints = result.get("new_endpoints", [])
    removed_endpoints = result.get("removed_endpoints", [])
    if not new_endpoints and not removed_endpoints:
        lines.append("- None")
        lines.append("")
        return "\n".join(lines)

    if new_endpoints:
        lines.append("### New Endpoints")
        for endpoint in new_endpoints:
            lines.append(f"- `{endpoint.get('method', 'ALL')}` `{endpoint.get('path', '?')}`")
    if removed_endpoints:
        lines.append("### Removed Endpoints")
        for endpoint in removed_endpoints:
            lines.append(f"- `{endpoint.get('method', 'ALL')}` `{endpoint.get('path', '?')}`")
    lines.append("")
    return "\n".join(lines)


def _resolve_repo_context(project_root: str) -> tuple[Path, Path]:
    project_path = Path(project_root).resolve()
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        cwd=str(project_path),
    )
    if result.returncode != 0:
        raise RuntimeError(f"Could not resolve git repo for {project_root}")

    repo_root = Path(result.stdout.strip()).resolve()
    try:
        project_subpath = project_path.relative_to(repo_root)
    except ValueError as exc:
        raise RuntimeError(f"Project root {project_path} is outside repo {repo_root}") from exc

    return repo_root, project_subpath


def _extract_archive(archive_bytes: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise RuntimeError(f"Unsafe path in git archive: {member.name}")
        archive.extractall(destination)


def _export_ref_snapshot(ref: str, repo_root: Path, destination: Path) -> Path:
    result = subprocess.run(
        ["git", "archive", "--format=tar", ref],
        capture_output=True,
        cwd=str(repo_root),
    )
    if result.returncode != 0:
        raise RuntimeError(f"git archive failed for {ref}: {(result.stderr or b'')[:200]!r}")
    _extract_archive(result.stdout, destination)
    return destination


def _run_scan(scan_root: Path, tools: str, output_path: str) -> dict | None:
    orchestrator = Path(__file__).resolve().parent / "scan_orchestrator.py"
    cmd = [
        sys.executable, str(orchestrator), str(scan_root),
        "--tools", tools, "--format", "json", "--output", output_path,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode not in (0, 2):
        log.warning("Scan failed for %s: %s", scan_root, result.stderr[:200])
        return None
    return load_artifact(output_path)


def _scan_ref(
    ref: str,
    project_root: str,
    tools: str,
    *,
    scan_runner=_run_scan,
) -> dict | None:
    """Materialize a git ref into a snapshot and run the scan orchestrator."""
    try:
        repo_root, project_subpath = _resolve_repo_context(project_root)
        with tempfile.TemporaryDirectory(prefix="vuln-scout-diff-") as snapshot_dir, tempfile.TemporaryDirectory(
            prefix="vuln-scout-diff-out-"
        ) as output_dir:
            snapshot_root = _export_ref_snapshot(ref, repo_root, Path(snapshot_dir))
            scan_root = snapshot_root / project_subpath if project_subpath != Path(".") else snapshot_root
            if not scan_root.exists():
                log.info("Project path %s does not exist in ref %s; treating as empty scan", project_subpath, ref)
                return {"findings": []}
            output_path = str(Path(output_dir) / "findings.json")
            return scan_runner(scan_root, tools, output_path)
    except Exception as e:
        log.warning("Failed to scan ref %s: %s", ref, e)
        return None


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Differential security analysis")
    parser.add_argument("--base", required=True, help="Base git ref")
    parser.add_argument("--head", default="HEAD", help="Head git ref (default: HEAD)")
    parser.add_argument("--tools", default="semgrep", help="Scanning tools")
    parser.add_argument("--project-root", default=".", help="Project root")
    parser.add_argument("--format", choices=["json", "md"], default="json")
    parser.add_argument("--fail-on-regression", action="store_true")
    parser.add_argument("--output", default=".claude/security-diff.json")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)

    # Scan both refs
    log.info("Scanning base ref: %s", args.base)
    baseline = _scan_ref(args.base, args.project_root, args.tools)

    log.info("Scanning head ref: %s", args.head)
    current = _scan_ref(args.head, args.project_root, args.tools)

    if not baseline or not current:
        log.error("Could not scan both refs")
        return 1

    # Compute diff
    diff = diff_security(current, baseline)
    result = diff_to_dict(diff)

    # Write output
    content = json.dumps(result, indent=2) if args.format == "json" else _render_markdown(result)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(content + "\n")
    log.info("Wrote security diff to %s", args.output)
    print(content)

    # Exit code
    if args.fail_on_regression and diff.regression_score > 0:
        log.warning("Regression detected: score=%+.1f", diff.regression_score)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
