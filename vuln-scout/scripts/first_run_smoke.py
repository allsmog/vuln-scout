#!/usr/bin/env python3
"""First-run smoke test for VulnScout install paths."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "vuln-scout"
DEMO_ROOT = ROOT / "demo" / "vulnerable-app"


def _run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def _load_findings(findings_path: Path) -> dict:
    return json.loads(findings_path.read_text())


def _assert_demo_findings(artifact: dict) -> None:
    findings = artifact.get("findings", [])
    severities = [finding.get("severity") for finding in findings]
    expected = ["high", "high", "medium", "medium"]
    if len(findings) != 4 or severities != expected:
        raise AssertionError(f"expected 4 demo findings {expected}, got {severities}")


def _assert_bundle(bundle_path: Path) -> None:
    expected = {
        "findings.json",
        "findings.sarif",
        "vex.json",
        "attestation.json",
        "report.html",
        "README.md",
    }
    present = {path.name for path in bundle_path.iterdir()} if bundle_path.exists() else set()
    missing = sorted(expected - present)
    if missing:
        raise AssertionError(f"bundle missing files: {', '.join(missing)}")


def main() -> int:
    _run([sys.executable, str(PLUGIN_ROOT / "scripts" / "doctor.py"), "--json", "--strict"])
    with tempfile.TemporaryDirectory(prefix="vulnscout-first-run-") as tmpdir:
        workspace = Path(tmpdir) / "vulnerable-app"
        findings_path = workspace / ".claude" / "first-run.json"
        html_path = workspace / "first-run.html"
        bundle_path = workspace / "first-run-bundle"
        shutil.copytree(DEMO_ROOT, workspace, ignore=shutil.ignore_patterns(".claude", ".joern", "workspace"))
        _run([
            sys.executable,
            str(PLUGIN_ROOT / "scripts" / "scan_orchestrator.py"),
            str(workspace),
            "--profile",
            "quick",
            "--output",
            str(findings_path),
        ])
        _assert_demo_findings(_load_findings(findings_path))
        _run([
            sys.executable,
            str(PLUGIN_ROOT / "scripts" / "report.py"),
            str(findings_path),
            "--format",
            "html",
            "--output",
            str(html_path),
        ])
        _run([
            sys.executable,
            str(PLUGIN_ROOT / "scripts" / "report.py"),
            str(findings_path),
            "--format",
            "bundle",
            "--output",
            str(bundle_path),
        ])
        _assert_bundle(bundle_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
