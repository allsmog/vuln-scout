#!/usr/bin/env python3
"""First-run smoke test for VulnScout install paths."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "vuln-scout"
FINDINGS_PATH = Path("/tmp/first-run.json")
HTML_PATH = Path("/tmp/first-run.html")
BUNDLE_PATH = Path("/tmp/first-run-bundle")


def _run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def _load_findings() -> dict:
    return json.loads(FINDINGS_PATH.read_text())


def _assert_demo_findings(artifact: dict) -> None:
    findings = artifact.get("findings", [])
    severities = [finding.get("severity") for finding in findings]
    expected = ["high", "high", "medium", "medium"]
    if len(findings) != 4 or severities != expected:
        raise AssertionError(f"expected 4 demo findings {expected}, got {severities}")


def _assert_bundle() -> None:
    expected = {
        "findings.json",
        "findings.sarif",
        "vex.json",
        "attestation.json",
        "report.html",
        "README.md",
    }
    present = {path.name for path in BUNDLE_PATH.iterdir()} if BUNDLE_PATH.exists() else set()
    missing = sorted(expected - present)
    if missing:
        raise AssertionError(f"bundle missing files: {', '.join(missing)}")


def main() -> int:
    _run([sys.executable, str(PLUGIN_ROOT / "scripts" / "doctor.py"), "--json", "--strict"])
    _run([
        sys.executable,
        str(PLUGIN_ROOT / "scripts" / "scan_orchestrator.py"),
        "demo/vulnerable-app",
        "--profile",
        "quick",
        "--output",
        str(FINDINGS_PATH),
    ])
    _assert_demo_findings(_load_findings())
    _run([
        sys.executable,
        str(PLUGIN_ROOT / "scripts" / "report.py"),
        str(FINDINGS_PATH),
        "--format",
        "html",
        "--output",
        str(HTML_PATH),
    ])
    _run([
        sys.executable,
        str(PLUGIN_ROOT / "scripts" / "report.py"),
        str(FINDINGS_PATH),
        "--format",
        "bundle",
        "--output",
        str(BUNDLE_PATH),
    ])
    _assert_bundle()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
