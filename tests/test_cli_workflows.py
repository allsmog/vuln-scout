from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "whitebox-pentest" / "scripts"
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "artifacts"

sys.path.insert(0, str(SCRIPTS_DIR))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scan_orchestrator = load_module("scan_orchestrator_cli", SCRIPTS_DIR / "scan_orchestrator.py")
run_diff = load_module("run_diff_cli", SCRIPTS_DIR / "run_diff.py")


class ScanCliParityTests(unittest.TestCase):
    def test_scan_help_includes_supported_public_flags(self):
        help_text = scan_orchestrator.build_arg_parser().format_help()

        self.assertIn("--workspace", help_text)
        self.assertIn("--no-claude-analysis", help_text)
        self.assertNotIn("--scope", help_text)

    def test_resolve_workspace_finds_nested_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            workspace = repo / "services" / "api"
            workspace.mkdir(parents=True)
            (workspace / "package.json").write_text("{}\n")

            resolved = scan_orchestrator.resolve_workspace(repo, "api")

            self.assertEqual(resolved, workspace.resolve())

    def test_resolve_target_path_rejects_scope_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope_file = Path(tmpdir) / ".claude" / "scope-api.md"
            scope_file.parent.mkdir(parents=True)
            scope_file.write_text("# saved scope\n")

            with self.assertRaisesRegex(ValueError, "scanner input"):
                scan_orchestrator.resolve_target_path(str(scope_file))


class ReportCliTests(unittest.TestCase):
    def test_report_cli_renders_markdown_and_html(self):
        artifact = FIXTURES_DIR / "sample-findings.json"
        script = SCRIPTS_DIR / "report.py"

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = Path(tmpdir) / "report.md"
            html_path = Path(tmpdir) / "report.html"

            md_result = subprocess.run(
                [sys.executable, str(script), str(artifact), "--format", "md", "--output", str(md_path)],
                capture_output=True,
                text=True,
            )
            html_result = subprocess.run(
                [sys.executable, str(script), str(artifact), "--format", "html", "--output", str(html_path)],
                capture_output=True,
                text=True,
            )

            self.assertEqual(md_result.returncode, 0, md_result.stderr)
            self.assertEqual(html_result.returncode, 0, html_result.stderr)
            self.assertIn("VulnScout Scan Report", md_path.read_text())
            self.assertIn("<html", html_path.read_text().lower())

    def test_report_cli_fail_on_returns_exit_2(self):
        artifact = FIXTURES_DIR / "sample-findings.json"
        script = SCRIPTS_DIR / "report.py"

        result = subprocess.run(
            [sys.executable, str(script), str(artifact), "--format", "json", "--fail-on", "high"],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn('"summary"', result.stdout)


class RunDiffCliTests(unittest.TestCase):
    def test_run_diff_markdown_output(self):
        baseline = {
            "findings": [
                {
                    "stable_key": "a",
                    "id": "VSCOUT-0001",
                    "type": "xss",
                    "severity": "low",
                    "file": "app.py",
                    "verdict": "unverified",
                    "kind": "finding",
                }
            ],
            "entry_points": [],
        }
        current = {
            "findings": [
                {
                    "stable_key": "a",
                    "id": "VSCOUT-0001",
                    "type": "xss",
                    "severity": "high",
                    "file": "app.py",
                    "verdict": "verified",
                    "kind": "finding",
                },
                {
                    "stable_key": "b",
                    "id": "VSCOUT-0002",
                    "type": "sql-injection",
                    "severity": "critical",
                    "file": "db.py",
                    "verdict": "unverified",
                    "kind": "finding",
                },
            ],
            "entry_points": [{"method": "GET", "path": "/admin"}],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "security-diff.md"
            argv = [
                "run_diff.py",
                "--base",
                "base",
                "--head",
                "head",
                "--format",
                "md",
                "--output",
                str(output_path),
            ]

            with mock.patch.object(run_diff, "_scan_ref", side_effect=[baseline, current]):
                with mock.patch.object(sys, "argv", argv):
                    exit_code = run_diff.main()

            text = output_path.read_text()
            self.assertEqual(exit_code, 0)
            self.assertIn("# VulnScout Security Diff", text)
            self.assertIn("## Changed Findings", text)
            self.assertIn("severity low -> high", text)
            self.assertNotIn('"new_findings"', text)


if __name__ == "__main__":
    unittest.main()
