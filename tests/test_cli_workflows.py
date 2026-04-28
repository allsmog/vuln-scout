from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "whitebox-pentest" / "scripts"
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "artifacts"
DEMO_DIR = ROOT / "demo" / "vulnerable-app"

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
semgrep_runner = load_module("semgrep_runner_cli", SCRIPTS_DIR / "tool_runners" / "semgrep_runner.py")
doctor = load_module("doctor_cli", SCRIPTS_DIR / "doctor.py")


class ScanCliParityTests(unittest.TestCase):
    def test_scan_help_includes_supported_public_flags(self):
        help_text = scan_orchestrator.build_arg_parser().format_help()

        self.assertIn("--profile", help_text)
        self.assertIn("--workspace", help_text)
        self.assertIn("--require-tools", help_text)
        self.assertIn("--custom-rules", help_text)
        self.assertIn("--extended-detectors", help_text)
        self.assertIn("--no-filter", help_text)
        self.assertIn("--no-claude-analysis", help_text)
        self.assertNotIn("--scope", help_text)

    def test_quick_profile_uses_bundled_local_rules(self):
        tools, rules = scan_orchestrator.resolve_profile_config("quick", None, None)

        self.assertEqual(tools, ["semgrep"])
        self.assertEqual(rules, str(scan_orchestrator.DEFAULT_LOCAL_RULES))
        self.assertTrue(Path(rules).exists())

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

    def test_scan_main_fails_when_requested_tool_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "app.py").write_text("print('hello')\n")
            argv = ["scan_orchestrator.py", str(target), "--tools", "semgrep"]

            with mock.patch.object(sys, "argv", argv):
                with mock.patch.object(scan_orchestrator.semgrep_runner, "is_available", return_value=True):
                    failed = scan_orchestrator.ToolRunResult([], [], ["semgrep"])
                    with mock.patch.object(scan_orchestrator, "run_tools", return_value=failed):
                        exit_code = scan_orchestrator.main()

            self.assertEqual(exit_code, 1)
            artifact_path = target / ".claude" / "findings.json"
            self.assertTrue(artifact_path.exists())
            artifact = json.loads(artifact_path.read_text())
            self.assertEqual(artifact["tool_status"]["failed"], ["semgrep"])
            self.assertEqual(artifact["tool_status"]["unavailable"], [])
            self.assertEqual(artifact["tool_status"]["by_tool"]["semgrep"]["state"], "failed")

    def test_tool_status_preserves_partial_analyzer_state(self):
        artifact = {}
        result = scan_orchestrator.ToolRunResult(
            findings=[],
            tools_succeeded=["codeql"],
            tools_failed=[],
            tool_statuses={
                "codeql": {
                    "tool": "codeql",
                    "state": "partially_skipped",
                    "findings": 1,
                    "languages": {
                        "python": {"state": "succeeded", "findings": 1},
                        "java": {"state": "timed_out", "findings": 0},
                    },
                }
            },
        )

        scan_orchestrator.attach_tool_status(artifact, ["codeql", "joern"], ["codeql"], result)

        self.assertEqual(artifact["tool_status"]["by_tool"]["codeql"]["state"], "partially_skipped")
        self.assertEqual(artifact["tool_status"]["by_tool"]["codeql"]["languages"]["java"]["state"], "timed_out")
        self.assertEqual(artifact["tool_status"]["by_tool"]["joern"]["state"], "unavailable")

    def test_detect_languages_excludes_analyzer_cache_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text("print('real')\n")
            codeql_copy = root / ".codeql" / "_source_views" / "old-python"
            codeql_copy.mkdir(parents=True)
            (codeql_copy / "app.py").write_text("print('copy')\n")
            joern_copy = root / ".joern" / "_source_views" / "old-go"
            joern_copy.mkdir(parents=True)
            (joern_copy / "main.go").write_text("package main\n")

            scope = scan_orchestrator.ScanScope(
                target_path=root,
                changed_files=None,
                excluded_patterns=list(scan_orchestrator.BASELINE_EXCLUDES),
                diff_ref=None,
            )
            languages = scan_orchestrator.detect_languages(scope)

            self.assertEqual(languages, {"python": ["app.py"]})

    def test_demo_quick_scan_writes_expected_offline_artifact(self):
        semgrep_payload = {
            "errors": [],
            "results": [
                {
                    "check_id": "vuln-scout.local.python.sql-fstring-execute",
                    "path": "app.py",
                    "start": {"line": 12},
                    "extra": {
                        "severity": "ERROR",
                        "message": "SQL injection risk",
                        "lines": "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
                        "metadata": {
                            "category": "security",
                            "confidence": "HIGH",
                            "cwe": ["CWE-89"],
                            "subcategory": ["vuln"],
                        },
                    },
                },
                {
                    "check_id": "vuln-scout.local.python.shell-true",
                    "path": "app.py",
                    "start": {"line": 18},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Command injection risk",
                        "lines": "os.system(f\"tar -czf /tmp/demo.tgz {target}\")",
                        "metadata": {
                            "category": "security",
                            "confidence": "HIGH",
                            "cwe": ["CWE-78"],
                            "subcategory": ["vuln"],
                        },
                    },
                },
                {
                    "check_id": "vuln-scout.local.javascript.inner-html-assignment",
                    "path": "public/app.js",
                    "start": {"line": 3},
                    "extra": {
                        "severity": "WARNING",
                        "message": "XSS risk",
                        "lines": "banner.innerHTML = name;",
                        "metadata": {
                            "category": "security",
                            "confidence": "MEDIUM",
                            "cwe": ["CWE-79"],
                            "subcategory": ["vuln"],
                        },
                    },
                },
                {
                    "check_id": "vuln-scout.local.javascript.express-open-redirect",
                    "path": "server.js",
                    "start": {"line": 7},
                    "extra": {
                        "severity": "WARNING",
                        "message": "Open redirect risk",
                        "lines": "res.redirect(req.query.next);",
                        "metadata": {
                            "category": "security",
                            "confidence": "MEDIUM",
                            "cwe": ["CWE-601"],
                            "subcategory": ["vuln"],
                        },
                    },
                },
            ],
        }
        commands: list[list[str]] = []
        envs: list[dict[str, str]] = []

        def fake_run(cmd, *args, **kwargs):
            commands.append(cmd)
            envs.append(kwargs.get("env", {}))
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout=json.dumps(semgrep_payload),
                stderr="",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "vulnerable-app"
            shutil.copytree(DEMO_DIR, target)
            output_path = Path(tmpdir) / "scan.json"
            argv = [
                "scan_orchestrator.py",
                str(target),
                "--profile",
                "quick",
                "--format",
                "json",
                "--output",
                str(output_path),
            ]

            with mock.patch.object(sys, "argv", argv):
                with mock.patch.object(scan_orchestrator.semgrep_runner, "is_available", return_value=True):
                    with mock.patch.object(scan_orchestrator.semgrep_runner.subprocess, "run", side_effect=fake_run):
                        with mock.patch.object(scan_orchestrator.rule_generator, "generate_rules", return_value=(None, [])):
                            with mock.patch.object(scan_orchestrator.vuln_class_detectors, "run_all_detectors", return_value=[]):
                                with mock.patch.object(scan_orchestrator.auto_propagate, "propagate", return_value=[]):
                                    with mock.patch.object(scan_orchestrator.entry_point_mapper, "discover_entry_points", return_value=[]):
                                        exit_code = scan_orchestrator.main()

            self.assertEqual(exit_code, 0)
            configs = [
                cmd[index + 1]
                for cmd in commands
                for index, part in enumerate(cmd)
                if part == "--config"
            ]
            self.assertIn(str(scan_orchestrator.DEFAULT_LOCAL_RULES), configs)
            self.assertNotIn("auto", configs)
            self.assertTrue(all("SEMGREP_LOG_FILE" in env for env in envs))

            artifact = json.loads((target / ".claude" / "findings.json").read_text())
            self.assertEqual(artifact["scan_profile"], "quick")
            self.assertEqual(artifact["summary"]["total_findings"], 4)
            self.assertEqual(artifact["summary"]["high"], 2)
            self.assertEqual(artifact["summary"]["medium"], 2)
            self.assertEqual(artifact["tool_status"]["succeeded"], ["semgrep"])
            self.assertEqual(artifact["tool_status"]["unavailable"], [])


class DoctorTests(unittest.TestCase):
    def test_doctor_reports_offline_ready_when_semgrep_and_local_rules_exist(self):
        def fake_which(binary: str):
            return f"/usr/bin/{binary}" if binary == "semgrep" else None

        with mock.patch.object(doctor.shutil, "which", side_effect=fake_which):
            with mock.patch.object(doctor, "_version", return_value="semgrep 1.0.0"):
                report = doctor.collect(check_network=False)

        self.assertTrue(report["offline_ready"])
        self.assertTrue(report["local_rules"]["exists"])
        semgrep = next(tool for tool in report["tools"] if tool["name"] == "semgrep")
        self.assertTrue(semgrep["available"])


class SemgrepRunnerTests(unittest.TestCase):
    def test_semgrep_runner_raises_on_invalid_json_output(self):
        completed = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=1,
            stdout="",
            stderr="PermissionError: cannot write semgrep.log",
        )

        with mock.patch.object(semgrep_runner.shutil, "which", return_value="/usr/bin/semgrep"):
            with mock.patch.object(semgrep_runner.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
                    semgrep_runner.run("/tmp/project")

    def test_semgrep_runner_accepts_noisy_stdout_with_json_payload(self):
        completed = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=0,
            stdout='status text\n{"results": [], "errors": []}\n',
            stderr="",
        )

        with mock.patch.object(semgrep_runner.shutil, "which", return_value="/usr/bin/semgrep"):
            with mock.patch.object(semgrep_runner.subprocess, "run", return_value=completed):
                self.assertEqual(semgrep_runner.run("/tmp/project"), [])


class KuzushiModuleTests(unittest.TestCase):
    def test_kuzushi_module_exports_all_commands(self):
        script = """
          const mod = await import('./kuzushi-module.js');
          console.log(JSON.stringify(mod.default.tools.map((tool) => tool.name).sort()));
        """
        result = subprocess.run(
            ["node", "-e", script],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        tools = json.loads(result.stdout)
        self.assertEqual(tools, sorted([
            "vuln-scout:audit",
            "vuln-scout:scan",
            "vuln-scout:trace",
            "vuln-scout:verify",
            "vuln-scout:sinks",
            "vuln-scout:fix",
            "vuln-scout:report",
            "vuln-scout:threats",
            "vuln-scout:scope",
            "vuln-scout:propagate",
            "vuln-scout:diff",
            "vuln-scout:create-rule",
            "vuln-scout:mutate",
        ]))


class PackageContentsTests(unittest.TestCase):
    def test_npm_package_contents_include_product_assets_and_exclude_caches(self):
        if shutil.which("npm") is None:
            self.skipTest("npm is not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                ["npm", "--cache", str(Path(tmpdir) / "npm-cache"), "pack", "--dry-run", "--json"],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        pack = json.loads(result.stdout)[0]
        paths = {entry["path"] for entry in pack["files"]}

        self.assertIn("whitebox-pentest/rules/vuln-scout-local.yml", paths)
        self.assertIn("whitebox-pentest/scripts/doctor.py", paths)
        self.assertIn("demo/vulnerable-app/README.md", paths)
        self.assertIn("docs/feature-maturity.md", paths)
        self.assertIn("docs/ci/github-actions.yml", paths)
        self.assertNotIn("tests/test_cli_workflows.py", paths)
        self.assertFalse(any("__pycache__" in path for path in paths))
        self.assertFalse(any(".pytest_cache" in path for path in paths))


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

    def test_report_cli_writes_evidence_bundle(self):
        artifact = FIXTURES_DIR / "sample-findings.json"
        suppressions = FIXTURES_DIR / "sample.vuln-scout-ignore"
        script = SCRIPTS_DIR / "report.py"

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "bundle"
            result = subprocess.run(
                [
                    sys.executable, str(script), str(artifact),
                    "--format", "bundle",
                    "--suppressions", str(suppressions),
                    "--output", str(output_dir),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("findings.json", "findings.sarif", "vex.json", "attestation.json", "README.md"):
                self.assertTrue((output_dir / name).exists(), name)

            findings = json.loads((output_dir / "findings.json").read_text())
            sarif = json.loads((output_dir / "findings.sarif").read_text())
            vex = json.loads((output_dir / "vex.json").read_text())
            attestation = json.loads((output_dir / "attestation.json").read_text())

            self.assertEqual(findings["summary"]["total_findings"], 1)
            self.assertEqual(len(sarif["runs"][0]["results"]), 1)
            self.assertEqual(vex["vulnerabilities"][0]["analysis"]["state"], "affected")
            self.assertEqual(attestation["suppressions"]["provided"], 1)
            self.assertEqual(attestation["suppressions"]["applied"], 1)
            self.assertRegex(attestation["source_artifact_sha256"], r"^[0-9a-f]{64}$")

    def test_report_cli_bundle_requires_output_directory(self):
        artifact = FIXTURES_DIR / "sample-findings.json"
        script = SCRIPTS_DIR / "report.py"

        missing_output = subprocess.run(
            [sys.executable, str(script), str(artifact), "--format", "bundle"],
            capture_output=True,
            text=True,
        )

        self.assertEqual(missing_output.returncode, 1)
        self.assertIn("--output is required", missing_output.stderr)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "bundle"
            output_file.write_text("not a directory\n")
            file_output = subprocess.run(
                [
                    sys.executable, str(script), str(artifact),
                    "--format", "bundle",
                    "--output", str(output_file),
                ],
                capture_output=True,
                text=True,
            )

        self.assertEqual(file_output.returncode, 1)
        self.assertIn("must be a directory", file_output.stderr)

    def test_report_cli_bundle_vex_statuses_follow_verdicts(self):
        script = SCRIPTS_DIR / "report.py"
        artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        artifact["findings"][0]["stable_key"] = "fixture:affected"
        artifact["findings"][0]["verdict"] = "verified"
        artifact["findings"][2]["stable_key"] = "fixture:not-affected"
        artifact["findings"][2]["verdict"] = "false_positive"
        artifact["findings"][2]["kind"] = "finding"
        artifact["summary"] = {
            "total_findings": 2, "total_hotspots": 1,
            "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_path = Path(tmpdir) / "findings.json"
            artifact_path.write_text(json.dumps(artifact))
            output_dir = Path(tmpdir) / "bundle"
            result = subprocess.run(
                [
                    sys.executable, str(script), str(artifact_path),
                    "--format", "bundle",
                    "--output", str(output_dir),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            states = [
                vulnerability["analysis"]["state"]
                for vulnerability in json.loads((output_dir / "vex.json").read_text())["vulnerabilities"]
            ]

        self.assertEqual(states, ["affected", "not_affected"])


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
