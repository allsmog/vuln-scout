from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "whitebox-pentest" / "scripts"
JOERN_DIR = SCRIPTS_DIR / "joern"

sys.path.insert(0, str(SCRIPTS_DIR))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


poc_generator = load_module("poc_generator_hardening", SCRIPTS_DIR / "poc_generator.py")
entry_point_mapper = load_module("entry_point_mapper_hardening", SCRIPTS_DIR / "entry_point_mapper.py")
create_cpg = load_module("create_cpg_hardening", SCRIPTS_DIR / "create_cpg.py")
api_spec_parser = load_module("api_spec_parser_hardening", SCRIPTS_DIR / "api_spec_parser.py")
run_diff = load_module("run_diff_hardening", SCRIPTS_DIR / "run_diff.py")
batch_verify = load_module("batch_verify_hardening", SCRIPTS_DIR / "batch_verify.py")
joern_runner = load_module(
    "joern_runner_hardening",
    SCRIPTS_DIR / "tool_runners" / "joern_runner.py",
)


class PocHardeningTests(unittest.TestCase):
    def test_generate_poc_treats_metadata_as_data(self):
        finding = {
            "id": "VSCOUT-1",
            "type": "ssrf",
            "file": "app.py",
            "line": 7,
            "title": 'demo"""\nimport os\nos.system("echo pwned")\n#',
            "cvss_score": 9.1,
        }
        entry_points = [{
            "file": "app.py",
            "path": '/x"\nimport os\nos.system("echo pwned")\n#',
        }]

        script = poc_generator.generate_poc(finding, entry_points)

        self.assertIsNotNone(script)
        ast.parse(script)
        self.assertNotIn('\nimport os\n', script)
        self.assertIn("json.loads(", script)

    def test_generate_all_pocs_sanitizes_output_filename(self):
        finding = {
            "id": "../../very bad id",
            "type": "sql-injection",
            "file": "api.py",
            "line": 3,
            "title": "SQL injection",
            "cvss_score": 9.8,
            "verdict": "verified",
            "severity": "critical",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            generated = poc_generator.generate_all_pocs([finding], tmpdir)

            self.assertEqual(len(generated), 1)
            self.assertEqual(generated[0]["file"], ".claude/pocs/poc_very_bad_id.py")
            self.assertTrue((Path(tmpdir) / ".claude" / "pocs" / "poc_very_bad_id.py").exists())


class PathHardeningTests(unittest.TestCase):
    def test_entry_point_mapper_skips_external_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            external = root / "external.ts"
            external.write_text('app.get("/outside", handler)\n')
            repo = root / "repo"
            repo.mkdir()
            (repo / "linked.ts").symlink_to(external)

            entries = entry_point_mapper.discover_entry_points(str(repo), frameworks=["express"])

            self.assertEqual(entries, [])

    def test_entry_point_mapper_allows_internal_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            real_file = repo / "routes.ts"
            real_file.write_text('app.get("/inside", handler)\n')
            (repo / "linked.ts").symlink_to(real_file)

            entries = entry_point_mapper.discover_entry_points(str(repo), frameworks=["express"])

            self.assertTrue(any(entry.file == "linked.ts" for entry in entries))

    def test_create_cpg_hash_ignores_external_symlink_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo = root / "repo"
            repo.mkdir()
            (repo / "safe.py").write_text("print('safe')\n")
            external = root / "outside.py"
            external.write_text("print('v1')\n")
            (repo / "linked.py").symlink_to(external)

            first = create_cpg.compute_source_hash(str(repo), "python")
            external.write_text("print('v2')\n")
            second = create_cpg.compute_source_hash(str(repo), "python")

            self.assertEqual(first, second)

    def test_api_spec_discovery_skips_external_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            external = root / "openapi.json"
            external.write_text('{"openapi": "3.0.0", "paths": {}}')
            repo = root / "repo"
            repo.mkdir()
            (repo / "spec.json").symlink_to(external)

            specs = api_spec_parser.discover_specs(str(repo))

            self.assertEqual(specs, [])


class RunDiffHardeningTests(unittest.TestCase):
    def _git(self, repo: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def test_scan_ref_uses_snapshots_for_each_ref(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            self._git(repo, "init")
            self._git(repo, "config", "user.email", "audit@example.com")
            self._git(repo, "config", "user.name", "Audit Bot")

            project_root = repo / "service"
            project_root.mkdir()
            app_file = project_root / "app.py"

            app_file.write_text("print('base')\n")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "base")
            base_ref = self._git(repo, "rev-parse", "HEAD")

            app_file.write_text("print('head')\n")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "head")
            head_ref = self._git(repo, "rev-parse", "HEAD")

            seen: list[tuple[Path, str]] = []

            def fake_scan(scan_root: Path, tools: str, output_path: str):
                seen.append((scan_root.resolve(), (scan_root / "app.py").read_text().strip()))
                return {"findings": [{"stable_key": (scan_root / "app.py").read_text().strip()}]}

            baseline = run_diff._scan_ref(base_ref, str(project_root), "semgrep", scan_runner=fake_scan)
            current = run_diff._scan_ref(head_ref, str(project_root), "semgrep", scan_runner=fake_scan)

            self.assertIsNotNone(baseline)
            self.assertIsNotNone(current)
            self.assertEqual([content for _, content in seen], ["print('base')", "print('head')"])
            self.assertTrue(all(path != project_root.resolve() for path, _ in seen))
            self.assertNotEqual(seen[0][0], seen[1][0])


class JoernBundleHardeningTests(unittest.TestCase):
    def _predictable_bundle_path(self, script_name: str) -> Path:
        return Path("/tmp") / f"bundled-{script_name}"

    def test_joern_runner_avoids_predictable_bundle_path(self):
        victim_dir = tempfile.TemporaryDirectory()
        self.addCleanup(victim_dir.cleanup)
        victim = Path(victim_dir.name) / "victim.txt"
        victim.write_text("ORIGINAL")

        legacy_path = self._predictable_bundle_path("verify-generic.sc")
        if legacy_path.exists() or legacy_path.is_symlink():
            legacy_path.unlink()
        legacy_path.symlink_to(victim)
        self.addCleanup(lambda: legacy_path.unlink(missing_ok=True))

        fake_result = subprocess.CompletedProcess(
            args=["joern"],
            returncode=0,
            stdout='{"verdict":"VERIFIED","confidence":1.0}',
            stderr="",
        )

        with mock.patch.object(joern_runner.subprocess, "run", return_value=fake_result):
            result = joern_runner._run_verify(
                "fake.cpg",
                JOERN_DIR / "verify-generic.sc",
                "app.py",
                1,
                1,
            )

        self.assertIsNotNone(result)
        self.assertEqual(victim.read_text(), "ORIGINAL")

    def test_batch_verify_avoids_predictable_bundle_path(self):
        victim_dir = tempfile.TemporaryDirectory()
        self.addCleanup(victim_dir.cleanup)
        victim = Path(victim_dir.name) / "victim.txt"
        victim.write_text("ORIGINAL")

        legacy_path = self._predictable_bundle_path("verify-generic.sc")
        if legacy_path.exists() or legacy_path.is_symlink():
            legacy_path.unlink()
        legacy_path.symlink_to(victim)
        self.addCleanup(lambda: legacy_path.unlink(missing_ok=True))

        fake_result = subprocess.CompletedProcess(
            args=["joern"],
            returncode=0,
            stdout='{"verdict":"VERIFIED","confidence":1.0}',
            stderr="",
        )

        with mock.patch.object(batch_verify.subprocess, "run", return_value=fake_result):
            result = batch_verify.run_single_verify(
                "fake.cpg",
                JOERN_DIR / "verify-generic.sc",
                "app.py",
                1,
                1,
            )

        self.assertIsNotNone(result)
        self.assertEqual(victim.read_text(), "ORIGINAL")


if __name__ == "__main__":
    unittest.main()
