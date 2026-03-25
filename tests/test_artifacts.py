from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "whitebox-pentest" / "scripts"
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "artifacts"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


artifact_utils = load_module("artifact_utils", SCRIPTS_DIR / "artifact_utils.py")
deduplicate_findings = artifact_utils.deduplicate_findings


class ArtifactTests(unittest.TestCase):
    def test_sample_artifact_matches_schema_contract(self) -> None:
        artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        errors = artifact_utils.validate_findings_artifact(artifact)
        self.assertEqual(errors, [])

    def test_suppressions_recompute_summary(self) -> None:
        artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        suppressions = artifact_utils.parse_suppressions(FIXTURES_DIR / "sample.vuln-scout-ignore")
        updated = artifact_utils.apply_suppressions(artifact, suppressions)

        self.assertTrue(updated["findings"][2]["suppressed"])
        self.assertEqual(updated["summary"]["total_findings"], 1)
        self.assertEqual(updated["summary"]["high"], 0)
        self.assertEqual(updated["summary"]["total_hotspots"], 1)

    def test_sarif_conversion_emits_only_reportable_findings(self) -> None:
        artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        sarif = artifact_utils.to_sarif(artifact)
        self.assertEqual(sarif["version"], "2.1.0")

        run = sarif["runs"][0]
        self.assertEqual(len(run["results"]), 2)
        uris = [result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in run["results"]]
        self.assertNotIn("tests/fixtures/code/js/nextjs-redirect/app/actions.ts", uris)

    def test_deduplication_merges_same_stable_key(self):
        findings = [
            {
                "id": "1",
                "stable_key": "abc123",
                "kind": "finding",
                "severity": "medium",
                "type": "sql-injection",
                "title": "SQLi",
                "file": "app.py",
                "line": 10,
                "verdict": "unverified",
                "confidence": "medium",
                "source_tool": "semgrep",
                "message": "Possible SQLi",
                "evidence": [{"type": "source", "label": "input", "path": "app.py", "line": 10, "excerpt": "req.args"}],
            },
            {
                "id": "2",
                "stable_key": "abc123",
                "kind": "finding",
                "severity": "high",
                "type": "sql-injection",
                "title": "SQLi",
                "file": "app.py",
                "line": 10,
                "verdict": "verified",
                "confidence": "high",
                "source_tool": "joern",
                "message": "Confirmed SQLi",
                "evidence": [{"type": "sink", "label": "query", "path": "app.py", "line": 12, "excerpt": "db.query()"}],
            },
        ]
        result = deduplicate_findings(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["verdict"], "verified")
        self.assertEqual(result[0]["severity"], "high")
        self.assertEqual(result[0]["source_tool"], "multi")
        self.assertEqual(len(result[0]["evidence"]), 2)

    def test_empty_findings_list_validates(self) -> None:
        artifact = {
            "schema_version": "1.0.0",
            "scan_id": "test-empty",
            "project_path": "/tmp/test",
            "completed_at": "2026-01-01T00:00:00Z",
            "source_tool": "test",
            "summary": {
                "total_findings": 0,
                "total_hotspots": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "findings": [],
        }
        errors = artifact_utils.validate_findings_artifact(artifact)
        self.assertEqual(errors, [])

    def test_missing_required_key_fails_validation(self) -> None:
        artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        del artifact["schema_version"]
        errors = artifact_utils.validate_findings_artifact(artifact)
        self.assertTrue(len(errors) > 0, "Should fail when schema_version is missing")

    def test_stable_key_deterministic(self) -> None:
        finding = {
            "source_tool": "semgrep", "kind": "finding", "type": "sql-injection",
            "file": "app.py", "line": 10, "rule_id": "sqli-001", "title": "SQLi",
        }
        key1 = artifact_utils.stable_key_for(finding)
        key2 = artifact_utils.stable_key_for(finding)
        self.assertEqual(key1, key2)

    def test_stable_key_changes_with_different_input(self) -> None:
        finding1 = {
            "source_tool": "semgrep", "kind": "finding", "type": "sql-injection",
            "file": "app.py", "line": 10, "rule_id": "sqli-001", "title": "SQLi",
        }
        finding2 = {
            "source_tool": "semgrep", "kind": "finding", "type": "sql-injection",
            "file": "app.py", "line": 20, "rule_id": "sqli-001", "title": "SQLi",
        }
        key1 = artifact_utils.stable_key_for(finding1)
        key2 = artifact_utils.stable_key_for(finding2)
        self.assertNotEqual(key1, key2)

    def test_dedup_single_finding_unchanged(self) -> None:
        findings = [{
            "id": "1", "stable_key": "abc", "kind": "finding", "severity": "high",
            "type": "xss", "title": "XSS", "file": "a.js", "line": 1,
            "verdict": "verified", "confidence": "high", "source_tool": "semgrep",
            "message": "XSS", "evidence": [{"type": "source", "label": "x", "path": "a.js", "line": 1, "excerpt": "x"}],
        }]
        result = deduplicate_findings(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source_tool"], "semgrep")

    def test_cli_writes_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "findings.sarif.json"
            artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
            sarif = artifact_utils.to_sarif(artifact)
            artifact_utils.dump_json(sarif, output_path)
            written = json.loads(output_path.read_text())
            self.assertEqual(written["runs"][0]["tool"]["driver"]["name"], "VulnScout")


if __name__ == "__main__":
    unittest.main()
