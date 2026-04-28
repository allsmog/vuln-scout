from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "whitebox-pentest" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


codeql_model_pack = load_module("codeql_model_pack_tests", SCRIPTS_DIR / "codeql_model_pack.py")


def _finding(
    *,
    finding_id: str = "VSCOUT-0001",
    file: str = "app.py",
    kind: str = "finding",
    verdict: str = "verified",
    verification_level: int = 1,
    suppressed: bool = False,
) -> dict:
    finding = {
        "id": finding_id,
        "stable_key": f"fixture:{finding_id}",
        "kind": kind,
        "severity": "high",
        "type": "sql-injection",
        "title": "SQL injection",
        "file": file,
        "line": 12,
        "verdict": verdict,
        "confidence": "high",
        "source_tool": "joern",
        "message": "Verified SQL injection",
        "verification_level": verification_level,
        "evidence": [{
            "type": "dataflow",
            "role": "sink",
            "label": "query sink",
            "path": file,
            "line": 12,
            "excerpt": "db.execute(query)",
        }],
    }
    if suppressed:
        finding["suppressed"] = True
    return finding


class CodeqlModelPackTests(unittest.TestCase):
    def test_verified_finding_produces_model_pack(self):
        artifact = {"findings": [_finding(file="app.py")]}

        with tempfile.TemporaryDirectory() as tmpdir:
            summary = codeql_model_pack.generate_model_packs(artifact, tmpdir)
            pack_dir = Path(tmpdir) / "vuln-scout-python-models"

            self.assertEqual(summary["packs"][0]["language"], "python")
            self.assertTrue((pack_dir / "qlpack.yml").exists())
            self.assertTrue((pack_dir / "models" / "vuln-scout-sinks.yml").exists())
            qlpack = (pack_dir / "qlpack.yml").read_text()
            model = (pack_dir / "models" / "vuln-scout-sinks.yml").read_text()

        self.assertIn("library: true", qlpack)
        self.assertIn("codeql/python-all", qlpack)
        self.assertIn("extensible: sinkModel", model)
        self.assertIn('"sql-injection"', model)

    def test_skips_suppressed_hotspot_unverified_and_false_positive(self):
        artifact = {
            "findings": [
                _finding(finding_id="suppressed", suppressed=True),
                _finding(finding_id="hotspot", kind="hotspot"),
                _finding(finding_id="unverified", verdict="unverified", verification_level=0),
                _finding(finding_id="false-positive", verdict="false_positive"),
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            summary = codeql_model_pack.generate_model_packs(artifact, tmpdir)

        self.assertEqual(summary["packs"], [])
        self.assertEqual(summary["skipped"]["ineligible"], 4)

    def test_unsupported_language_is_reported_but_not_fatal(self):
        artifact = {"findings": [_finding(file="contract.sol")]}

        with tempfile.TemporaryDirectory() as tmpdir:
            summary = codeql_model_pack.generate_model_packs(artifact, tmpdir)
            summary_file = json.loads((Path(tmpdir) / "summary.json").read_text())

        self.assertEqual(summary["packs"], [])
        self.assertEqual(summary["skipped"]["unsupported_language"], 1)
        self.assertEqual(summary_file["unsupported_languages"], [".sol"])

    def test_generates_javascript_pack_for_typescript(self):
        artifact = {"findings": [_finding(file="src/app.ts")]}

        with tempfile.TemporaryDirectory() as tmpdir:
            summary = codeql_model_pack.generate_model_packs(artifact, tmpdir)
            pack_dir = Path(tmpdir) / "vuln-scout-javascript-models"

            self.assertEqual(summary["packs"][0]["language"], "javascript")
            self.assertIn("codeql/javascript-all", (pack_dir / "qlpack.yml").read_text())


if __name__ == "__main__":
    unittest.main()
