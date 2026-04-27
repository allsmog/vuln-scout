from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "whitebox-pentest"
FIXTURES = ROOT / "tests" / "fixtures" / "code"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


consistency = load_module("check_consistency", PLUGIN_ROOT / "scripts" / "check_consistency.py")


class RepoContractTests(unittest.TestCase):
    def test_consistency_script_passes(self) -> None:
        self.assertEqual(consistency.validate(), [])

    def test_language_fixtures_exist(self) -> None:
        expected = {"js", "python", "go", "java", "solidity", "ruby"}
        actual = {path.name for path in FIXTURES.iterdir() if path.is_dir()}
        self.assertTrue(expected.issubset(actual))

    def test_full_audit_uses_hotspots_for_framework_pivots(self) -> None:
        text = (PLUGIN_ROOT / "commands" / "full-audit.md").read_text().lower()
        self.assertIn("record a hotspot", text)
        self.assertIn("do not escalate it to a reportable finding", text)

    def test_full_audit_references_shared_prompt_fragments(self) -> None:
        text = (PLUGIN_ROOT / "commands" / "full-audit.md").read_text()
        for fragment in ("phases.md", "artifact-contract.md", "safety.md"):
            path = PLUGIN_ROOT / "references" / "full-audit" / fragment
            self.assertTrue(path.exists())
            self.assertIn(f"references/full-audit/{fragment}", text)

    def test_trace_command_requires_evidence_per_hop(self) -> None:
        text = (PLUGIN_ROOT / "commands" / "trace.md").read_text()
        for phrase in ("Language-specific tracing templates", "Source evidence", "Hop chain", "Exploitability evidence"):
            self.assertIn(phrase, text)

    def test_joern_helpers_are_language_aware(self) -> None:
        common = (PLUGIN_ROOT / "scripts" / "joern" / "common.sc").read_text()
        for phrase in ("detectLanguage", "javascript", "python", "go", "java", "unsupportedResult"):
            self.assertIn(phrase, common)


if __name__ == "__main__":
    unittest.main()
