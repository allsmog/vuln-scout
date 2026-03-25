"""SARIF output format tests."""
from __future__ import annotations

import importlib.util
import json
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


class SarifTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        self.sarif = artifact_utils.to_sarif(self.artifact)

    def test_sarif_schema_version(self) -> None:
        self.assertEqual(self.sarif["version"], "2.1.0")
        self.assertIn("$schema", self.sarif)

    def test_sarif_excludes_hotspots(self) -> None:
        """Only kind=='finding' entries should appear in SARIF results."""
        run = self.sarif["runs"][0]
        for result in run["results"]:
            # Results should only come from 'finding' kind entries
            # The sample artifact has a hotspot which should be excluded
            self.assertNotEqual(
                result.get("message", {}).get("text", ""),
                "",
                "SARIF result should have a non-empty message",
            )
        # The sample has 2 findings and 1 hotspot; SARIF should have 2 results
        self.assertEqual(len(run["results"]), 2)

    def test_sarif_tool_driver_name(self) -> None:
        run = self.sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "VulnScout")

    def test_sarif_results_have_locations(self) -> None:
        run = self.sarif["runs"][0]
        for result in run["results"]:
            self.assertIn("locations", result)
            self.assertTrue(len(result["locations"]) > 0)
            loc = result["locations"][0]
            self.assertIn("physicalLocation", loc)
            self.assertIn("artifactLocation", loc["physicalLocation"])

    def test_sarif_results_have_level(self) -> None:
        run = self.sarif["runs"][0]
        valid_levels = {"error", "warning", "note", "none"}
        for result in run["results"]:
            self.assertIn("level", result)
            self.assertIn(result["level"], valid_levels)

    def test_sarif_suppressed_findings_excluded(self) -> None:
        """When suppressions are applied before SARIF conversion, suppressed findings are excluded."""
        suppressions = artifact_utils.parse_suppressions(FIXTURES_DIR / "sample.vuln-scout-ignore")
        updated = artifact_utils.apply_suppressions(self.artifact, suppressions)
        sarif = artifact_utils.to_sarif(updated)
        run = sarif["runs"][0]
        # After suppression, one finding is suppressed, leaving 1 finding (hotspot already excluded)
        self.assertEqual(len(run["results"]), 1)

    def test_sarif_results_have_message(self) -> None:
        run = self.sarif["runs"][0]
        for result in run["results"]:
            self.assertIn("message", result)
            self.assertIn("text", result["message"])
            self.assertTrue(len(result["message"]["text"]) > 0)


if __name__ == "__main__":
    unittest.main()
