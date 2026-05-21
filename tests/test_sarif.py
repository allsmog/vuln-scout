"""SARIF output format tests."""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "vuln-scout" / "scripts"
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

    def test_sarif_rule_tags_include_chain_cwes(self) -> None:
        # Synthetic artifact with a finding carrying chain_cwes should
        # produce SARIF rule tags for each CWE.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "title": "T1",
                 "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "message": "Patch.",
                 "chain_cwes": ["CWE-312", "CWE-639"]},
            ],
        }
        sarif = artifact_utils.to_sarif(artifact)
        run = sarif["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        tags = rule["properties"]["tags"]
        self.assertIn("external/cwe/cwe-312", tags)
        self.assertIn("external/cwe/cwe-639", tags)

    def test_sarif_related_locations_exclude_suppressed_chain_links(self) -> None:
        # Two findings in the same suppressed chain → SARIF must not
        # surface them as related locations.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "title": "T1", "severity": "high",
                 "kind": "finding", "file": "a.java", "line": 1,
                 "message": "p", "chain_id": "chain-001"},
                {"id": "F2", "type": "y", "title": "T2", "severity": "high",
                 "kind": "finding", "file": "b.java", "line": 2,
                 "message": "q", "chain_id": "chain-001"},
            ],
            "chains": [
                {"id": "chain-001", "pattern": "p", "severity": "high",
                 "suppressed": True, "finding_ids": ["F1", "F2"]},
            ],
        }
        sarif = artifact_utils.to_sarif(artifact)
        for r in sarif["runs"][0]["results"]:
            self.assertNotIn(
                "relatedLocations", r,
                f"suppressed chain should not produce related locations, got: {r}",
            )

    def test_sarif_related_locations_include_multi_chain_links(self) -> None:
        # Finding A participates only in chain-001 (primary). Finding B
        # has chain-001 in chain_participations only. Both should be
        # related-linked despite B's chain_id being unset.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "title": "T1",
                 "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "message": "p",
                 "chain_id": "chain-001"},
                {"id": "F2", "type": "y", "title": "T2",
                 "severity": "high", "kind": "finding",
                 "file": "b.java", "line": 2,
                 "message": "q",
                 "chain_participations": [
                     {"chain_id": "chain-001", "role": "sink"},
                 ]},
            ],
        }
        sarif = artifact_utils.to_sarif(artifact)
        results = sarif["runs"][0]["results"]
        # Find F1 (located at a.java:1) and F2 (b.java:2) by their URIs.
        f1_result = next(
            r for r in results
            if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a.java"
        )
        f2_result = next(
            r for r in results
            if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "b.java"
        )
        # Both directions of the chain link should be present.
        f1_related = f1_result.get("relatedLocations") or []
        f2_related = f2_result.get("relatedLocations") or []
        self.assertTrue(
            any("T2" in rel.get("message", {}).get("text", "") for rel in f1_related),
            f"expected F2 in F1.relatedLocations, got: {f1_related}",
        )
        self.assertTrue(
            any("T1" in rel.get("message", {}).get("text", "") for rel in f2_related),
            f"expected F1 in F2.relatedLocations, got: {f2_related}",
        )


if __name__ == "__main__":
    unittest.main()
