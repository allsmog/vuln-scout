from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "vuln-scout" / "scripts"
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "artifacts"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


prompt_artifacts = load_module("prompt_artifacts", SCRIPTS_DIR / "prompt_artifacts.py")
artifact_utils = load_module("artifact_utils", SCRIPTS_DIR / "artifact_utils.py")
migrate_artifact = load_module("migrate_artifact", SCRIPTS_DIR / "migrate_artifact.py")
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

    def test_chain_pattern_empty_rule_is_ignored(self) -> None:
        # `{"chain_pattern:": "..."}` or `{"chain_pattern:   ": "..."}`
        # (empty/whitespace-only slug) should NOT match every chain.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "chain_pattern": "mobile-token-replay"},
            ],
        }
        suppressions = {"chain_pattern:   ": "operator typo"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        self.assertFalse(updated["findings"][0].get("suppressed"))

    def test_chain_pattern_supports_fnmatch_middle_wildcard(self) -> None:
        # `chain_pattern:*-webview-*` should match BOTH
        # mobile-webview-dispatch AND ios-webview-injection.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "chain_pattern": "mobile-webview-dispatch"},
                {"id": "F2", "type": "y", "severity": "high", "kind": "finding",
                 "file": "b.swift", "line": 2,
                 "chain_pattern": "ios-webview-injection"},
                {"id": "F3", "type": "z", "severity": "high", "kind": "finding",
                 "file": "c.java", "line": 3,
                 "chain_pattern": "mobile-backup-exfil"},
            ],
        }
        suppressions = {"chain_pattern:*-webview-*": "silence all webview chains"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        by_id = {f["id"]: f for f in updated["findings"]}
        self.assertTrue(by_id["F1"].get("suppressed"))
        self.assertTrue(by_id["F2"].get("suppressed"))
        self.assertFalse(by_id["F3"].get("suppressed"))

    def test_suppressions_by_chain_pattern_supports_prefix_wildcard(self) -> None:
        # `chain_pattern:mobile-*` should suppress every finding whose
        # chain_pattern (or any chain_participations entry) starts with
        # "mobile-". iOS chains should stay unsuppressed.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "chain_pattern": "mobile-debuggable-secret"},
                {"id": "F2", "type": "y", "severity": "high", "kind": "finding",
                 "file": "b.java", "line": 2,
                 "chain_pattern": "mobile-token-replay"},
                {"id": "F3", "type": "z", "severity": "high", "kind": "finding",
                 "file": "c.swift", "line": 3,
                 "chain_pattern": "ios-webview-injection"},
            ],
        }
        suppressions = {"chain_pattern:mobile-*": "silence mobile family"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        by_id = {f["id"]: f for f in updated["findings"]}
        self.assertTrue(by_id["F1"].get("suppressed"))
        self.assertTrue(by_id["F2"].get("suppressed"))
        self.assertFalse(by_id["F3"].get("suppressed"))
        self.assertEqual(
            by_id["F1"].get("suppression_reason"),
            "silence mobile family",
        )

    def test_suppressions_by_chain_pattern_matches_participations(self) -> None:
        # A finding whose primary chain_pattern is "mobile-backup-exfil"
        # but who also participates in "mobile-token-replay" via
        # chain_participations[] should be suppressed by EITHER pattern rule.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "chain_pattern": "mobile-backup-exfil",
                 "chain_participations": [
                     {"chain_id": "chain-003", "role": "sink",
                      "pattern": "mobile-backup-exfil"},
                     {"chain_id": "chain-005", "role": "source",
                      "pattern": "mobile-token-replay"},
                 ]},
            ],
        }
        # Rule targeting the SECONDARY participation must still suppress.
        suppressions = {"chain_pattern:mobile-token-replay": "skip token-replay"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        self.assertTrue(updated["findings"][0].get("suppressed"))
        self.assertEqual(
            updated["findings"][0].get("suppression_reason"),
            "skip token-replay",
        )

    def test_summary_tracks_suppressed_chain_count_and_breakdown(self) -> None:
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "chain_pattern": "mobile-debuggable-secret"},
                {"id": "F2", "type": "z", "severity": "medium", "kind": "finding",
                 "file": "c.java", "line": 3,
                 "chain_pattern": "mobile-token-replay"},
            ],
            "chains": [
                {"id": "chain-001", "pattern": "mobile-debuggable-secret",
                 "severity": "high", "finding_ids": ["F1"]},
                {"id": "chain-002", "pattern": "mobile-token-replay",
                 "severity": "high", "finding_ids": ["F2"]},
            ],
            "summary": {"total_chains": 2,
                        "chains_by_pattern": {},
                        "chains_by_severity": {}},
        }
        suppressions = {"chain_pattern:mobile-debuggable-secret": "shadow"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        # Active chains count goes down
        self.assertEqual(updated["summary"]["total_chains"], 1)
        # Suppressed chain count is tracked
        self.assertEqual(updated["summary"]["suppressed_chains"], 1)
        # Suppressed-pattern breakdown is present
        self.assertEqual(
            updated["summary"]["suppressed_chains_by_pattern"],
            {"mobile-debuggable-secret": 1},
        )

    def test_severity_rank_constants_pinned(self) -> None:
        # Pin the SEVERITY_RANK + SEVERITY_ORDER shape. A future
        # contributor adding a tier (e.g. "blocker") needs to update
        # every consumer (chain_detector, mobile_scan literal copy);
        # this test makes that breakage visible upfront.
        self.assertEqual(
            artifact_utils.SEVERITY_RANK,
            {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0},
        )
        self.assertEqual(
            artifact_utils.SEVERITY_ORDER,
            ["critical", "high", "medium", "low", "info"],
        )
        # The set of keys/values must match VALID_SEVERITIES.
        self.assertEqual(
            set(artifact_utils.SEVERITY_RANK.keys()),
            artifact_utils.VALID_SEVERITIES,
        )
        # The order list must be sorted by rank descending.
        ranks = [artifact_utils.SEVERITY_RANK[s] for s in artifact_utils.SEVERITY_ORDER]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_summarize_findings_tolerates_none(self) -> None:
        # Defensive: callers may pass artifact.get("findings") without
        # a fallback. None should produce a zero-summary, not a crash.
        summary = artifact_utils.summarize_findings(None)
        # All keys present and zero
        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["total_hotspots"], 0)
        for sev in ("critical", "high", "medium", "low", "info"):
            self.assertEqual(summary.get(sev, 0), 0)

    def test_apply_suppressions_handles_null_findings_field(self) -> None:
        # `"findings": null` (vs missing or []) should be tolerated.
        artifact = {"findings": None}
        updated = artifact_utils.apply_suppressions(artifact, {"vscout:abc": "x"})
        # Doesn't crash, finds nothing to suppress, normalizes summary.
        self.assertEqual(updated["summary"]["total_findings"], 0)

    def test_to_sarif_handles_null_findings_field(self) -> None:
        sarif = artifact_utils.to_sarif({"findings": None})
        # No findings → empty results / rules, but valid SARIF document.
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_apply_suppressions_accepts_none_suppressions(self) -> None:
        # None should be treated as "no suppression rules" — useful for
        # callers who haven't loaded a .vuln-scout-ignore file.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1},
            ],
        }
        updated = artifact_utils.apply_suppressions(artifact, None)
        self.assertFalse(updated["findings"][0].get("suppressed"))
        # And empty dict should produce the same result
        updated_empty = artifact_utils.apply_suppressions(artifact, {})
        self.assertEqual(
            updated["findings"][0].get("suppressed"),
            updated_empty["findings"][0].get("suppressed"),
        )

    def test_apply_suppressions_resets_suppressed_chains_to_zero_when_empty(self) -> None:
        # Symmetric to the total_chains=0 default: suppressed_chains must
        # also reset to 0 when there are no chains.
        artifact = {
            "findings": [],
            "summary": {"suppressed_chains": 99, "total_chains": 99},
        }
        updated = artifact_utils.apply_suppressions(artifact, {})
        self.assertEqual(updated["summary"]["suppressed_chains"], 0)
        self.assertEqual(updated["summary"]["total_chains"], 0)

    def test_apply_suppressions_normalizes_rollups_when_no_chains(self) -> None:
        # An artifact with no `chains` array (or empty) should still
        # have summary.total_chains/chains_by_*/etc. reset to safe
        # defaults after apply_suppressions, so dashboards never see
        # stale pre-suppression values.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1},
            ],
            # Stale rollup values left over from a prior pipeline stage
            "summary": {"total_chains": 5,
                        "chains_by_pattern": {"old-slug": 5},
                        "chains_by_severity": {"high": 5}},
        }
        updated = artifact_utils.apply_suppressions(artifact, {})
        self.assertEqual(updated["summary"]["total_chains"], 0)
        self.assertEqual(updated["summary"]["chains_by_pattern"], {})
        self.assertEqual(updated["summary"]["chains_by_severity"], {})

    def test_file_glob_empty_pattern_is_ignored(self) -> None:
        # `{"file:": "..."}` or `{"file:   ": "..."}` (empty/whitespace-only
        # glob) should be silently dropped — NOT used as an fnmatch
        # pattern that matches every file path.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "src/auth/Login.java", "line": 1},
            ],
        }
        suppressions = {"file:   ": "operator typo"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        # Finding must NOT be suppressed despite the empty pattern
        self.assertFalse(updated["findings"][0].get("suppressed"))

    def test_file_glob_suppression_cascades_to_chain_level(self) -> None:
        # If every participant in a chain is file-glob-suppressed, the
        # chain itself should also be marked suppressed and excluded
        # from rollups (mirrors chain_pattern: behavior).
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "src/test/Helper.java", "line": 1,
                 "chain_pattern": "mobile-debuggable-secret"},
                {"id": "F2", "type": "y", "severity": "high", "kind": "finding",
                 "file": "src/test/Other.java", "line": 2,
                 "chain_pattern": "mobile-debuggable-secret"},
            ],
            "chains": [
                {"id": "chain-001", "pattern": "mobile-debuggable-secret",
                 "severity": "high", "finding_ids": ["F1", "F2"]},
            ],
            "summary": {"total_chains": 1,
                        "chains_by_pattern": {"mobile-debuggable-secret": 1},
                        "chains_by_severity": {"high": 1}},
        }
        suppressions = {"file:src/test/*": "test code"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        # All chain participants suppressed → chain itself suppressed
        self.assertTrue(updated["chains"][0].get("suppressed"))
        # And the chain rollups exclude it
        self.assertEqual(updated["summary"]["total_chains"], 0)
        self.assertEqual(updated["summary"]["suppressed_chains"], 1)

    def test_legacy_key_precedes_severity_floor(self) -> None:
        # Legacy stable_key (pre-v1.1.0 hash form) matches should win
        # over a severity floor — same priority as stable_key. Computes
        # the legacy key the way artifact_utils does and asserts it.
        artifact_utils_mod = artifact_utils
        # Pick a finding that yields a known legacy_key
        finding = {"id": "F1", "type": "x", "kind": "finding",
                   "severity": "low", "source_tool": "test",
                   "file": "a.java", "line": 1, "title": "T1"}
        legacy = artifact_utils_mod._legacy_stable_key(finding)
        artifact = {"findings": [dict(finding)]}
        suppressions = {
            legacy: "specific legacy override",
            "severity:low": "noise floor",
        }
        updated = artifact_utils_mod.apply_suppressions(artifact, suppressions)
        self.assertTrue(updated["findings"][0].get("suppressed"))
        self.assertEqual(
            updated["findings"][0].get("suppression_reason"),
            "specific legacy override",
            "legacy_key match should win over severity floor",
        )

    def test_severity_floor_precedes_file_glob(self) -> None:
        # Closes the priority-chain adjacent-pair coverage: severity:
        # wins over file:<glob>. A low-severity finding under src/test/*
        # gets the severity reason, not the file reason.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "low", "kind": "finding",
                 "file": "src/test/Helper.java", "line": 1},
            ],
        }
        suppressions = {
            "severity:low": "noise floor",
            "file:src/test/*": "test code",
        }
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        self.assertTrue(updated["findings"][0].get("suppressed"))
        self.assertEqual(
            updated["findings"][0].get("suppression_reason"),
            "noise floor",
            "severity: should win over file:<glob>",
        )

    def test_stable_key_precedes_severity_floor(self) -> None:
        # When a finding matches both an exact stable_key rule AND a
        # severity floor, the stable_key wins (it's more specific).
        # Pins the first adjacent step in the priority chain.
        artifact = {
            "findings": [
                {"id": "F1", "stable_key": "vscout:abcd1234",
                 "type": "x", "severity": "low", "kind": "finding",
                 "file": "a.java", "line": 1},
            ],
        }
        suppressions = {
            "vscout:abcd1234": "specific override",
            "severity:low": "noise floor",
        }
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        self.assertTrue(updated["findings"][0].get("suppressed"))
        self.assertEqual(
            updated["findings"][0].get("suppression_reason"),
            "specific override",
            "stable_key match should win over severity floor",
        )

    def test_file_glob_rule_precedes_chain_pattern_rule(self) -> None:
        # When a finding matches both a file: rule AND a chain_pattern:
        # rule, the file rule wins (per documented priority order).
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "src/test/Helper.java", "line": 1,
                 "chain_pattern": "mobile-foo"},
            ],
        }
        suppressions = {
            "file:src/test/*": "test code",
            "chain_pattern:mobile-foo": "chain rule",
        }
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        self.assertTrue(updated["findings"][0].get("suppressed"))
        self.assertEqual(
            updated["findings"][0].get("suppression_reason"),
            "test code",
            "file: should win over chain_pattern:",
        )

    def test_severity_rule_precedes_chain_pattern_rule(self) -> None:
        # A low-severity finding that ALSO sits in a suppressible chain
        # should be tagged with the `severity:` reason, not the
        # `chain_pattern:` one — priority order is severity → chain_pattern.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "low", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "chain_pattern": "mobile-foo"},
            ],
        }
        suppressions = {
            "severity:low": "noise floor",
            "chain_pattern:mobile-foo": "chain rule",
        }
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        self.assertTrue(updated["findings"][0].get("suppressed"))
        self.assertEqual(
            updated["findings"][0].get("suppression_reason"),
            "noise floor",
            "severity: should win over chain_pattern: per priority order",
        )

    def test_severity_floor_suppression(self) -> None:
        # `severity:low` should suppress every low + info finding,
        # leaving medium/high/critical untouched.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "critical", "kind": "finding",
                 "file": "a.java", "line": 1},
                {"id": "F2", "type": "y", "severity": "high", "kind": "finding",
                 "file": "b.java", "line": 2},
                {"id": "F3", "type": "z", "severity": "medium", "kind": "finding",
                 "file": "c.java", "line": 3},
                {"id": "F4", "type": "n", "severity": "low", "kind": "finding",
                 "file": "d.java", "line": 4},
                {"id": "F5", "type": "i", "severity": "info", "kind": "finding",
                 "file": "e.java", "line": 5},
            ],
        }
        suppressions = {"severity:low": "CI ignores noise below medium"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        by_id = {f["id"]: f for f in updated["findings"]}
        self.assertFalse(by_id["F1"].get("suppressed"))  # critical
        self.assertFalse(by_id["F2"].get("suppressed"))  # high
        self.assertFalse(by_id["F3"].get("suppressed"))  # medium
        self.assertTrue(by_id["F4"].get("suppressed"))   # low
        self.assertTrue(by_id["F5"].get("suppressed"))   # info
        self.assertEqual(by_id["F4"].get("suppression_reason"),
                         "CI ignores noise below medium")

    def test_file_glob_suppression_silences_matching_paths(self) -> None:
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "src/com/example/test/Helper.java", "line": 1},
                {"id": "F2", "type": "y", "severity": "high", "kind": "finding",
                 "file": "build/generated/Stub.java", "line": 1},
                {"id": "F3", "type": "z", "severity": "high", "kind": "finding",
                 "file": "src/com/example/auth/Login.java", "line": 1},
            ],
        }
        suppressions = {
            "file:*/test/*": "test code, not shipped",
            "file:build/generated/*": "auto-generated code",
        }
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        by_id = {f["id"]: f for f in updated["findings"]}
        self.assertTrue(by_id["F1"].get("suppressed"))
        self.assertEqual(by_id["F1"].get("suppression_reason"),
                         "test code, not shipped")
        self.assertTrue(by_id["F2"].get("suppressed"))
        self.assertEqual(by_id["F2"].get("suppression_reason"),
                         "auto-generated code")
        self.assertFalse(by_id["F3"].get("suppressed"))

    def test_chain_pattern_rule_strips_leading_whitespace_in_slug(self) -> None:
        # Programmatic callers may pass `chain_pattern: mobile-*` (with a
        # space after the colon) — strip it so the rule still applies
        # rather than silently no-op'ing.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "chain_pattern": "mobile-backup-exfil"},
            ],
        }
        suppressions = {"chain_pattern:  mobile-*": "tolerate whitespace"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        self.assertTrue(updated["findings"][0].get("suppressed"))

    def test_chain_pattern_suppression_drops_chain_from_rollups(self) -> None:
        # When all chain participants are suppressed via chain_pattern,
        # the chain itself is marked suppressed AND chain rollups are
        # recomputed to exclude it.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "chain_pattern": "mobile-debuggable-secret"},
                {"id": "F2", "type": "y", "severity": "high", "kind": "finding",
                 "file": "b.java", "line": 2,
                 "chain_pattern": "mobile-debuggable-secret"},
                {"id": "F3", "type": "z", "severity": "medium", "kind": "finding",
                 "file": "c.java", "line": 3,
                 "chain_pattern": "mobile-token-replay"},
            ],
            "chains": [
                {"id": "chain-001", "pattern": "mobile-debuggable-secret",
                 "severity": "high",
                 "finding_ids": ["F1", "F2"]},
                {"id": "chain-002", "pattern": "mobile-token-replay",
                 "severity": "high",
                 "finding_ids": ["F3"]},
            ],
            "summary": {"total_chains": 2,
                        "chains_by_pattern": {"mobile-debuggable-secret": 1, "mobile-token-replay": 1},
                        "chains_by_severity": {"high": 2}},
        }
        suppressions = {"chain_pattern:mobile-debuggable-secret": "shadow build"}
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        # The fully-suppressed chain is marked
        chain_by_id = {c["id"]: c for c in updated["chains"]}
        self.assertTrue(chain_by_id["chain-001"].get("suppressed"))
        self.assertFalse(chain_by_id["chain-002"].get("suppressed"))
        # Rollups exclude it
        self.assertEqual(updated["summary"]["total_chains"], 1)
        self.assertNotIn("mobile-debuggable-secret",
                         updated["summary"]["chains_by_pattern"])
        self.assertIn("mobile-token-replay",
                      updated["summary"]["chains_by_pattern"])

    def test_suppressions_by_chain_pattern(self) -> None:
        # New rule shape: `chain_pattern:<slug>  reason text`
        # Drops every finding whose chain_pattern matches the slug.
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1,
                 "chain_pattern": "mobile-debuggable-secret"},
                {"id": "F2", "type": "y", "severity": "medium", "kind": "finding",
                 "file": "b.java", "line": 2,
                 "chain_pattern": "mobile-token-replay"},
                {"id": "F3", "type": "z", "severity": "low", "kind": "finding",
                 "file": "c.java", "line": 3},
            ],
        }
        suppressions = {
            "chain_pattern:mobile-debuggable-secret": "too noisy on test builds",
        }
        updated = artifact_utils.apply_suppressions(artifact, suppressions)
        by_id = {f["id"]: f for f in updated["findings"]}
        self.assertTrue(by_id["F1"].get("suppressed"))
        self.assertEqual(by_id["F1"].get("suppression_reason"), "too noisy on test builds")
        self.assertFalse(by_id["F2"].get("suppressed"))
        self.assertFalse(by_id["F3"].get("suppressed"))

    def test_normalize_artifact_metadata_uses_finding_sources(self) -> None:
        artifact = {
            "source_tool": "semgrep",
            "coverage": {"tools_used": ["semgrep"]},
            "findings": [
                {
                    "source_tool": "api-spec-parser",
                    "kind": "finding",
                    "severity": "medium",
                }
            ],
        }

        updated = artifact_utils.normalize_artifact_metadata(artifact)

        self.assertEqual(updated["source_tool"], "api-spec-parser")
        self.assertEqual(updated["summary"]["total_findings"], 1)

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

    def test_malformed_trust_metadata_fails_validation(self) -> None:
        artifact = json.loads((FIXTURES_DIR / "sample-findings-v1_2_0.json").read_text())
        artifact["findings"][0]["trust_metadata"] = {
            "provenance": {"origin": "impossible", "contributors": ["deterministic_tool"]},
            "exploitability_status": "confirmed",
            "false_positive_risk": {"level": "low"},
        }

        errors = artifact_utils.validate_findings_artifact(artifact)

        self.assertTrue(any("trust_metadata.provenance.origin" in error for error in errors))

    def test_migration_backfills_partial_trust_metadata(self) -> None:
        artifact = json.loads((FIXTURES_DIR / "sample-findings.json").read_text())
        artifact["findings"][0]["trust_metadata"] = {
            "provenance": {"origin": "human_review"},
            "confidence_reason": "Preserve reviewer-provided context.",
        }

        migrated = migrate_artifact.migrate_to_1_2_0(artifact)
        trust = migrated["findings"][0]["trust_metadata"]

        self.assertEqual(trust["provenance"]["origin"], "human_review")
        self.assertIn("contributors", trust["provenance"])
        self.assertIn("exploitability_status", trust)
        self.assertIn("false_positive_risk", trust)
        self.assertIs(trust["inferred_from_legacy_artifact"], True)
        self.assertEqual(artifact_utils.validate_findings_artifact(migrated), [])

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
