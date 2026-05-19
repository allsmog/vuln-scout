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
EVALS_DIR = ROOT / "vuln-scout" / "evals"

sys.path.insert(0, str(SCRIPTS_DIR))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


prompt_artifacts = load_module("prompt_artifacts_test", SCRIPTS_DIR / "prompt_artifacts.py")
validate_evals = load_module("validate_evals_test", SCRIPTS_DIR / "validate_evals.py")
check_consistency = load_module("check_consistency_test", SCRIPTS_DIR / "check_consistency.py")


class PromptArtifactTests(unittest.TestCase):
    def test_sample_review_ledger_validates(self) -> None:
        ledger = json.loads((FIXTURES_DIR / "sample-review-ledger.json").read_text())
        self.assertEqual(prompt_artifacts.validate_review_ledger(ledger), [])

    def test_audit_plan_requires_all_sections(self) -> None:
        plan = "# Audit Plan\n\n## Context\n"
        errors = prompt_artifacts.validate_audit_plan(plan)
        self.assertTrue(errors)
        self.assertIn("Audit Strategy", errors[0])

    def test_state_validation_requires_new_artifacts_and_review_state(self) -> None:
        state = {
            "artifacts": {
                "scope_architecture": ".claude/scope-architecture.md",
                "threat_model": ".claude/threat-model.md",
                "audit_plan": ".claude/audit-plan.md",
                "audit_report": ".claude/audit-report.md",
                "findings_json": ".claude/findings.json",
                "review_ledger": ".claude/review-ledger.json",
                "state_json": ".claude/whitebox-pentest-state.json",
            },
            "review_state": {
                "audit_plan": "APPROVED",
                "threat_model": "APPROVED",
                "findings": "UNRESOLVED",
            },
            "phases_completed": [
                "audit-plan",
                "threat-review",
                "finding-review",
            ],
        }
        self.assertEqual(prompt_artifacts.validate_orchestration_state(state), [])


class EvalValidationTests(unittest.TestCase):
    def test_repo_eval_files_validate(self) -> None:
        self.assertEqual(validate_evals.validate_eval_suite(EVALS_DIR), [])

    def test_trigger_eval_minimums_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            evals_dir = Path(tmpdir)
            (evals_dir / "trigger_evals.json").write_text(json.dumps([
                {
                    "id": "too-few",
                    "kind": "command",
                    "query": "/whitebox-pentest:full-audit .",
                    "expected_targets": ["/whitebox-pentest:full-audit"],
                    "should_trigger": True,
                }
            ]))
            (evals_dir / "workflow_evals.json").write_text(json.dumps([
                {
                    "id": "workflow-1",
                    "command": "/whitebox-pentest:full-audit",
                    "prompt": "/whitebox-pentest:full-audit . --quick",
                    "fixture_path": "tests/fixtures/code/python/vulnerable-ssrf",
                    "expected_artifacts": [".claude/audit-plan.md"],
                    "required_sections": {".claude/audit-plan.md": ["Context"]},
                    "expected_subject_types": ["audit-plan"],
                },
                {
                    "id": "workflow-2",
                    "command": "/whitebox-pentest:threats",
                    "prompt": "/whitebox-pentest:threats",
                    "fixture_path": "tests/fixtures/code/js/nextjs-redirect",
                    "expected_artifacts": [".claude/threat-model.md"],
                    "required_sections": {".claude/threat-model.md": ["Executive Summary"]},
                    "expected_subject_types": ["threat-model"],
                },
                {
                    "id": "workflow-3",
                    "command": "/whitebox-pentest:verify",
                    "prompt": "/whitebox-pentest:verify app.py:4 --type ssrf",
                    "fixture_path": "tests/fixtures/code/python/vulnerable-ssrf",
                    "expected_artifacts": [".claude/review-ledger.json"],
                    "required_sections": {".claude/review-ledger.json": ["ignored"]},
                    "expected_subject_types": ["finding-verification"],
                },
            ]))
            (evals_dir / "benchmark.json").write_text("{}\n")
            (evals_dir / "benchmark.md").write_text("# Benchmark\n")

            errors = validate_evals.validate_eval_suite(evals_dir)
            self.assertTrue(errors)
            self.assertTrue(any("at least 6 cases" in error for error in errors))


class CommandDocContractTests(unittest.TestCase):
    def test_full_audit_documents_condensed_quick_plan(self) -> None:
        text = (ROOT / "vuln-scout" / "commands" / "full-audit.md").read_text()
        self.assertIn("Condensed audit plan", text)
        self.assertIn(".claude/audit-plan.md", text)

    def test_unresolved_review_notes_stay_needs_review(self) -> None:
        full_audit = (ROOT / "vuln-scout" / "commands" / "full-audit.md").read_text()
        verify = (ROOT / "vuln-scout" / "commands" / "verify.md").read_text()
        self.assertIn("[REVIEWER NOTE: unresolved]", full_audit)
        self.assertIn("needs_review", full_audit)
        self.assertIn("[REVIEWER NOTE: unresolved]", verify)
        self.assertIn("needs_review", verify)

    def test_no_interactive_path_forbids_ask_user_question(self) -> None:
        text = (ROOT / "vuln-scout" / "commands" / "full-audit.md").read_text()
        self.assertIn("When `--no-interactive` is passed, **NEVER call AskUserQuestion**.", text)
        self.assertIn("NEVER call `AskUserQuestion`", text)

    def test_consistency_gate_passes(self) -> None:
        self.assertEqual(check_consistency.validate(), [])


if __name__ == "__main__":
    unittest.main()
