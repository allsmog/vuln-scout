#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import sys


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "vuln-scout"
EVALS_DIR = PLUGIN_ROOT / "evals"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import prompt_artifacts
import validate_evals


def _normalize_identifier(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def _prepare_workspace(fixture_path: str, plugin_enabled: bool) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    tempdir = tempfile.TemporaryDirectory()
    workspace_root = Path(tempdir.name) / "workspace"
    source = (ROOT / fixture_path).resolve()

    if source.is_dir():
        shutil.copytree(source, workspace_root)
    else:
        workspace_root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, workspace_root / source.name)

    if plugin_enabled:
        plugins_dir = workspace_root / ".claude" / "plugins"
        plugins_dir.mkdir(parents=True, exist_ok=True)
        target = plugins_dir / "vuln-scout"
        target.symlink_to(PLUGIN_ROOT)

    return tempdir, workspace_root


def _run_claude_prompt(claude_bin: str, prompt: str, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [claude_bin, "-p", prompt],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _detect_targets(output: str, expected_targets: list[str]) -> list[str]:
    normalized_output = _normalize_identifier(output)
    matched: list[str] = []
    for target in expected_targets:
        if _normalize_identifier(target) in normalized_output:
            matched.append(target)
    return matched


def _score_required_sections(workspace: Path, required_sections: dict[str, list[str]]) -> tuple[float, dict[str, Any]]:
    detail: dict[str, Any] = {}
    path_scores: list[float] = []

    for relative_path, sections in required_sections.items():
        artifact_path = workspace / relative_path
        if not artifact_path.exists():
            detail[relative_path] = {"exists": False, "missing_sections": list(sections)}
            path_scores.append(0.0)
            continue

        if artifact_path.suffix == ".md":
            missing = prompt_artifacts.missing_markdown_sections(artifact_path.read_text(), sections)
            score = 1.0 if not missing else (len(sections) - len(missing)) / len(sections)
            detail[relative_path] = {"exists": True, "missing_sections": missing}
            path_scores.append(score)
            continue

        detail[relative_path] = {"exists": True, "missing_sections": []}
        path_scores.append(1.0)

    if not path_scores:
        return 1.0, detail
    return sum(path_scores) / len(path_scores), detail


def _score_verdict_quality(workspace: Path, case: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    details: dict[str, Any] = {}
    scores: list[float] = []

    review_ledger_path = workspace / ".claude" / "review-ledger.json"
    if review_ledger_path.exists():
        ledger = json.loads(review_ledger_path.read_text())
        ledger_errors = prompt_artifacts.validate_review_ledger(ledger)
        details["review_ledger_errors"] = ledger_errors
        scores.append(1.0 if not ledger_errors else 0.0)
        expected_subject_types = case.get("expected_subject_types", [])
        if expected_subject_types:
            seen_subject_types = {
                subject.get("subject_type")
                for subject in ledger.get("subjects", [])
                if isinstance(subject, dict)
            }
            matched_subject_types = [
                subject_type for subject_type in expected_subject_types if subject_type in seen_subject_types
            ]
            details["matched_subject_types"] = matched_subject_types
            scores.append(len(matched_subject_types) / len(expected_subject_types))

    state_path = workspace / ".claude" / "whitebox-pentest-state.json"
    if state_path.exists():
        state_errors = prompt_artifacts.validate_orchestration_state(json.loads(state_path.read_text()))
        details["state_errors"] = state_errors
        scores.append(1.0 if not state_errors else 0.0)

    findings_path = workspace / ".claude" / "findings.json"
    expected_verdicts = case.get("expected_verdicts", [])
    if findings_path.exists() and expected_verdicts:
        findings_artifact = json.loads(findings_path.read_text())
        seen_verdicts = {
            finding.get("verdict")
            for finding in findings_artifact.get("findings", [])
            if isinstance(finding, dict)
        }
        matched = [verdict for verdict in expected_verdicts if verdict in seen_verdicts]
        details["matched_verdicts"] = matched
        scores.append(len(matched) / len(expected_verdicts))

    if not scores:
        return 0.0, details
    return sum(scores) / len(scores), details


def _run_trigger_case(case: dict[str, Any], claude_bin: str, timeout: int) -> dict[str, Any]:
    expected_targets = case.get("expected_targets", [])
    fixture_path = case.get("fixture_path", ".")
    repeat = case.get("repeat", 3)
    results: dict[str, Any] = {"id": case["id"], "kind": "trigger", "modes": {}}

    for mode_name, plugin_enabled in (("plugin_enabled", True), ("baseline", False)):
        matches = 0
        runs: list[dict[str, Any]] = []
        for _ in range(repeat):
            tempdir, workspace = _prepare_workspace(fixture_path, plugin_enabled=plugin_enabled)
            try:
                proc = _run_claude_prompt(claude_bin, case["query"], workspace, timeout)
            finally:
                tempdir.cleanup()
            output = f"{proc.stdout}\n{proc.stderr}"
            matched_targets = _detect_targets(output, expected_targets)
            if matched_targets:
                matches += 1
            runs.append(
                {
                    "returncode": proc.returncode,
                    "matched_targets": matched_targets,
                }
            )
        results["modes"][mode_name] = {
            "trigger_rate": matches / repeat,
            "runs": runs,
        }
    return results


def _run_workflow_case(case: dict[str, Any], claude_bin: str, timeout: int) -> dict[str, Any]:
    results: dict[str, Any] = {"id": case["id"], "kind": "workflow", "modes": {}}

    for mode_name, plugin_enabled in (("plugin_enabled", True), ("baseline", False)):
        tempdir, workspace = _prepare_workspace(case["fixture_path"], plugin_enabled=plugin_enabled)
        try:
            proc = _run_claude_prompt(claude_bin, case["prompt"], workspace, timeout)
            artifact_hits = sum(
                1 for relative_path in case["expected_artifacts"] if (workspace / relative_path).exists()
            )
            artifact_score = artifact_hits / len(case["expected_artifacts"])
            section_score, section_detail = _score_required_sections(workspace, case["required_sections"])
            verdict_score, verdict_detail = _score_verdict_quality(workspace, case)
        finally:
            tempdir.cleanup()

        results["modes"][mode_name] = {
            "returncode": proc.returncode,
            "artifact_presence": artifact_score,
            "section_completeness": section_score,
            "verdict_quality": verdict_score,
            "overall_score": (artifact_score + section_score + verdict_score) / 3,
            "section_detail": section_detail,
            "verdict_detail": verdict_detail,
        }

    return results


def _render_benchmark_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Prompt Eval Benchmark",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Trigger cases: {report['summary']['trigger_cases']}",
        f"- Workflow cases: {report['summary']['workflow_cases']}",
        "",
        "## Results",
        "",
    ]

    for result in report["results"]:
        lines.append(f"### {result['id']}")
        for mode_name, mode_result in result["modes"].items():
            if result["kind"] == "trigger":
                lines.append(f"- {mode_name}: trigger rate {mode_result['trigger_rate']:.2f}")
            else:
                lines.append(
                    "- "
                    f"{mode_name}: artifact={mode_result['artifact_presence']:.2f}, "
                    f"sections={mode_result['section_completeness']:.2f}, "
                    f"verdicts={mode_result['verdict_quality']:.2f}, "
                    f"overall={mode_result['overall_score']:.2f}"
                )
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run prompt/skill evals for VulnScout")
    parser.add_argument("--evals-dir", default=str(EVALS_DIR), help="Directory containing prompt eval definitions")
    parser.add_argument("--timeout", type=int, default=120, help="Per-run timeout in seconds")
    parser.add_argument("--claude-bin", default=shutil.which("claude") or "", help="Path to the Claude CLI binary")
    args = parser.parse_args()

    evals_dir = Path(args.evals_dir)
    errors = validate_evals.validate_eval_suite(evals_dir)
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1

    if not args.claude_bin:
        print("error: Claude CLI not found. Run validate_evals.py for schema-only checks.")
        return 2

    trigger_cases = json.loads((evals_dir / "trigger_evals.json").read_text())
    workflow_cases = json.loads((evals_dir / "workflow_evals.json").read_text())

    results: list[dict[str, Any]] = []
    for case in trigger_cases:
        results.append(_run_trigger_case(case, args.claude_bin, args.timeout))
    for case in workflow_cases:
        results.append(_run_workflow_case(case, args.claude_bin, args.timeout))

    report = {
        "generated_at": subprocess.run(
            ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
        "summary": {
            "trigger_cases": len(trigger_cases),
            "workflow_cases": len(workflow_cases),
        },
        "results": results,
    }

    (evals_dir / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
    (evals_dir / "benchmark.md").write_text(_render_benchmark_markdown(report))
    print(f"ok: wrote {(evals_dir / 'benchmark.json')} and {(evals_dir / 'benchmark.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
