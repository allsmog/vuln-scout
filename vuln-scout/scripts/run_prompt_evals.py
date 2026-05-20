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
import pr_comment
import validate_evals
from migrate_artifact import migrate_to_1_2_0


CLAUDE_SUITES = {"triggers", "workflows"}
LOCAL_SUITES = {"report-quality"}
SUITES = CLAUDE_SUITES | LOCAL_SUITES


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


def _run_claude_prompt(
    claude_bin: str,
    prompt: str,
    cwd: Path,
    timeout: int,
    *,
    activation_only: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = [claude_bin, "-p", prompt]
    if activation_only:
        command.extend([
            "--output-format",
            "json",
            "--append-system-prompt",
            (
                "This is a VulnScout trigger activation eval. Do not perform the requested "
                "workflow. Classify the user request using this catalog: "
                "review-pr = PR review, pull request scan, or diff scan against a base ref; "
                "start-audit = start an audit, audit this repo, or review a codebase for vulnerabilities; "
                "verify-finding = verify VSCOUT finding, confirm a specific finding, or assess if a finding is exploitable; "
                "package-evidence = package, export, share, or bundle evidence; "
                "scope-repo = scope a repo, decide audit focus, or handle a large codebase; "
                "threat-modeling = STRIDE, trust boundaries, threat model, or security architecture; "
                "cpg-analysis = Joern CPG or CPGQL source-to-sink syntax; "
                "compliance-mapping = SOC 2, compliance controls, or evidence requirements; "
                "dangerous-functions = dangerous functions, sink lists, or sink patterns; "
                "full-audit = explicit /vuln-scout:full-audit command; "
                "threats = explicit /vuln-scout:threats command; "
                "verify = explicit /vuln-scout:verify command; "
                "false-positive-verifier = false-positive verification. "
                "Respond only with matching target names separated by commas, or none."
            ),
        ])
    try:
        return subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            command,
            124,
            exc.stdout or "",
            exc.stderr or f"timed out after {timeout} seconds",
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
    must_not_targets = case.get("must_not_targets", [])
    fixture_path = case.get("fixture_path", ".")
    repeat = case.get("repeat", 3)
    results: dict[str, Any] = {"id": case["id"], "kind": "trigger", "modes": {}}

    for mode_name, plugin_enabled in (("plugin_enabled", True), ("baseline", False)):
        matches = 0
        forbidden_matches = 0
        runs: list[dict[str, Any]] = []
        for _ in range(repeat):
            tempdir, workspace = _prepare_workspace(fixture_path, plugin_enabled=plugin_enabled)
            try:
                proc = _run_claude_prompt(
                    claude_bin,
                    case["query"],
                    workspace,
                    timeout,
                    activation_only=True,
                )
            finally:
                tempdir.cleanup()
            output = f"{proc.stdout}\n{proc.stderr}"
            matched_targets = _detect_targets(output, expected_targets)
            forbidden_targets = _detect_targets(output, must_not_targets)
            if matched_targets:
                matches += 1
            if forbidden_targets:
                forbidden_matches += 1
            runs.append(
                {
                    "returncode": proc.returncode,
                    "matched_targets": matched_targets,
                    "forbidden_targets": forbidden_targets,
                }
            )
        results["modes"][mode_name] = {
            "trigger_rate": matches / repeat,
            "forbidden_rate": forbidden_matches / repeat,
            "runs": runs,
        }
    return results


def _trigger_case_errors(result: dict[str, Any], case: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    plugin_result = result.get("modes", {}).get("plugin_enabled", {})
    trigger_rate = float(plugin_result.get("trigger_rate", 0.0))
    forbidden_rate = float(plugin_result.get("forbidden_rate", 0.0))
    min_rate = float(case.get("min_trigger_rate", 0.67))

    comparable_trigger_rate = round(trigger_rate, 2)
    if case.get("should_trigger") and comparable_trigger_rate < min_rate:
        errors.append(f"trigger_rate {trigger_rate:.2f} below required {min_rate:.2f}")
    if not case.get("should_trigger") and comparable_trigger_rate > min_rate:
        errors.append(f"unexpected trigger_rate {trigger_rate:.2f} above allowed {min_rate:.2f}")
    if case.get("must_not_targets") and forbidden_rate > 0:
        errors.append(f"forbidden target rate {forbidden_rate:.2f} above 0.00")

    timed_out = [
        run for run in plugin_result.get("runs", [])
        if run.get("returncode") == 124
    ]
    if timed_out:
        errors.append(f"{len(timed_out)} plugin-enabled run(s) timed out")
    return errors


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


def _run_report_renderer(case: dict[str, Any], timeout: int) -> dict[str, Any]:
    renderer = case["renderer"]
    fixture_path = ROOT / case["input_fixture"]
    errors: list[str] = []
    details: dict[str, Any] = {}

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        if renderer == "bundle":
            output_path = tmp_path / "bundle"
            cmd = [
                sys.executable,
                str(PLUGIN_ROOT / "scripts" / "report.py"),
                str(fixture_path),
                "--format",
                "bundle",
                "-o",
                str(output_path),
            ]
        elif renderer == "pr_comment":
            artifact = json.loads(fixture_path.read_text())
            output = pr_comment.generate(artifact)
            output_path = tmp_path / "pr-comment.md"
            output_path.write_text(output)
            proc = subprocess.CompletedProcess(cmd := ["pr_comment.generate"], 0, "", "")
        else:
            format_name = {"markdown": "md", "html": "html", "sarif": "sarif"}[renderer]
            suffix = {"markdown": ".md", "html": ".html", "sarif": ".sarif"}[renderer]
            output_path = tmp_path / f"report{suffix}"
            cmd = [
                sys.executable,
                str(PLUGIN_ROOT / "scripts" / "report.py"),
                str(fixture_path),
                "--format",
                format_name,
                "-o",
                str(output_path),
            ]

        if renderer != "pr_comment":
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        details["command"] = cmd
        details["returncode"] = proc.returncode
        if proc.returncode != 0:
            errors.append(f"renderer exited {proc.returncode}: {proc.stderr.strip()}")

        if renderer == "bundle":
            expected_files = case.get("expected_bundle_files", [])
            missing_files = [name for name in expected_files if not (output_path / name).exists()]
            if missing_files:
                errors.append(f"missing bundle files: {', '.join(missing_files)}")
            details["bundle_files"] = sorted(path.name for path in output_path.iterdir()) if output_path.exists() else []

            vex_path = output_path / "vex.json"
            if vex_path.exists():
                vex = json.loads(vex_path.read_text())
                seen_states = sorted({
                    item.get("analysis", {}).get("state")
                    for item in vex.get("vulnerabilities", [])
                    if isinstance(item, dict)
                })
                missing_states = [state for state in case.get("expected_vex_states", []) if state not in seen_states]
                if missing_states:
                    errors.append(f"missing VEX states: {', '.join(missing_states)}")
                details["vex_states"] = seen_states

            attestation_path = output_path / "attestation.json"
            if attestation_path.exists():
                attestation = json.loads(attestation_path.read_text())
                missing_keys = [key for key in case.get("attestation_must_contain_keys", []) if key not in attestation]
                if missing_keys:
                    errors.append(f"missing attestation keys: {', '.join(missing_keys)}")
                details["attestation_keys"] = sorted(attestation.keys())
        else:
            output = output_path.read_text() if output_path.exists() else ""
            missing_text = [value for value in case.get("must_contain", []) if value not in output]
            forbidden_text = [value for value in case.get("must_not_contain", []) if value in output]
            if missing_text:
                errors.append(f"missing text: {', '.join(missing_text)}")
            if forbidden_text:
                errors.append(f"forbidden text present: {', '.join(forbidden_text)}")
            max_bytes = case.get("max_bytes")
            output_bytes = len(output.encode("utf-8"))
            if max_bytes is not None and output_bytes > max_bytes:
                errors.append(f"output is {output_bytes} bytes, max is {max_bytes}")
            details["output_bytes"] = output_bytes

    return {
        "id": case["id"],
        "kind": "report-quality",
        "passed": not errors,
        "errors": errors,
        "details": details,
    }


def _run_report_assertion(case: dict[str, Any]) -> dict[str, Any]:
    assertion = case["assertion"]
    fixture_path = ROOT / case["input_fixture"]
    fixture = json.loads(fixture_path.read_text())
    errors: list[str] = []
    details: dict[str, Any] = {"assertion": assertion}

    if assertion == "hotspot_with_verification_level_ge_3_becomes_finding":
        pre = fixture.get("pre_graduation", {})
        post = fixture.get("post_graduation", {})
        details.update({
            "pre_kind": pre.get("kind"),
            "post_kind": post.get("kind"),
            "post_verification_level": post.get("verification_level"),
        })
        if pre.get("kind") != "hotspot":
            errors.append("pre_graduation.kind must be hotspot")
        if post.get("kind") != "finding":
            errors.append("post_graduation.kind must be finding")
        if int(post.get("verification_level") or 0) < 3:
            errors.append("post_graduation.verification_level must be >= 3")
        if pre.get("stable_key") != post.get("stable_key"):
            errors.append("pre/post stable_key must match")
    elif assertion == "migrate_then_migrate_equal":
        migrated_once = migrate_to_1_2_0(fixture)
        migrated_twice = migrate_to_1_2_0(migrated_once)
        details["schema_version"] = migrated_once.get("schema_version")
        if migrated_once != migrated_twice:
            errors.append("migration is not idempotent")
        if migrated_once.get("schema_version") != "1.2.0":
            errors.append("migration did not produce schema_version 1.2.0")
    else:
        errors.append(f"unknown report-quality assertion: {assertion}")

    return {
        "id": case["id"],
        "kind": "report-quality",
        "passed": not errors,
        "errors": errors,
        "details": details,
    }


def _run_report_quality_case(case: dict[str, Any], timeout: int) -> dict[str, Any]:
    if "renderer" in case:
        return _run_report_renderer(case, timeout)
    return _run_report_assertion(case)


def _render_benchmark_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Prompt Eval Benchmark",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Trigger cases: {report['summary']['trigger_cases']}",
        f"- Workflow cases: {report['summary']['workflow_cases']}",
        f"- Report-quality cases: {report['summary'].get('report_quality_cases', 0)}",
        "",
        "## Results",
        "",
    ]

    for result in report["results"]:
        lines.append(f"### {result['id']}")
        if result["kind"] == "report-quality":
            status = "pass" if result["passed"] else "fail"
            lines.append(f"- report-quality: {status}")
            for error in result.get("errors", []):
                lines.append(f"  - {error}")
        else:
            for mode_name, mode_result in result["modes"].items():
                if result["kind"] == "trigger":
                    lines.append(f"- {mode_name}: trigger rate {mode_result['trigger_rate']:.2f}")
                elif result["kind"] == "workflow":
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
    parser.add_argument(
        "--suite",
        choices=["all", "triggers", "workflows", "report-quality"],
        default="all",
        help="Eval suite to run (default: all)",
    )
    parser.add_argument("--timeout", type=int, default=120, help="Per-run timeout in seconds")
    parser.add_argument("--claude-bin", default=shutil.which("claude") or "", help="Path to the Claude CLI binary")
    args = parser.parse_args()

    evals_dir = Path(args.evals_dir)
    errors = validate_evals.validate_eval_suite(evals_dir)
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1

    selected_suites = SUITES if args.suite == "all" else {args.suite}
    needs_claude = bool(selected_suites.intersection(CLAUDE_SUITES))

    if needs_claude and not args.claude_bin:
        print("error: Claude CLI not found. Run validate_evals.py for schema-only checks.")
        return 2
    if needs_claude and shutil.which(args.claude_bin) is None:
        print(f"error: Claude CLI is not executable: {args.claude_bin}")
        return 2

    results: list[dict[str, Any]] = []
    trigger_cases: list[dict[str, Any]] = []
    workflow_cases: list[dict[str, Any]] = []
    report_quality_cases: list[dict[str, Any]] = []

    if "triggers" in selected_suites:
        trigger_cases = json.loads((evals_dir / "trigger_evals.json").read_text())
        for case in trigger_cases:
            result = _run_trigger_case(case, args.claude_bin, args.timeout)
            result["passed"] = not _trigger_case_errors(result, case)
            result["errors"] = _trigger_case_errors(result, case)
            results.append(result)
    if "workflows" in selected_suites:
        workflow_cases = json.loads((evals_dir / "workflow_evals.json").read_text())
        for case in workflow_cases:
            results.append(_run_workflow_case(case, args.claude_bin, args.timeout))
    if "report-quality" in selected_suites:
        report_quality_cases = json.loads((evals_dir / "report_quality_evals.json").read_text())
        for case in report_quality_cases:
            results.append(_run_report_quality_case(case, args.timeout))

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
            "report_quality_cases": len(report_quality_cases),
        },
        "results": results,
    }

    if selected_suites == {"report-quality"}:
        print(f"ok: ran {len(report_quality_cases)} report-quality evals")
    else:
        (evals_dir / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
        (evals_dir / "benchmark.md").write_text(_render_benchmark_markdown(report))
        print(f"ok: wrote {(evals_dir / 'benchmark.json')} and {(evals_dir / 'benchmark.md')}")
    failed_report_quality = [
        result for result in results
        if result.get("kind") == "report-quality" and not result.get("passed")
    ]
    failed_triggers = [
        result for result in results
        if result.get("kind") == "trigger" and not result.get("passed", True)
    ]
    if failed_report_quality or failed_triggers:
        for result in failed_report_quality + failed_triggers:
            for error in result.get("errors", []):
                print(f"error: {result['id']}: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
