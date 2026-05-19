#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVALS_DIR = ROOT / "vuln-scout" / "evals"
VALID_TRIGGER_KINDS = {"command", "skill", "hybrid"}
VALID_WORKFLOW_COMMANDS = {
    "/vuln-scout:full-audit",
    "/vuln-scout:threats",
    "/vuln-scout:verify",
}
VALID_REPORT_RENDERERS = {"markdown", "html", "sarif", "bundle", "pr_comment"}
VALID_REPORT_ASSERTIONS = {
    "hotspot_with_verification_level_ge_3_becomes_finding",
    "migrate_then_migrate_equal",
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def validate_trigger_cases(cases: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(cases, list):
        return ["trigger_evals.json must contain a list"]

    if len(cases) < 6:
        errors.append("trigger_evals.json must contain at least 6 cases")

    true_cases = 0
    false_cases = 0
    for index, case in enumerate(cases):
        location = f"trigger_evals[{index}]"
        if not isinstance(case, dict):
            errors.append(f"{location} must be an object")
            continue

        for key in ("id", "kind", "query", "expected_targets", "should_trigger"):
            if key not in case:
                errors.append(f"{location} missing key: {key}")

        if not isinstance(case.get("id"), str) or not case.get("id", "").strip():
            errors.append(f"{location}.id must be a non-empty string")

        if case.get("kind") not in VALID_TRIGGER_KINDS:
            errors.append(f"{location}.kind must be one of {sorted(VALID_TRIGGER_KINDS)}")

        if not isinstance(case.get("query"), str) or not case.get("query", "").strip():
            errors.append(f"{location}.query must be a non-empty string")

        expected_targets = case.get("expected_targets")
        if not isinstance(expected_targets, list):
            errors.append(f"{location}.expected_targets must be a list")
        elif any(not isinstance(item, str) or not item.strip() for item in expected_targets):
            errors.append(f"{location}.expected_targets entries must be non-empty strings")

        should_trigger = case.get("should_trigger")
        if not isinstance(should_trigger, bool):
            errors.append(f"{location}.should_trigger must be true or false")
        elif should_trigger:
            true_cases += 1
        else:
            false_cases += 1

        repeat = case.get("repeat", 3)
        if not isinstance(repeat, int) or repeat < 1:
            errors.append(f"{location}.repeat must be an integer >= 1")

        min_rate = case.get("min_trigger_rate", 0.67)
        if not isinstance(min_rate, (int, float)) or not 0 <= float(min_rate) <= 1:
            errors.append(f"{location}.min_trigger_rate must be between 0 and 1")

    if true_cases < 2:
        errors.append("trigger_evals.json must contain at least 2 positive trigger cases")
    if false_cases < 2:
        errors.append("trigger_evals.json must contain at least 2 negative trigger cases")

    return errors


def validate_workflow_cases(cases: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(cases, list):
        return ["workflow_evals.json must contain a list"]

    if len(cases) < 3:
        errors.append("workflow_evals.json must contain at least 3 cases")

    for index, case in enumerate(cases):
        location = f"workflow_evals[{index}]"
        if not isinstance(case, dict):
            errors.append(f"{location} must be an object")
            continue

        for key in (
            "id",
            "command",
            "prompt",
            "fixture_path",
            "expected_artifacts",
            "required_sections",
            "expected_subject_types",
        ):
            if key not in case:
                errors.append(f"{location} missing key: {key}")

        if not isinstance(case.get("id"), str) or not case.get("id", "").strip():
            errors.append(f"{location}.id must be a non-empty string")

        if case.get("command") not in VALID_WORKFLOW_COMMANDS:
            errors.append(f"{location}.command must be one of {sorted(VALID_WORKFLOW_COMMANDS)}")

        if not isinstance(case.get("prompt"), str) or not case.get("prompt", "").strip():
            errors.append(f"{location}.prompt must be a non-empty string")

        fixture_path = case.get("fixture_path")
        if not isinstance(fixture_path, str) or not fixture_path.strip():
            errors.append(f"{location}.fixture_path must be a non-empty string")

        expected_artifacts = case.get("expected_artifacts")
        if not isinstance(expected_artifacts, list) or not expected_artifacts:
            errors.append(f"{location}.expected_artifacts must be a non-empty list")

        required_sections = case.get("required_sections")
        if not isinstance(required_sections, dict) or not required_sections:
            errors.append(f"{location}.required_sections must be a non-empty object")

        expected_subject_types = case.get("expected_subject_types")
        if not isinstance(expected_subject_types, list) or not expected_subject_types:
            errors.append(f"{location}.expected_subject_types must be a non-empty list")

    return errors


def validate_report_quality_cases(cases: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(cases, list):
        return ["report_quality_evals.json must contain a list"]

    if len(cases) < 5:
        errors.append("report_quality_evals.json must contain at least 5 cases")

    for index, case in enumerate(cases):
        location = f"report_quality_evals[{index}]"
        if not isinstance(case, dict):
            errors.append(f"{location} must be an object")
            continue

        for key in ("id", "input_fixture"):
            if key not in case:
                errors.append(f"{location} missing key: {key}")

        if not isinstance(case.get("id"), str) or not case.get("id", "").strip():
            errors.append(f"{location}.id must be a non-empty string")

        input_fixture = case.get("input_fixture")
        if not isinstance(input_fixture, str) or not input_fixture.strip():
            errors.append(f"{location}.input_fixture must be a non-empty string")

        renderer = case.get("renderer")
        assertion = case.get("assertion")
        if renderer is None and assertion is None:
            errors.append(f"{location} must define either renderer or assertion")
        if renderer is not None and assertion is not None:
            errors.append(f"{location} must not define both renderer and assertion")

        if renderer is not None:
            if renderer not in VALID_REPORT_RENDERERS:
                errors.append(f"{location}.renderer must be one of {sorted(VALID_REPORT_RENDERERS)}")

            for list_key in ("must_contain", "must_not_contain", "expected_bundle_files", "expected_vex_states"):
                value = case.get(list_key)
                if value is not None:
                    if not isinstance(value, list):
                        errors.append(f"{location}.{list_key} must be a list")
                    elif any(not isinstance(item, str) or not item.strip() for item in value):
                        errors.append(f"{location}.{list_key} entries must be non-empty strings")

            attestation_keys = case.get("attestation_must_contain_keys")
            if attestation_keys is not None:
                if not isinstance(attestation_keys, list):
                    errors.append(f"{location}.attestation_must_contain_keys must be a list")
                elif any(not isinstance(item, str) or not item.strip() for item in attestation_keys):
                    errors.append(f"{location}.attestation_must_contain_keys entries must be non-empty strings")

            max_bytes = case.get("max_bytes")
            if max_bytes is not None and (not isinstance(max_bytes, int) or max_bytes < 1):
                errors.append(f"{location}.max_bytes must be an integer >= 1")

        if assertion is not None and assertion not in VALID_REPORT_ASSERTIONS:
            errors.append(f"{location}.assertion must be one of {sorted(VALID_REPORT_ASSERTIONS)}")

    return errors


def validate_eval_suite(evals_dir: Path = DEFAULT_EVALS_DIR) -> list[str]:
    errors: list[str] = []

    benchmark_json_path = evals_dir / "benchmark.json"
    benchmark_md_path = evals_dir / "benchmark.md"

    eval_paths = sorted(evals_dir.glob("*_evals.json"))
    expected_eval_files = {"trigger_evals.json", "workflow_evals.json", "report_quality_evals.json"}
    seen_eval_files = {path.name for path in eval_paths}

    for name in sorted(expected_eval_files - seen_eval_files):
        errors.append(f"missing eval artifact: {name}")

    for path in (benchmark_json_path, benchmark_md_path):
        if not path.exists():
            errors.append(f"missing eval artifact: {path.name}")

    if errors:
        return errors

    try:
        loaded = {path.name: _load_json(path) for path in eval_paths}
    except json.JSONDecodeError as exc:
        return [f"invalid eval JSON: {exc}"]

    validators = {
        "trigger_evals.json": validate_trigger_cases,
        "workflow_evals.json": validate_workflow_cases,
        "report_quality_evals.json": validate_report_quality_cases,
    }
    for path in eval_paths:
        validator = validators.get(path.name)
        if validator is None:
            errors.append(f"no validator registered for eval artifact: {path.name}")
            continue
        errors.extend(validator(loaded[path.name]))

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate VulnScout prompt eval definitions")
    parser.add_argument("evals_dir", nargs="?", default=str(DEFAULT_EVALS_DIR), help="Directory containing eval definitions")
    args = parser.parse_args()

    errors = validate_eval_suite(Path(args.evals_dir))
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1

    print("ok: prompt eval definitions passed validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
