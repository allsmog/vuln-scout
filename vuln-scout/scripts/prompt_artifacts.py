#!/usr/bin/env python3
from __future__ import annotations

import re
from typing import Any


AUDIT_PLAN_REQUIRED_SECTIONS = (
    "Context",
    "Audit Strategy",
    "Module Prioritization",
    "Attack Surfaces",
    "Verification Strategy",
    "Task List",
    "Audit Scenarios",
)

REVIEW_LEDGER_SCHEMA_VERSION = "1.0.0"
VALID_REVIEW_SUBJECT_TYPES = {
    "audit-plan",
    "threat-model",
    "module-findings",
    "finding-verification",
}
VALID_REVIEW_STATUS = {"APPROVED", "CHANGES_REQUESTED", "UNRESOLVED"}
REVIEWER_UNRESOLVED_TAG = "[REVIEWER NOTE: unresolved]"
REQUIRED_STATE_ARTIFACT_KEYS = (
    "scope_architecture",
    "threat_model",
    "audit_plan",
    "audit_report",
    "findings_json",
    "review_ledger",
    "state_json",
)
REQUIRED_REVIEW_STATE_KEYS = ("audit_plan", "threat_model", "findings")
REQUIRED_PHASE_MARKERS = {"audit-plan", "threat-review", "finding-review"}


def _normalize_heading(value: str) -> str:
    value = re.sub(r"^#+\s*", "", value).strip().lower()
    return re.sub(r"\s+", " ", value)


def extract_markdown_headings(text: str) -> set[str]:
    headings: set[str] = set()
    for line in text.splitlines():
        if not line.lstrip().startswith("#"):
            continue
        headings.add(_normalize_heading(line))
    return headings


def missing_markdown_sections(text: str, required_sections: tuple[str, ...] | list[str]) -> list[str]:
    headings = extract_markdown_headings(text)
    return [section for section in required_sections if _normalize_heading(section) not in headings]


def validate_audit_plan(text: str) -> list[str]:
    errors: list[str] = []
    missing = missing_markdown_sections(text, list(AUDIT_PLAN_REQUIRED_SECTIONS))
    if missing:
        errors.append(f"audit plan missing sections: {', '.join(missing)}")
    return errors


def default_review_ledger() -> dict[str, Any]:
    return {
        "schema_version": REVIEW_LEDGER_SCHEMA_VERSION,
        "generated_at": None,
        "subjects": [],
    }


def validate_review_ledger(ledger: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    for key in ("schema_version", "generated_at", "subjects"):
        if key not in ledger:
            errors.append(f"missing top-level key: {key}")

    if ledger.get("schema_version") != REVIEW_LEDGER_SCHEMA_VERSION:
        errors.append(f"schema_version must be {REVIEW_LEDGER_SCHEMA_VERSION}")

    generated_at = ledger.get("generated_at")
    if generated_at is not None and not isinstance(generated_at, str):
        errors.append("generated_at must be a string or null")

    subjects = ledger.get("subjects")
    if not isinstance(subjects, list):
        errors.append("subjects must be a list")
        return errors

    for index, subject in enumerate(subjects):
        location = f"subjects[{index}]"
        if not isinstance(subject, dict):
            errors.append(f"{location} must be an object")
            continue

        for key in ("subject_type", "subject_id", "round", "reviewers", "status", "notes"):
            if key not in subject:
                errors.append(f"{location} missing key: {key}")

        if subject.get("subject_type") not in VALID_REVIEW_SUBJECT_TYPES:
            errors.append(
                f"{location}.subject_type must be one of {sorted(VALID_REVIEW_SUBJECT_TYPES)}"
            )

        subject_id = subject.get("subject_id")
        if not isinstance(subject_id, str) or not subject_id.strip():
            errors.append(f"{location}.subject_id must be a non-empty string")

        round_number = subject.get("round")
        if not isinstance(round_number, int) or round_number < 1:
            errors.append(f"{location}.round must be an integer >= 1")

        reviewers = subject.get("reviewers")
        if not isinstance(reviewers, list) or not reviewers:
            errors.append(f"{location}.reviewers must be a non-empty list")
        else:
            for reviewer_index, reviewer in enumerate(reviewers):
                reviewer_loc = f"{location}.reviewers[{reviewer_index}]"
                if isinstance(reviewer, str):
                    if not reviewer.strip():
                        errors.append(f"{reviewer_loc} must not be empty")
                    continue
                if not isinstance(reviewer, dict):
                    errors.append(f"{reviewer_loc} must be a string or object")
                    continue
                if not any(
                    isinstance(reviewer.get(key), str) and reviewer.get(key, "").strip()
                    for key in ("name", "angle", "summary")
                ):
                    errors.append(f"{reviewer_loc} must include reviewer context")

        status = subject.get("status")
        if status not in VALID_REVIEW_STATUS:
            errors.append(f"{location}.status must be one of {sorted(VALID_REVIEW_STATUS)}")

        notes = subject.get("notes")
        if not isinstance(notes, list):
            errors.append(f"{location}.notes must be a list")
            continue
        if status == "UNRESOLVED" and not any(
            isinstance(note, str) and REVIEWER_UNRESOLVED_TAG in note for note in notes
        ):
            errors.append(f"{location}.notes must include {REVIEWER_UNRESOLVED_TAG!r} when unresolved")

    return errors


def validate_orchestration_state(state: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    artifacts = state.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("artifacts must be an object")
        artifacts = {}

    review_state = state.get("review_state")
    if not isinstance(review_state, dict):
        errors.append("review_state must be an object")
        review_state = {}

    phases_completed = state.get("phases_completed")
    if not isinstance(phases_completed, list):
        errors.append("phases_completed must be a list")
        phases_completed = []

    for key in REQUIRED_STATE_ARTIFACT_KEYS:
        if key not in artifacts:
            errors.append(f"artifacts missing key: {key}")

    for key in REQUIRED_REVIEW_STATE_KEYS:
        if key not in review_state:
            errors.append(f"review_state missing key: {key}")

    missing_phase_markers = sorted(REQUIRED_PHASE_MARKERS.difference(phases_completed))
    if missing_phase_markers:
        errors.append(f"phases_completed missing markers: {', '.join(missing_phase_markers)}")

    return errors
