#!/usr/bin/env python3
"""Context-aware auto-triage for findings.

Adjusts severity and kind based on contextual signals:
  - Test files: demote to info
  - Behind auth: reduce severity by one level
  - Internet-reachable: boost severity
  - Dead code indicators: demote to info
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")

# Patterns that indicate test/spec files
_TEST_FILE_PATTERNS = re.compile(
    r"""(?:test_|_test\.|\.test\.|\.spec\.|__tests__|/tests?/|/spec/|/fixtures/|/mocks?/|_mock\.)""",
    re.IGNORECASE,
)

# Severity demotion ladder
_SEVERITY_LADDER = ["critical", "high", "medium", "low", "info"]


def _demote_severity(severity: str) -> str:
    """Lower severity by one level."""
    try:
        idx = _SEVERITY_LADDER.index(severity)
        return _SEVERITY_LADDER[min(idx + 1, len(_SEVERITY_LADDER) - 1)]
    except ValueError:
        return severity


def _promote_severity(severity: str) -> str:
    """Raise severity by one level."""
    try:
        idx = _SEVERITY_LADDER.index(severity)
        return _SEVERITY_LADDER[max(idx - 1, 0)]
    except ValueError:
        return severity


def auto_triage(
    findings: list[dict[str, Any]],
    entry_points: list[dict[str, Any]] | None = None,
    demote_test_files: bool = True,
    auth_reduces_severity: bool = True,
    exposure_boosts_severity: bool = True,
) -> list[dict[str, Any]]:
    """Apply context-aware triage rules to findings.

    Args:
        findings: List of findings to triage.
        entry_points: Discovered entry points (for auth/exposure context).
        demote_test_files: Demote findings in test files to info severity.
        auth_reduces_severity: Reduce severity for findings behind auth.
        exposure_boosts_severity: Boost severity for internet-reachable findings.

    Returns:
        Updated findings list (modified in place).
    """
    # Build endpoint auth lookup: file -> has_auth
    auth_by_file: dict[str, bool] = {}
    exposure_by_file: dict[str, bool] = {}
    if entry_points:
        for ep in entry_points:
            f = ep.get("file", "")
            if f:
                auth_by_file[f] = ep.get("has_auth", False)
                # If any endpoint in the file lacks auth, it's unauthenticated
                if not ep.get("has_auth", True):
                    exposure_by_file[f] = True

    triaged = 0

    for finding in findings:
        file_path = finding.get("file", "")
        original_severity = finding.get("severity", "")
        triage_reasons: list[str] = []

        # Rule 1: Test file demotion
        if demote_test_files and _TEST_FILE_PATTERNS.search(file_path):
            finding["severity"] = "info"
            finding["kind"] = "hotspot"
            triage_reasons.append("test file")

        # Rule 2: Auth reduces severity
        if auth_reduces_severity and auth_by_file.get(file_path):
            if finding.get("severity") not in ("info",):
                finding["severity"] = _demote_severity(finding["severity"])
                triage_reasons.append("behind auth")

        # Rule 3: Unauthenticated/internet-reachable boosts severity
        if exposure_boosts_severity and exposure_by_file.get(file_path):
            if finding.get("severity") not in ("critical",):
                finding["severity"] = _promote_severity(finding["severity"])
                triage_reasons.append("unauthenticated endpoint")

        # Rule 4: Generated/vendor file demotion
        if any(indicator in file_path.lower() for indicator in
               ("generated", "vendor/", "node_modules/", "migrations/", ".min.", "dist/")):
            finding["severity"] = "info"
            finding["kind"] = "hotspot"
            triage_reasons.append("generated/vendor file")

        if triage_reasons:
            finding["triage_reasons"] = triage_reasons
            triaged += 1

    if triaged:
        log.info("Auto-triage: adjusted %d findings", triaged)

    return findings
