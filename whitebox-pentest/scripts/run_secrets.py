#!/usr/bin/env python3
"""Run secret scanning (gitleaks/trufflehog) and normalize to VulnScout findings."""
from __future__ import annotations

import argparse
import json
import logging
import math
import shutil
import subprocess
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifact_utils import (
    SCHEMA_VERSION,
    SEVERITY_PRIORITY,
    stable_key_for,
    summarize_findings,
    deduplicate_findings,
    apply_suppressions,
    parse_suppressions,
    validate_findings_artifact,
    dump_json,
    cvss_vector_for,
    cvss_score_from_vector,
)

log = logging.getLogger("vuln-scout")

# Secret type -> severity mapping
SECRET_SEVERITY_KEYWORDS: list[tuple[str, str]] = [
    ("aws", "critical"),
    ("gcp", "critical"),
    ("azure", "critical"),
    ("private-key", "critical"),
    ("private_key", "critical"),
    ("stripe.*secret", "critical"),
    ("database", "high"),
    ("github", "high"),
    ("gitlab", "high"),
    ("slack", "high"),
    ("twilio", "high"),
    ("sendgrid", "high"),
    ("api-key", "medium"),
    ("api_key", "medium"),
    ("jwt", "medium"),
    ("password", "medium"),
    ("token", "medium"),
    ("generic", "low"),
]

_EXCLUDE_PATTERNS = [
    "tests/", "test/", "fixtures/", "examples/", "docs/",
    "*.example", "*.sample", "*.test.*",
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact_secret(value: str) -> str:
    """Redact a secret value, keeping only first 4 + last 4 chars."""
    if not value:
        return "[REDACTED]"
    if len(value) <= 8:
        return "****"
    return value[:4] + "..." + value[-4:]


def classify_severity(rule_id: str, description: str = "") -> str:
    """Map secret type to severity."""
    combined = (rule_id + " " + description).lower()
    for keyword, severity in SECRET_SEVERITY_KEYWORDS:
        if keyword in combined:
            return severity
    return "medium"


def detect_tool(preferred: str | None) -> str | None:
    """Detect available secret scanning tool."""
    if preferred and preferred != "auto":
        if shutil.which(preferred):
            return preferred
        return None
    if shutil.which("gitleaks"):
        return "gitleaks"
    if shutil.which("trufflehog"):
        return "trufflehog"
    return None


def run_gitleaks(path: str, since_commit: str | None, *, strict: bool = False) -> list[dict[str, Any]]:
    """Run gitleaks and return raw results."""
    cmd = ["gitleaks", "detect", "--source", path, "--report-format", "json", "--report-path", "/dev/stdout"]
    if since_commit:
        cmd.extend(["--log-opts", f"{since_commit}...HEAD"])
    cmd.append("--no-banner")
    if not strict:
        for pattern in _EXCLUDE_PATTERNS:
            cmd.extend(["--exclude-path", pattern])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    # gitleaks exits 1 when leaks found (not error)
    if result.returncode not in (0, 1):
        log.warning("gitleaks error: %s", result.stderr[:300])
        return []

    try:
        data = json.loads(result.stdout) if result.stdout.strip() else []
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        log.warning("Failed to parse gitleaks output")
        return []


def run_trufflehog(path: str, since_commit: str | None) -> list[dict[str, Any]]:
    """Run trufflehog and return raw results (NDJSON)."""
    cmd = ["trufflehog", "filesystem", path, "--json"]
    if since_commit:
        cmd.extend(["--since-commit", since_commit])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        log.warning("trufflehog error: %s", result.stderr[:300])
        return []

    results = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def normalize_gitleaks(result: dict[str, Any], index: int, *, strict: bool = False) -> dict[str, Any]:
    """Normalize a gitleaks result to VulnScout finding."""
    rule_id = result.get("RuleID", "unknown")
    description = result.get("Description", "")
    secret = result.get("Secret", result.get("Match", ""))

    kind = "finding"
    if not strict and _shannon_entropy(secret) < 3.0:
        kind = "hotspot"

    finding: dict[str, Any] = {
        "id": f"SECRET-{index:04d}",
        "stable_key": "",
        "kind": kind,
        "severity": classify_severity(rule_id, description),
        "type": "hardcoded-secret",
        "title": description or f"Secret detected: {rule_id}",
        "file": result.get("File", "unknown"),
        "line": result.get("StartLine", 0),
        "verdict": "unverified",
        "confidence": "high",
        "source_tool": "gitleaks",
        "message": f"{description} (rule: {rule_id})",
        "rule_id": rule_id,
        "evidence": [{
            "type": "secret-match",
            "label": rule_id,
            "path": result.get("File", "unknown"),
            "line": result.get("StartLine", 0),
            "excerpt": redact_secret(secret),
        }],
    }
    finding["stable_key"] = stable_key_for(finding)

    vector = cvss_vector_for(finding)
    if vector:
        finding["cvss_vector"] = vector
        finding["cvss_score"] = cvss_score_from_vector(vector)

    return finding


def normalize_trufflehog(result: dict[str, Any], index: int, *, strict: bool = False) -> dict[str, Any]:
    """Normalize a trufflehog result to VulnScout finding."""
    detector = result.get("DetectorName", "unknown")
    raw = result.get("Raw", "")
    source_meta = result.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
    verified = result.get("Verified", False)

    if verified:
        kind = "finding"
        verdict = "verified"
        confidence = "verified"
    else:
        kind = "hotspot"
        verdict = "unverified"
        confidence = "medium"

    # Entropy-based demotion for unverified results
    if not strict and not verified and _shannon_entropy(raw) < 3.0:
        kind = "hotspot"

    finding: dict[str, Any] = {
        "id": f"SECRET-{index:04d}",
        "stable_key": "",
        "kind": kind,
        "severity": classify_severity(detector),
        "type": "hardcoded-secret",
        "title": f"Secret detected: {detector}",
        "file": source_meta.get("file", "unknown"),
        "line": source_meta.get("line", 0),
        "verdict": verdict,
        "confidence": confidence,
        "source_tool": "trufflehog",
        "message": f"Detected {detector} secret" + (" (verified active)" if result.get("Verified") else ""),
        "rule_id": detector,
        "evidence": [{
            "type": "secret-match",
            "label": detector,
            "path": source_meta.get("file", "unknown"),
            "line": source_meta.get("line", 0),
            "excerpt": redact_secret(raw),
        }],
    }
    finding["stable_key"] = stable_key_for(finding)

    vector = cvss_vector_for(finding)
    if vector:
        finding["cvss_vector"] = vector
        finding["cvss_score"] = cvss_score_from_vector(vector)

    return finding


def main() -> int:
    parser = argparse.ArgumentParser(description="Run secret scanning and normalize to VulnScout findings")
    parser.add_argument("path", nargs="?", default=".", help="Target directory")
    parser.add_argument("--tool", choices=["gitleaks", "trufflehog", "auto"], default="auto")
    parser.add_argument("--since-commit", help="Scan changes since this commit")
    parser.add_argument("--diff-base", help="Alias for --since-commit")
    parser.add_argument("--suppressions", help="Path to .vuln-scout-ignore")
    parser.add_argument("--format", choices=["json", "sarif"], default="json")
    parser.add_argument("--fail-on", choices=list(SEVERITY_PRIORITY.keys()))
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--strict", action="store_true",
                        help="Skip path exclusions and entropy-based demotion")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)

    tool = detect_tool(args.tool)
    if not tool:
        log.error("No secret scanner found. Install gitleaks or trufflehog.")
        return 1

    since = args.since_commit or args.diff_base
    target = str(Path(args.path).resolve())

    log.info("Running %s on %s", tool, target)

    if tool == "gitleaks":
        raw_results = run_gitleaks(target, since, strict=args.strict)
        findings = [normalize_gitleaks(r, i, strict=args.strict) for i, r in enumerate(raw_results)]
    else:
        raw_results = run_trufflehog(target, since)
        findings = [normalize_trufflehog(r, i, strict=args.strict) for i, r in enumerate(raw_results)]

    log.info("Found %d secrets", len(findings))

    findings = deduplicate_findings(findings)

    artifact: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scan_id": str(uuid.uuid4()),
        "project_path": target,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "source_tool": tool,
        "summary": summarize_findings(findings),
        "findings": findings,
    }

    if args.suppressions:
        suppressions = parse_suppressions(args.suppressions)
        artifact = apply_suppressions(artifact, suppressions)

    errors = validate_findings_artifact(artifact)
    for err in errors:
        log.warning("Schema validation: %s", err)

    if args.output:
        dump_json(artifact, args.output)
        log.info("Wrote %d findings to %s", len(findings), args.output)
    else:
        print(json.dumps(artifact, indent=2))

    if args.fail_on:
        threshold = SEVERITY_PRIORITY.get(args.fail_on, 0)
        for sev, priority in SEVERITY_PRIORITY.items():
            if priority >= threshold and artifact["summary"].get(sev, 0) > 0:
                return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
