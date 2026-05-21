"""Secret scanning tool runner for the scan orchestrator."""
from __future__ import annotations

import json
import logging
import math
import shutil
import subprocess
from collections import Counter
from typing import Any

log = logging.getLogger("vuln-scout")

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


def _redact(value: str) -> str:
    if not value or len(value) <= 8:
        return "****"
    return value[:4] + "..." + value[-4:]


def is_available() -> bool:
    return shutil.which("gitleaks") is not None or shutil.which("trufflehog") is not None


def run(target: str, since_commit: str | None = None, strict: bool = False) -> list[dict[str, Any]]:
    """Run secret scanning and return normalized findings.

    Args:
        target: Path to scan.
        since_commit: Only scan changes after this commit.
        strict: When True, skip path exclusions and entropy demotion.
    """
    if shutil.which("gitleaks"):
        return _run_gitleaks(target, since_commit, strict=strict)
    if shutil.which("trufflehog"):
        return _run_trufflehog(target, since_commit, strict=strict)
    log.warning("No secret scanner installed, skipping")
    return []


def _run_gitleaks(target: str, since: str | None, *, strict: bool = False) -> list[dict[str, Any]]:
    cmd = ["gitleaks", "detect", "--source", target, "--report-format", "json",
           "--report-path", "/dev/stdout", "--no-banner"]
    if not strict:
        for pattern in _EXCLUDE_PATTERNS:
            cmd.extend(["--exclude-path", pattern])
    if since:
        cmd.extend(["--log-opts", f"{since}...HEAD"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    if result.returncode not in (0, 1):
        return []

    try:
        raw = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return []

    findings = []
    for i, r in enumerate(raw if isinstance(raw, list) else []):
        secret = r.get("Secret", r.get("Match", ""))
        kind = "finding"
        if not strict and _shannon_entropy(secret) < 3.0:
            kind = "hotspot"
        findings.append({
            "id": f"SECRET-{i:04d}", "stable_key": "", "kind": kind,
            "severity": "high", "type": "hardcoded-secret",
            "title": r.get("Description", "Secret detected"),
            "file": r.get("File", "unknown"), "line": r.get("StartLine", 0),
            "verdict": "unverified", "confidence": "high",
            "source_tool": "gitleaks", "message": r.get("Description", ""),
            "rule_id": r.get("RuleID", "unknown"),
            "evidence": [{"type": "secret-match", "label": r.get("RuleID", ""),
                         "path": r.get("File", ""), "line": r.get("StartLine", 0),
                         "excerpt": _redact(secret)}],
        })
    log.info("gitleaks found %d secrets", len(findings))
    return findings


def _run_trufflehog(target: str, since: str | None, *, strict: bool = False) -> list[dict[str, Any]]:
    cmd = ["trufflehog", "filesystem", target, "--json"]
    if since:
        cmd.extend(["--since-commit", since])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    findings = []
    for i, line in enumerate(result.stdout.strip().split("\n")):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        verified = r.get("Verified", False)
        if verified:
            kind = "finding"
            verdict = "verified"
            confidence = "verified"
        else:
            kind = "hotspot"
            verdict = "unverified"
            confidence = "medium"
        raw_secret = r.get("Raw", "")
        # Entropy-based demotion for unverified results
        if not strict and not verified and _shannon_entropy(raw_secret) < 3.0:
            kind = "hotspot"
        findings.append({
            "id": f"SECRET-{i:04d}", "stable_key": "", "kind": kind,
            "severity": "high", "type": "hardcoded-secret",
            "title": f"Secret: {r.get('DetectorName', 'unknown')}",
            "file": meta.get("file", "unknown"), "line": meta.get("line", 0),
            "verdict": verdict, "confidence": confidence,
            "source_tool": "trufflehog", "message": f"Detected {r.get('DetectorName', '')}",
            "rule_id": r.get("DetectorName", ""),
            "evidence": [{"type": "secret-match", "label": r.get("DetectorName", ""),
                         "path": meta.get("file", ""), "line": meta.get("line", 0),
                         "excerpt": _redact(raw_secret)}],
        })
    log.info("trufflehog found %d secrets", len(findings))
    return findings
