#!/usr/bin/env python3
"""Run Semgrep and normalize results to VulnScout findings schema."""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure sibling imports work when invoked directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifact_utils import (
    SCHEMA_VERSION,
    SEVERITY_PRIORITY,
    classify_semgrep_result,
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

# ---------------------------------------------------------------------------
# CWE -> VulnScout vulnerability type mapping
# ---------------------------------------------------------------------------
CWE_TYPE_MAP: dict[str, str] = {
    "CWE-89": "sql-injection",
    "CWE-78": "command-injection",
    "CWE-79": "xss",
    "CWE-22": "path-traversal",
    "CWE-918": "ssrf",
    "CWE-502": "deserialization",
    "CWE-1321": "prototype-pollution",
    "CWE-94": "code-injection",
    "CWE-1333": "redos",
    "CWE-611": "xxe",
    "CWE-90": "ldap-injection",
    "CWE-330": "insecure-randomness",
    "CWE-327": "cryptographic-failure",
    "CWE-798": "hardcoded-secret",
    "CWE-352": "csrf",
    "CWE-601": "open-redirect",
}

# Semgrep severity -> VulnScout severity
SEVERITY_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_changed_files(since_commit: str, path: str) -> list[str]:
    """Get files changed since a git commit."""
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{since_commit}...HEAD", "--", path],
        capture_output=True, text=True, cwd=path,
    )
    if result.returncode != 0:
        log.warning("git diff failed: %s", result.stderr.strip())
        return []
    return [f for f in result.stdout.strip().split("\n") if f]


def map_severity(semgrep_severity: str) -> str:
    """Map Semgrep severity to VulnScout severity."""
    return SEVERITY_MAP.get(semgrep_severity.upper(), "medium")


def classify_kind(result: dict[str, Any]) -> str | None:
    """Classify a Semgrep result using the shared three-tier logic.

    Returns "finding", "hotspot", or None (Tier 3 -- drop).
    """
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    return classify_semgrep_result(extra, metadata)


def map_vuln_type(rule_id: str, metadata: dict[str, Any]) -> str:
    """Map Semgrep rule to VulnScout vulnerability type."""
    # Try CWE mapping first
    for cwe in metadata.get("cwe", []):
        cwe_id = cwe if isinstance(cwe, str) else str(cwe)
        # Normalize: "CWE-89: SQL Injection" -> "CWE-89"
        cwe_key = cwe_id.split(":")[0].strip()
        if cwe_key in CWE_TYPE_MAP:
            return CWE_TYPE_MAP[cwe_key]

    # Fallback: guess from rule_id keywords
    rule_lower = rule_id.lower()
    for keyword, vuln_type in [
        ("sqli", "sql-injection"), ("sql-injection", "sql-injection"),
        ("xss", "xss"), ("cross-site-scripting", "xss"),
        ("cmdi", "command-injection"), ("command-injection", "command-injection"),
        ("ssrf", "ssrf"), ("path-traversal", "path-traversal"),
        ("deserialization", "deserialization"), ("xxe", "xxe"),
        ("ssti", "ssti"), ("template-injection", "ssti"),
        ("open-redirect", "open-redirect"), ("csrf", "csrf"),
        ("hardcoded", "hardcoded-secret"), ("secret", "hardcoded-secret"),
    ]:
        if keyword in rule_lower:
            return vuln_type

    # Use rule_id slug as fallback
    return rule_id.split(".")[-1] if "." in rule_id else rule_id


def normalize_result(result: dict[str, Any], index: int, no_filter: bool = False) -> dict[str, Any] | None:
    """Convert a Semgrep JSON result to a VulnScout finding dict.

    Returns None for Tier 3 results that should be dropped (unless *no_filter*
    is True, in which case they are kept as hotspots).
    """
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})

    vuln_type = map_vuln_type(result.get("check_id", "unknown"), metadata)
    severity = map_severity(extra.get("severity", "WARNING"))
    kind = classify_kind(result)

    # Tier 3: drop unless no_filter is set
    if kind is None:
        if no_filter:
            kind = "hotspot"
        else:
            return None

    evidence = [{
        "type": "pattern-match",
        "label": result.get("check_id", "unknown"),
        "path": result.get("path", "unknown"),
        "line": result.get("start", {}).get("line", 0),
        "excerpt": extra.get("lines", "").strip()[:200],
    }]

    # Add dataflow trace evidence if available
    dataflow = extra.get("dataflow_trace")
    if dataflow and isinstance(dataflow, dict):
        taint_source = dataflow.get("taint_source")
        if taint_source and isinstance(taint_source, list) and len(taint_source) > 0:
            src = taint_source[0] if isinstance(taint_source[0], dict) else {}
            loc = src.get("location", {})
            evidence.append({
                "type": "taint-source",
                "label": "Semgrep taint source",
                "path": loc.get("path", result.get("path", "")),
                "line": loc.get("start", {}).get("line", 0),
                "excerpt": src.get("content", "")[:200],
            })

    # Propagate Semgrep's confidence directly from metadata
    semgrep_conf = metadata.get("confidence", "MEDIUM").upper()
    confidence = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(semgrep_conf, "medium")

    finding: dict[str, Any] = {
        "id": f"VSCOUT-{index:04d}",
        "stable_key": "",  # computed below
        "kind": kind,
        "severity": severity,
        "type": vuln_type,
        "title": metadata.get("message", extra.get("message", vuln_type)),
        "file": result.get("path", "unknown"),
        "line": result.get("start", {}).get("line", 0),
        "verdict": "unverified",
        "confidence": confidence,
        "source_tool": "semgrep",
        "message": extra.get("message", ""),
        "rule_id": result.get("check_id", ""),
        "evidence": evidence,
    }

    # Add CWE if available
    cwes = metadata.get("cwe", [])
    if cwes:
        finding["cwe"] = cwes[0] if isinstance(cwes[0], str) else str(cwes[0])

    # Compute stable key
    finding["stable_key"] = stable_key_for(finding)

    # Add CVSS if we have a mapping
    vector = cvss_vector_for(finding)
    if vector:
        finding["cvss_vector"] = vector
        finding["cvss_score"] = cvss_score_from_vector(vector)

    return finding


def build_artifact(findings: list[dict[str, Any]], project_path: str) -> dict[str, Any]:
    """Wrap findings into a full artifact envelope."""
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": str(uuid.uuid4()),
        "project_path": str(Path(project_path).resolve()),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "source_tool": "semgrep",
        "summary": summarize_findings(findings),
        "findings": findings,
    }


def check_fail_on(summary: dict[str, Any], fail_on: str) -> bool:
    """Return True if exit code should be 2."""
    threshold = SEVERITY_PRIORITY.get(fail_on, 0)
    for sev, priority in SEVERITY_PRIORITY.items():
        if priority >= threshold and summary.get(sev, 0) > 0:
            return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Semgrep and normalize to VulnScout findings")
    parser.add_argument("path", nargs="?", default=".", help="Target directory")
    parser.add_argument("--rules", default="auto", help="Semgrep ruleset (default: auto)")
    parser.add_argument("--since-commit", help="Only scan files changed since this commit")
    parser.add_argument("--diff-base", help="Alias for --since-commit")
    parser.add_argument("--exclude", action="append", default=[], help="Exclusion patterns")
    parser.add_argument("--suppressions", help="Path to .vuln-scout-ignore")
    parser.add_argument("--format", choices=["json", "sarif"], default="json")
    parser.add_argument("--fail-on", choices=list(SEVERITY_PRIORITY.keys()))
    parser.add_argument("--no-filter", action="store_true",
                        help="Keep Tier 3 (audit/low/no-CWE) results instead of dropping them")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)

    # Check semgrep is installed
    if not shutil.which("semgrep"):
        log.error("semgrep not found. Install via: pip install semgrep")
        return 1

    target = args.path
    since = args.since_commit or args.diff_base

    # Build semgrep command (--severity WARNING drops INFO-level noise)
    cmd = ["semgrep", "--config", args.rules, "--severity", "WARNING", "--json", target]

    # Add exclusions
    for pattern in args.exclude:
        cmd.extend(["--exclude", pattern])
    # Baseline exclusions
    for baseline in ["node_modules", "vendor", "dist", "build", "__pycache__"]:
        cmd.extend(["--exclude", baseline])

    # Filter to changed files if --since-commit
    changed_files: list[str] | None = None
    if since:
        changed_files = get_changed_files(since, target)
        if not changed_files:
            log.info("No changed files found since %s", since)
            # Write empty artifact
            artifact = build_artifact([], target)
            if args.output:
                dump_json(artifact, args.output)
            else:
                print(json.dumps(artifact, indent=2))
            return 0
        for f in changed_files:
            cmd.extend(["--include", f])

    log.info("Running: %s", " ".join(cmd[:6]) + " ...")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        log.error("Semgrep timed out after 300 seconds")
        return 1
    except FileNotFoundError:
        log.error("semgrep not found on PATH")
        return 1

    # Semgrep exits 1 when findings are found (not an error)
    if result.returncode not in (0, 1):
        log.error("Semgrep failed (exit %d): %s", result.returncode, result.stderr[:500])
        return 1

    try:
        semgrep_output = json.loads(result.stdout)
    except json.JSONDecodeError:
        log.error("Failed to parse Semgrep JSON output")
        return 1

    results = semgrep_output.get("results", [])
    log.info("Semgrep returned %d results", len(results))

    # Normalize results (Tier 3 results return None and are filtered out)
    no_filter = args.no_filter
    raw = [normalize_result(r, i, no_filter=no_filter) for i, r in enumerate(results)]
    findings = [f for f in raw if f is not None]
    dropped = len(raw) - len(findings)
    if dropped:
        log.info("Dropped %d Tier 3 (audit/low/no-CWE) results", dropped)

    # Mark in_diff
    if changed_files is not None:
        changed_set = set(changed_files)
        for f in findings:
            f["in_diff"] = f.get("file", "") in changed_set

    # Deduplicate
    findings = deduplicate_findings(findings)

    # Build artifact
    artifact = build_artifact(findings, target)

    # Apply suppressions
    if args.suppressions:
        suppressions = parse_suppressions(args.suppressions)
        artifact = apply_suppressions(artifact, suppressions)

    # Validate
    errors = validate_findings_artifact(artifact)
    for err in errors:
        log.warning("Schema validation: %s", err)

    # Output
    if args.output:
        dump_json(artifact, args.output)
        log.info("Wrote %d findings to %s", len(findings), args.output)
    else:
        print(json.dumps(artifact, indent=2))

    # Exit code
    if args.fail_on and check_fail_on(artifact["summary"], args.fail_on):
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
