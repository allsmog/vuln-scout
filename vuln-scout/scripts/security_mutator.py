#!/usr/bin/env python3
"""Security mutation testing and differential security analysis.

Security Mutation Testing:
  Remove sanitizers and security controls, re-scan. If the pipeline
  doesn't detect the now-vulnerable code, that's a detection gap.

Differential Security Analysis:
  Compare security posture between two git refs. Report new vulns,
  fixed vulns, changed severity, new/removed endpoints.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")


# ---------------------------------------------------------------------------
# Security Mutation Testing
# ---------------------------------------------------------------------------

@dataclass
class Mutation:
    """A security-weakening code mutation."""
    file: str
    line: int
    original: str
    mutated: str
    mutation_type: str
    description: str


@dataclass
class MutationResult:
    """Result of running the scan pipeline on mutated code."""
    mutation: Mutation
    detected: bool
    finding_id: str = ""


# Mutation patterns: (regex_to_find, replacement, type, description)
_MUTATIONS: list[tuple[re.Pattern[str], str, str, str]] = [
    # Remove parameterized query -> string concat
    (re.compile(r"""(\.(?:query|execute)\s*\([^,]+),\s*\[[^\]]+\]\s*\)"""),
     r"\1)", "remove-parameterization",
     "Removed parameter binding from SQL query"),

    # Remove auth middleware from route
    (re.compile(r""",\s*\w*[Aa]uth\w*\s*,"""),
     ",", "remove-auth-middleware",
     "Removed auth middleware from route handler"),

    # Remove CSRF token check
    (re.compile(r"""(?:csrf|xsrf)(?:_token|Token)\s*(?:===?|!==?)\s*\w+"""),
     "true", "remove-csrf-check",
     "Replaced CSRF token check with true"),

    # Change shell=False to shell=True
    (re.compile(r"""shell\s*=\s*False"""),
     "shell=True", "enable-shell",
     "Changed shell=False to shell=True in subprocess"),

    # Remove input validation/sanitization
    (re.compile(r"""(?:sanitize|escape|validate|clean|purify)\w*\s*\(([^)]+)\)"""),
     r"\1", "remove-sanitizer",
     "Removed sanitizer/validator function call"),

    # Remove rate limiting
    (re.compile(r"""(?:rateLimit|rateLimiter|throttle)\s*\([^)]*\)\s*,?"""),
     "", "remove-rate-limit",
     "Removed rate limiting middleware"),
]


def find_mutations(target_path: str) -> list[Mutation]:
    """Find all possible security-weakening mutations in the codebase."""
    root = Path(target_path).resolve()
    mutations: list[Mutation] = []
    extensions = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".php"}
    excluded = {"node_modules", "vendor", "dist", ".git", "__pycache__"}

    for f in root.rglob("*"):
        if not f.is_file() or f.suffix not in extensions:
            continue
        if any(ex in f.parts for ex in excluded):
            continue

        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue

        rel = str(f.relative_to(root))
        for i, line in enumerate(text.splitlines(), 1):
            for pattern, replacement, mut_type, description in _MUTATIONS:
                m = pattern.search(line)
                if m:
                    mutated = pattern.sub(replacement, line)
                    if mutated != line:
                        mutations.append(Mutation(
                            file=rel, line=i,
                            original=line.strip(),
                            mutated=mutated.strip(),
                            mutation_type=mut_type,
                            description=description,
                        ))

    log.info("Found %d possible security mutations", len(mutations))
    return mutations


def mutation_report(mutations: list[Mutation]) -> dict[str, Any]:
    """Generate a mutation testing report (without actually running mutations).

    The report identifies security controls that, if removed, would create
    vulnerabilities -- and whether the current scanning pipeline would detect them.
    """
    by_type: dict[str, int] = {}
    for m in mutations:
        by_type[m.mutation_type] = by_type.get(m.mutation_type, 0) + 1

    return {
        "total_mutations": len(mutations),
        "by_type": by_type,
        "mutations": [
            {
                "file": m.file,
                "line": m.line,
                "type": m.mutation_type,
                "description": m.description,
                "original": m.original[:200],
                "mutated": m.mutated[:200],
            }
            for m in mutations
        ],
    }


# ---------------------------------------------------------------------------
# Differential Security Analysis
# ---------------------------------------------------------------------------

@dataclass
class SecurityDiff:
    """Diff between two security scans."""
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    fixed_findings: list[dict[str, Any]] = field(default_factory=list)
    changed_findings: list[dict[str, Any]] = field(default_factory=list)
    new_endpoints: list[dict[str, Any]] = field(default_factory=list)
    removed_endpoints: list[dict[str, Any]] = field(default_factory=list)
    regression_score: float = 0.0


def diff_security(
    current_artifact: dict[str, Any],
    baseline_artifact: dict[str, Any],
) -> SecurityDiff:
    """Compare two findings artifacts and produce a security diff.

    Args:
        current_artifact: The latest scan results.
        baseline_artifact: Previous scan results to compare against.

    Returns:
        SecurityDiff with categorized changes.
    """
    result = SecurityDiff()

    # Index by stable_key
    current_by_key = {f.get("stable_key", ""): f for f in current_artifact.get("findings", [])}
    baseline_by_key = {f.get("stable_key", ""): f for f in baseline_artifact.get("findings", [])}

    # New findings (in current but not baseline)
    for key, finding in current_by_key.items():
        if key not in baseline_by_key:
            result.new_findings.append(finding)

    # Fixed findings (in baseline but not current)
    for key, finding in baseline_by_key.items():
        if key not in current_by_key:
            result.fixed_findings.append(finding)

    # Changed findings (same key, different verdict/severity)
    for key in current_by_key.keys() & baseline_by_key.keys():
        current = current_by_key[key]
        baseline = baseline_by_key[key]
        changes: dict[str, Any] = {}

        if current.get("severity") != baseline.get("severity"):
            changes["severity"] = {"old": baseline.get("severity"), "new": current.get("severity")}
        if current.get("verdict") != baseline.get("verdict"):
            changes["verdict"] = {"old": baseline.get("verdict"), "new": current.get("verdict")}
        if current.get("kind") != baseline.get("kind"):
            changes["kind"] = {"old": baseline.get("kind"), "new": current.get("kind")}

        if changes:
            result.changed_findings.append({
                "finding": current,
                "changes": changes,
            })

    # Endpoint diff
    current_eps = {f"{e.get('method')}:{e.get('path')}" for e in current_artifact.get("entry_points", [])}
    baseline_eps = {f"{e.get('method')}:{e.get('path')}" for e in baseline_artifact.get("entry_points", [])}

    for ep_key in current_eps - baseline_eps:
        method, path = ep_key.split(":", 1) if ":" in ep_key else ("ALL", ep_key)
        result.new_endpoints.append({"method": method, "path": path})
    for ep_key in baseline_eps - current_eps:
        method, path = ep_key.split(":", 1) if ":" in ep_key else ("ALL", ep_key)
        result.removed_endpoints.append({"method": method, "path": path})

    # Compute regression score: positive = worse, negative = better
    severity_weight = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    new_weight = sum(severity_weight.get(f.get("severity", "info"), 0) for f in result.new_findings)
    fixed_weight = sum(severity_weight.get(f.get("severity", "info"), 0) for f in result.fixed_findings)
    result.regression_score = new_weight - fixed_weight

    log.info("Security diff: +%d new, -%d fixed, ~%d changed, score=%+.1f",
             len(result.new_findings), len(result.fixed_findings),
             len(result.changed_findings), result.regression_score)

    return result


def diff_to_dict(diff: SecurityDiff) -> dict[str, Any]:
    """Convert SecurityDiff to JSON-serializable dict."""
    return {
        "new_findings": len(diff.new_findings),
        "fixed_findings": len(diff.fixed_findings),
        "changed_findings": len(diff.changed_findings),
        "new_endpoints": diff.new_endpoints,
        "removed_endpoints": diff.removed_endpoints,
        "regression_score": diff.regression_score,
        "details": {
            "new": [{"id": f.get("id"), "type": f.get("type"), "severity": f.get("severity"), "file": f.get("file")} for f in diff.new_findings],
            "fixed": [{"id": f.get("id"), "type": f.get("type"), "severity": f.get("severity"), "file": f.get("file")} for f in diff.fixed_findings],
            "changed": diff.changed_findings,
        },
    }
