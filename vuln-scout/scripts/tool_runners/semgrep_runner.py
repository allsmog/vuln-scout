"""Semgrep tool runner for the scan orchestrator."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# Ensure sibling imports work when invoked from the tool_runners package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from artifact_utils import classify_semgrep_result  # noqa: E402

log = logging.getLogger("vuln-scout")

CWE_TYPE_MAP: dict[str, str] = {
    "CWE-89": "sql-injection", "CWE-78": "command-injection",
    "CWE-79": "xss", "CWE-22": "path-traversal",
    "CWE-918": "ssrf", "CWE-502": "deserialization",
    "CWE-94": "code-injection", "CWE-611": "xxe",
    "CWE-90": "ldap-injection", "CWE-330": "insecure-randomness",
    "CWE-798": "hardcoded-secret",
}

# Fallback: map Semgrep rule name fragments to VulnScout types when CWE is missing.
# Many Semgrep rules (especially Express/framework-specific) use descriptive names
# without CWE tags.
RULE_NAME_TYPE_MAP: dict[str, str] = {
    "sendfile": "path-traversal",
    "res-sendfile": "path-traversal",
    "open-redirect": "open-redirect",
    "directory-listing": "security-misconfiguration",
    "eval-detected": "code-injection",
    "eval-injection": "code-injection",
    "notevil": "deserialization",
    "vm-runincontext": "deserialization",
    "hardcoded-secret": "hardcoded-secret",
    "hardcoded-password": "hardcoded-secret",
    "sqli": "sql-injection",
    "sql-injection": "sql-injection",
    "xss": "xss",
    "xxe": "xxe",
    "ssrf": "ssrf",
    "path-traversal": "path-traversal",
    "command-injection": "command-injection",
    "prototype-pollution": "prototype-pollution",
    "open-redirect": "open-redirect",
    "csrf": "csrf",
    "cors": "cors-misconfig",
    "deserialization": "deserialization",
    "insecure-random": "insecure-randomness",
    "weak-crypto": "cryptographic-failure",
    "missing-auth": "auth-bypass",
}

SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def is_available() -> bool:
    return shutil.which("semgrep") is not None


def _tail(text: str, limit: int = 1000) -> str:
    text = text.strip()
    return text[-limit:] if len(text) > limit else text


def _parse_semgrep_json(stdout: str) -> dict[str, Any]:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        # Some Semgrep versions/plugins may print status text before the JSON
        # payload. Accept that shape only when a valid JSON object follows.
        json_start = stdout.find("{")
        if json_start > 0:
            try:
                return json.loads(stdout[json_start:])
            except json.JSONDecodeError:
                pass
        raise RuntimeError("semgrep produced invalid JSON output") from exc


def _semgrep_env(target: str) -> dict[str, str]:
    """Keep Semgrep state inside the scan target for sandboxed runners."""
    state_dir = Path(target).resolve() / ".claude" / "semgrep"
    config_dir = state_dir / "config"
    cache_dir = state_dir / "cache"
    config_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(config_dir)
    env["XDG_CACHE_HOME"] = str(cache_dir)
    env["SEMGREP_LOG_FILE"] = str(state_dir / "semgrep.log")
    env["SEMGREP_SETTINGS_FILE"] = str(state_dir / "settings.yml")
    env["SEMGREP_VERSION_CACHE_PATH"] = str(cache_dir / "semgrep_version")
    return env


def _source_excerpt(target: str, result_path: str, line: int) -> str:
    path = Path(result_path)
    if not path.is_absolute():
        path = Path(target).resolve() / path
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if line <= 0 or line > len(lines):
        return ""
    return lines[line - 1].strip()[:200]


def run(
    target: str,
    rules: str = "auto",
    exclude: list[str] | None = None,
    changed_files: list[str] | None = None,
    no_filter: bool = False,
    frameworks: list[str] | None = None,
    languages: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Run Semgrep and return normalized findings.

    Args:
        target: Directory or file to scan.
        rules: Semgrep ruleset (default ``auto``).
        exclude: Extra glob exclusion patterns.
        changed_files: Restrict scan to these paths (diff-aware mode).
        no_filter: When True, keep Tier 3 results instead of dropping them.
        frameworks: Optional list of detected framework names. When provided,
            framework-specific Semgrep rulesets are added automatically.
    """
    if not is_available():
        log.warning("semgrep not installed, skipping")
        return []

    cmd = ["semgrep", "--config", rules]
    uses_local_config = rules != "auto" and Path(rules).exists()

    # Add base language security rulesets (p/php, p/java, p/python, etc.)
    if languages and not uses_local_config:
        from framework_detector import rulesets_for_languages
        for ruleset in rulesets_for_languages(languages):
            cmd.extend(["--config", ruleset])

    # Add framework-specific rulesets when available
    if frameworks and not uses_local_config:
        from framework_detector import rulesets_for_frameworks
        for ruleset in rulesets_for_frameworks(frameworks):
            cmd.extend(["--config", ruleset])

    cmd.extend(["--severity", "ERROR", "--severity", "WARNING", "--json", target])
    for pattern in (exclude or []):
        cmd.extend(["--exclude", pattern])
    for baseline in ["node_modules", "vendor", "dist", "__pycache__"]:
        cmd.extend(["--exclude", baseline])
    if changed_files:
        for f in changed_files:
            cmd.extend(["--include", f])

    log.info("Running semgrep (%s rules)", rules)
    env = _semgrep_env(target)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("semgrep timed out after 300 seconds") from exc
    except FileNotFoundError as exc:
        raise RuntimeError("semgrep executable disappeared before scan") from exc

    if result.returncode not in (0, 1):
        # Framework rulesets may fail (e.g., requires Semgrep login or ruleset
        # name changed).  Retry with just the base config.
        if frameworks and not uses_local_config:
            log.warning("semgrep exit %d with framework rules, retrying with base config only", result.returncode)
            cmd_fallback = ["semgrep", "--config", rules, "--severity", "ERROR", "--severity", "WARNING", "--json", target]
            for pattern in (exclude or []):
                cmd_fallback.extend(["--exclude", pattern])
            for baseline in ["node_modules", "vendor", "dist", "__pycache__"]:
                cmd_fallback.extend(["--exclude", baseline])
            if changed_files:
                for f in changed_files:
                    cmd_fallback.extend(["--include", f])
            try:
                result = subprocess.run(cmd_fallback, capture_output=True, text=True, timeout=300, env=env)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("semgrep fallback timed out after 300 seconds") from exc
            except FileNotFoundError as exc:
                raise RuntimeError("semgrep executable disappeared before fallback scan") from exc

        if result.returncode not in (0, 1):
            detail = _tail(result.stderr) or _tail(result.stdout)
            raise RuntimeError(f"semgrep failed with exit {result.returncode}: {detail}")

    try:
        data = _parse_semgrep_json(result.stdout)
    except RuntimeError as exc:
        stderr = _tail(result.stderr)
        detail = f": {stderr}" if stderr else ""
        raise RuntimeError(f"{exc}{detail}") from exc

    if result.returncode == 1 and data.get("errors") and not data.get("results"):
        raise RuntimeError(f"semgrep returned errors: {data.get('errors')}")

    findings = []
    dropped = 0
    for i, r in enumerate(data.get("results", [])):
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        rule_id = r.get("check_id", "unknown")

        # Map type from CWE first, then fall back to rule name matching
        vuln_type = rule_id.split(".")[-1] if "." in rule_id else rule_id
        cwe_mapped = False
        for cwe in metadata.get("cwe", []):
            cwe_key = (cwe if isinstance(cwe, str) else str(cwe)).split(":")[0].strip()
            if cwe_key in CWE_TYPE_MAP:
                vuln_type = CWE_TYPE_MAP[cwe_key]
                cwe_mapped = True
                break

        # Fallback: match rule name fragments against known vuln types
        if not cwe_mapped:
            rule_lower = rule_id.lower()
            for fragment, mapped_type in RULE_NAME_TYPE_MAP.items():
                if fragment in rule_lower:
                    vuln_type = mapped_type
                    break

        kind = classify_semgrep_result(extra, metadata)

        # Tier 3: drop unless no_filter is set
        if kind is None:
            if no_filter:
                kind = "hotspot"
            else:
                dropped += 1
                continue

        # Propagate Semgrep's confidence directly from metadata
        semgrep_conf = metadata.get("confidence", "MEDIUM").upper()
        confidence = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(semgrep_conf, "medium")
        line = r.get("start", {}).get("line", 0)
        result_path = r.get("path", "unknown")
        excerpt = extra.get("lines", "").strip()
        if not excerpt or excerpt == "requires login":
            excerpt = _source_excerpt(target, result_path, line)

        findings.append({
            "id": f"VSCOUT-{i:04d}",
            "stable_key": "",
            "kind": kind,
            "severity": SEVERITY_MAP.get(extra.get("severity", "WARNING").upper(), "medium"),
            "type": vuln_type,
            "title": metadata.get("message", extra.get("message", vuln_type)),
            "file": result_path,
            "line": line,
            "verdict": "unverified",
            "confidence": confidence,
            "source_tool": "semgrep",
            "message": extra.get("message", ""),
            "rule_id": rule_id,
            "evidence": [{
                "type": "pattern-match",
                "label": rule_id,
                "path": result_path,
                "line": line,
                "excerpt": excerpt[:200],
            }],
        })

    if dropped:
        log.info("semgrep: dropped %d Tier 3 (audit/low/no-CWE) results", dropped)
    log.info("semgrep returned %d results", len(findings))
    return findings
