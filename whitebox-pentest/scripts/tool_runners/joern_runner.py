"""Joern CPG tool runner for the scan orchestrator.

Supports two modes:
- **Verification**: confirms/refutes existing findings from other tools.
- **Discovery**: scans the full CPG for vulnerabilities that pattern-based
  tools like Semgrep cannot find (cross-function dataflow, etc.).
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from bundle_joern import temporary_bundle

log = logging.getLogger("vuln-scout")

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "joern"

DISCOVERY_SCRIPTS = {
    "sql-injection": "discover-sqli.sc",
    "command-injection": "discover-cmdi.sc",
    "ssrf": "discover-ssrf.sc",
    "path-traversal": "discover-path.sc",
}

LAST_DISCOVERY_STATUS: dict[str, Any] = {
    "tool": "joern",
    "state": "skipped",
    "findings": 0,
    "queries": {},
    "languages": {},
}

JOERN_FILE_LANGUAGES: dict[str, str] = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".sol": "solidity",
}

JOERN_SUPPORTED_LANGUAGES = {"javascript", "python", "go", "java", "php", "ruby", "csharp"}


def is_available() -> bool:
    return shutil.which("joern") is not None and shutil.which("joern-parse") is not None


def _set_discovery_status(status: dict[str, Any]) -> None:
    global LAST_DISCOVERY_STATUS
    LAST_DISCOVERY_STATUS = status


# ---------------------------------------------------------------------------
# CPG creation (shared by verify and discover)
# ---------------------------------------------------------------------------

def _language_for_file(file: str) -> str:
    return JOERN_FILE_LANGUAGES.get(Path(file).suffix.lower(), "unsupported")


def _normalize_cpg_file(file: str) -> str:
    marker = "/.joern/_source_views/"
    normalized = file.replace("\\", "/")
    if marker in normalized:
        tail = normalized.split(marker, 1)[1]
        parts = tail.split("/", 1)
        if len(parts) == 2:
            return parts[1]
    return file


def _create_cpgs(target: str, cache_dir: str = ".joern") -> tuple[dict[str, str], dict[str, Any]]:
    """Create/reuse one CPG per Joern-supported language."""
    create_cpg_script = Path(__file__).resolve().parents[1] / "create_cpg.py"
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(create_cpg_script),
                target,
                "--cache-dir",
                cache_dir,
                "--all-languages",
                "--json",
            ],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            log.warning("CPG creation failed: %s", result.stderr[:300])
            return {}, {
                "state": "failed",
                "languages": {},
                "reason": result.stderr[:500] or "CPG creation failed",
            }
        payload = json.loads(result.stdout.strip() or "{}")
        cpgs = {str(lang): str(path) for lang, path in payload.get("cpgs", {}).items()}
        language_status = {
            str(lang): dict(status)
            for lang, status in payload.get("languages", {}).items()
        }
        return cpgs, {"state": "succeeded" if cpgs else "skipped", "languages": language_status}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        log.warning("CPG creation error")
        return {}, {"state": "timed_out", "languages": {}, "reason": "CPG creation timed out or script was unavailable"}
    except json.JSONDecodeError as exc:
        log.warning("CPG creation returned invalid JSON: %s", exc)
        return {}, {"state": "failed", "languages": {}, "reason": "invalid CPG creation output"}


def _create_cpg(target: str, cache_dir: str = ".joern") -> str | None:
    """Backward-compatible helper: return the first created CPG path."""
    cpgs, _ = _create_cpgs(target, cache_dir)
    return next(iter(cpgs.values()), None)


# ---------------------------------------------------------------------------
# Verification mode
# ---------------------------------------------------------------------------

def run(
    target: str,
    findings: list[dict[str, Any]] | None = None,
    cache_dir: str = ".joern",
    timeout: int = 120,
) -> list[dict[str, Any]]:
    """Run Joern verification on existing findings.

    Uses batch mode (single JVM) for all findings instead of spawning one
    JVM per finding.  Falls back to per-finding mode on batch failure.
    """
    if not is_available():
        log.warning("joern/joern-parse not installed, skipping")
        return []

    if not findings:
        log.info("No findings to verify with Joern")
        return []

    unverified = [f for f in findings if f.get("verdict") == "unverified"]
    if not unverified:
        return []

    cpgs, cpg_status = _create_cpgs(target, cache_dir)
    if not cpgs and not cpg_status.get("languages"):
        return []

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in unverified:
        language = _language_for_file(str(finding.get("file", "")))
        if language not in JOERN_SUPPORTED_LANGUAGES:
            _apply_result(
                finding,
                {
                    "verdict": "NA_CPG",
                    "confidence": 0.0,
                    "reason": f"Joern CPG verification is not supported for {language}",
                },
            )
            continue
        if language not in cpgs:
            finding["verdict"] = "needs_review"
            finding["confidence"] = "low"
            finding["message"] = (
                finding.get("message", "")
                + f" [Joern: no CPG available for {language}]"
            )
            continue
        grouped[language].append(finding)

    if not grouped:
        return unverified

    # Batch mode: one JVM per language CPG.
    from batch_verify import run_batch_verify

    for language, language_findings in grouped.items():
        cpg_path = cpgs[language]
        batch_timeout = max(timeout * len(language_findings), 300)
        batch_timeout = min(batch_timeout, 1200)
        batch_results = run_batch_verify(cpg_path, language_findings, timeout=batch_timeout)

        if batch_results:
            for f in language_findings:
                fid = f.get("stable_key") or f.get("id", "unknown")
                joern_result = batch_results.get(fid)
                if joern_result:
                    _apply_result(f, joern_result)
            continue

        # Fallback: per-finding verification (if batch produced no results)
        log.warning("Batch verification returned no results for %s, falling back to per-finding mode", language)
        for f in language_findings:
            script = _get_script(f.get("type", ""))
            joern_result = _run_verify(cpg_path, script, f.get("file", ""), f.get("line", 0), timeout)
            if joern_result:
                _apply_result(f, joern_result)

    return unverified


# ---------------------------------------------------------------------------
# Discovery mode
# ---------------------------------------------------------------------------

def discover(
    target: str,
    cache_dir: str = ".joern",
    timeout: int = 300,
) -> list[dict[str, Any]]:
    """Run Joern discovery queries to find vulnerabilities Semgrep misses.

    Unlike verification (which confirms existing findings), discovery scans
    the entire CPG for cross-function dataflow from attacker sources to
    dangerous sinks without proper sanitization.
    """
    if not is_available():
        log.warning("joern not installed, skipping discovery")
        _set_discovery_status({
            "tool": "joern",
            "state": "unavailable",
            "findings": 0,
            "queries": {},
            "languages": {},
            "reason": "joern or joern-parse binary not found",
        })
        return []

    cpgs, cpg_status = _create_cpgs(target, cache_dir)
    if not cpgs:
        languages = cpg_status.get("languages", {})
        state = "skipped" if languages else cpg_status.get("state", "failed")
        _set_discovery_status({
            "tool": "joern",
            "state": state,
            "findings": 0,
            "queries": {},
            "languages": languages,
            "reason": cpg_status.get("reason", "No Joern-supported languages detected"),
        })
        return []

    all_findings: list[dict[str, Any]] = []
    query_status: dict[str, dict[str, Any]] = {}
    for vuln_type, script_name in DISCOVERY_SCRIPTS.items():
        script = SCRIPT_DIR / script_name
        if not script.exists():
            log.warning("Discovery script not found: %s", script)
            query_status[vuln_type] = {
                "state": "failed",
                "findings": 0,
                "reason": f"discovery script missing: {script_name}",
            }
            continue
        results: list[dict[str, Any]] = []
        per_language: dict[str, dict[str, Any]] = {}
        for language, cpg_path in sorted(cpgs.items()):
            language_results = _run_discovery(cpg_path, script, timeout)
            results.extend(language_results)
            per_language[language] = {"state": "succeeded", "findings": len(language_results)}
        query_status[vuln_type] = {
            "state": "succeeded",
            "findings": len(results),
            "languages": per_language,
        }
        for r in results:
            result_file = _normalize_cpg_file(r.get("file", "unknown"))
            finding = {
                "id": f"JOERN-D-{len(all_findings):04d}",
                "stable_key": "",
                "kind": "finding",
                "severity": "high",
                "type": r.get("type", vuln_type),
                "title": (
                    f"Joern discovered: {r.get('type', vuln_type)} "
                    f"at {result_file}:{r.get('line', 0)}"
                ),
                "file": result_file,
                "line": r.get("line", 0),
                "verdict": "verified",
                "confidence": "high",
                "source_tool": "joern",
                "message": (
                    f"Dataflow analysis found {r.get('type', vuln_type)} -- "
                    "attacker input reaches sink without sanitization"
                ),
                "rule_id": f"joern/{r.get('type', vuln_type)}",
                "evidence": [
                    {
                        "type": "cpg-dataflow",
                        "label": f"Joern CPG discovery: {r.get('type', vuln_type)}",
                        "path": result_file,
                        "line": r.get("line", 0),
                        "excerpt": r.get("sink", "")[:200],
                    }
                ],
            }
            all_findings.append(finding)

    log.info("Joern discovery found %d new findings", len(all_findings))
    states = [status["state"] for status in query_status.values()]
    if states and all(state == "succeeded" for state in states):
        overall = "succeeded"
    elif states and any(state == "succeeded" for state in states):
        overall = "partially_skipped"
    else:
        overall = "failed"
    _set_discovery_status({
        "tool": "joern",
        "state": overall,
        "findings": len(all_findings),
        "queries": query_status,
        "languages": cpg_status.get("languages", {}),
    })
    return all_findings


def discover_with_status(
    target: str,
    cache_dir: str = ".joern",
    timeout: int = 300,
) -> dict[str, Any]:
    findings = discover(target, cache_dir=cache_dir, timeout=timeout)
    return {"findings": findings, "status": LAST_DISCOVERY_STATUS}


# ---------------------------------------------------------------------------
# Verify helpers
# ---------------------------------------------------------------------------

def _get_script(finding_type: str) -> Path:
    """Resolve verify script from finding type."""
    from batch_verify import VERIFY_SCRIPT_MAP
    name = VERIFY_SCRIPT_MAP.get(finding_type, "verify-generic.sc")
    path = SCRIPT_DIR / name
    return path if path.exists() else SCRIPT_DIR / "verify-generic.sc"


def _run_verify(cpg: str, script: Path, file: str, line: int, timeout: int) -> dict[str, Any] | None:
    """Run a Joern verify script and parse the JSON object result."""
    with temporary_bundle(script.name) as bundled_path:
        script_path = bundled_path or script
        cmd = ["joern", "--script", str(script_path),
               "--param", f"cpgFile={cpg}", "--param", f"file={file}", "--param", f"line={line}"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
    # Parse JSON regardless of exit code -- Joern may still produce output
    # despite CPG pass errors on some TypeScript patterns.
    # Parse JSON: find last { ... } block in output (may span multiple lines)
    text = result.stdout.strip()
    depth, end, start = 0, -1, -1
    for i in range(len(text) - 1, -1, -1):
        if text[i] == '}':
            if depth == 0: end = i
            depth += 1
        elif text[i] == '{':
            depth -= 1
            if depth == 0:
                start = i
                break
    if start >= 0 and end >= 0:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return None


def _apply_result(finding: dict[str, Any], result: dict[str, Any]) -> None:
    verdict_map = {"VERIFIED": "verified", "FALSE_POSITIVE": "false_positive",
                   "NEEDS_REVIEW": "needs_review", "NA_CPG": "na_cpg"}
    finding["verdict"] = verdict_map.get(result.get("verdict", ""), "needs_review")
    conf = result.get("confidence", 0.5)
    finding["confidence"] = "verified" if finding["verdict"] == "verified" else (
        "high" if conf >= 0.8 else "medium" if conf >= 0.5 else "low")

    reason = result.get("reason", "")
    if reason:
        finding["message"] = finding.get("message", "") + f" [Joern: {reason}]"

    evidence_entry: dict[str, Any] = {
        "type": "cpg-verification",
        "label": f"Joern CPG ({finding['verdict']})",
        "path": finding.get("file", ""),
        "line": finding.get("line", 0),
        "excerpt": reason[:200] if reason else "CPG analysis complete",
    }

    data_flow = result.get("dataFlow")
    if data_flow and isinstance(data_flow, dict):
        evidence_entry["excerpt"] = (
            f"Source: {data_flow.get('source', {}).get('code', 'unknown')} -> "
            f"Sink: {data_flow.get('sink', {}).get('code', 'unknown')}"
        )[:200]

    finding.setdefault("evidence", []).append(evidence_entry)

    sanitizers = result.get("sanitizers", [])
    if sanitizers:
        finding["message"] += f" Sanitizers: {', '.join(sanitizers)}"


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

def _run_discovery(cpg: str, script: Path, timeout: int) -> list[dict[str, Any]]:
    """Run a Joern discovery script and parse the JSON array result."""
    with temporary_bundle(script.name) as bundled:
        script_path = bundled or script
        cmd = ["joern", "--script", str(script_path), "--param", f"cpgFile={cpg}"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    text = result.stdout.strip()
    parsed = _parse_json_array(text)
    if parsed is not None:
        return parsed
    parsed = _parse_json_array(result.stderr.strip())
    if parsed is not None:
        return parsed
    return []


def _parse_json_array(text: str) -> list[dict[str, Any]] | None:
    """Extract the last JSON array from noisy Joern output."""
    candidates: list[list[dict[str, Any]]] = []
    for start, char in enumerate(text):
        if char != "[":
            continue
        next_index = start + 1
        while next_index < len(text) and text[next_index].isspace():
            next_index += 1
        if next_index >= len(text) or text[next_index] not in "{]":
            continue

        depth = 0
        in_string = False
        escaped = False
        for end in range(start, len(text)):
            current = text[end]
            if in_string:
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == "\"":
                    in_string = False
                continue
            if current == "\"":
                in_string = True
            elif current == "[":
                depth += 1
            elif current == "]":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start:end + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(parsed, list):
                        candidates.append(parsed)
                    break
    return candidates[-1] if candidates else None
