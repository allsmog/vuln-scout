"""CodeQL tool runner for the scan orchestrator."""
from __future__ import annotations

import json
import logging
import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any
from safe_paths import resolve_within_root, safe_read_bytes, safe_walk_files

log = logging.getLogger("vuln-scout")

CODEQL_LANG_MAP: dict[str, str] = {
    "javascript": "javascript",
    "typescript": "javascript",  # CodeQL handles both
    "python": "python",
    "java": "java",
    "go": "go",
    "ruby": "ruby",
    "csharp": "csharp",
    "rust": "rust",
}

CODEQL_LANG_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "javascript": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    "python": (".py",),
    "java": (".java", ".kt", ".kts"),
    "go": (".go",),
    "ruby": (".rb",),
    "csharp": (".cs",),
    "rust": (".rs",),
}

CODEQL_BUILD_MODES: dict[str, str] = {
    "javascript": "none",
    "python": "none",
    "java": "none",
    "ruby": "none",
    "csharp": "none",
    "rust": "none",
    "go": "autobuild",
}

CWE_TYPE_MAP: dict[str, str] = {
    "CWE-89": "sql-injection",
    "CWE-78": "command-injection",
    "CWE-79": "xss",
    "CWE-22": "path-traversal",
    "CWE-918": "ssrf",
    "CWE-502": "deserialization",
    "CWE-94": "code-injection",
    "CWE-611": "xxe",
    "CWE-90": "ldap-injection",
    "CWE-330": "insecure-randomness",
    "CWE-798": "hardcoded-secret",
}

SEVERITY_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

_PACKS_OUTPUT_CACHE: str | None = None
CODEQL_EXCLUDED_DIRS = {"node_modules", "vendor", "__pycache__", ".git", ".joern", ".codeql", ".claude"}

LAST_STATUS: dict[str, Any] = {
    "tool": "codeql",
    "state": "skipped",
    "findings": 0,
    "languages": {},
}


def is_available() -> bool:
    return shutil.which("codeql") is not None


def _set_status(status: dict[str, Any]) -> None:
    global LAST_STATUS
    LAST_STATUS = status


def run_with_status(
    target: str,
    languages: dict[str, list[str]] | None = None,
    cache_dir: str = ".codeql",
    model_packs: str | list[str] | None = None,
) -> dict[str, Any]:
    findings = run(target, languages=languages, cache_dir=cache_dir, model_packs=model_packs)
    return {"findings": findings, "status": LAST_STATUS}


def run(
    target: str,
    languages: dict[str, list[str]] | None = None,
    cache_dir: str = ".codeql",
    model_packs: str | list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run CodeQL and return normalized findings.

    Args:
        target: Directory or file to scan.
        languages: Mapping of VulnScout language names to file lists.
        cache_dir: Directory for CodeQL databases, relative to *target*.
        model_packs: Optional CodeQL model pack path(s) passed to analysis.
    """
    if not is_available():
        log.info("codeql not installed, skipping")
        _set_status({
            "tool": "codeql",
            "state": "unavailable",
            "findings": 0,
            "languages": {},
            "reason": "codeql binary not found",
        })
        return []

    if not languages:
        log.info("codeql: no languages provided, skipping")
        _set_status({
            "tool": "codeql",
            "state": "skipped",
            "findings": 0,
            "languages": {},
            "reason": "no languages provided",
        })
        return []

    # Determine unique CodeQL languages from the provided VulnScout languages.
    codeql_language_files: dict[str, list[str]] = {}
    unsupported_languages: list[str] = []
    for lang_name, files in languages.items():
        codeql_lang = CODEQL_LANG_MAP.get(lang_name.lower())
        if codeql_lang:
            codeql_language_files.setdefault(codeql_lang, []).extend(files)
        else:
            unsupported_languages.append(lang_name)

    if not codeql_language_files:
        log.info("codeql: no supported languages detected, skipping")
        _set_status({
            "tool": "codeql",
            "state": "skipped",
            "findings": 0,
            "languages": {},
            "unsupported_languages": sorted(unsupported_languages or languages.keys()),
            "reason": "no CodeQL-supported languages detected",
        })
        return []

    target_path = Path(target).resolve()
    cache_path = target_path / cache_dir

    all_findings: list[dict[str, Any]] = []
    language_status: dict[str, dict[str, Any]] = {}

    for lang in sorted(codeql_language_files):
        source_hash = _compute_source_hash(target_path, lang, codeql_language_files[lang])
        db_path = cache_path / f"{source_hash}-{lang}-db"
        sarif_path = cache_path / f"{source_hash}-{lang}-results.sarif"
        source_root = _prepare_source_view(
            target_path,
            cache_path,
            lang,
            source_hash,
            codeql_language_files[lang],
        )

        # Step 1: Create database
        create_status = _create_database_status(source_root, db_path, lang)
        if create_status["state"] != "succeeded":
            language_status[lang] = create_status
            continue

        # Step 2: Analyze database
        analyze_status = _analyze_database_status(db_path, sarif_path, lang, model_packs=model_packs)
        if analyze_status["state"] != "succeeded":
            language_status[lang] = analyze_status
            continue

        # Step 3: Parse SARIF results
        findings = _parse_sarif(sarif_path, lang)
        all_findings.extend(findings)
        language_status[lang] = {
            "state": "succeeded",
            "stage": "analyze",
            "findings": len(findings),
            "database": str(db_path),
            "sarif": str(sarif_path),
            "cache_key": source_hash,
        }

    # Re-number findings sequentially across all languages
    for i, finding in enumerate(all_findings):
        finding["id"] = f"CODEQL-{i:04d}"

    log.info("codeql returned %d results", len(all_findings))
    states = [status.get("state", "failed") for status in language_status.values()]
    if states and all(state == "succeeded" for state in states):
        overall = "succeeded"
    elif states and all(state == "timed_out" for state in states):
        overall = "timed_out"
    elif states and any(state == "succeeded" for state in states):
        overall = "partially_skipped"
    elif states and any(state == "timed_out" for state in states):
        overall = "timed_out"
    else:
        overall = "failed"

    _set_status({
        "tool": "codeql",
        "state": overall,
        "findings": len(all_findings),
        "languages": language_status,
        "unsupported_languages": sorted(unsupported_languages),
    })
    return all_findings


def _compute_source_hash(target_path: Path, lang: str, files: list[str] | None = None) -> str:
    """Compute a content hash for the CodeQL database cache key."""
    root = target_path.resolve()
    candidates = _source_files_for_language(root, lang, files)

    file_hashes: list[str] = []
    for path in sorted(candidates):
        content = safe_read_bytes(root, path)
        if content is None:
            continue
        rel = path.resolve().relative_to(root)
        file_hashes.append(f"{rel.as_posix()}:{hashlib.sha256(content).hexdigest()}")

    basis = f"source-view-v1\n{lang}\n" + "\n".join(file_hashes)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _is_excluded_relative(path: Path) -> bool:
    return any(part in CODEQL_EXCLUDED_DIRS for part in path.parts)


def _source_files_for_language(root: Path, lang: str, files: list[str] | None = None) -> list[Path]:
    root = root.resolve()
    exts = CODEQL_LANG_EXTENSIONS.get(lang, ())
    candidates: list[Path] = []
    if files:
        for file_name in sorted(set(files)):
            resolved = resolve_within_root(root, file_name, strict=True)
            if resolved is None or not resolved.is_file():
                continue
            relative = resolved.relative_to(root)
            if _is_excluded_relative(relative) or resolved.suffix not in exts:
                continue
            candidates.append(resolved)
    else:
        candidates = list(
            safe_walk_files(
                root,
                extensions=set(exts),
                excluded_dirs=CODEQL_EXCLUDED_DIRS,
            )
        )
    return sorted(candidates)


def _prepare_source_view(
    target_path: Path,
    cache_path: Path,
    lang: str,
    source_hash: str,
    files: list[str],
) -> Path:
    """Build a CodeQL source root that excludes analyzer cache directories."""
    target_path = target_path.resolve()
    source_view = cache_path / "_source_views" / f"{source_hash}-{lang}"
    if source_view.exists():
        shutil.rmtree(source_view)
    source_view.mkdir(parents=True, exist_ok=True)

    for source_file in _source_files_for_language(target_path, lang, files):
        relative = source_file.relative_to(target_path)
        destination = source_view / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, destination)

    return source_view


def _is_database_valid(db_path: Path) -> bool:
    return db_path.is_dir() and (db_path / "codeql-database.yml").exists()


def _create_database(target_path: Path, db_path: Path, lang: str) -> bool:
    """Create a CodeQL database for the given language.

    Returns True on success, False on failure.
    """
    return _create_database_status(target_path, db_path, lang)["state"] == "succeeded"


def _create_database_status(target_path: Path, db_path: Path, lang: str) -> dict[str, Any]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if _is_database_valid(db_path):
        return {
            "state": "succeeded",
            "stage": "database-create",
            "findings": 0,
            "cache_hit": True,
            "database": str(db_path),
        }
    if db_path.exists():
        shutil.rmtree(db_path)

    cmd = [
        "codeql", "database", "create",
        str(db_path),
        f"--language={lang}",
        "--source-root", str(target_path),
    ]
    build_mode = CODEQL_BUILD_MODES.get(lang)
    if build_mode:
        cmd.append(f"--build-mode={build_mode}")

    log.info("codeql: creating %s database at %s", lang, db_path)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        log.warning("codeql: database creation timed out for %s (600s limit)", lang)
        return {"state": "timed_out", "stage": "database-create", "findings": 0, "reason": "database creation timed out after 600s"}
    except FileNotFoundError:
        log.warning("codeql: binary not found during database creation")
        return {"state": "unavailable", "stage": "database-create", "findings": 0, "reason": "codeql binary not found"}

    if result.returncode != 0:
        stderr_snippet = (result.stderr or "")[:500]
        log.warning(
            "codeql: database creation failed for %s (exit %d): %s",
            lang, result.returncode, stderr_snippet,
        )
        return {
            "state": "failed",
            "stage": "database-create",
            "findings": 0,
            "reason": stderr_snippet or f"codeql database create exited {result.returncode}",
        }

    return {
        "state": "succeeded",
        "stage": "database-create",
        "findings": 0,
        "cache_hit": False,
        "database": str(db_path),
        "build_mode": build_mode or "",
    }


def _analyze_database(
    db_path: Path,
    sarif_path: Path,
    lang: str,
    model_packs: str | list[str] | None = None,
) -> bool:
    """Run CodeQL analysis on a database.

    Returns True on success, False on failure.
    """
    return _analyze_database_status(db_path, sarif_path, lang, model_packs=model_packs)["state"] == "succeeded"


def _normalize_model_packs(model_packs: str | list[str] | None) -> str | None:
    if model_packs is None:
        return None
    if isinstance(model_packs, str):
        value = model_packs.strip()
        return value or None
    values = [str(path).strip() for path in model_packs if str(path).strip()]
    return ",".join(values) if values else None


def _analyze_database_status(
    db_path: Path,
    sarif_path: Path,
    lang: str,
    model_packs: str | list[str] | None = None,
) -> dict[str, Any]:
    sarif_path.parent.mkdir(parents=True, exist_ok=True)

    query_suite = f"codeql/{lang}-queries:codeql-suites/{lang}-security-and-quality.qls"
    pack_status = _ensure_query_pack(lang)
    if pack_status["state"] != "succeeded":
        return pack_status

    cmd = [
        "codeql", "database", "analyze",
        str(db_path),
        query_suite,
        "--format=sarif-latest",
        f"--output={sarif_path}",
        "--download",
    ]
    model_packs_value = _normalize_model_packs(model_packs)
    if model_packs_value:
        cmd.extend(["--model-packs", model_packs_value])

    log.info("codeql: analyzing %s database with %s", lang, query_suite)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        log.warning("codeql: analysis timed out for %s (600s limit)", lang)
        return {"state": "timed_out", "stage": "analyze", "findings": 0, "reason": "analysis timed out after 600s"}
    except FileNotFoundError:
        log.warning("codeql: binary not found during analysis")
        return {"state": "unavailable", "stage": "analyze", "findings": 0, "reason": "codeql binary not found"}

    if result.returncode != 0:
        stderr_snippet = (result.stderr or "")[:500]
        log.warning(
            "codeql: analysis failed for %s (exit %d): %s",
            lang, result.returncode, stderr_snippet,
        )
        return {
            "state": "failed",
            "stage": "analyze",
            "findings": 0,
            "reason": stderr_snippet or f"codeql database analyze exited {result.returncode}",
        }

    if not sarif_path.exists():
        log.warning("codeql: SARIF output missing for %s", lang)
        return {"state": "failed", "stage": "analyze", "findings": 0, "reason": "SARIF output missing"}

    status = {"state": "succeeded", "stage": "analyze", "findings": 0, "query_pack": query_suite}
    if model_packs_value:
        status["model_packs"] = model_packs_value
    return status


def _resolve_packs_output() -> str:
    global _PACKS_OUTPUT_CACHE
    if _PACKS_OUTPUT_CACHE is not None:
        return _PACKS_OUTPUT_CACHE
    try:
        result = subprocess.run(
            ["codeql", "resolve", "packs", "--show-hidden-packs"],
            capture_output=True, text=True, timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        _PACKS_OUTPUT_CACHE = ""
        return ""
    _PACKS_OUTPUT_CACHE = (result.stdout or "") + "\n" + (result.stderr or "")
    return _PACKS_OUTPUT_CACHE


def _ensure_query_pack(lang: str) -> dict[str, Any]:
    pack = f"codeql/{lang}-queries"
    if f"{pack}:" in _resolve_packs_output():
        return {"state": "succeeded", "stage": "query-pack", "findings": 0, "query_pack": pack}

    log.info("codeql: query pack %s not found locally; attempting download", pack)
    try:
        result = subprocess.run(
            ["codeql", "pack", "download", pack],
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {"state": "timed_out", "stage": "query-pack", "findings": 0, "reason": f"query pack download timed out: {pack}"}
    except FileNotFoundError:
        return {"state": "unavailable", "stage": "query-pack", "findings": 0, "reason": "codeql binary not found"}

    if result.returncode != 0:
        reason = (result.stderr or result.stdout or "")[:500]
        return {
            "state": "failed",
            "stage": "query-pack",
            "findings": 0,
            "reason": reason or f"query pack unavailable: {pack}",
        }

    global _PACKS_OUTPUT_CACHE
    _PACKS_OUTPUT_CACHE = None
    return {"state": "succeeded", "stage": "query-pack", "findings": 0, "query_pack": pack}


def _parse_sarif(sarif_path: Path, language: str) -> list[dict[str, Any]]:
    """Parse a SARIF file and return normalized VulnScout findings."""
    try:
        data = json.loads(sarif_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("codeql: failed to parse SARIF for %s: %s", language, exc)
        return []

    findings: list[dict[str, Any]] = []

    for run_obj in data.get("runs", []):
        # Build a rule lookup for CWE extraction and metadata
        rules_by_id: dict[str, dict[str, Any]] = {}
        tool_obj = run_obj.get("tool", {})
        driver = tool_obj.get("driver", {})
        for rule in driver.get("rules", []):
            rule_id = rule.get("id", "")
            if rule_id:
                rules_by_id[rule_id] = rule

        for result in run_obj.get("results", []):
            finding = _normalize_result(result, rules_by_id, language)
            if finding:
                findings.append(finding)

    return findings


def _normalize_result(
    result: dict[str, Any],
    rules_by_id: dict[str, dict[str, Any]],
    language: str,
) -> dict[str, Any] | None:
    """Normalize a single SARIF result to VulnScout finding format."""
    rule_id = result.get("ruleId", "unknown")
    message_text = result.get("message", {}).get("text", rule_id)
    level = result.get("level", "warning")

    rule = rules_by_id.get(rule_id, {})
    severity = _severity_for_result(result, rule, level)

    # Extract file and line from the first location
    file_path = "unknown"
    line_number = 0
    locations = result.get("locations", [])
    if locations:
        phys = locations[0].get("physicalLocation", {})
        artifact_loc = phys.get("artifactLocation", {})
        file_path = artifact_loc.get("uri", "unknown")
        region = phys.get("region", {})
        line_number = region.get("startLine", 0)

    # Determine if this result has dataflow (codeFlows)
    code_flows = result.get("codeFlows", [])
    has_codeflows = len(code_flows) > 0

    kind = "finding" if has_codeflows else "hotspot"
    confidence = "high" if has_codeflows else "medium"

    # Extract CWE from rule tags
    cwe_ids = _extract_cwes(rule_id, rules_by_id)

    # Determine vulnerability type from CWE or rule_id
    vuln_type = rule_id
    for cwe_id in cwe_ids:
        if cwe_id in CWE_TYPE_MAP:
            vuln_type = CWE_TYPE_MAP[cwe_id]
            break

    # Build evidence list
    evidence = _build_evidence(result, code_flows, file_path, line_number, rule_id)

    return {
        "id": "CODEQL-0000",  # re-numbered by caller
        "stable_key": "",  # computed by caller
        "kind": kind,
        "severity": severity,
        "type": vuln_type,
        "title": message_text,
        "file": file_path,
        "line": line_number,
        "verdict": "unverified",
        "confidence": confidence,
        "source_tool": "codeql",
        "message": message_text,
        "rule_id": rule_id,
        "evidence": evidence,
    }


def _extract_cwes(
    rule_id: str,
    rules_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    """Extract CWE identifiers from SARIF rule tags.

    SARIF rules have properties.tags like ["external/cwe/cwe-89", "security"].
    Returns a list such as ["CWE-89"].
    """
    rule = rules_by_id.get(rule_id, {})
    tags = rule.get("properties", {}).get("tags", [])

    cwes: list[str] = []
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("external/cwe/cwe-"):
            # "external/cwe/cwe-89" -> "CWE-89"
            cwe_num = tag.split("external/cwe/cwe-")[-1]
            cwes.append(f"CWE-{cwe_num}")

    return cwes


def _severity_for_result(result: dict[str, Any], rule: dict[str, Any], level: str) -> str:
    properties = rule.get("properties", {})
    security_severity = properties.get("security-severity")
    if security_severity is not None:
        try:
            score = float(security_severity)
        except (TypeError, ValueError):
            score = -1.0
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 0.0:
            return "low"

    default_level = rule.get("defaultConfiguration", {}).get("level")
    if default_level:
        return SEVERITY_MAP.get(str(default_level), "medium")
    return SEVERITY_MAP.get(level, "medium")


def _build_evidence(
    result: dict[str, Any],
    code_flows: list[dict[str, Any]],
    file_path: str,
    line_number: int,
    rule_id: str,
) -> list[dict[str, Any]]:
    """Build an evidence list from codeFlows or locations."""
    evidence: list[dict[str, Any]] = []

    if code_flows:
        # Extract steps from the first code flow's first thread flow
        for flow in code_flows:
            for thread_flow in flow.get("threadFlows", []):
                for step in thread_flow.get("locations", []):
                    loc = step.get("location", {})
                    phys = loc.get("physicalLocation", {})
                    artifact_loc = phys.get("artifactLocation", {})
                    region = phys.get("region", {})
                    step_msg = loc.get("message", {}).get("text", "")
                    snippet = region.get("snippet", {}).get("text", "")

                    evidence.append({
                        "type": "dataflow",
                        "label": step_msg or rule_id,
                        "path": artifact_loc.get("uri", file_path),
                        "line": region.get("startLine", 0),
                        "excerpt": (snippet or step_msg)[:200],
                    })
                # Only use the first thread flow
                break
            # Only use the first code flow
            break
    else:
        # No dataflow -- use the result location as pattern-match evidence
        locations = result.get("locations", [])
        for loc in locations:
            phys = loc.get("physicalLocation", {})
            artifact_loc = phys.get("artifactLocation", {})
            region = phys.get("region", {})
            snippet = region.get("snippet", {}).get("text", "")

            evidence.append({
                "type": "pattern-match",
                "label": rule_id,
                "path": artifact_loc.get("uri", file_path),
                "line": region.get("startLine", line_number),
                "excerpt": (snippet or result.get("message", {}).get("text", ""))[:200],
            })

    # Ensure at least one evidence entry
    if not evidence:
        evidence.append({
            "type": "pattern-match",
            "label": rule_id,
            "path": file_path,
            "line": line_number,
            "excerpt": result.get("message", {}).get("text", "")[:200],
        })

    return evidence
