#!/usr/bin/env python3
# ruff: noqa: S603 S607
"""Dynamic Semgrep rule generator.

Analyzes a target codebase to generate custom Semgrep YAML rules tailored
to its specific ORM layer, auth middleware, input validation patterns, and
custom helpers.

NOTE: This module contains regex patterns that *detect* dangerous sinks in
target codebases (pickle, shell exec, etc).  These are detection rules for
a security scanner -- not actual invocations of those dangerous functions.

Generated rules are written to a temp directory and passed as --config to
subsequent Semgrep runs.
"""
from __future__ import annotations

import logging
import re
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")

_RULE_TEMPLATE = "rules:\n{rules_yaml}\n"

_SINGLE_RULE = """\
  - id: vuln-scout.custom.{rule_id}
    patterns:
{patterns}
    message: "{message}"
    languages: [{languages}]
    severity: {severity}
    metadata:
      category: security
      confidence: HIGH
      cwe: ["{cwe}"]
      subcategory: ["vuln"]
"""

_EXCLUDED_DIRS = frozenset({
    "node_modules", "vendor", "dist", "build", ".git",
    "__pycache__", ".joern", ".claude", "test", "tests",
    "__tests__", "spec", "fixtures", "skills", "references",
    "docs", "examples", "agents", "commands", "hooks",
})

_LANG_EXT_MAP: dict[str, list[str]] = {
    "python": [".py"], "javascript": [".js", ".jsx", ".mjs"],
    "typescript": [".ts", ".tsx"], "go": [".go"], "java": [".java"],
    "ruby": [".rb"], "php": [".php"], "csharp": [".cs"], "rust": [".rs"],
}


def _lang_extensions(languages: list[str]) -> list[str]:
    exts: list[str] = []
    for lang in languages:
        exts.extend(_LANG_EXT_MAP.get(lang.strip(), []))
    return exts


_PLUGIN_DIR_NAMES = frozenset({"whitebox-pentest", ".claude-plugin"})


def _is_excluded(path: Path) -> bool:
    parts = path.parts
    if any(part in _EXCLUDED_DIRS for part in parts):
        return True
    if any(part in _PLUGIN_DIR_NAMES for part in parts):
        return True
    return False


def _scan_for_pattern(root: Path, pattern: str, langs: str) -> bool:
    """Check if *pattern* appears anywhere in files of the given languages."""
    compiled = re.compile(pattern)
    lang_list = [l.strip() for l in langs.split(",")]
    for ext in _lang_extensions(lang_list):
        for f in root.rglob(f"*{ext}"):
            if _is_excluded(f):
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            if compiled.search(text):
                return True
    return False


# Each tuple: (regex, languages, CWE, rule-id, message, severity)
_VULN_SINK_PATTERNS: list[tuple[str, str, str, str, str, str]] = [
    # --- SQL injection sinks ---
    (r'\.(?:execute|query|raw)\s*\(\s*f["\']', "python", "CWE-89",
     "sql-fstring", "SQL injection via f-string in database call", "ERROR"),
    (r'\.(?:execute|query|raw)\s*\([^)]*\.format\(', "python", "CWE-89",
     "sql-format", "SQL injection via .format() in database call", "ERROR"),
    (r'\.(?:query|execute|raw)\s*\(\s*`', "javascript, typescript", "CWE-89",
     "sql-template-literal", "SQL injection via template literal in query", "ERROR"),
    (r'(?:Query|Exec|QueryRow)\w*\(\s*fmt\.Sprintf', "go", "CWE-89",
     "sql-sprintf", "SQL injection via fmt.Sprintf in database call", "ERROR"),
    (r'(?:createQuery|createNativeQuery|prepareStatement)\s*\(\s*["\'][^"\']*["\']\s*\+',
     "java", "CWE-89", "sql-concat",
     "SQL injection via string concatenation in query", "ERROR"),
    (r'\.(?:where|find_by_sql|joins|having)\s*\(\s*["\'][^"\']*#\{',
     "ruby", "CWE-89", "sql-interpolation",
     "SQL injection via string interpolation in ActiveRecord", "ERROR"),

    # --- Unsafe deserialization sinks ---
    (r'yaml\.(?:load|unsafe_load)\s*\(', "python", "CWE-502",
     "unsafe-yaml", "Unsafe YAML load (use safe_load)", "ERROR"),
    (r'ObjectInputStream\s*\(', "java", "CWE-502",
     "unsafe-object-stream", "Unsafe Java deserialization via ObjectInputStream", "ERROR"),
    (r'unserialize\s*\(', "php", "CWE-502",
     "unsafe-unserialize", "Unsafe PHP unserialize", "ERROR"),
    (r'Marshal\.load\s*\(', "ruby", "CWE-502",
     "unsafe-marshal", "Unsafe Ruby Marshal.load", "ERROR"),

    # --- Command injection sinks ---
    (r'os\.system\s*\(', "python", "CWE-78",
     "os-system", "Command injection risk via os.system", "ERROR"),
    (r'subprocess\.\w+\([^)]*shell\s*=\s*True', "python", "CWE-78",
     "subprocess-shell", "Command injection risk via subprocess with shell=True", "ERROR"),
    (r'(?:system|passthru|shell_exec|popen)\s*\(', "php", "CWE-78",
     "php-command", "Command injection risk via PHP command function", "ERROR"),
]


def _detect_sink_rules(root: Path) -> list[dict[str, Any]]:
    """Scan the codebase and generate rules only for sinks that actually exist."""
    rules: list[dict[str, Any]] = []
    for pattern, langs, cwe, rule_id, msg, severity in _VULN_SINK_PATTERNS:
        if _scan_for_pattern(root, pattern, langs):
            rules.append({
                "id": rule_id, "pattern_regex": pattern,
                "languages": langs, "cwe": cwe,
                "message": msg, "severity": severity,
            })
    return rules


def detect_auth_middleware_names(root: Path) -> list[str]:
    """Detect the project's auth middleware names.

    Returns the list of detected names for use by the entry point mapper
    and other modules.  Does NOT generate Semgrep rules -- missing-auth
    detection requires understanding route structure, not simple regex.
    """
    auth_names: set[str] = set()
    auth_patterns = [
        re.compile(r'(?:app|router)\.\w+\([^)]+,\s*(\w*[Aa]uth\w*)\s*[,)]'),
        re.compile(r'@(\w*(?:login_required|auth_required|jwt_required|token_required)\w*)'),
        re.compile(r'before_action\s+:(\w*authenticate\w*)'),
        re.compile(r'\.Use\(\s*(\w*[Aa]uth\w*Middleware\w*)'),
        re.compile(r'@(Secured|PreAuthorize|RolesAllowed)'),
    ]
    for ext in ("*.ts", "*.js", "*.py", "*.go", "*.java", "*.rb", "*.php"):
        for f in root.rglob(ext):
            if _is_excluded(f):
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            for pat in auth_patterns:
                for m in pat.finditer(text):
                    auth_names.add(m.group(1))

    if auth_names:
        log.info("Detected auth middleware: %s", ", ".join(sorted(auth_names)))
    return sorted(auth_names)


def _rule_to_yaml(rule: dict[str, Any]) -> str:
    rule_id = rule["id"].replace(" ", "-").lower()
    pattern_regex = rule.get("pattern_regex", "")
    patterns = f"      - pattern-regex: '{pattern_regex}'" if pattern_regex else "      - pattern: '...'"
    return _SINGLE_RULE.format(
        rule_id=rule_id, patterns=patterns,
        message=rule["message"], languages=rule["languages"],
        severity=rule.get("severity", "WARNING"), cwe=rule.get("cwe", "CWE-000"),
    )


def generate_rules(
    target_path: str,
    frameworks: list[str] | None = None,
) -> tuple[str | None, list[dict[str, Any]]]:
    """Generate custom Semgrep rules for the target codebase.

    Returns (rules_dir_path, rules_metadata) or (None, []).
    """
    root = Path(target_path).resolve()
    if not root.is_dir():
        return None, []

    all_rules: list[dict[str, Any]] = []
    all_rules.extend(_detect_sink_rules(root))
    # Auth middleware detection is informational only -- names are used by
    # entry_point_mapper for auth context, not as Semgrep rules.
    detect_auth_middleware_names(root)

    if not all_rules:
        log.info("No custom rules generated for this codebase")
        return None, []

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for r in all_rules:
        if r["id"] not in seen:
            seen.add(r["id"])
            unique.append(r)

    yaml_content = _RULE_TEMPLATE.format(
        rules_yaml="\n".join(_rule_to_yaml(r) for r in unique)
    )
    rules_dir = tempfile.mkdtemp(prefix="vuln-scout-rules-")
    (Path(rules_dir) / "custom-rules.yaml").write_text(yaml_content)

    log.info("Generated %d custom Semgrep rules in %s", len(unique), rules_dir)
    return rules_dir, unique


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    rules_dir, rules = generate_rules(target)
    if rules_dir:
        print(f"Rules directory: {rules_dir}")
        for r in rules:
            print(f"  - {r['id']}: {r['message']}")
    else:
        print("No custom rules generated")
