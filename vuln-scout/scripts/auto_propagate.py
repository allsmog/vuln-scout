#!/usr/bin/env python3
"""Automated pattern propagation.

After a scan, verified findings represent confirmed anti-patterns.  This
module extracts those patterns and searches the codebase for additional
instances, creating new findings with medium confidence.

This is the automated equivalent of the interactive /propagate command.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")

_EXCLUDED_DIRS = frozenset({
    "node_modules", "vendor", "dist", "build", ".git",
    "__pycache__", ".joern", ".claude", "skills", "references",
    "docs", "examples", "agents", "commands", "hooks",
    "test", "tests", "__tests__", "fixtures",
})

_PLUGIN_DIR_NAMES = frozenset({"whitebox-pentest", ".claude-plugin"})


def _is_excluded(path: Path) -> bool:
    parts = path.parts
    if any(part in _EXCLUDED_DIRS for part in parts):
        return True
    if any(part in _PLUGIN_DIR_NAMES for part in parts):
        return True
    return False


# Map vuln type to regex patterns that capture the anti-pattern.
# These are intentionally broad -- they flag candidates, not confirmed vulns.
_TYPE_TO_PATTERN: dict[str, list[re.Pattern[str]]] = {
    "sql-injection": [
        re.compile(r"""(?:execute|query|raw)\s*\(\s*(?:f['"]|`|['"][^'"]*['"]?\s*\+|['"][^'"]*\.format)"""),
        re.compile(r"""(?:Query|Exec|QueryRow)\w*\(\s*fmt\.Sprintf"""),
    ],
    "command-injection": [
        re.compile(r"""os\.system\s*\("""),
        re.compile(r"""subprocess\.\w+\([^)]*shell\s*=\s*True"""),
    ],
    "xss": [
        re.compile(r"""(?:innerHTML|outerHTML|document\.write)\s*="""),
        re.compile(r"""\{\{\s*\w+\s*\|\s*safe\s*\}\}"""),  # Django |safe filter
    ],
    "path-traversal": [
        re.compile(r"""(?:readFile|readFileSync|open)\s*\([^)]*(?:req\.|params\.|query\.)"""),
    ],
    "ssrf": [
        re.compile(r"""(?:fetch|requests?\.\w+|http\.(?:Get|Post)|axios)\s*\([^)]*(?:req\.|params\.|query\.|body\.)"""),
    ],
    "ssti": [
        re.compile(r"""(?:render_template_string|Template\(|from_string)\s*\("""),
    ],
    "deserialization": [
        re.compile(r"""yaml\.(?:load|unsafe_load)\s*\("""),
        re.compile(r"""ObjectInputStream\s*\("""),
    ],
    "hardcoded-secret": [
        re.compile(r"""(?:password|secret|api_key|token|private_key)\s*=\s*['"][^'"]{8,}['"]""", re.IGNORECASE),
    ],
}

_LANG_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java",
    ".rb", ".php", ".cs", ".rs", ".sol", ".mjs", ".cjs",
}


def propagate(
    findings: list[dict[str, Any]],
    project_root: str,
    max_new: int = 50,
) -> list[dict[str, Any]]:
    """Search for additional instances of verified vulnerability patterns.

    Args:
        findings: Existing findings list (will not be modified).
        project_root: Root directory of the project.
        max_new: Maximum number of new findings to generate.

    Returns:
        List of new findings (not including originals).
    """
    root = Path(project_root).resolve()
    if not root.is_dir():
        return []

    # Collect verified vulnerability types
    verified_types: set[str] = set()
    for f in findings:
        if f.get("verdict") == "verified" and f.get("kind") == "finding":
            verified_types.add(f.get("type", ""))

    if not verified_types:
        log.info("No verified findings to propagate")
        return []

    # Collect existing finding locations to avoid duplicates
    existing_locations: set[tuple[str, int]] = set()
    for f in findings:
        existing_locations.add((f.get("file", ""), f.get("line", 0)))

    # Scan for pattern matches
    new_findings: list[dict[str, Any]] = []

    for vuln_type in verified_types:
        patterns = _TYPE_TO_PATTERN.get(vuln_type, [])
        if not patterns:
            continue

        for f in root.rglob("*"):
            if not f.is_file() or f.suffix not in _LANG_EXTENSIONS:
                continue
            if _is_excluded(f):
                continue

            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue

            rel = str(f.relative_to(root))
            lines = text.splitlines()

            for pattern in patterns:
                for i, line_text in enumerate(lines, 1):
                    if pattern.search(line_text):
                        loc = (rel, i)
                        if loc in existing_locations:
                            continue
                        existing_locations.add(loc)

                        new_findings.append({
                            "id": "",  # Will be assigned by orchestrator
                            "stable_key": "",
                            "kind": "finding",
                            "severity": "medium",
                            "type": vuln_type,
                            "title": f"Propagated {vuln_type} pattern",
                            "file": rel,
                            "line": i,
                            "verdict": "unverified",
                            "confidence": "medium",
                            "source_tool": "propagate",
                            "message": f"Similar pattern to verified {vuln_type} finding",
                            "evidence": [{
                                "type": "pattern-match",
                                "label": f"propagated-{vuln_type}",
                                "path": rel,
                                "line": i,
                                "excerpt": line_text.strip()[:200],
                                "role": "sink",
                                "order": 0,
                            }],
                        })

                        if len(new_findings) >= max_new:
                            log.info("Propagation: hit max %d new findings", max_new)
                            return new_findings

    log.info("Propagation: found %d new instances of %d verified pattern types",
             len(new_findings), len(verified_types))
    return new_findings
