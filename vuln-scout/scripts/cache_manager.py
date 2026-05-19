#!/usr/bin/env python3
"""Incremental scanning cache.

Caches findings by (file_path, content_hash) so subsequent scans only
re-analyze changed files.  Supports dependency-aware invalidation:
changing file B invalidates all files that import B.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")

CACHE_DIR_NAME = ".vuln-scout-cache"
CACHE_FILE = "findings-cache.json"
IMPORT_GRAPH_FILE = "import-graph.json"


class ScanCache:
    """File-hash-keyed findings cache with dependency-aware invalidation."""

    def __init__(self, project_root: str):
        self._root = Path(project_root).resolve()
        self._cache_dir = self._root / CACHE_DIR_NAME
        self._cache_path = self._cache_dir / CACHE_FILE
        self._import_graph_path = self._cache_dir / IMPORT_GRAPH_FILE
        self._cache: dict[str, dict[str, Any]] = {}
        self._import_graph: dict[str, list[str]] = {}  # file -> [files that import it]
        self._load()

    def _load(self) -> None:
        if self._cache_path.is_file():
            try:
                self._cache = json.loads(self._cache_path.read_text())
                log.info("Loaded scan cache with %d entries", len(self._cache))
            except (json.JSONDecodeError, OSError):
                self._cache = {}
        if self._import_graph_path.is_file():
            try:
                self._import_graph = json.loads(self._import_graph_path.read_text())
            except (json.JSONDecodeError, OSError):
                self._import_graph = {}

    def save(self) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_path.write_text(json.dumps(self._cache, indent=2))
        self._import_graph_path.write_text(json.dumps(self._import_graph, indent=2))
        log.info("Saved scan cache with %d entries", len(self._cache))

    def content_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash of file content."""
        full = self._root / file_path
        if not full.is_file():
            return ""
        try:
            return hashlib.sha256(full.read_bytes()).hexdigest()[:16]
        except OSError:
            return ""

    def get_cached_findings(self, file_path: str) -> list[dict[str, Any]] | None:
        """Get cached findings for a file if the content hasn't changed.

        Returns None if the file is not cached or has changed.
        """
        current_hash = self.content_hash(file_path)
        if not current_hash:
            return None

        entry = self._cache.get(file_path)
        if entry and entry.get("hash") == current_hash:
            return entry.get("findings", [])
        return None

    def store_findings(self, file_path: str, findings: list[dict[str, Any]]) -> None:
        """Store findings for a file with its current content hash."""
        content_hash = self.content_hash(file_path)
        if content_hash:
            self._cache[file_path] = {
                "hash": content_hash,
                "findings": findings,
            }

    def get_changed_files(self, all_files: list[str]) -> list[str]:
        """Return files whose content has changed since last cache.

        Also invalidates files that depend on changed files.
        """
        changed: set[str] = set()

        for file_path in all_files:
            current_hash = self.content_hash(file_path)
            entry = self._cache.get(file_path)
            if not entry or entry.get("hash") != current_hash:
                changed.add(file_path)

        # Dependency-aware invalidation
        dependents_to_add: set[str] = set()
        for changed_file in changed:
            for dependent in self._import_graph.get(changed_file, []):
                if dependent not in changed:
                    dependents_to_add.add(dependent)

        changed.update(dependents_to_add)
        if dependents_to_add:
            log.info("Dependency invalidation: %d additional files", len(dependents_to_add))

        return sorted(changed)

    def get_cached_file_findings(self, unchanged_files: list[str]) -> list[dict[str, Any]]:
        """Retrieve all cached findings for files that haven't changed."""
        findings: list[dict[str, Any]] = []
        for file_path in unchanged_files:
            cached = self.get_cached_findings(file_path)
            if cached:
                findings.extend(cached)
        return findings

    def update_import_graph(self, all_files: list[str]) -> None:
        """Build a lightweight import graph via regex-based import parsing."""
        self._import_graph = {}
        file_set = set(all_files)

        for file_path in all_files:
            full = self._root / file_path
            if not full.is_file():
                continue
            try:
                text = full.read_text(errors="replace")
            except OSError:
                continue

            imports = _extract_imports(text, file_path)
            for imported in imports:
                # Try to resolve to a file in the project
                resolved = _resolve_import(imported, file_path, file_set)
                if resolved:
                    self._import_graph.setdefault(resolved, []).append(file_path)

    def invalidate_all(self) -> None:
        """Clear the entire cache."""
        self._cache = {}
        self._import_graph = {}


# ---------------------------------------------------------------------------
# Import parsing (lightweight, regex-based)
# ---------------------------------------------------------------------------

_IMPORT_PATTERNS = [
    # Python: import foo, from foo import bar
    re.compile(r"""(?:from|import)\s+([\w.]+)"""),
    # JS/TS: import ... from 'foo', require('foo')
    re.compile(r"""(?:from|require)\s*\(?['"]([^'"]+)['"]"""),
    # Go: import "foo/bar"
    re.compile(r"""import\s+(?:\w+\s+)?["']([^"']+)["']"""),
    # Java: import foo.bar.Baz
    re.compile(r"""import\s+([\w.]+)"""),
    # Ruby: require 'foo'
    re.compile(r"""require\s+['"]([^'"]+)['"]"""),
    # PHP: use Foo\Bar
    re.compile(r"""use\s+([\w\\]+)"""),
]


def _extract_imports(text: str, file_path: str) -> list[str]:
    """Extract import targets from source code."""
    imports: list[str] = []
    for pattern in _IMPORT_PATTERNS:
        for m in pattern.finditer(text):
            imports.append(m.group(1))
    return imports


def _resolve_import(import_path: str, importer: str, known_files: set[str]) -> str | None:
    """Try to resolve an import path to a known project file."""
    # Convert dots/slashes to path
    candidates = [
        import_path.replace(".", "/") + ".py",
        import_path.replace(".", "/") + ".ts",
        import_path.replace(".", "/") + ".js",
        import_path.replace(".", "/") + ".go",
        import_path + ".py",
        import_path + ".ts",
        import_path + ".js",
        import_path + "/index.ts",
        import_path + "/index.js",
    ]

    # Also try relative imports
    importer_dir = str(Path(importer).parent)
    for candidate in list(candidates):
        candidates.append(f"{importer_dir}/{candidate}")

    for candidate in candidates:
        normalized = str(Path(candidate))
        if normalized in known_files:
            return normalized

    return None
