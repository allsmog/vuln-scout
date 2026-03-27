#!/usr/bin/env python3
from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Iterator


def _coerce_candidate(root: Path, candidate: Path | str) -> Path:
    path = Path(candidate)
    return path if path.is_absolute() else root / path


def resolve_within_root(
    root: Path | str,
    candidate: Path | str,
    *,
    strict: bool = False,
) -> Path | None:
    """Resolve a repo path and reject anything that escapes the root."""
    root_path = Path(root).resolve()
    candidate_path = _coerce_candidate(root_path, candidate)
    try:
        resolved = candidate_path.resolve(strict=strict)
    except OSError:
        return None

    try:
        resolved.relative_to(root_path)
    except ValueError:
        return None
    return resolved


def is_within_root(root: Path | str, candidate: Path | str, *, strict: bool = False) -> bool:
    return resolve_within_root(root, candidate, strict=strict) is not None


def safe_read_text(
    root: Path | str,
    candidate: Path | str,
    *,
    errors: str = "strict",
    encoding: str = "utf-8",
) -> str | None:
    path = resolve_within_root(root, candidate, strict=True)
    if path is None or not path.is_file():
        return None
    try:
        return path.read_text(encoding=encoding, errors=errors)
    except OSError:
        return None


def safe_read_bytes(root: Path | str, candidate: Path | str) -> bytes | None:
    path = resolve_within_root(root, candidate, strict=True)
    if path is None or not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def safe_walk_files(
    root: Path | str,
    *,
    start: Path | str | None = None,
    extensions: set[str] | None = None,
    excluded_dirs: set[str] | frozenset[str] | tuple[str, ...] = (),
    include_patterns: tuple[str, ...] | list[str] | None = None,
) -> Iterator[Path]:
    """Yield files rooted under *root*, skipping paths that escape via symlinks."""
    root_path = Path(root).resolve()
    base = resolve_within_root(root_path, start if start is not None else root_path, strict=True)
    if base is None or not base.exists():
        return

    visited_dirs: set[Path] = set()
    for dirpath, dirnames, filenames in os.walk(base, followlinks=True):
        dir_path = Path(dirpath)
        resolved_dir = resolve_within_root(root_path, dir_path, strict=True)
        if resolved_dir is None or not resolved_dir.is_dir():
            dirnames[:] = []
            continue
        if resolved_dir in visited_dirs:
            dirnames[:] = []
            continue
        visited_dirs.add(resolved_dir)

        next_dirs: list[str] = []
        for dirname in dirnames:
            if dirname in excluded_dirs:
                continue
            candidate_dir = dir_path / dirname
            resolved_child = resolve_within_root(root_path, candidate_dir, strict=True)
            if resolved_child is None or not resolved_child.is_dir():
                continue
            if resolved_child in visited_dirs:
                continue
            next_dirs.append(dirname)
        dirnames[:] = next_dirs

        for filename in filenames:
            candidate = dir_path / filename
            resolved = resolve_within_root(root_path, candidate, strict=True)
            if resolved is None or not resolved.is_file():
                continue
            if extensions is not None and candidate.suffix not in extensions:
                continue
            relative = resolved.relative_to(root_path).as_posix()
            if include_patterns and not any(fnmatch.fnmatch(relative, pattern) for pattern in include_patterns):
                continue
            yield candidate
