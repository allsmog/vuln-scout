#!/usr/bin/env python3
"""Create or reuse a cached Joern CPG for a source directory."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from safe_paths import safe_read_bytes, safe_walk_files

log = logging.getLogger("vuln-scout")

LANG_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "javascript": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    "python": (".py",),
    "go": (".go",),
    "java": (".java",),
    "solidity": (".sol",),
    "php": (".php",),
    "ruby": (".rb",),
    "csharp": (".cs",),
}

JOERN_LANGUAGE_ARGS: dict[str, str | None] = {
    "javascript": None,
    "python": None,
    "go": None,
    "java": None,
    "php": None,
    "ruby": None,
    "csharp": None,
}

JOERN_SUPPORTED_LANGUAGES = set(JOERN_LANGUAGE_ARGS)

EXCLUDED_SOURCE_DIRS = {"node_modules", "vendor", "__pycache__", ".git", ".joern", ".codeql", ".claude"}


def detect_language(source_dir: str) -> str:
    """Detect dominant Joern-supported language from file extensions."""
    counts: dict[str, int] = {}
    for lang, count in detect_languages(source_dir).items():
        if lang in JOERN_SUPPORTED_LANGUAGES:
            counts[lang] = count
    if not counts:
        return "unknown"
    return max(counts, key=counts.get)  # type: ignore[arg-type]


def detect_languages(source_dir: str) -> dict[str, int]:
    """Count source files by known language extension."""
    counts: dict[str, int] = {}
    src = Path(source_dir).resolve()
    for f in safe_walk_files(src, excluded_dirs=EXCLUDED_SOURCE_DIRS):
        for lang, exts in LANG_EXTENSIONS.items():
            if f.suffix in exts:
                counts[lang] = counts.get(lang, 0) + 1
                break
    return counts


def compute_source_hash(source_dir: str, language: str) -> str:
    """Compute SHA-256 hash of source files for cache key."""
    exts = LANG_EXTENSIONS.get(language, ())
    src = Path(source_dir).resolve()

    file_hashes: list[str] = []
    for f in sorted(
        safe_walk_files(
            src,
            extensions=set(exts),
            excluded_dirs=EXCLUDED_SOURCE_DIRS,
        )
    ):
        content = safe_read_bytes(src, f)
        if content is None:
            continue
        content_hash = hashlib.sha256(content).hexdigest()
        file_hashes.append(f"{f.relative_to(src)}:{content_hash}")

    combined = "\n".join(file_hashes)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def language_source_files(source_dir: str, language: str) -> list[Path]:
    """Return source files for one language, rooted under source_dir."""
    exts = LANG_EXTENSIONS.get(language, ())
    src = Path(source_dir).resolve()
    return sorted(
        safe_walk_files(
            src,
            extensions=set(exts),
            excluded_dirs=EXCLUDED_SOURCE_DIRS,
        )
    )


def get_cpg_path(cache_dir: str, source_hash: str, language: str) -> Path:
    """Return the cached CPG file path."""
    return Path(cache_dir) / f"{source_hash}-{language}.cpg"


def is_cache_valid(cpg_path: Path) -> bool:
    """Check if cached CPG exists and is non-empty."""
    return cpg_path.exists() and cpg_path.stat().st_size > 0


def create_cpg(source_dir: str, cpg_path: Path, language: str) -> None:
    """Run joern-parse to create a CPG."""
    if language not in JOERN_LANGUAGE_ARGS:
        raise ValueError(f"Joern CPG creation is not supported for {language}")
    joern_language = JOERN_LANGUAGE_ARGS[language]

    cpg_path.parent.mkdir(parents=True, exist_ok=True)
    source_hash = cpg_path.name.split("-", 1)[0]
    source_view = cpg_path.parent / "_source_views" / f"{source_hash}-{language}"
    build_source_view(source_dir, language, source_view)

    cmd = [
        "joern-parse",
        str(source_view),
        "--output",
        str(cpg_path),
    ]
    if joern_language:
        cmd.extend(["--language", joern_language])

    log.info("Creating CPG: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, cmd, result.stdout, result.stderr
        )
    log.info("CPG created: %s (%d bytes)", cpg_path, cpg_path.stat().st_size)


def build_source_view(source_dir: str, language: str, source_view: Path) -> None:
    """Materialize a language-only source tree for Joern frontends."""
    src = Path(source_dir).resolve()
    files = language_source_files(source_dir, language)
    if not files:
        raise ValueError(f"No {language} files found in {source_dir}")

    if source_view.exists():
        shutil.rmtree(source_view)
    source_view.mkdir(parents=True, exist_ok=True)

    for file_path in files:
        relative = file_path.resolve().relative_to(src)
        destination = source_view / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, destination)


def cache_root_for(source_dir: str, cache_dir: str) -> Path:
    """Resolve cache_dir; relative paths live under the scanned source root."""
    root = Path(cache_dir)
    if root.is_absolute():
        return root
    return Path(source_dir).resolve() / root


def create_or_reuse_cpg(source_dir: str, cache_dir: str, language: str, no_cache: bool = False) -> Path:
    """Create or reuse one language-specific CPG and return its path."""
    if language not in JOERN_SUPPORTED_LANGUAGES:
        raise ValueError(f"Joern CPG creation is not supported for {language}")

    source_hash = compute_source_hash(source_dir, language)
    cpg_path = get_cpg_path(str(cache_root_for(source_dir, cache_dir)), source_hash, language)

    if not no_cache and is_cache_valid(cpg_path):
        log.info("Using cached CPG: %s", cpg_path)
    else:
        create_cpg(source_dir, cpg_path, language)
    return cpg_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or reuse a cached Joern CPG")
    parser.add_argument("source_dir", help="Source directory to parse")
    parser.add_argument("--language", help="Override language detection")
    parser.add_argument("--all-languages", action="store_true", help="Create one CPG per detected Joern-supported language")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable CPG paths and statuses")
    parser.add_argument("--no-cache", action="store_true", help="Force CPG recreation")
    parser.add_argument("--cache-dir", default=".joern", help="CPG cache directory")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)

    if not shutil.which("joern-parse"):
        log.error("joern-parse not found. Install Joern: https://joern.io/")
        return 1

    source_dir = str(Path(args.source_dir).resolve())

    if args.all_languages:
        detected = detect_languages(source_dir)
        languages = sorted(lang for lang in detected if lang in JOERN_SUPPORTED_LANGUAGES)
        statuses: dict[str, dict[str, object]] = {}
        cpgs: dict[str, str] = {}
        for lang in sorted(detected):
            if lang not in JOERN_SUPPORTED_LANGUAGES:
                statuses[lang] = {
                    "state": "unsupported",
                    "findings": 0,
                    "reason": "Joern frontend not supported; use language-specific tools",
                }
        for language in languages:
            try:
                cpg_path = create_or_reuse_cpg(source_dir, args.cache_dir, language, args.no_cache)
            except subprocess.CalledProcessError as e:
                statuses[language] = {
                    "state": "failed",
                    "findings": 0,
                    "reason": (e.stderr or str(e))[:500],
                }
                continue
            except subprocess.TimeoutExpired:
                statuses[language] = {
                    "state": "timed_out",
                    "findings": 0,
                    "reason": "CPG creation timed out after 600 seconds",
                }
                continue
            except ValueError as e:
                statuses[language] = {"state": "unsupported", "findings": 0, "reason": str(e)}
                continue
            cpgs[language] = str(cpg_path)
            statuses[language] = {"state": "succeeded", "findings": 0, "cpg": str(cpg_path)}
        if args.json:
            print(json.dumps({"cpgs": cpgs, "languages": statuses}, sort_keys=True))
        else:
            for path in cpgs.values():
                print(path)
        return 0 if cpgs or statuses else 1

    language = args.language or detect_language(source_dir)
    if language == "unknown":
        log.error("No Joern-supported source files found in %s", source_dir)
        return 1

    try:
        cpg_path = create_or_reuse_cpg(source_dir, args.cache_dir, language, args.no_cache)
    except ValueError as e:
        log.error(str(e))
        return 1
    except subprocess.CalledProcessError as e:
        log.error("CPG creation failed: %s", e.stderr[:500] if e.stderr else str(e))
        return 1
    except subprocess.TimeoutExpired:
        log.error("CPG creation timed out after 600 seconds")
        return 1

    if args.json:
        print(json.dumps({"cpgs": {language: str(cpg_path)}, "languages": {language: {"state": "succeeded", "findings": 0, "cpg": str(cpg_path)}}}, sort_keys=True))
    else:
        print(str(cpg_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
