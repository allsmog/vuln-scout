#!/usr/bin/env python3
"""Bundle a Joern verify script with common.sc into a standalone script.

Joern's --script mode does not support $file.common Ammonite-style imports.
This script concatenates common.sc + a verify script, stripping the import line.

Usage:
    python3 bundle_joern.py verify-sqli.sc > /tmp/bundled-verify-sqli.sc
    joern --script /tmp/bundled-verify-sqli.sc --params "cpgFile=...,file=...,line=..."
"""
from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from pathlib import Path

JOERN_DIR = Path(__file__).resolve().parent / "joern"


def bundle(script_name: str) -> str:
    common = (JOERN_DIR / "common.sc").read_text()
    script = (JOERN_DIR / script_name).read_text()

    # Strip the $file.common import line from the verify script
    lines = [line for line in script.split("\n") if "import $file.common" not in line]
    script_body = "\n".join(lines)

    # Replace importCpg with safeImportCpg in bundled output so that
    # upstream Joern CPG pass errors don't kill the entire script.
    script_body = script_body.replace("importCpg(cpgFile)", "safeImportCpg(cpgFile)")

    return common + "\n" + script_body


@contextlib.contextmanager
def temporary_bundle(script_name: str):
    """Write a bundled Joern script to a secure temp file for one-time use."""
    temp_path: Path | None = None
    try:
        bundled = bundle(script_name)
        fd, raw_path = tempfile.mkstemp(prefix="vscout-joern-", suffix=f"-{script_name}")
        temp_path = Path(raw_path)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(bundled)
        yield temp_path
    except OSError:
        yield None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <verify-script.sc>", file=sys.stderr)
        return 1

    script_name = sys.argv[1]
    script_path = JOERN_DIR / script_name
    if not script_path.exists():
        print(f"Script not found: {script_path}", file=sys.stderr)
        return 1

    print(bundle(script_name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
