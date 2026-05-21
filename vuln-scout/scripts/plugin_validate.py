#!/usr/bin/env python3
"""Validate VulnScout plugin packaging without requiring Claude CLI."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOTS = (ROOT / "vuln-scout", ROOT / "whitebox-pentest")
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"
PACKAGE = ROOT / "package.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def validate_internal() -> list[str]:
    errors: list[str] = []
    package_version = _load_json(PACKAGE).get("version")
    marketplace = _load_json(MARKETPLACE)
    plugin_entries = {entry["name"]: entry for entry in marketplace.get("plugins", [])}

    for plugin_root in PLUGIN_ROOTS:
        manifest_path = plugin_root / ".claude-plugin" / "plugin.json"
        if not manifest_path.exists():
            errors.append(f"{manifest_path.relative_to(ROOT)} missing")
            continue
        manifest = _load_json(manifest_path)
        name = manifest.get("name")
        if name not in plugin_entries:
            errors.append(f"{name} missing from marketplace manifest")
        elif (ROOT / plugin_entries[name].get("source", "")).resolve() != plugin_root.resolve():
            errors.append(f"{name} marketplace source does not point to {plugin_root.relative_to(ROOT)}")
        if manifest.get("version") != package_version:
            errors.append(f"{manifest_path.relative_to(ROOT)} version must match package.json")
        commands_dir = plugin_root / "commands"
        command_files = sorted(commands_dir.glob("*.md"))
        if not command_files:
            errors.append(f"{commands_dir.relative_to(ROOT)} has no commands")
        for command_file in command_files:
            text = command_file.read_text()
            if not text.startswith("---\n"):
                errors.append(f"{command_file.relative_to(ROOT)} missing YAML frontmatter")
            if "description:" not in text.split("---", 2)[1]:
                errors.append(f"{command_file.relative_to(ROOT)} missing frontmatter description")
    return errors


def validate_with_claude(strict: bool) -> list[str]:
    claude = shutil.which("claude")
    if not claude:
        return []
    errors: list[str] = []
    for path in (ROOT / "vuln-scout", ROOT / "whitebox-pentest", ROOT / ".claude-plugin" / "marketplace.json"):
        cmd = [claude, "plugin", "validate"]
        if strict:
            cmd.append("--strict")
        cmd.append(str(path))
        result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            errors.append(f"{path.relative_to(ROOT)} failed Claude validation: {(result.stderr or result.stdout).strip()}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate VulnScout plugin manifests and marketplace metadata.")
    parser.add_argument("--strict", action="store_true", help="Run Claude plugin validate --strict when Claude CLI is installed.")
    parser.add_argument("--json", action="store_true", help="Emit JSON result.")
    args = parser.parse_args()
    errors = validate_internal() + validate_with_claude(strict=args.strict)
    result = {"ok": not errors, "errors": errors, "claude_cli_available": bool(shutil.which("claude"))}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
    else:
        print("ok: plugin validation passed")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
