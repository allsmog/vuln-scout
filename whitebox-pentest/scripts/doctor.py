#!/usr/bin/env python3
"""Check VulnScout local runtime readiness."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LOCAL_RULES = PLUGIN_ROOT / "rules" / "vuln-scout-local.yml"


@dataclass
class ToolCheck:
    name: str
    available: bool
    path: str | None = None
    version: str | None = None
    required_for: str = "optional"
    note: str = ""


def _version(path: str, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0][:160] if output else None


def _check_tool(
    name: str,
    binary: str,
    version_args: list[str],
    required_for: str,
    note: str = "",
    include_versions: bool = False,
) -> ToolCheck:
    path = shutil.which(binary)
    if not path:
        return ToolCheck(name=name, available=False, required_for=required_for, note=note)
    return ToolCheck(
        name=name,
        available=True,
        path=path,
        version=_version(path, version_args) if include_versions else None,
        required_for=required_for,
        note=note,
    )


def _check_secret_scanner(include_versions: bool = False) -> ToolCheck:
    for binary, args in (("gitleaks", ["version"]), ("trufflehog", ["--version"])):
        path = shutil.which(binary)
        if path:
            return ToolCheck(
                name="secret-scanner",
                available=True,
                path=path,
                version=_version(path, args) if include_versions else None,
                required_for="deep/audit",
                note=f"using {binary}",
            )
    return ToolCheck(
        name="secret-scanner",
        available=False,
        required_for="deep/audit",
        note="install gitleaks or trufflehog",
    )


def _check_network(enabled: bool) -> dict[str, object]:
    if not enabled:
        return {
            "checked": False,
            "available": None,
            "note": "skipped; quick profile uses bundled local rules",
        }
    try:
        with urllib.request.urlopen("https://semgrep.dev", timeout=5) as response:
            return {
                "checked": True,
                "available": 200 <= response.status < 500,
                "status": response.status,
            }
    except Exception as exc:  # pragma: no cover - environment dependent
        return {
            "checked": True,
            "available": False,
            "error": str(exc),
        }


def collect(check_network: bool = False, include_versions: bool = False) -> dict[str, object]:
    tools = [
        _check_tool("semgrep", "semgrep", ["--version"], "quick/deep/audit", "required for scanner profiles", include_versions),
        _check_tool("joern", "joern", ["--help"], "deep/audit", "CPG verification", include_versions),
        _check_tool("codeql", "codeql", ["version"], "deep/audit", "CodeQL security suites", include_versions),
        _check_tool("slither", "slither", ["--version"], "deep", "Solidity analysis", include_versions),
        _check_secret_scanner(include_versions),
        _check_tool("repomix", "repomix", ["--version"], "Claude Code plugin", "large-codebase compression", include_versions),
        _check_tool("trivy", "trivy", ["--version"], "deep", "container/IaC dependency context", include_versions),
        _check_tool("checkov", "checkov", ["--version"], "deep", "IaC checks", include_versions),
    ]

    semgrep_ready = next(tool.available for tool in tools if tool.name == "semgrep")
    offline_ready = semgrep_ready and LOCAL_RULES.exists()
    return {
        "ok": offline_ready,
        "offline_ready": offline_ready,
        "local_rules": {
            "path": str(LOCAL_RULES),
            "exists": LOCAL_RULES.exists(),
        },
        "profiles": {
            "quick": "ready" if offline_ready else "blocked",
            "deep": "available tools are used; missing optional tools are reported in tool_status",
            "audit": "Claude-assisted workflow plus installed verification tools",
        },
        "tools": [asdict(tool) for tool in tools],
        "network": _check_network(check_network),
    }


def _print_text(report: dict[str, object]) -> None:
    print("VulnScout doctor")
    print(f"offline_ready: {'yes' if report['offline_ready'] else 'no'}")
    local_rules = report["local_rules"]
    assert isinstance(local_rules, dict)
    print(f"local_rules: {'found' if local_rules['exists'] else 'missing'} ({local_rules['path']})")
    print("")
    print("Tools:")
    for tool in report["tools"]:
        assert isinstance(tool, dict)
        status = "ok" if tool["available"] else "missing"
        detail = tool.get("version") or tool.get("note") or ""
        print(f"  {status:7} {tool['name']:15} {tool['required_for']:18} {detail}")
    network = report["network"]
    assert isinstance(network, dict)
    print("")
    if network.get("checked"):
        print(f"network: {'ok' if network.get('available') else 'unavailable'}")
    else:
        print(f"network: skipped ({network.get('note')})")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check VulnScout runtime dependencies.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--versions", action="store_true", help="Run tool version commands")
    parser.add_argument("--check-network", action="store_true", help="Check Semgrep registry network reachability")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when the quick offline profile is not ready")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    report = collect(check_network=args.check_network, include_versions=args.versions)
    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        _print_text(report)
    return 1 if args.strict and not report["offline_ready"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
