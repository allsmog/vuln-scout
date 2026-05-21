#!/usr/bin/env python3
"""Generic MCP server for VulnScout.

The implementation intentionally has no hard dependency on the MCP Python SDK.
It speaks the small stdio JSON-RPC subset needed by MCP hosts and keeps the
actual security work in the existing VulnScout scripts.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import unquote
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import create_cpg
import doctor
from artifact_utils import dump_json, load_artifact, validate_findings_artifact
from safe_paths import resolve_within_root
from tool_runners import joern_runner


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PLUGIN_ROOT / "scripts"
MAX_TEXT_BYTES = 256_000


class McpError(ValueError):
    pass


def _schema_string(description: str) -> dict[str, str]:
    return {"type": "string", "description": description}


def _schema_bool(description: str) -> dict[str, str]:
    return {"type": "boolean", "description": description}


def _enum(values: list[str], description: str) -> dict[str, Any]:
    return {"type": "string", "enum": values, "description": description}


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "vulnscout_doctor",
        "description": "Return VulnScout runtime readiness, including Semgrep, Joern, CodeQL, and Slither availability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_versions": _schema_bool("Run tool version commands."),
                "check_network": _schema_bool("Check Semgrep registry reachability."),
            },
        },
    },
    {
        "name": "vulnscout_scan",
        "description": "Run the VulnScout scan orchestrator and return the generated findings artifact.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _schema_string("Workspace directory to scan."),
                "profile": _enum(["quick", "deep", "audit"], "Scan profile."),
                "tools": _schema_string("Optional comma-separated scanner tools."),
                "workspace": _schema_string("Optional workspace/module under the target."),
                "since_commit": _schema_string("Optional git commit/ref for diff-aware scanning."),
                "suppressions": _schema_string("Optional .vuln-scout-ignore path inside the workspace."),
                "fail_on": _enum(["critical", "high", "medium", "low", "info"], "Optional fail-on threshold."),
                "output": _schema_string("Optional output findings path inside the workspace."),
            },
            "required": ["target"],
        },
    },
    {
        "name": "vulnscout_report",
        "description": "Render a VulnScout findings artifact to JSON, SARIF, Markdown, HTML, PR comment, or bundle output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _schema_string("Workspace directory."),
                "input": _schema_string("Findings artifact path inside the workspace. Defaults to .claude/findings.json."),
                "format": _enum(["json", "sarif", "md", "html", "pr-comment", "bundle"], "Report format."),
                "output": _schema_string("Output file path, or directory path for bundle, inside the workspace."),
                "suppressions": _schema_string("Optional .vuln-scout-ignore path inside the workspace."),
                "fail_on": _enum(["critical", "high", "medium", "low", "info"], "Optional fail-on threshold."),
                "include_content": _schema_bool("Include rendered report text in the MCP response. Defaults to false."),
                "max_content_bytes": {"type": "integer", "description": "Maximum report content bytes when include_content is true.", "default": 65536},
            },
            "required": ["target", "format"],
        },
    },
    {
        "name": "vulnscout_create_cpg",
        "description": "Create or reuse cached Joern CPGs for all supported languages in a workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _schema_string("Workspace directory."),
                "language": _schema_string("Optional single Joern-supported language."),
                "cache_dir": _schema_string("CPG cache directory inside the workspace. Defaults to .joern."),
                "no_cache": _schema_bool("Force CPG recreation."),
                "timeout": {"type": "integer", "description": "joern-parse timeout in seconds. Defaults to 600.", "default": 600},
            },
            "required": ["target"],
        },
    },
    {
        "name": "vulnscout_joern_query",
        "description": "Run a bounded raw local Joern CPGQL snippet against an existing or newly created CPG.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _schema_string("Workspace directory."),
                "query": _schema_string("Scala/CPGQL expression evaluated after importCpg(cpgFile)."),
                "language": _schema_string("Language CPG to create/use when cpg_path is omitted."),
                "cpg_path": _schema_string("Existing CPG path inside the workspace."),
                "timeout": {"type": "integer", "description": "Timeout in seconds.", "default": 120},
                "max_output_bytes": {"type": "integer", "description": "Maximum stdout/stderr bytes returned.", "default": 65536},
            },
            "required": ["target", "query"],
        },
    },
    {
        "name": "vulnscout_joern_discover",
        "description": "Run VulnScout's Joern discovery queries and return normalized findings plus tool status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _schema_string("Workspace directory."),
                "cache_dir": _schema_string("CPG cache directory inside the workspace. Defaults to .joern."),
                "timeout": {"type": "integer", "description": "Timeout in seconds.", "default": 300},
            },
            "required": ["target"],
        },
    },
    {
        "name": "vulnscout_verify_findings",
        "description": "Run Joern batch verification against a findings artifact or inline findings list.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _schema_string("Workspace directory."),
                "findings_path": _schema_string("Findings artifact path inside the workspace."),
                "findings": {"type": "array", "items": {"type": "object"}, "description": "Inline findings to verify."},
                "cache_dir": _schema_string("CPG cache directory inside the workspace. Defaults to .joern."),
                "timeout": {"type": "integer", "description": "Per-finding timeout in seconds.", "default": 120},
            },
            "required": ["target"],
        },
    },
    {
        "name": "vulnscout_read_artifact",
        "description": "Read a safe VulnScout artifact from the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _schema_string("Workspace directory."),
                "artifact": _enum(
                    ["findings", "review-ledger", "cpg-status", "tool-status", "attestation"],
                    "Artifact to read.",
                ),
                "path": _schema_string("Optional explicit artifact path inside the workspace."),
            },
            "required": ["target", "artifact"],
        },
    },
]

RESOURCE_TEMPLATES = [
    {"uriTemplate": "vulnscout://findings/{workspace}", "name": "VulnScout findings", "mimeType": "application/json"},
    {"uriTemplate": "vulnscout://review-ledger/{workspace}", "name": "VulnScout review ledger", "mimeType": "application/json"},
    {"uriTemplate": "vulnscout://cpg-status/{workspace}", "name": "VulnScout CPG status", "mimeType": "application/json"},
    {"uriTemplate": "vulnscout://tool-status/{workspace}", "name": "VulnScout tool status", "mimeType": "application/json"},
]

PROMPTS = [
    {"name": "verify-finding", "description": "Verify one VulnScout finding with CPG evidence and source review."},
    {"name": "triage-hotspots", "description": "Prioritize hotspots for manual review and CPG verification."},
    {"name": "explain-cpg-path", "description": "Explain a Joern source-to-sink path in reviewer language."},
    {"name": "review-pr-security", "description": "Run a diff-aware PR security review using VulnScout artifacts."},
]


def _workspace(target: str | None) -> Path:
    raw = target or "."
    path = Path(raw)
    resolved = path.resolve() if path.is_absolute() else (Path.cwd() / path).resolve()
    if not resolved.is_dir():
        raise McpError(f"workspace not found: {raw}")
    return resolved


def _safe_path(workspace: Path, value: str | None, default: str | None = None, *, must_exist: bool = False) -> Path:
    candidate = value or default
    if not candidate:
        raise McpError("path is required")
    resolved = resolve_within_root(workspace, candidate, strict=must_exist)
    if resolved is None:
        raise McpError(f"path escapes workspace or is unavailable: {candidate}")
    return resolved


def _safe_cache_dir(workspace: Path, value: str | None) -> str:
    path = _safe_path(workspace, value or ".joern", must_exist=False)
    return str(path)


def _run(args: list[str], *, cwd: Path = ROOT, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def _parse_json_output(result: subprocess.CompletedProcess[str]) -> Any:
    if result.returncode != 0:
        raise McpError((result.stderr or result.stdout or "command failed").strip()[:2000])
    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise McpError(f"command returned invalid JSON: {exc}") from exc


def _read_text_limited(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > MAX_TEXT_BYTES:
        return data[:MAX_TEXT_BYTES].decode("utf-8", errors="replace") + "\n...[truncated]"
    return data.decode("utf-8", errors="replace")


def _read_text_limited_to(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()
    if len(data) > max_bytes:
        return data[:max_bytes].decode("utf-8", errors="replace") + "\n...[truncated]"
    return data.decode("utf-8", errors="replace")


def _clean_joern_stdout(stdout: str) -> str:
    """Remove Joern loader chatter while preserving query output lines."""
    noisy_prefixes = ("[INFO", "[WARN", "SLF4J:")
    lines = [
        line
        for line in stdout.splitlines()
        if line.strip() and not line.lstrip().startswith(noisy_prefixes)
    ]
    return "\n".join(lines)


def _content(payload: Any) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, indent=2, sort_keys=True),
            }
        ]
    }


def tool_vulnscout_doctor(args: dict[str, Any]) -> dict[str, Any]:
    return doctor.collect(
        check_network=bool(args.get("check_network", False)),
        include_versions=bool(args.get("include_versions", False)),
    )


def tool_vulnscout_scan(args: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace(args.get("target"))
    output = _safe_path(workspace, args.get("output"), ".claude/findings.json", must_exist=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(SCRIPTS_DIR / "scan_orchestrator.py"),
        str(workspace),
        "--profile",
        str(args.get("profile") or "quick"),
        "--format",
        "json",
        "--output",
        str(output),
    ]
    if args.get("tools"):
        cmd.extend(["--tools", str(args["tools"])])
    if args.get("workspace"):
        cmd.extend(["--workspace", str(args["workspace"])])
    if args.get("since_commit"):
        cmd.extend(["--since-commit", str(args["since_commit"])])
    if args.get("suppressions"):
        cmd.extend(["--suppressions", str(_safe_path(workspace, args.get("suppressions"), must_exist=True))])
    if args.get("fail_on"):
        cmd.extend(["--fail-on", str(args["fail_on"])])

    result = _run(cmd, timeout=1800)
    if result.returncode not in (0, 2):
        raise McpError((result.stderr or result.stdout or "scan failed").strip()[:2000])
    artifact = load_artifact(output)
    errors = validate_findings_artifact(artifact)
    return {
        "ok": not errors,
        "exit_code": result.returncode,
        "output": str(output),
        "summary": artifact.get("summary", {}),
        "errors": errors,
        "artifact": artifact,
    }


def tool_vulnscout_report(args: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace(args.get("target"))
    input_path = _safe_path(workspace, args.get("input"), ".claude/findings.json", must_exist=True)
    fmt = str(args.get("format"))
    output_arg = args.get("output")
    if fmt == "bundle" and not output_arg:
        output_arg = "evidence-bundle"
    output_path = _safe_path(workspace, output_arg, f"report.{fmt}", must_exist=False)
    if fmt == "bundle":
        output_path.mkdir(parents=True, exist_ok=True)
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(SCRIPTS_DIR / "report.py"),
        str(input_path),
        "--format",
        fmt,
        "--output",
        str(output_path),
    ]
    if args.get("suppressions"):
        cmd.extend(["--suppressions", str(_safe_path(workspace, args.get("suppressions"), must_exist=True))])
    if args.get("fail_on"):
        cmd.extend(["--fail-on", str(args["fail_on"])])
    result = _run(cmd)
    if result.returncode not in (0, 2):
        raise McpError((result.stderr or result.stdout or "report failed").strip()[:2000])
    payload: dict[str, Any] = {
        "ok": True,
        "exit_code": result.returncode,
        "format": fmt,
        "output": str(output_path),
    }
    try:
        payload["summary"] = load_artifact(input_path).get("summary", {})
    except Exception:
        payload["summary"] = {}
    if fmt == "bundle":
        payload["files"] = sorted(path.name for path in output_path.iterdir())
    elif args.get("include_content"):
        max_bytes = int(args.get("max_content_bytes") or 65536)
        payload["content"] = _read_text_limited_to(output_path, max(1024, min(max_bytes, MAX_TEXT_BYTES)))
    return payload


def tool_vulnscout_create_cpg(args: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace(args.get("target"))
    cache_dir = _safe_cache_dir(workspace, args.get("cache_dir"))
    cmd = [
        sys.executable,
        str(SCRIPTS_DIR / "create_cpg.py"),
        str(workspace),
        "--cache-dir",
        cache_dir,
        "--json",
    ]
    if args.get("language"):
        cmd.extend(["--language", str(args["language"])])
    else:
        cmd.append("--all-languages")
    if args.get("timeout"):
        cmd.extend(["--timeout", str(int(args["timeout"]))])
    if args.get("no_cache"):
        cmd.append("--no-cache")
    result = _run(cmd, timeout=900)
    if result.returncode != 0:
        try:
            payload = json.loads(result.stdout) if result.stdout.strip() else None
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict) and payload.get("languages"):
            payload["ok"] = False
            states = {
                str(status.get("state"))
                for status in payload.get("languages", {}).values()
                if isinstance(status, dict) and status.get("state")
            }
            payload.setdefault("state", "timed_out" if states == {"timed_out"} else "failed")
            return payload
        return {
            "ok": False,
            "state": "failed",
            "cpgs": {},
            "languages": {},
            "reason": (result.stderr or result.stdout or "CPG creation failed").strip()[:2000],
        }
    payload = _parse_json_output(result)
    if isinstance(payload, dict):
        payload.setdefault("ok", True)
    return payload


def _select_cpg(workspace: Path, args: dict[str, Any]) -> Path:
    if args.get("cpg_path"):
        return _safe_path(workspace, args.get("cpg_path"), must_exist=True)
    payload = tool_vulnscout_create_cpg({
        "target": str(workspace),
        "language": args.get("language"),
        "cache_dir": args.get("cache_dir"),
    })
    if payload.get("ok") is False:
        raise McpError(str(payload.get("reason") or "no Joern CPG available"))
    cpgs = payload.get("cpgs", {})
    if not cpgs:
        raise McpError("no Joern CPG available")
    language = args.get("language")
    if language and language in cpgs:
        return Path(cpgs[language])
    return Path(next(iter(cpgs.values())))


def tool_vulnscout_joern_query(args: dict[str, Any]) -> dict[str, Any]:
    if not shutil.which("joern"):
        return {"ok": False, "state": "unavailable", "reason": "joern binary not found"}
    workspace = _workspace(args.get("target"))
    cpg_path = _select_cpg(workspace, args)
    query = str(args.get("query") or "").strip()
    if not query:
        raise McpError("query is required")
    timeout = int(args.get("timeout") or 120)
    max_bytes = int(args.get("max_output_bytes") or 65536)
    script = (
        "@main def main(cpgFile: String): Unit = {\n"
        "  importCpg(cpgFile)\n"
        "  val result = {\n"
        f"{query}\n"
        "  }\n"
        f"  println(result.toString.take({max_bytes}))\n"
        "}\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".sc", prefix="vscout-mcp-query-", delete=False) as handle:
        handle.write(script)
        script_path = Path(handle.name)
    try:
        result = _run(
            ["joern", "--script", str(script_path), "--param", f"cpgFile={cpg_path}"],
            cwd=workspace,
            timeout=timeout,
        )
    finally:
        script_path.unlink(missing_ok=True)
    stdout = (result.stdout or "")[:max_bytes]
    stderr = (result.stderr or "")[:max_bytes]
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "cpg": str(cpg_path),
        "output": _clean_joern_stdout(stdout),
        "stdout": stdout,
        "stderr": stderr,
    }


def tool_vulnscout_joern_discover(args: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace(args.get("target"))
    return joern_runner.discover_with_status(
        str(workspace),
        cache_dir=_safe_cache_dir(workspace, args.get("cache_dir")),
        timeout=int(args.get("timeout") or 300),
    )


def tool_vulnscout_verify_findings(args: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace(args.get("target"))
    if args.get("findings") is not None:
        findings = list(args.get("findings") or [])
    else:
        findings_path = _safe_path(workspace, args.get("findings_path"), ".claude/findings.json", must_exist=True)
        findings = list(load_artifact(findings_path).get("findings", []))
    verified = joern_runner.run(
        str(workspace),
        findings=findings,
        cache_dir=_safe_cache_dir(workspace, args.get("cache_dir")),
        timeout=int(args.get("timeout") or 120),
    )
    return {"ok": True, "findings": verified, "count": len(verified)}


def tool_vulnscout_read_artifact(args: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace(args.get("target"))
    artifact = str(args.get("artifact"))
    defaults = {
        "findings": ".claude/findings.json",
        "review-ledger": ".claude/review-ledger.json",
        "cpg-status": ".joern",
        "tool-status": ".claude/findings.json",
        "attestation": "evidence-bundle/attestation.json",
    }
    path = _safe_path(workspace, args.get("path"), defaults.get(artifact), must_exist=True)
    if path.is_dir():
        return {"path": str(path), "files": sorted(p.name for p in path.iterdir())}
    text = _read_text_limited(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = text
    if artifact == "tool-status" and isinstance(data, dict):
        data = data.get("tool_status", {})
    return {"path": str(path), "artifact": data}


TOOLS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "vulnscout_doctor": tool_vulnscout_doctor,
    "vulnscout_scan": tool_vulnscout_scan,
    "vulnscout_report": tool_vulnscout_report,
    "vulnscout_create_cpg": tool_vulnscout_create_cpg,
    "vulnscout_joern_query": tool_vulnscout_joern_query,
    "vulnscout_joern_discover": tool_vulnscout_joern_discover,
    "vulnscout_verify_findings": tool_vulnscout_verify_findings,
    "vulnscout_read_artifact": tool_vulnscout_read_artifact,
}


def list_tools() -> list[dict[str, Any]]:
    return TOOL_DEFINITIONS


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    if name not in TOOLS:
        raise McpError(f"unknown tool: {name}")
    return TOOLS[name](arguments or {})


def get_prompt(name: str) -> dict[str, Any]:
    prompts = {
        "verify-finding": "Use VulnScout MCP tools to inspect findings, run CPG verification, then explain the verdict and evidence.",
        "triage-hotspots": "Use VulnScout findings and CPG tools to rank hotspots by exploitability and false-positive risk.",
        "explain-cpg-path": "Explain the Joern CPG path in concise reviewer language, including source, sink, sanitizer, and uncertainty.",
        "review-pr-security": "Run a diff-aware VulnScout review, verify changed findings, and produce a PR comment payload.",
    }
    if name not in prompts:
        raise McpError(f"unknown prompt: {name}")
    return {"description": next(p["description"] for p in PROMPTS if p["name"] == name), "messages": [{"role": "user", "content": {"type": "text", "text": prompts[name]}}]}


def read_resource(uri: str) -> dict[str, Any]:
    if not uri.startswith("vulnscout://"):
        raise McpError(f"unsupported resource URI: {uri}")
    remainder = uri.removeprefix("vulnscout://")
    if "/" not in remainder:
        raise McpError("resource URI must include artifact and workspace")
    artifact, encoded_workspace = remainder.split("/", 1)
    workspace = unquote(encoded_workspace)
    payload = tool_vulnscout_read_artifact({"target": workspace, "artifact": artifact})
    return {
        "contents": [
            {
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(payload, indent=2, sort_keys=True),
            }
        ]
    }


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    request_id = request.get("id")
    params = request.get("params") or {}
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "vuln-scout", "version": "3.2.0"},
            }
        elif method == "notifications/initialized":
            return None
        elif method == "tools/list":
            result = {"tools": list_tools()}
        elif method == "tools/call":
            result = _content(call_tool(str(params.get("name")), params.get("arguments") or {}))
        elif method == "resources/templates/list":
            result = {"resourceTemplates": RESOURCE_TEMPLATES}
        elif method == "resources/list":
            result = {"resources": []}
        elif method == "resources/read":
            result = read_resource(str(params.get("uri") or ""))
        elif method == "prompts/list":
            result = {"prompts": PROMPTS}
        elif method == "prompts/get":
            result = get_prompt(str(params.get("name")))
        else:
            raise McpError(f"unsupported method: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32000, "message": str(exc)},
        }


def serve_stdio() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
        else:
            response = handle_request(request)
        if response is not None:
            print(json.dumps(response, separators=(",", ":")), flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the VulnScout MCP server.")
    parser.add_argument("--list-tools", action="store_true", help="Print MCP tool definitions and exit")
    args = parser.parse_args()
    if args.list_tools:
        print(json.dumps({"tools": list_tools(), "resources": RESOURCE_TEMPLATES, "prompts": PROMPTS}, indent=2, sort_keys=True))
        return 0
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
