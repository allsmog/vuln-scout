#!/usr/bin/env python3
"""End-to-end smoke test for the VulnScout MCP server."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "vuln-scout" / "scripts" / "mcp_server.py"
DEMO = ROOT / "demo" / "vulnerable-app"


class RpcClient:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(ROOT),
        )
        self.next_id = 1

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: int = 900) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        start = time.time()
        while True:
            if time.time() - start > timeout:
                raise TimeoutError(f"timeout waiting for {method}")
            line = self.proc.stdout.readline()
            if not line:
                stderr = self.proc.stderr.read() if self.proc.stderr else ""
                raise RuntimeError(f"MCP server exited during {method}: {stderr}")
            response = json.loads(line)
            if response.get("id") != request_id:
                continue
            if "error" in response:
                raise RuntimeError(f"{method} failed: {response['error']}")
            return response["result"]

    def tool(self, name: str, arguments: dict[str, Any] | None = None, timeout: int = 900) -> dict[str, Any]:
        result = self.request("tools/call", {"name": name, "arguments": arguments or {}}, timeout=timeout)
        return json.loads(result["content"][0]["text"])


def _ok(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_smoke(require_joern: bool = False) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="vulnscout-mcp-smoke-") as tmpdir:
        workspace = Path(tmpdir) / "vulnerable-app"
        shutil.copytree(DEMO, workspace)
        client = RpcClient()
        try:
            initialize = client.request("initialize")
            _ok(initialize["serverInfo"]["name"] == "vuln-scout", "unexpected MCP server name")
            tools = {tool["name"] for tool in client.request("tools/list")["tools"]}
            _ok("vulnscout_scan" in tools and "vulnscout_joern_query" in tools, "MCP tools missing")

            doctor = client.tool("vulnscout_doctor", {"include_versions": False, "check_network": False})
            _ok(doctor.get("offline_ready") is True, "doctor did not report offline_ready")

            scan = client.tool(
                "vulnscout_scan",
                {"target": str(workspace), "profile": "quick", "output": ".claude/mcp-findings.json"},
            )
            finding_count = len(scan.get("artifact", {}).get("findings", []))
            _ok(finding_count == 4, f"expected 4 findings, got {finding_count}")

            report = client.tool(
                "vulnscout_report",
                {
                    "target": str(workspace),
                    "input": ".claude/mcp-findings.json",
                    "format": "html",
                    "output": "mcp-report.html",
                },
            )
            _ok(report.get("ok") is True, "HTML report failed")
            _ok("content" not in report, "report content should be opt-in")

            artifact = client.tool(
                "vulnscout_read_artifact",
                {"target": str(workspace), "artifact": "findings", "path": ".claude/mcp-findings.json"},
            )
            read_count = len(artifact.get("artifact", {}).get("findings", []))
            _ok(read_count == 4, f"expected 4 findings from artifact read, got {read_count}")

            cpg = client.tool(
                "vulnscout_create_cpg",
                {"target": str(workspace), "language": "javascript"},
                timeout=1200,
            )
            cpg_ok = cpg.get("ok") is True
            query_ok: bool | str = "skipped"
            if cpg_ok:
                query = client.tool(
                    "vulnscout_joern_query",
                    {"target": str(workspace), "language": "javascript", "query": "cpg.method.name.l.take(5)"},
                    timeout=300,
                )
                query_ok = query.get("ok") is True
                _ok(query_ok is True, "Joern query failed")
            elif require_joern:
                raise AssertionError(f"Joern CPG creation failed: {cpg.get('reason')}")

            return {
                "doctor_offline_ready": doctor.get("offline_ready"),
                "scan_findings_count": finding_count,
                "report_ok": report.get("ok"),
                "report_content_included": "content" in report,
                "read_artifact_count": read_count,
                "cpg_ok": cpg_ok,
                "joern_query_ok_or_skipped": query_ok,
            }
        finally:
            client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the VulnScout MCP end-to-end smoke test.")
    parser.add_argument("--require-joern", action="store_true", help="Fail if CPG creation/query cannot run.")
    parser.add_argument("--json", action="store_true", help="Emit JSON only.")
    args = parser.parse_args()
    result = run_smoke(require_joern=args.require_joern)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
