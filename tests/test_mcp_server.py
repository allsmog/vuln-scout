from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "vuln-scout" / "scripts"
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "artifacts"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


mcp_server = load_module("mcp_server_test", SCRIPTS_DIR / "mcp_server.py")


class McpServerTests(unittest.TestCase):
    def test_tool_schemas_include_full_bridge(self) -> None:
        names = {tool["name"] for tool in mcp_server.list_tools()}

        self.assertEqual(names, {
            "vulnscout_doctor",
            "vulnscout_scan",
            "vulnscout_report",
            "vulnscout_create_cpg",
            "vulnscout_joern_query",
            "vulnscout_joern_discover",
            "vulnscout_verify_findings",
            "vulnscout_read_artifact",
        })
        report = next(tool for tool in mcp_server.list_tools() if tool["name"] == "vulnscout_report")
        self.assertEqual(
            set(report["inputSchema"]["properties"]["format"]["enum"]),
            {"json", "sarif", "md", "html", "pr-comment", "bundle"},
        )

    def test_safe_path_rejects_workspace_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            with self.assertRaisesRegex(mcp_server.McpError, "escapes workspace"):
                mcp_server._safe_path(workspace, "../outside.txt", must_exist=False)

    def test_doctor_tool_returns_structured_report(self) -> None:
        report = mcp_server.call_tool("vulnscout_doctor", {"include_versions": False})

        self.assertIn("offline_ready", report)
        self.assertIn("tools", report)
        self.assertIn("profile_maturity", report)

    def test_report_tool_omits_content_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            artifact_dir = workspace / ".claude"
            artifact_dir.mkdir()
            shutil.copyfile(FIXTURES_DIR / "sample-findings.json", artifact_dir / "findings.json")

            report = mcp_server.call_tool(
                "vulnscout_report",
                {"target": tmpdir, "format": "html", "output": "report.html"},
            )

        self.assertTrue(report["ok"])
        self.assertIn("summary", report)
        self.assertNotIn("content", report)

    def test_report_tool_includes_content_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            artifact_dir = workspace / ".claude"
            artifact_dir.mkdir()
            shutil.copyfile(FIXTURES_DIR / "sample-findings.json", artifact_dir / "findings.json")

            report = mcp_server.call_tool(
                "vulnscout_report",
                {
                    "target": tmpdir,
                    "format": "md",
                    "output": "report.md",
                    "include_content": True,
                    "max_content_bytes": 4096,
                },
            )

        self.assertTrue(report["ok"])
        self.assertIn("content", report)
        self.assertIn("VulnScout", report["content"])

    def test_json_rpc_tools_list(self) -> None:
        response = mcp_server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        })

        assert response is not None
        self.assertEqual(response["id"], 1)
        self.assertIn("tools", response["result"])

    def test_json_rpc_resource_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            artifact_dir = workspace / ".claude"
            artifact_dir.mkdir()
            (artifact_dir / "findings.json").write_text(json.dumps({"schema_version": "1.2.0", "findings": []}))
            uri = f"vulnscout://findings/{quote(str(workspace), safe='')}"

            response = mcp_server.handle_request({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": {"uri": uri},
            })

        assert response is not None
        self.assertEqual(response["id"], 2)
        contents = response["result"]["contents"]
        self.assertEqual(contents[0]["uri"], uri)
        self.assertIn("schema_version", contents[0]["text"])

    def test_stdio_smoke(self) -> None:
        request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}) + "\n"
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "mcp_server.py")],
            input=request,
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=5,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["id"], 1)
        self.assertTrue(payload["result"]["tools"])

    def test_joern_unavailable_query_is_structured(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.object(mcp_server.shutil, "which", return_value=None):
                result = mcp_server.call_tool(
                    "vulnscout_joern_query",
                    {"target": tmpdir, "query": "cpg.method.name.l"},
                )

        self.assertEqual(result["state"], "unavailable")

    def test_cpg_creation_failure_is_structured(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            failed = subprocess.CompletedProcess(
                args=["create_cpg.py"],
                returncode=1,
                stdout="",
                stderr="joern-parse failed",
            )
            with mock.patch.object(mcp_server, "_run", return_value=failed):
                result = mcp_server.call_tool("vulnscout_create_cpg", {"target": tmpdir})

        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("joern-parse failed", result["reason"])

    def test_cpg_creation_preserves_json_timeout_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            failed = subprocess.CompletedProcess(
                args=["create_cpg.py"],
                returncode=1,
                stdout=json.dumps({
                    "cpgs": {},
                    "languages": {
                        "java": {
                            "state": "timed_out",
                            "findings": 0,
                            "reason": "CPG creation timed out after 600 seconds",
                        }
                    },
                }),
                stderr="[ERROR] CPG creation timed out after 600 seconds",
            )
            with mock.patch.object(mcp_server, "_run", return_value=failed):
                result = mcp_server.call_tool("vulnscout_create_cpg", {"target": tmpdir, "language": "java"})

        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "timed_out")
        self.assertEqual(result["languages"]["java"]["state"], "timed_out")

    def test_joern_stdout_cleaner_removes_loader_chatter(self) -> None:
        cleaned = mcp_server._clean_joern_stdout(
            "[INFO ] initialising from existing storage\n"
            "List(decode, encode)\n"
        )

        self.assertEqual(cleaned, "List(decode, encode)")


if __name__ == "__main__":
    unittest.main()
