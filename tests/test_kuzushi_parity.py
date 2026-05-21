import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TOOLS = {
    "vuln-scout:full-audit",
    "vuln-scout:scan",
    "vuln-scout:trace",
    "vuln-scout:verify",
    "vuln-scout:sinks",
    "vuln-scout:auto-fix",
    "vuln-scout:report",
    "vuln-scout:threats",
    "vuln-scout:scope",
    "vuln-scout:propagate",
    "vuln-scout:diff",
    "vuln-scout:create-rule",
    "vuln-scout:org-memory-compile",
    "vuln-scout:mutate",
}


def _load_tools() -> list[dict]:
    script = """
      import('./kuzushi-module.js').then((m) => {
        console.log(JSON.stringify(m.default.tools));
      });
    """
    result = subprocess.run(
        ["node", "-e", script],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return json.loads(result.stdout)


class KuzushiParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tools = _load_tools()

    def test_exports_expected_tools(self) -> None:
        self.assertEqual({tool["name"] for tool in self.tools}, EXPECTED_TOOLS)

    def test_report_format_enum_has_all_formats(self) -> None:
        report = next(tool for tool in self.tools if tool["name"] == "vuln-scout:report")
        enum = report["inputSchema"]["properties"]["format"]["enum"]
        self.assertEqual(set(enum), {"sarif", "md", "json", "html", "pr-comment", "bundle"})

    def test_structured_schemas_expose_core_flags(self) -> None:
        by_name = {tool["name"]: tool for tool in self.tools}
        scan_props = by_name["vuln-scout:scan"]["inputSchema"]["properties"]
        for key in ("profile", "failOn", "suppressions", "sinceCommit", "workspace", "format", "output"):
            self.assertIn(key, scan_props)
        report_props = by_name["vuln-scout:report"]["inputSchema"]["properties"]
        for key in ("format", "output", "suppressions", "failOn"):
            self.assertIn(key, report_props)

    def test_tools_are_headless_with_required_schema(self) -> None:
        for tool in self.tools:
            with self.subTest(tool=tool["name"]):
                self.assertIs(tool.get("headless"), True)
                self.assertIn("required", tool["inputSchema"])
                self.assertTrue(tool["inputSchema"]["required"])


if __name__ == "__main__":
    unittest.main()
