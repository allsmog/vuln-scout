import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "vuln-scout" / "scripts" / "org_memory_compiler.py"
sys.path.insert(0, str(ROOT / "vuln-scout" / "scripts"))

import org_memory_compiler


def _record(index: int) -> dict:
    return {
        "id": f"VSCOUT-{index:04d}",
        "stable_key": f"fixture:{index}",
        "rule_id": "semgrep.fixture.sqli",
        "type": "sql-injection",
        "verdict": "verified",
        "confidence": "high",
        "file": f"src/app{index}.py",
        "line": index,
        "cwe": "CWE-89",
        "message": "SQL query uses attacker-controlled input.",
        "trust_metadata": {
            "provenance": {
                "origin": "human_review",
                "contributors": ["deterministic_tool", "human_review"],
            }
        },
        "evidence": [
            {
                "type": "code",
                "label": "query",
                "path": f"src/app{index}.py",
                "line": index,
                "excerpt": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            }
        ],
    }


class OrgMemoryCompilerTests(unittest.TestCase):
    def test_privacy_modes_transform_sample_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            history = root / ".claude" / "scan-history"
            history.mkdir(parents=True)
            (history / "scan-001.json").write_text(json.dumps([_record(1), _record(2), _record(3)]))

            open_result = org_memory_compiler.compile_org_memory(root, "open")
            hashed_result = org_memory_compiler.compile_org_memory(root, "hashed")
            strict_result = org_memory_compiler.compile_org_memory(root, "strict")

            self.assertEqual(open_result["confirmed_findings"][0]["sample_paths"][0], "src/app1.py")
            self.assertTrue(hashed_result["confirmed_findings"][0]["sample_paths"][0].startswith("sha256:"))
            self.assertEqual(strict_result["confirmed_findings"][0]["sample_paths"], [])

    def test_strict_manifest_refuses_open_without_force(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = root / ".vuln-scout" / "org-memory"
            output.mkdir(parents=True)
            (output / "manifest.json").write_text(json.dumps({"privacy": "strict"}))

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--project-root",
                    str(root),
                    "--privacy",
                    "open",
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(proc.returncode, 2)
            self.assertIn("refusing to overwrite strict", proc.stderr)

    def test_default_write_adds_org_memory_gitignore_entry(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            history = root / ".claude" / "scan-history"
            history.mkdir(parents=True)
            (history / "scan-001.json").write_text(json.dumps([_record(1), _record(2), _record(3)]))

            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--project-root", str(root)],
                capture_output=True,
                text=True,
            )

            self.assertEqual(proc.returncode, 0)
            self.assertIn(".vuln-scout/org-memory/", (root / ".gitignore").read_text())


if __name__ == "__main__":
    unittest.main()
