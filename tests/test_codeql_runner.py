from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "whitebox-pentest" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


codeql_runner = load_module(
    "codeql_runner_contract",
    SCRIPTS_DIR / "tool_runners" / "codeql_runner.py",
)


class CodeQlRunnerTests(unittest.TestCase):
    def test_language_map_includes_rust_but_not_php_or_solidity(self) -> None:
        self.assertEqual(codeql_runner.CODEQL_LANG_MAP["rust"], "rust")
        self.assertNotIn("php", codeql_runner.CODEQL_LANG_MAP)
        self.assertNotIn("solidity", codeql_runner.CODEQL_LANG_MAP)

    def test_sarif_security_severity_and_codeflows_are_normalized(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "py/sql-injection",
                                    "properties": {
                                        "security-severity": "9.1",
                                        "tags": ["external/cwe/cwe-89", "security"],
                                    },
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "py/sql-injection",
                            "level": "warning",
                            "message": {"text": "SQL injection"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 12, "snippet": {"text": "db.execute(q)"}},
                                    }
                                }
                            ],
                            "codeFlows": [
                                {
                                    "threadFlows": [
                                        {
                                            "locations": [
                                                {
                                                    "location": {
                                                        "message": {"text": "source"},
                                                        "physicalLocation": {
                                                            "artifactLocation": {"uri": "app.py"},
                                                            "region": {"startLine": 4, "snippet": {"text": "request.args"}},
                                                        },
                                                    }
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_path = Path(tmpdir) / "results.sarif"
            sarif_path.write_text(json.dumps(sarif))
            findings = codeql_runner._parse_sarif(sarif_path, "python")

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["type"], "sql-injection")
        self.assertEqual(finding["kind"], "finding")
        self.assertEqual(finding["evidence"][0]["type"], "dataflow")

    def test_source_hash_changes_with_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            app = root / "app.rs"
            app.write_text("fn main() {}\n")
            first = codeql_runner._compute_source_hash(root, "rust", ["app.rs"])
            app.write_text("fn main() { println!(\"hi\"); }\n")
            second = codeql_runner._compute_source_hash(root, "rust", ["app.rs"])

        self.assertNotEqual(first, second)

    def test_source_view_excludes_analyzer_cache_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text("print('real')\n")
            joern_copy = root / ".joern" / "_source_views" / "old-python"
            joern_copy.mkdir(parents=True)
            (joern_copy / "app.py").write_text("print('joern copy')\n")
            codeql_copy = root / ".codeql" / "_source_views" / "old-python"
            codeql_copy.mkdir(parents=True)
            (codeql_copy / "app.py").write_text("print('codeql copy')\n")
            files = [
                "app.py",
                ".joern/_source_views/old-python/app.py",
                ".codeql/_source_views/old-python/app.py",
            ]

            source_hash = codeql_runner._compute_source_hash(root, "python", files)
            source_view = codeql_runner._prepare_source_view(
                root,
                root / ".codeql",
                "python",
                source_hash,
                files,
            )

            copied = sorted(path.relative_to(source_view).as_posix() for path in source_view.rglob("*.py"))
            self.assertEqual(copied, ["app.py"])


if __name__ == "__main__":
    unittest.main()
