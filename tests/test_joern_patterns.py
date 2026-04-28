"""Structural tests for Joern verification scripts (no Joern runtime needed)."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JOERN_DIR = ROOT / "whitebox-pentest" / "scripts" / "joern"
SCRIPTS_DIR = ROOT / "whitebox-pentest" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import batch_verify  # noqa: E402
import create_cpg  # noqa: E402


class JoernPatternTests(unittest.TestCase):
    def _verify_scripts(self) -> list[Path]:
        return sorted(JOERN_DIR.glob("verify-*.sc"))

    def test_all_verify_scripts_import_common(self) -> None:
        for script in self._verify_scripts():
            text = script.read_text()
            self.assertIn(
                "import $file.common",
                text,
                f"{script.name} must import common utilities",
            )

    def test_all_verify_scripts_call_detectLanguage(self) -> None:
        for script in self._verify_scripts():
            text = script.read_text()
            self.assertIn(
                "detectLanguage(file)",
                text,
                f"{script.name} must detect the target file language",
            )

    def test_all_verify_scripts_call_unsupportedResult(self) -> None:
        for script in self._verify_scripts():
            text = script.read_text()
            self.assertIn(
                "unsupportedResult",
                text,
                f"{script.name} must return NA_CPG for unsupported languages",
            )

    def test_common_sources_have_supported_languages(self) -> None:
        """Sources object should have entries for all languages in the Languages object."""
        text = (JOERN_DIR / "common.sc").read_text()
        # Find language val declarations
        lang_vals = re.findall(r'val (\w+) = "(\w+)"', text)
        langs = {name for name, _ in lang_vals if name not in {"unsupported", "solidity"}}

        # Check parameterPatterns has entries for each language
        for lang in langs:
            self.assertIn(
                f"Languages.{lang} ->",
                text,
                f"Sources.parameterPatterns missing entry for {lang}",
            )

    def test_solidity_is_not_a_joern_cpg_language(self) -> None:
        self.assertNotIn("solidity", create_cpg.JOERN_SUPPORTED_LANGUAGES)
        self.assertNotIn("reentrancy", batch_verify.VERIFY_SCRIPT_MAP)
        self.assertNotIn("integer-overflow", batch_verify.VERIFY_SCRIPT_MAP)
        common = (JOERN_DIR / "common.sc").read_text()
        self.assertIn("case \"reentrancy\" =>\n    Set.empty[String]", common)

    def test_language_aware_sink_helpers_are_used(self) -> None:
        common = (JOERN_DIR / "common.sc").read_text()
        for phrase in (
            "callsMatching",
            "callMatches",
            "sqlCalls",
            "sqlSinksFor",
            "ssrfSinksFor",
            "requests\\\\.(get|post|put|delete|request)",
            "httpx\\\\.(get|post|put|delete|request)",
            "http\\\\.(Get|Post|Head|NewRequest|NewRequestWithContext)",
            "goSqlSinks",
            "phpSqlSinks",
            "csharpSqlSinks",
        ):
            self.assertIn(phrase, common)

        self.assertNotIn(
            "|^(get|post|put|delete|request|urlopen)$",
            common,
            "Python SSRF sinks must not match every call named get/request",
        )
        self.assertNotIn(
            "|^(Get|Post|Head|Do|NewRequest|NewRequestWithContext)$",
            common,
            "Go SSRF sinks must not match every call named Get",
        )
        self.assertIn(
            'val sqlSinks = "^(query|execute|raw|rawQuery|knex|sequelize|PreparedStatement|createStatement)$"',
            common,
            "Generic SQL sink names must stay anchored so source text like request.args.get('query') is not a sink",
        )

        expected = {
            "discover-sqli.sc": "sqlCalls(language)",
            "discover-ssrf.sc": "callsMatching(Sinks.ssrfSinksFor(language))",
            "verify-sqli.sc": "sqlCalls(language)",
            "verify-ssrf.sc": "callsMatching(Sinks.ssrfSinksFor(language))",
            "verify-randomness.sc": "callsMatching(Sinks.randomnessSinks)",
        }
        for script_name, phrase in expected.items():
            self.assertIn(phrase, (JOERN_DIR / script_name).read_text())

    def test_batch_script_only_includes_needed_verifiers(self) -> None:
        script = batch_verify._generate_mega_script({"verify-ssrf.sc", "verify-generic.sc"})

        self.assertIn("// --- verify-ssrf.sc ---", script)
        self.assertIn('case "ssrf" => verifySsrf(file, line)', script)
        self.assertIn("case _ => verifyGeneric(file, line)", script)
        self.assertNotIn("// --- verify-deser.sc ---", script)
        self.assertNotIn('case "deserialization" => verifyDeser(file, line)', script)

    def test_sanitizer_patterns_are_anchored(self) -> None:
        """All Sanitizer patterns should be anchored with ^(...)$ to prevent partial matches."""
        text = (JOERN_DIR / "common.sc").read_text()
        # Extract lines in the Sanitizers object
        in_sanitizers = False
        for line in text.split("\n"):
            if "object Sanitizers" in line:
                in_sanitizers = True
                continue
            if in_sanitizers and line.strip().startswith("}"):
                break
            if in_sanitizers and "val " in line and '= "' in line:
                # Extract the pattern value
                match = re.search(r'= "(.*)"', line)
                if match:
                    pattern = match.group(1)
                    # Skip comment-only lines
                    if pattern.startswith("^(") and pattern.endswith(")$"):
                        continue
                    self.fail(
                        f"Sanitizer pattern not anchored: {line.strip()} "
                        f"(should use ^(...)$ to prevent partial matches)"
                    )


if __name__ == "__main__":
    unittest.main()
