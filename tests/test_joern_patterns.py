"""Structural tests for Joern verification scripts (no Joern runtime needed)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JOERN_DIR = ROOT / "whitebox-pentest" / "scripts" / "joern"


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
        langs = {name for name, _ in lang_vals if name != "unsupported"}

        # Check parameterPatterns has entries for each language
        for lang in langs:
            self.assertIn(
                f"Languages.{lang} ->",
                text,
                f"Sources.parameterPatterns missing entry for {lang}",
            )

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
