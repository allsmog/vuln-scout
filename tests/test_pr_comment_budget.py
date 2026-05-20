import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vuln-scout" / "scripts"))

import pr_comment


class PrCommentBudgetTests(unittest.TestCase):
    def test_thousand_finding_comment_keeps_legend_under_budget(self):
        artifact = json.loads((ROOT / "tests" / "fixtures" / "artifacts" / "sample-findings-v1_2_0.json").read_text())
        base = next(finding for finding in artifact["findings"] if finding.get("kind") == "finding")
        findings = []
        for index in range(1000):
            finding = copy.deepcopy(base)
            finding["id"] = f"VSCOUT-BUDGET-{index:04d}"
            finding["stable_key"] = f"fixture:budget:{index}"
            finding["title"] = f"Synthetic budget finding {index}"
            finding["line"] = index + 1
            finding["in_diff"] = index < 25
            findings.append(finding)
        artifact["findings"] = findings
        artifact["summary"] = {
            "total_findings": 1000,
            "total_hotspots": 0,
            "critical": 1000,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        body = pr_comment.generate(artifact)

        self.assertLessEqual(len(body.encode("utf-8")), pr_comment.MAX_COMMENT_BYTES)
        self.assertIn("**Trust legend:**", body)


if __name__ == "__main__":
    unittest.main()
