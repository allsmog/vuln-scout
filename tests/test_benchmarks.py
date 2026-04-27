from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS_DIR = ROOT / "whitebox-pentest" / "benchmarks"

sys.path.insert(0, str(BENCHMARKS_DIR))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


run_benchmark = load_module("run_benchmark_tests", BENCHMARKS_DIR / "run_benchmark.py")


class BenchmarkQualityGateTests(unittest.TestCase):
    def test_quality_gate_uses_profile_targets(self):
        results = [{"precision": 0.72, "recall": 0.31, "f1": 0.41}]

        failures = run_benchmark.quality_gate_failures(results, "quick")

        self.assertEqual(failures, [])

    def test_quality_gate_reports_precision_recall_and_f1_failures(self):
        results = [{"precision": 0.50, "recall": 0.20, "f1": 0.25}]

        failures = run_benchmark.quality_gate_failures(results, "deep")

        self.assertTrue(any("precision" in failure for failure in failures))
        self.assertTrue(any("recall" in failure for failure in failures))
        self.assertTrue(any("f1" in failure for failure in failures))

    def test_quality_gate_allows_explicit_overrides(self):
        results = [{"precision": 0.50, "recall": 0.20, "f1": 0.25}]

        failures = run_benchmark.quality_gate_failures(
            results,
            "deep",
            min_precision=0.40,
            min_recall=0.10,
            min_f1=0.20,
        )

        self.assertEqual(failures, [])

    def test_quality_gate_fails_without_results(self):
        failures = run_benchmark.quality_gate_failures([], "quick")

        self.assertEqual(failures, ["no benchmark results were produced"])


if __name__ == "__main__":
    unittest.main()
