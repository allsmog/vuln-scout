#!/usr/bin/env python3
"""Benchmark runner for measuring VulnScout precision and recall.

Downloads known-vulnerable applications, scans them with the pipeline,
and compares findings against ground truth to compute precision, recall,
and F1 score by vulnerability type and language.

Usage:
  python3 run_benchmark.py juice-shop    # Scan one app
  python3 run_benchmark.py --all         # Scan all benchmarks
  python3 run_benchmark.py --list        # List available benchmarks
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from ground_truth import BENCHMARKS, KnownVuln

log = logging.getLogger("vuln-scout")

ORCHESTRATOR = Path(__file__).resolve().parent.parent / "scripts" / "scan_orchestrator.py"

PROFILE_QUALITY_TARGETS: dict[str, dict[str, float]] = {
    # Quick is an offline smoke profile; it should stay precise even if recall is modest.
    "quick": {"precision": 0.70, "recall": 0.30, "f1": 0.40},
    # Deep uses external analyzers and should materially improve recall.
    "deep": {"precision": 0.75, "recall": 0.50, "f1": 0.55},
    # Audit adds reviewer-oriented context and should not regress precision.
    "audit": {"precision": 0.80, "recall": 0.50, "f1": 0.60},
}


def clone_repo(repo_url: str, target_dir: str, shallow: bool = True) -> bool:
    """Clone a git repository."""
    cmd = ["git", "clone"]
    if shallow:
        cmd.extend(["--depth", "1"])
    cmd.extend([repo_url, target_dir])

    log.info("Cloning %s -> %s", repo_url, target_dir)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return result.returncode == 0


def scan_target(target_dir: str, profile: str = "quick", tools: str | None = None) -> dict[str, Any] | None:
    """Run the scan orchestrator on a target directory."""
    output_path = Path(target_dir) / ".claude" / "findings.json"
    cmd = [
        sys.executable, str(ORCHESTRATOR), target_dir,
        "--profile", profile, "--format", "json",
    ]
    if tools:
        cmd.extend(["--tools", tools])

    log.info("Scanning %s with profile=%s tools=%s", target_dir, profile, tools or "<profile default>")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    if not output_path.exists():
        log.warning("Scan produced no findings.json")
        return None

    try:
        return json.loads(output_path.read_text())
    except json.JSONDecodeError:
        log.warning("Failed to parse findings.json")
        return None


def match_finding(finding: dict[str, Any], known: KnownVuln) -> bool:
    """Check if a finding matches a known vulnerability."""
    from ground_truth import TYPE_ALIASES

    finding_type = finding.get("type", finding.get("vuln_type", ""))

    # Type must match (exact OR via alias)
    type_matches = finding_type == known.type
    if not type_matches:
        # Check if the finding type is an alias for the known type
        aliases = TYPE_ALIASES.get(known.type, set())
        type_matches = finding_type in aliases
    if not type_matches:
        # Check reverse: known type might be an alias for the finding type
        for canonical, alias_set in TYPE_ALIASES.items():
            if known.type in alias_set and finding_type == canonical:
                type_matches = True
                break
            if finding_type in alias_set and known.type == canonical:
                type_matches = True
                break
    if not type_matches:
        return False

    # File must contain the known path (partial match)
    finding_file = finding.get("file", "")
    if known.file not in finding_file:
        return False

    # Line match (if specified)
    if known.line > 0 and finding.get("line") != known.line:
        return False

    return True


def compute_metrics(
    findings: list[dict[str, Any]],
    ground_truth: list[KnownVuln],
) -> dict[str, Any]:
    """Compute precision, recall, and F1 score."""
    # True positives: findings that match a known vuln
    matched_known: set[int] = set()
    true_positives = 0
    false_positives = 0

    for finding in findings:
        if finding.get("kind", "finding") != "finding":
            continue
        matched = False
        for i, known in enumerate(ground_truth):
            if i not in matched_known and match_finding(finding, known):
                matched = True
                matched_known.add(i)
                true_positives += 1
                break
        if not matched:
            false_positives += 1

    false_negatives = len(ground_truth) - len(matched_known)

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # Per-type breakdown
    by_type: dict[str, dict[str, int]] = {}
    for known in ground_truth:
        by_type.setdefault(known.type, {"known": 0, "found": 0})
        by_type[known.type]["known"] += 1
    for i in matched_known:
        by_type.setdefault(ground_truth[i].type, {"known": 0, "found": 0})
        by_type[ground_truth[i].type]["found"] += 1

    # Missed vulns
    missed = [ground_truth[i] for i in range(len(ground_truth)) if i not in matched_known]

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "by_type": by_type,
        "missed": [{"type": m.type, "file": m.file, "description": m.description} for m in missed],
    }


def run_benchmark(
    benchmark_name: str,
    profile: str = "quick",
    tools: str | None = None,
    keep_clone: bool = False,
) -> dict[str, Any]:
    """Run a single benchmark and return metrics."""
    if benchmark_name not in BENCHMARKS:
        log.error("Unknown benchmark: %s (available: %s)", benchmark_name, ", ".join(BENCHMARKS.keys()))
        return {}

    benchmark = BENCHMARKS[benchmark_name]
    log.info("=== Benchmark: %s (%s) ===", benchmark["name"], benchmark["language"])

    with tempfile.TemporaryDirectory() as tmpdir:
        clone_dir = str(Path(tmpdir) / benchmark_name)

        if not clone_repo(benchmark["repo"], clone_dir):
            log.error("Failed to clone %s", benchmark["repo"])
            return {}

        artifact = scan_target(clone_dir, profile=profile, tools=tools)
        if not artifact:
            log.error("Scan failed for %s", benchmark_name)
            return {}

        findings = artifact.get("findings", [])
        metrics = compute_metrics(findings, benchmark["vulns"])

        log.info("Results for %s:", benchmark["name"])
        log.info("  Precision: %.1f%%", metrics["precision"] * 100)
        log.info("  Recall:    %.1f%%", metrics["recall"] * 100)
        log.info("  F1:        %.1f%%", metrics["f1"] * 100)
        log.info("  TP=%d FP=%d FN=%d", metrics["true_positives"], metrics["false_positives"], metrics["false_negatives"])

        if metrics["missed"]:
            log.info("  Missed vulns:")
            for m in metrics["missed"]:
                log.info("    - %s in %s: %s", m["type"], m["file"], m["description"])

        return {
            "benchmark": benchmark_name,
            "name": benchmark["name"],
            "language": benchmark["language"],
            "profile": profile,
            "total_findings": len(findings),
            "total_known_vulns": len(benchmark["vulns"]),
            **metrics,
        }


def quality_gate_failures(
    results: list[dict[str, Any]],
    profile: str,
    *,
    min_precision: float | None = None,
    min_recall: float | None = None,
    min_f1: float | None = None,
) -> list[str]:
    """Return quality-gate failure messages for benchmark results."""
    if not results:
        return ["no benchmark results were produced"]

    targets = dict(PROFILE_QUALITY_TARGETS[profile])
    if min_precision is not None:
        targets["precision"] = min_precision
    if min_recall is not None:
        targets["recall"] = min_recall
    if min_f1 is not None:
        targets["f1"] = min_f1

    averages = {
        "precision": sum(r["precision"] for r in results) / len(results),
        "recall": sum(r["recall"] for r in results) / len(results),
        "f1": sum(r["f1"] for r in results) / len(results),
    }

    failures: list[str] = []
    for metric, threshold in targets.items():
        if averages[metric] < threshold:
            failures.append(
                f"average {metric} {averages[metric]:.3f} below {profile} target {threshold:.3f}"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScout benchmark runner")
    parser.add_argument("benchmark", nargs="?", help="Benchmark name (juice-shop, dvwa, webgoat)")
    parser.add_argument("--all", action="store_true", help="Run all benchmarks")
    parser.add_argument("--list", action="store_true", help="List available benchmarks")
    parser.add_argument("--profile", choices=sorted(PROFILE_QUALITY_TARGETS), default="quick", help="Scan profile to benchmark")
    parser.add_argument("--tools", help="Override scanning tools instead of using the profile default")
    parser.add_argument("--output", help="Save results to JSON file")
    parser.add_argument("--quality-gate", action="store_true", help="Fail if average precision/recall/F1 miss the profile targets")
    parser.add_argument("--min-precision", type=float, help="Override the profile precision target")
    parser.add_argument("--min-recall", type=float, help="Override the profile recall target")
    parser.add_argument("--min-f1", type=float, help="Override the profile F1 target")
    parser.add_argument("--fail-below-f1", type=float, help="Deprecated alias for --min-f1 with --quality-gate")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)

    if args.list:
        for name, info in BENCHMARKS.items():
            print(f"  {name:15s} {info['name']:25s} ({info['language']}, {len(info['vulns'])} known vulns)")
        return 0

    results: list[dict[str, Any]] = []

    if args.all:
        for name in BENCHMARKS:
            result = run_benchmark(name, profile=args.profile, tools=args.tools)
            if result:
                results.append(result)
    elif args.benchmark:
        result = run_benchmark(args.benchmark, profile=args.profile, tools=args.tools)
        if result:
            results.append(result)
    else:
        parser.print_help()
        return 1

    min_f1 = args.min_f1 if args.min_f1 is not None else args.fail_below_f1
    enforce_gate = args.quality_gate or any(
        value is not None for value in (args.min_precision, args.min_recall, min_f1)
    )

    # Summary
    if results:
        print("\n=== BENCHMARK SUMMARY ===")
        for r in results:
            print(f"  {r['name']:25s}  P={r['precision']:.1%}  R={r['recall']:.1%}  F1={r['f1']:.1%}  (TP={r['true_positives']} FP={r['false_positives']} FN={r['false_negatives']})")

        if args.output:
            Path(args.output).write_text(json.dumps(results, indent=2))
            print(f"\nResults saved to {args.output}")

        if enforce_gate:
            failures = quality_gate_failures(
                results,
                args.profile,
                min_precision=args.min_precision,
                min_recall=args.min_recall,
                min_f1=min_f1,
            )
            for failure in failures:
                log.error("Quality gate failed: %s", failure)
            if failures:
                return 1
    elif enforce_gate:
        log.error("Quality gate failed: no benchmark results were produced")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
