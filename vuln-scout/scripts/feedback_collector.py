#!/usr/bin/env python3
"""Feedback loop and rule effectiveness tracking.

Records verified/false_positive verdicts across scans and uses historical
data to auto-suppress repeat false positives and calibrate per-rule
confidence levels.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")

HISTORY_DIR = ".claude/scan-history"
RULE_STATS_FILE = ".claude/rule-stats.json"
ORG_MEMORY_DIR = ".vuln-scout/org-memory"
ORG_ACCEPTED_SUPPRESSIONS_FILE = f"{ORG_MEMORY_DIR}/accepted-suppressions.yaml"
ORG_CONFIRMED_FINDINGS_FILE = f"{ORG_MEMORY_DIR}/confirmed-findings.yaml"

# Auto-suppress threshold: if a rule's FP rate exceeds this across N+ samples
FP_RATE_DEMOTE_THRESHOLD = 0.80
MIN_SAMPLES_FOR_DEMOTE = 10


class FeedbackCollector:
    """Collects and applies verdict feedback across scans."""

    def __init__(self, project_root: str):
        self._root = Path(project_root).resolve()
        self._history_dir = self._root / HISTORY_DIR
        self._rule_stats_path = self._root / RULE_STATS_FILE
        self._rule_stats: dict[str, dict[str, int]] = {}
        self._load_rule_stats()

    def _load_rule_stats(self) -> None:
        if self._rule_stats_path.is_file():
            try:
                self._rule_stats = json.loads(self._rule_stats_path.read_text())
            except (json.JSONDecodeError, OSError):
                self._rule_stats = {}

    def save_rule_stats(self) -> None:
        self._rule_stats_path.parent.mkdir(parents=True, exist_ok=True)
        self._rule_stats_path.write_text(json.dumps(self._rule_stats, indent=2))

    def record_scan(self, findings: list[dict[str, Any]], scan_id: str) -> None:
        """Record findings and their verdicts from a completed scan."""
        self._history_dir.mkdir(parents=True, exist_ok=True)

        # Save scan history
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        history_file = self._history_dir / f"scan-{timestamp}-{scan_id[:8]}.json"
        records = []
        for f in findings:
            records.append({
                "stable_key": f.get("stable_key", ""),
                "rule_id": f.get("rule_id", ""),
                "type": f.get("type", ""),
                "verdict": f.get("verdict", ""),
                "confidence": f.get("confidence", ""),
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "id": f.get("id", ""),
                "kind": f.get("kind", ""),
                "severity": f.get("severity", ""),
                "title": f.get("title", ""),
                "message": f.get("message", ""),
                "cwe": f.get("cwe", ""),
                "suppressed": bool(f.get("suppressed")),
                "suppression_reason": f.get("suppression_reason", ""),
                "fp_indicator": f.get("fp_indicator", ""),
                "trust_metadata": f.get("trust_metadata", {}),
                "claude_analysis": f.get("claude_analysis", {}),
                "evidence": f.get("evidence", []),
            })
        history_file.write_text(json.dumps(records, indent=2))

        # Update rule stats
        for f in findings:
            rule_id = f.get("rule_id", "")
            if not rule_id:
                continue
            verdict = f.get("verdict", "")
            stats = self._rule_stats.setdefault(rule_id, {
                "total": 0, "verified": 0, "false_positive": 0,
                "needs_review": 0, "unverified": 0,
            })
            stats["total"] += 1
            if verdict in stats:
                stats[verdict] += 1

        self.save_rule_stats()
        log.info("Recorded %d findings to scan history", len(records))

    def get_auto_suppressions(self) -> dict[str, str]:
        """Find stable_keys that were marked false_positive in 2+ previous scans."""
        fp_counts: dict[str, int] = {}

        if self._history_dir.is_dir():
            for history_file in sorted(self._history_dir.glob("scan-*.json")):
                try:
                    records = json.loads(history_file.read_text())
                except (json.JSONDecodeError, OSError):
                    continue
                for r in records:
                    if r.get("verdict") == "false_positive":
                        key = r.get("stable_key", "")
                        if key:
                            fp_counts[key] = fp_counts.get(key, 0) + 1

        # Auto-suppress keys with 2+ FP verdicts
        suppressions: dict[str, str] = {}
        for key, count in fp_counts.items():
            if count >= 2:
                suppressions[key] = f"Auto-suppressed: false positive in {count} previous scans"

        suppressions.update(self._load_org_memory_suppressions())

        if suppressions:
            log.info("Auto-suppression: %d findings from scan history", len(suppressions))
        return suppressions

    def get_regressions(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Find findings that were previously verified and have reappeared."""
        previously_verified: set[str] = set()

        if not self._history_dir.is_dir():
            return []

        for history_file in self._history_dir.glob("scan-*.json"):
            try:
                records = json.loads(history_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            for r in records:
                if r.get("verdict") == "verified":
                    previously_verified.add(r.get("stable_key", ""))

        regressions = []
        for f in findings:
            key = f.get("stable_key", "")
            if key in previously_verified and f.get("verdict") == "unverified":
                regressions.append(f)

        if regressions:
            log.info("Regression detection: %d previously-verified findings reappeared", len(regressions))
        return regressions

    def get_noisy_rules(self) -> list[dict[str, Any]]:
        """Identify rules with high false positive rates."""
        noisy: list[dict[str, Any]] = []
        for rule_id, stats in self._rule_stats.items():
            total = stats.get("total", 0)
            fp = stats.get("false_positive", 0)
            if total >= MIN_SAMPLES_FOR_DEMOTE:
                fp_rate = fp / total
                if fp_rate >= FP_RATE_DEMOTE_THRESHOLD:
                    noisy.append({
                        "rule_id": rule_id,
                        "total": total,
                        "false_positive": fp,
                        "verified": stats.get("verified", 0),
                        "fp_rate": round(fp_rate, 3),
                        "recommendation": "demote to hotspot",
                    })
        return noisy

    def apply_rule_calibration(self, findings: list[dict[str, Any]]) -> int:
        """Demote findings from noisy rules to hotspot."""
        noisy_rules = {r["rule_id"] for r in self.get_noisy_rules()}
        demoted = 0
        for f in findings:
            rule_id = f.get("rule_id", "")
            if rule_id in noisy_rules and f.get("kind") == "finding":
                f["kind"] = "hotspot"
                f["confidence"] = "low"
                f["fp_indicator"] = f"rule {rule_id} has >{FP_RATE_DEMOTE_THRESHOLD*100:.0f}% FP rate"
                demoted += 1
        if demoted:
            log.info("Rule calibration: demoted %d findings from noisy rules", demoted)
        return demoted

    def _load_org_memory_suppressions(self) -> dict[str, str]:
        path = self._root / ORG_ACCEPTED_SUPPRESSIONS_FILE
        records = _parse_yaml_records(path, "suppressions")
        suppressions: dict[str, str] = {}
        for record in records:
            stable_key = record.get("stable_key", "")
            if not stable_key:
                continue
            suppressions[stable_key] = record.get("reason", "Org memory accepted suppression")
        return suppressions

    def _load_org_memory_confirmed_rules(self) -> set[str]:
        path = self._root / ORG_CONFIRMED_FINDINGS_FILE
        return {
            record.get("rule_id", "")
            for record in _parse_yaml_records(path, "confirmed_findings")
            if record.get("rule_id")
        }

    def apply_org_memory_rules(self, findings: list[dict[str, Any]]) -> int:
        """Apply confirmed human-reviewed org memory patterns to current findings."""
        confirmed_rules = self._load_org_memory_confirmed_rules()
        if not confirmed_rules:
            return 0

        applied = 0
        for finding in findings:
            if finding.get("rule_id") not in confirmed_rules:
                continue
            trust = finding.setdefault("trust_metadata", {})
            provenance = trust.setdefault("provenance", {})
            provenance["origin"] = "human_review"
            contributors = provenance.setdefault("contributors", [])
            if isinstance(contributors, list) and "human_review" not in contributors:
                contributors.append("human_review")
            trust["confidence_reason"] = "Matched human-reviewed org memory confirmed pattern."
            finding["confidence"] = "high"
            applied += 1

        if applied:
            log.info("Org memory: applied %d confirmed human-reviewed patterns", applied)
        return applied


def _parse_yaml_records(path: Path, top_key: str) -> list[dict[str, str]]:
    """Parse the narrow YAML list-of-objects shape written by org_memory_compiler.py."""
    if not path.is_file():
        return []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []

    records: list[dict[str, str]] = []
    in_section = False
    current: dict[str, str] | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" ") and stripped.endswith(":"):
            if current:
                records.append(current)
                current = None
            in_section = stripped[:-1] == top_key
            continue
        if not in_section:
            continue
        if stripped == "[]":
            continue
        if stripped == "-":
            if current:
                records.append(current)
            current = {}
            continue
        if current is None or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        current[key.strip()] = _unquote_yaml_scalar(value.strip())

    if current:
        records.append(current)
    return records


def _unquote_yaml_scalar(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value
