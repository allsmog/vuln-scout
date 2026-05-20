#!/usr/bin/env python3
"""Compile human-reviewed scan history into VulnScout org memory."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from feedback_collector import MIN_SAMPLES_FOR_DEMOTE
except ImportError:  # pragma: no cover - direct execution from unusual cwd
    MIN_SAMPLES_FOR_DEMOTE = 10


COMPILER_VERSION = "1.0.0"
ORG_MEMORY_DIR = ".vuln-scout/org-memory"
HISTORY_GLOB = ".claude/scan-history/*.json"
RULE_STATS_PATH = ".claude/rule-stats.json"
REVIEW_LEDGER_PATH = ".claude/review-ledger.json"
VALID_PRIVACY_MODES = {"open", "hashed", "strict"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return default


def _load_history(project_root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(project_root.glob(HISTORY_GLOB)):
        data = _load_json(path, [])
        if not isinstance(data, list):
            continue
        for item in data:
            if isinstance(item, dict):
                normalized = dict(item)
                normalized.setdefault("_history_file", str(path.relative_to(project_root)))
                records.append(normalized)
    return records


def _human_reviewed(record: dict[str, Any]) -> bool:
    trust = record.get("trust_metadata") or {}
    provenance = trust.get("provenance") or {}
    if provenance.get("origin") == "human_review":
        return True
    contributors = provenance.get("contributors") or []
    return "human_review" in contributors


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _privacy_value(value: str, privacy: str) -> str:
    if privacy == "open":
        return value
    if privacy == "hashed":
        return f"sha256:{_sha(value)}"
    return ""


def _privacy_list(values: list[str], privacy: str) -> list[str]:
    if privacy == "strict":
        return []
    return [_privacy_value(value, privacy) for value in values if value]


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "rule"


def _language_from_path(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return {
        ".go": "go",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".py": "python",
        ".java": "java",
        ".rs": "rust",
        ".php": "php",
        ".cs": "csharp",
        ".rb": "ruby",
        ".sol": "solidity",
    }.get(suffix, "generic")


def _first_sentence(value: str | None, max_chars: int = 180) -> str:
    text = " ".join(str(value or "").split())
    if not text:
        return ""
    match = re.match(r"(.+?[.!?])(?:\s|$)", text)
    sentence = match.group(1) if match else text
    return sentence[:max_chars].rstrip()


def _message_template(records: list[dict[str, Any]]) -> str:
    messages = sorted({
        str(record.get("message") or record.get("title") or "").strip()
        for record in records
        if str(record.get("message") or record.get("title") or "").strip()
    })
    return messages[0] if messages else "Confirmed organization-specific vulnerability pattern."


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "":
        return '""'
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _yaml_lines(value: Any, indent: int = 0) -> list[str]:
    prefix = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key in sorted(value):
            item = value[key]
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(_yaml_lines(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {_yaml_scalar(item)}")
        return lines
    if isinstance(value, list):
        if not value:
            return [f"{prefix}[]"]
        lines = []
        for item in value:
            if isinstance(item, dict):
                lines.append(f"{prefix}-")
                lines.extend(_yaml_lines(item, indent + 2))
            elif isinstance(item, list):
                lines.append(f"{prefix}-")
                lines.extend(_yaml_lines(item, indent + 2))
            else:
                lines.append(f"{prefix}- {_yaml_scalar(item)}")
        return lines
    return [f"{prefix}{_yaml_scalar(value)}"]


def _dump_yaml(value: Any) -> str:
    return "\n".join(_yaml_lines(value)) + "\n"


def _group_by_rule(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        rule_id = str(record.get("rule_id") or "").strip()
        if rule_id:
            grouped[rule_id].append(record)
    return dict(grouped)


def _confirmed_findings(records: list[dict[str, Any]], privacy: str) -> list[dict[str, Any]]:
    confirmed: list[dict[str, Any]] = []
    for rule_id, rule_records in sorted(_group_by_rule(records).items()):
        total = len(rule_records)
        verified_records = [record for record in rule_records if record.get("verdict") == "verified"]
        verified = len(verified_records)
        if verified < 3 or verified / total < 0.5:
            continue
        sample_paths = sorted({
            str(record.get("file", "")).strip()
            for record in verified_records
            if str(record.get("file", "")).strip()
        })[:5]
        cwes = sorted({
            str(record.get("cwe", "")).strip()
            for record in verified_records
            if str(record.get("cwe", "")).strip()
        })
        confirmed.append({
            "rule_id": rule_id,
            "verified": verified,
            "total": total,
            "verified_rate": round(verified / total, 3),
            "cwe": cwes[0] if cwes else "",
            "sample_paths": _privacy_list(sample_paths, privacy),
            "message_template": _message_template(verified_records),
            "provenance": "human_review",
        })
    return confirmed


def _accepted_suppressions(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if not record.get("suppressed"):
            continue
        stable_key = str(record.get("stable_key") or "").strip()
        if stable_key:
            grouped[stable_key].append(record)

    suppressions: list[dict[str, Any]] = []
    for stable_key, items in sorted(grouped.items()):
        if len(items) < 2:
            continue
        reasons = sorted({
            str(item.get("suppression_reason") or item.get("fp_indicator") or "Human-reviewed suppression").strip()
            for item in items
        })
        reviewers = sorted({
            str(item.get("reviewer") or "human_review").strip()
            for item in items
        })
        suppressions.append({
            "stable_key": stable_key,
            "times_suppressed": len(items),
            "reason": reasons[0],
            "reviewer": reviewers[0],
            "provenance": "human_review",
        })
    return suppressions


def _semgrep_rules(confirmed: list[dict[str, Any]], records: list[dict[str, Any]], privacy: str) -> dict[str, dict[str, Any]]:
    by_rule = _group_by_rule(records)
    generated: dict[str, dict[str, Any]] = {}
    for item in confirmed:
        rule_id = item["rule_id"]
        if "semgrep" not in rule_id:
            continue
        rule_records = by_rule.get(rule_id, [])
        languages = sorted({
            _language_from_path(str(record.get("file", "")))
            for record in rule_records
            if str(record.get("file", "")).strip()
        })
        languages = [language for language in languages if language != "generic"] or ["generic"]
        excerpts = sorted({
            str(evidence.get("excerpt", "")).strip()
            for record in rule_records
            for evidence in record.get("evidence", [])
            if isinstance(evidence, dict) and str(evidence.get("excerpt", "")).strip()
        })[:3]
        pattern = "$SOURCE ... $SINK"
        if privacy == "open" and excerpts:
            pattern = excerpts[0]
        generated[f"{_slug(rule_id)}.yaml"] = {
            "schema": "vuln-scout.org.v1",
            "rules": [
                {
                    "id": f"vuln-scout.org.{_slug(rule_id)}",
                    "message": item["message_template"],
                    "severity": "ERROR",
                    "languages": languages,
                    "patterns": [{"pattern": pattern}],
                    "metadata": {
                        "source_rule_id": rule_id,
                        "cwe": item.get("cwe", ""),
                        "provenance": "human_review",
                        "privacy": privacy,
                    },
                }
            ],
        }
    return generated


def _review_patterns(records: list[dict[str, Any]], rule_stats: dict[str, Any]) -> list[dict[str, Any]]:
    patterns: list[dict[str, Any]] = []
    for rule_id, rule_records in sorted(_group_by_rule(records).items()):
        stats = rule_stats.get(rule_id, {}) if isinstance(rule_stats, dict) else {}
        total = int(stats.get("total") or len(rule_records))
        false_positive = int(stats.get("false_positive") or 0)
        if total < MIN_SAMPLES_FOR_DEMOTE:
            continue
        if false_positive / total < 0.8:
            continue
        reasons: dict[str, int] = defaultdict(int)
        for record in rule_records:
            if record.get("verdict") != "false_positive":
                continue
            analysis = record.get("claude_analysis") or {}
            reason = _first_sentence(
                record.get("fp_indicator")
                or analysis.get("reasoning")
                or record.get("message")
            )
            if reason:
                reasons[reason] += 1
        hints = [
            {"match": reason, "count": count, "action": "demote-if-matches"}
            for reason, count in sorted(reasons.items())
        ]
        if hints:
            patterns.append({
                "rule_id": rule_id,
                "total": total,
                "false_positive": false_positive,
                "fp_rate": round(false_positive / total, 3),
                "hints": hints,
            })
    return patterns


def _ledger_reviewers(project_root: Path) -> dict[str, str]:
    ledger = _load_json(project_root / REVIEW_LEDGER_PATH, {})
    reviewers: dict[str, str] = {}
    for subject in ledger.get("subjects", []) if isinstance(ledger, dict) else []:
        if not isinstance(subject, dict):
            continue
        subject_id = str(subject.get("subject_id") or "")
        if not subject_id.startswith("finding:"):
            continue
        names = [
            str(reviewer.get("name") or "").strip()
            for reviewer in subject.get("reviewers", [])
            if isinstance(reviewer, dict) and str(reviewer.get("name") or "").strip()
        ]
        if names:
            reviewers[subject_id.removeprefix("finding:")] = names[0]
    return reviewers


def compile_org_memory(project_root: Path, privacy: str) -> dict[str, Any]:
    records = _load_history(project_root)
    reviewers_by_id = _ledger_reviewers(project_root)
    for record in records:
        finding_id = str(record.get("id") or "")
        if finding_id in reviewers_by_id:
            record.setdefault("reviewer", reviewers_by_id[finding_id])
    human_records = [
        record for record in records
        if record.get("verdict") in {"verified", "false_positive"} and _human_reviewed(record)
    ]
    rule_stats = _load_json(project_root / RULE_STATS_PATH, {})
    confirmed = _confirmed_findings(human_records, privacy)
    suppressions = _accepted_suppressions(human_records)
    review_patterns = _review_patterns(human_records, rule_stats)
    semgrep_rules = _semgrep_rules(confirmed, human_records, privacy)
    return {
        "accepted_suppressions": suppressions,
        "confirmed_findings": confirmed,
        "custom_semgrep_rules": semgrep_rules,
        "review_patterns": review_patterns,
    }


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(output_dir: Path, privacy: str, files: list[Path]) -> dict[str, Any]:
    return {
        "version": COMPILER_VERSION,
        "last_updated": _utc_now(),
        "privacy": privacy,
        "hashes": {
            str(path.relative_to(output_dir)): _file_hash(path)
            for path in sorted(files)
            if path.is_file()
        },
    }


def _write_outputs(output_dir: Path, compiled: dict[str, Any], privacy: str) -> None:
    semgrep_dir = output_dir / "custom-rules" / "semgrep"
    joern_dir = output_dir / "custom-rules" / "joern"
    semgrep_dir.mkdir(parents=True, exist_ok=True)
    joern_dir.mkdir(parents=True, exist_ok=True)

    outputs = {
        output_dir / "accepted-suppressions.yaml": {"suppressions": compiled["accepted_suppressions"]},
        output_dir / "confirmed-findings.yaml": {"confirmed_findings": compiled["confirmed_findings"]},
        output_dir / "review-patterns.yaml": {"review_patterns": compiled["review_patterns"]},
    }
    written: list[Path] = []
    for path, payload in outputs.items():
        path.write_text(_dump_yaml(payload))
        written.append(path)

    for filename, payload in compiled["custom_semgrep_rules"].items():
        path = semgrep_dir / filename
        path.write_text(_dump_yaml(payload))
        written.append(path)

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest(output_dir, privacy, written), indent=2, sort_keys=True) + "\n")


def _render_dry_run(compiled: dict[str, Any]) -> str:
    return _dump_yaml({
        "accepted_suppressions": compiled["accepted_suppressions"],
        "confirmed_findings": compiled["confirmed_findings"],
        "custom_semgrep_rule_files": sorted(compiled["custom_semgrep_rules"]),
        "review_patterns": compiled["review_patterns"],
    })


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compile VulnScout org memory from human-reviewed history.")
    parser.add_argument("--project-root", default=".", help="Audited repository root (default: current directory)")
    parser.add_argument("--output", help=f"Output directory (default: {ORG_MEMORY_DIR} under project root)")
    parser.add_argument("--privacy", choices=sorted(VALID_PRIVACY_MODES), default="open")
    parser.add_argument("--dry-run", action="store_true", help="Print proposed org memory without writing files")
    parser.add_argument("--force", action="store_true", help="Allow privacy-mode downgrades when rewriting manifest")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    project_root = Path(args.project_root).resolve()
    output_dir = Path(args.output).resolve() if args.output else project_root / ORG_MEMORY_DIR
    manifest_path = output_dir / "manifest.json"
    existing_manifest = _load_json(manifest_path, {})
    existing_privacy = existing_manifest.get("privacy") if isinstance(existing_manifest, dict) else None
    if existing_privacy == "strict" and args.privacy == "open" and not args.force:
        print("error: refusing to overwrite strict org memory with open privacy without --force", file=sys.stderr)
        return 2

    compiled = compile_org_memory(project_root, args.privacy)
    if args.dry_run:
        sys.stdout.write(_render_dry_run(compiled))
        return 0

    _write_outputs(output_dir, compiled, args.privacy)
    print(f"ok: wrote org memory to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
