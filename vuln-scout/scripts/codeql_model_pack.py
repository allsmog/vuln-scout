#!/usr/bin/env python3
"""Generate opt-in CodeQL model packs from verified VulnScout findings."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from artifact_utils import load_artifact, stable_key_for


EXTENSION_TO_CODEQL_LANGUAGE = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".py": "python",
    ".java": "java",
    ".kt": "java",
    ".kts": "java",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp",
}

PACK_BY_LANGUAGE = {
    "javascript": "codeql/javascript-all",
    "python": "codeql/python-all",
    "java": "codeql/java-all",
    "go": "codeql/go-all",
    "ruby": "codeql/ruby-all",
    "csharp": "codeql/csharp-all",
}

THREE_COLUMN_LANGUAGES = {"javascript", "python", "ruby"}

SINK_KIND_BY_TYPE = {
    "sql-injection": "sql-injection",
    "command-injection": "command-injection",
    "code-injection": "code-injection",
    "path-traversal": "path-injection",
    "ssrf": "request-forgery",
    "xss": "html-injection",
    "open-redirect": "url-redirection",
    "log-injection": "log-injection",
    "ldap-injection": "ldap-injection",
    "deserialization": "unsafe-deserialization",
}

CALL_RE = re.compile(r"""([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(""")


def _language_for_finding(finding: dict[str, Any]) -> str | None:
    explicit = str(finding.get("language", "")).lower()
    if explicit in PACK_BY_LANGUAGE:
        return explicit
    suffix = Path(str(finding.get("file", ""))).suffix.lower()
    return EXTENSION_TO_CODEQL_LANGUAGE.get(suffix)


def _is_eligible(finding: dict[str, Any]) -> bool:
    if finding.get("kind") != "finding" or finding.get("suppressed"):
        return False
    verdict = finding.get("verdict")
    if verdict in {"false_positive", "unverified"}:
        return False
    verification_level = finding.get("verification_level", 0)
    try:
        level = int(verification_level)
    except (TypeError, ValueError):
        level = 0
    return verdict == "verified" or level >= 1


def _sink_kind(finding: dict[str, Any]) -> str:
    return SINK_KIND_BY_TYPE.get(str(finding.get("type", "")), str(finding.get("type", "custom-sink")))


def _sink_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    for evidence in finding.get("evidence", []):
        if evidence.get("role") == "sink":
            return evidence
    for evidence in finding.get("evidence", []):
        if evidence.get("type") in {"sink", "dataflow"}:
            return evidence
    return {}


def _extract_call_chain(excerpt: str) -> list[str]:
    matches = list(CALL_RE.finditer(excerpt))
    if not matches:
        return []
    raw = matches[-1].group(1)
    return [part.strip() for part in raw.split(".") if part.strip()]


def _three_column_row(chain: list[str], sink_kind: str) -> list[str]:
    if not chain:
        return []
    path = ".".join(f"Member[{part}]" for part in chain)
    return ["global", f"{path}.Argument[0]", sink_kind]


def _callable_row(chain: list[str], sink_kind: str) -> list[Any]:
    if not chain:
        return []
    method = chain[-1]
    type_name = chain[-2] if len(chain) > 1 else ""
    return ["", type_name, True, method, "", "", "Argument[0]", sink_kind, "manual"]


def _model_row(finding: dict[str, Any], language: str) -> list[Any]:
    evidence = _sink_evidence(finding)
    excerpt = str(evidence.get("excerpt") or finding.get("message") or finding.get("title") or "")
    chain = _extract_call_chain(excerpt)
    if language in THREE_COLUMN_LANGUAGES:
        return _three_column_row(chain, _sink_kind(finding))
    return _callable_row(chain, _sink_kind(finding))


def _yaml_row(row: list[Any]) -> str:
    return json.dumps(row)


def _model_yaml(language: str, rows: list[list[Any]]) -> str:
    pack = PACK_BY_LANGUAGE[language]
    data = "\n".join(f"      - {_yaml_row(row)}" for row in rows)
    return (
        "extensions:\n"
        "  - addsTo:\n"
        f"      pack: {pack}\n"
        "      extensible: sinkModel\n"
        "    data:\n"
        f"{data}\n"
    )


def _qlpack(language: str) -> str:
    pack = PACK_BY_LANGUAGE[language]
    return (
        f"name: vuln-scout/generated-{language}-models\n"
        "version: 0.0.1\n"
        "library: true\n"
        "extensionTargets:\n"
        f"  {pack}: \"*\"\n"
        "dataExtensions:\n"
        "  - models/**/*.yml\n"
    )


def _readme(language: str, findings: list[dict[str, Any]], skipped_models: int) -> str:
    lines = [
        f"# VulnScout Generated CodeQL Models: {language}",
        "",
        "This model pack is generated from verified VulnScout findings.",
        "It is opt-in and should be reviewed before being used as a persistent CodeQL model pack.",
        "",
        "## Source Findings",
        "",
    ]
    for finding in findings:
        lines.append(
            f"- `{finding.get('id', '')}` `{stable_key_for(finding)}` "
            f"{finding.get('type', '')} at {finding.get('file', '')}:{finding.get('line', 0)}"
        )
    if skipped_models:
        lines.extend([
            "",
            f"Skipped {skipped_models} eligible findings because no callable sink could be inferred.",
        ])
    lines.append("")
    return "\n".join(lines)


def generate_model_packs(
    artifact: dict[str, Any],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Generate model packs and return a summary dictionary."""
    output_path = Path(output_dir)
    if output_path.exists() and not output_path.is_dir():
        raise ValueError(f"model pack output must be a directory: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)

    by_language: dict[str, list[tuple[dict[str, Any], list[Any]]]] = {}
    skipped: dict[str, int] = {"ineligible": 0, "unsupported_language": 0, "unmodelable": 0}
    unsupported_languages: set[str] = set()

    for finding in artifact.get("findings", []):
        if not _is_eligible(finding):
            skipped["ineligible"] += 1
            continue
        language = _language_for_finding(finding)
        if not language:
            skipped["unsupported_language"] += 1
            unsupported_languages.add(Path(str(finding.get("file", ""))).suffix.lower() or "unknown")
            continue
        row = _model_row(finding, language)
        if not row:
            skipped["unmodelable"] += 1
            continue
        by_language.setdefault(language, []).append((finding, row))

    packs: list[dict[str, Any]] = []
    for language, entries in sorted(by_language.items()):
        pack_dir = output_path / f"vuln-scout-{language}-models"
        models_dir = pack_dir / "models"
        models_dir.mkdir(parents=True, exist_ok=True)

        rows: list[list[Any]] = []
        seen_rows: set[str] = set()
        source_findings: list[dict[str, Any]] = []
        for finding, row in entries:
            key = json.dumps(row, sort_keys=True)
            if key in seen_rows:
                continue
            seen_rows.add(key)
            rows.append(row)
            source_findings.append(finding)

        (pack_dir / "qlpack.yml").write_text(_qlpack(language))
        (models_dir / "vuln-scout-sinks.yml").write_text(_model_yaml(language, rows))
        (pack_dir / "README.md").write_text(_readme(language, source_findings, skipped["unmodelable"]))

        packs.append({
            "language": language,
            "path": str(pack_dir),
            "models": len(rows),
            "source_findings": [finding.get("id", "") for finding in source_findings],
        })

    summary = {
        "packs": packs,
        "skipped": skipped,
        "unsupported_languages": sorted(unsupported_languages),
    }
    (output_path / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate CodeQL model packs from verified VulnScout findings.")
    parser.add_argument("--findings", default=".claude/findings.json", help="Path to VulnScout findings.json")
    parser.add_argument("--output", default=".claude/codeql-model-packs", help="Output directory for generated model packs")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    try:
        summary = generate_model_packs(load_artifact(args.findings), args.output)
    except ValueError as exc:
        print(f"error: {exc}")
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
