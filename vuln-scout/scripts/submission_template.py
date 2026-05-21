#!/usr/bin/env python3
"""Bug-bounty submission template generator for VulnScout findings.

Given a findings.json artifact (typically the one written by `mobile_scan.py`
or `scan_orchestrator.py`), this script emits one markdown submission per
attack chain, plus a fallback "individual finding" template for any
high/critical finding that isn't part of a chain. Each submission follows the
generic bug-bounty platform shape:

    # Title
    ## Summary
    ## Impact
    ## Reproduction
    ## Affected Components
    ## Remediation

Submissions are written to ``<output-dir>/submission-<pattern>-<stable_key>.md``
(chains, when both `pattern` and `stable_key` are available) or
``<output-dir>/submission-<chain-id>.md`` (chains without a pattern slug),
and ``<output-dir>/submission-finding-<id>.md`` (individual high-severity
findings). The script does not invent CVSS scores or claim test results — it
draws strictly from the artifact's evidence and the chain's stated impact, so
the analyst can verify and edit before submitting.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any


log = logging.getLogger("vuln-scout-submission")


def _severity_to_cvss_rating(sev: str) -> str:
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
    }.get(sev, "Unknown")


def _findings_by_id(art: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f.get("id", ""): f for f in art.get("findings", []) if f.get("id")}


def _excerpt(finding: dict[str, Any]) -> str:
    ev = finding.get("evidence") or []
    if not ev:
        return ""
    first = ev[0]
    # ev[0] could be None in a hand-edited artifact — guard the .get().
    if not isinstance(first, dict):
        return ""
    return str(first.get("excerpt", "")).strip()


def _max_severity(findings: list[dict[str, Any]]) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    seen = {f.get("severity", "info") for f in findings}
    for s in order:
        if s in seen:
            return s
    return "info"


def _format_chain_submission(chain: dict[str, Any], findings_by_id: dict[str, dict[str, Any]]) -> str:
    chain_id = chain.get("id", "")
    stable_key = chain.get("stable_key", "")
    name = chain.get("name", "")
    impact = chain.get("impact", "")
    flow = chain.get("flow_description", "")
    participants = [findings_by_id[fid] for fid in chain.get("finding_ids", []) if fid in findings_by_id]
    # Prefer the chain's own severity (set by the chain detector during
    # ranking) over a recomputed max — the chain detector has the latest
    # rules for which participant severity dominates.
    sev = chain.get("severity") or (_max_severity(participants) if participants else "medium")

    lines: list[str] = []
    lines.append(f"# {name}")
    lines.append("")
    lines.append(f"**Severity (estimated)**: {_severity_to_cvss_rating(sev)}  ")
    chain_conf = chain.get("confidence")
    if chain_conf:
        lines.append(f"**Chain confidence**: {chain_conf}  ")
    lines.append(f"**Chain ID**: `{chain_id}`  ")
    if stable_key:
        lines.append(f"**Stable key**: `{stable_key}`  ")
    pattern = chain.get("pattern")
    if pattern:
        lines.append(f"**Chain pattern**: `{pattern}`  ")
    cwes = chain.get("cwes") or []
    if cwes:
        # Hyperlinks survive most bug-bounty platform renderers.
        cwe_links = [
            f"[{c}](https://cwe.mitre.org/data/definitions/{c.split('-')[-1]}.html)"
            for c in cwes
        ]
        lines.append(f"**CWE**: {', '.join(cwe_links)}  ")
    lines.append(f"**Affected components**: {len(participants)} findings")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(impact or "An exploitable primitive was identified across multiple components.")
    lines.append("")
    lines.append("## Attack flow")
    lines.append("")
    lines.append(flow or "See the affected components and evidence below.")
    lines.append("")
    if participants:
        lines.append("## Affected components")
        lines.append("")
        for p in participants:
            role = p.get("chain_role", "participant")
            file_loc = f"{p.get('file', '?')}:{p.get('line', '?')}"
            meta = p.get("metadata") or {}
            confidence = p.get("confidence")
            conf_extra = ""
            if confidence and confidence != "high":
                # Surface confidence and whether chain context corroborated
                # a previously hedged finding (audit trail for reviewers).
                if meta.get("confidence_boosted_by_chain"):
                    conf_extra = f", confidence {confidence} [boosted by chain]"
                else:
                    conf_extra = f", confidence {confidence}"
            lines.append(
                f"- **{role.title()}** — `{file_loc}` "
                f"({p.get('type', 'unknown')}, severity {p.get('severity', '?')}{conf_extra})"
            )
            excerpt = _excerpt(p)
            if excerpt:
                lines.append("  ```")
                lines.append(f"  {excerpt[:200]}")
                lines.append("  ```")
        lines.append("")
    lines.append("## Reproduction")
    lines.append("")
    lines.append("1. Identify the affected components listed above and confirm the build under test contains them.")
    lines.append("2. Reproduce the attack flow described in the Summary by satisfying each trigger condition in order.")
    lines.append("3. Capture the resulting impact (data leakage, code execution, etc.) and any logs / network traces.")
    lines.append("")
    lines.append("> Note: VulnScout produced this submission from deterministic detector evidence. Verify each "
                 "step against the actual build before submission.")
    lines.append("")
    lines.append("## Suggested remediation")
    lines.append("")
    # Pull remediation hints from finding messages and trigger conditions.
    seen_advice: set[str] = set()
    for p in participants:
        msg = p.get("message", "")
        # Final sentence of the message is usually the actionable
        # remediation. Strip a trailing `(CWE-NNN)` / `(CWE-X + CWE-Y)`
        # annotation first — otherwise that's what gets picked as
        # "remediation", masking the actual fix sentence.
        import re as _re
        msg_stripped = _re.sub(
            r"\s*\((?:CWE-\d+(?:\s*[+,]\s*CWE-\d+)*)\)\s*\.?\s*$",
            "", msg,
        ).rstrip()
        last_sentence = msg_stripped.rstrip(".").split(".")[-1].strip()
        if last_sentence and last_sentence not in seen_advice:
            seen_advice.add(last_sentence)
            lines.append(f"- {last_sentence}.")
    if not seen_advice:
        lines.append("- See VulnScout knowledge skill linked from each finding's type for class-specific guidance.")
    lines.append("")
    return "\n".join(lines)


def _format_finding_submission(finding: dict[str, Any]) -> str:
    sev = finding.get("severity", "info")
    title = finding.get("title", "Security finding")
    file_loc = f"{finding.get('file', '?')}:{finding.get('line', '?')}"
    lines = [
        f"# {title}",
        "",
        f"**Severity (estimated)**: {_severity_to_cvss_rating(sev)}  ",
        f"**Location**: `{file_loc}`  ",
        f"**Finding ID**: `{finding.get('id', '?')}` / `{finding.get('stable_key', '')}`",
        "",
        "## Summary",
        "",
        finding.get("message", "(no message)"),
        "",
        "## Evidence",
        "",
    ]
    excerpt = _excerpt(finding)
    if excerpt:
        lines.append("```")
        lines.append(excerpt[:400])
        lines.append("```")
    else:
        lines.append("(see scanner output for source excerpt)")
    lines.append("")
    lines.append("## Reproduction")
    lines.append("")
    lines.append("1. Open the affected file at the indicated line and confirm the pattern still exists.")
    lines.append("2. Trace the input source identified in the finding message to confirm reachability.")
    lines.append("3. Construct a minimal proof showing the impact (data leak, control bypass, etc.).")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate bug-bounty submission templates from a VulnScout artifact")
    parser.add_argument("artifact", help="Path to findings.json")
    parser.add_argument("--output-dir", default=None, help="Directory to write submissions (default: <artifact>.submissions/)")
    parser.add_argument("--min-severity", default="high", choices=["critical", "high", "medium", "low", "info"],
                        help="Minimum severity for individual (non-chain) finding submissions")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)

    artifact_path = Path(args.artifact).resolve()
    if not artifact_path.is_file():
        log.error("Artifact not found: %s", artifact_path)
        return 1
    try:
        art = json.loads(artifact_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Failed to read artifact: %s", exc)
        return 1

    output_dir = Path(args.output_dir).resolve() if args.output_dir else artifact_path.with_suffix(".submissions")
    output_dir.mkdir(parents=True, exist_ok=True)

    fbid = _findings_by_id(art)
    # Skip suppressed chains — those represent primitives the operator
    # chose to silence via `chain_pattern:` suppression rules; generating
    # submissions for them would defeat the suppression intent.
    chains = [
        c for c in (art.get("chains", []) or [])
        if not c.get("suppressed")
    ]
    chain_written = 0
    for chain in chains:
        md = _format_chain_submission(chain, fbid)
        # Filename uses pattern slug + stable_key (deterministic across
        # scans) when available, falling back to the volatile chain-NNN
        # id. With many submissions in one directory, the pattern slug
        # makes triage targeting much easier than `submission-chain-001.md`.
        pattern = chain.get("pattern")
        stable_key = chain.get("stable_key", "")
        if pattern and stable_key:
            name = f"submission-{pattern}-{stable_key.replace('chain-', '')}.md"
        elif pattern:
            name = f"submission-{pattern}-{chain.get('id', 'chain')}.md"
        else:
            name = f"submission-{chain.get('id', 'chain')}.md"
        path = output_dir / name
        path.write_text(md)
        chain_written += 1

    sev_priority = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    threshold = sev_priority.get(args.min_severity, 4)
    chain_finding_ids = {fid for c in chains for fid in c.get("finding_ids", []) if fid}
    individual_written = 0
    for f in art.get("findings", []):
        if f.get("kind") != "finding" or f.get("suppressed"):
            continue
        if f.get("id") in chain_finding_ids:
            continue  # already covered by a chain submission
        if sev_priority.get(f.get("severity", "info"), 0) < threshold:
            continue
        md = _format_finding_submission(f)
        path = output_dir / f"submission-finding-{f.get('id', 'X')}.md"
        path.write_text(md)
        individual_written += 1

    log.info(
        "Wrote %d chain submissions + %d individual-finding submissions to %s",
        chain_written, individual_written, output_dir,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
