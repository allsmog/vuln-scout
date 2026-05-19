#!/usr/bin/env python3
"""Generate an enhanced Markdown report from a VulnScout findings artifact.

Includes executive summary, attack-chain Mermaid diagrams, full findings list
(sorted by severity/CVSS), full hotspot list, and a coverage panel.
"""
from __future__ import annotations

from typing import Any

SEVERITY_PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_BADGE = {
    "critical": "![Critical](https://img.shields.io/badge/-CRITICAL-dc2626)",
    "high": "![High](https://img.shields.io/badge/-HIGH-ea580c)",
    "medium": "![Medium](https://img.shields.io/badge/-MEDIUM-ca8a04)",
    "low": "![Low](https://img.shields.io/badge/-LOW-2563eb)",
    "info": "![Info](https://img.shields.io/badge/-INFO-6b7280)",
}


def generate(artifact: dict[str, Any]) -> str:
    """Generate an enhanced markdown report from a findings artifact."""
    sections = [
        _header(artifact),
        _executive_summary(artifact),
        _tool_status(artifact),
        _attack_chains(artifact),
        _all_findings(artifact.get("findings", [])),
        _full_hotspot_list(artifact.get("findings", [])),
        _coverage_panel(artifact),
        _next_actions(artifact),
    ]
    return "\n\n".join(s for s in sections if s)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def _header(artifact: dict[str, Any]) -> str:
    return (
        f"# VulnScout Scan Report\n\n"
        f"**Project**: {artifact.get('project_path', 'unknown')}  \n"
        f"**Scan ID**: {artifact.get('scan_id', 'unknown')}  \n"
        f"**Date**: {artifact.get('completed_at', 'unknown')}  \n"
        f"**Tool**: {artifact.get('source_tool', 'unknown')}"
    )


# ---------------------------------------------------------------------------
# Executive Summary
# ---------------------------------------------------------------------------

def _risk_rating(summary: dict[str, Any]) -> str:
    """Return overall risk rating based on highest unsuppressed severity."""
    for sev in SEVERITY_ORDER:
        if summary.get(sev, 0) > 0:
            return sev.capitalize()
    return "None"


def _executive_summary(artifact: dict[str, Any]) -> str:
    summary = artifact.get("summary", {})
    chains = artifact.get("chains", [])
    coverage = artifact.get("coverage", {})
    findings = artifact.get("findings", [])

    risk = _risk_rating(summary)
    verified = sum(1 for f in findings if f.get("kind") == "finding" and f.get("verdict") == "verified" and not f.get("suppressed"))
    unverified = sum(1 for f in findings if f.get("kind") == "finding" and f.get("verdict") == "unverified" and not f.get("suppressed"))
    suppressed = sum(1 for f in findings if f.get("suppressed"))
    confidence_high = sum(1 for f in findings if f.get("kind") == "finding" and f.get("confidence") in ("verified", "high") and not f.get("suppressed"))

    # Severity table
    rows = [
        "## Executive Summary\n",
        f"**Overall Risk Rating**: {risk}  ",
        f"**Total Findings**: {summary.get('total_findings', 0)}  ",
        f"**Total Hotspots**: {summary.get('total_hotspots', 0)}  ",
        f"**Verified Findings**: {verified}  ",
        f"**Unverified Findings**: {unverified}  ",
        f"**High-Confidence Findings**: {confidence_high}  ",
        f"**Suppressed Entries**: {suppressed}  ",
        f"**Attack Chains**: {len(chains)}  ",
    ]

    # Tools used
    tools_used = coverage.get("tools_used", [])
    if tools_used:
        rows.append(f"**Tools Used**: {', '.join(tools_used)}  ")
    else:
        source = artifact.get("source_tool", "unknown")
        rows.append(f"**Tools Used**: {source}  ")

    # Scan scope
    scan_scope = coverage.get("scan_scope", "")
    if scan_scope:
        rows.append(f"**Scan Scope**: {scan_scope}  ")

    rows.append("")  # blank line before table

    rows.extend([
        "| Severity | Count |",
        "|----------|------:|",
    ])
    for sev in SEVERITY_ORDER:
        count = summary.get(sev, 0)
        rows.append(f"| {sev.capitalize()} | {count} |")

    return "\n".join(rows)


def _tool_status(artifact: dict[str, Any]) -> str:
    status = artifact.get("tool_status", {})
    if not status:
        return ""

    requested = status.get("requested", [])
    if not requested:
        return ""

    succeeded = set(status.get("succeeded", []))
    failed = set(status.get("failed", []))
    unavailable = set(status.get("unavailable", []))

    lines = [
        "## Tool Status\n",
        "| Tool | Status |",
        "|------|--------|",
    ]
    for tool in requested:
        if tool in failed:
            value = "failed"
        elif tool in unavailable:
            value = "unavailable"
        elif tool in succeeded or any(name.startswith(f"{tool}-") for name in succeeded):
            value = "succeeded"
        else:
            value = "not run"
        lines.append(f"| {tool} | {value} |")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Attack Chains (Mermaid diagrams)
# ---------------------------------------------------------------------------

def _attack_chains(artifact: dict[str, Any]) -> str:
    chains = artifact.get("chains", [])
    if not chains:
        return ""

    findings_by_id = {}
    for f in artifact.get("findings", []):
        fid = f.get("id")
        if fid:
            findings_by_id[fid] = f

    lines = ["## Attack Chains\n"]

    for chain in chains:
        chain_name = chain.get("name", "Unnamed Chain")
        chain_id = chain.get("id", "")
        finding_ids = chain.get("finding_ids", [])
        flow_desc = chain.get("flow_description", "")

        lines.append(f"### {chain_name}")
        if chain_id:
            lines.append(f"*Chain ID: {chain_id}*\n")

        if flow_desc:
            lines.append(f"{flow_desc}\n")

        # Build Mermaid diagram from linked findings
        if len(finding_ids) >= 2:
            nodes = []
            for fid in finding_ids:
                f = findings_by_id.get(fid)
                if f:
                    label = f"{f.get('title', fid)} in {f.get('file', '?')}:{f.get('line', '?')}"
                    # Sanitize label for Mermaid (remove brackets, quotes)
                    label = label.replace('"', "'").replace("[", "(").replace("]", ")")
                    nodes.append((fid, label))
                else:
                    nodes.append((fid, fid))

            lines.append("```mermaid")
            lines.append("graph LR")
            for i in range(len(nodes) - 1):
                src_id, src_label = nodes[i]
                dst_id, dst_label = nodes[i + 1]
                # Use index-based node IDs to avoid Mermaid conflicts
                lines.append(
                    f"    N{i}[\"{src_label}\"] --> N{i + 1}[\"{dst_label}\"]"
                )
            lines.append("```")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# All Findings (full list, sorted by severity desc then CVSS desc)
# ---------------------------------------------------------------------------

def _all_findings(findings: list[dict[str, Any]]) -> str:
    reportable = [
        f for f in findings
        if f.get("kind") == "finding" and not f.get("suppressed")
    ]
    reportable.sort(key=lambda f: (
        -SEVERITY_PRIORITY.get(f.get("severity", "info"), 0),
        -(f.get("cvss_score") or 0),
    ))

    if not reportable:
        return "## Findings\n\nNo security findings detected."

    lines = [f"## Findings ({len(reportable)} total)\n"]

    for f in reportable:
        sev = f.get("severity", "info")
        badge = SEVERITY_BADGE.get(sev, "")
        title = f.get("title", "Unknown")
        file_loc = f"`{f.get('file', '?')}:{f.get('line', '?')}`"
        verdict = f.get("verdict", "unverified")
        cvss = f.get("cvss_score")
        cvss_str = f" | CVSS: **{cvss:.1f}**" if cvss else ""
        cwe = f.get("cwe")
        cwe_items = cwe if isinstance(cwe, list) else ([cwe] if cwe else [])
        cwe_str = ""
        if cwe_items:
            cwe_links = [f"[{c}](https://cwe.mitre.org/data/definitions/{c.split('-')[-1]}.html)"
                         if c.startswith("CWE-") else c for c in cwe_items]
            cwe_str = f" | {', '.join(cwe_links)}"

        lines.append(f"### {badge} {title}")
        lines.append(f"**Location**: {file_loc}{cvss_str}{cwe_str}  ")
        confidence = f.get("confidence", "unknown")
        lines.append(f"**Verdict**: {verdict} | **Confidence**: {confidence} | **ID**: `{f.get('id', '?')}`\n")

        # Message / description
        message = f.get("message", "")
        if message:
            lines.append(f"{message}\n")

        # Evidence excerpts
        evidence_list = f.get("evidence", [])
        if evidence_list:
            lines.append("<details>")
            lines.append(f"<summary>Evidence ({len(evidence_list)} item{'s' if len(evidence_list) != 1 else ''})</summary>\n")
            for ev in evidence_list:
                ev_label = ev.get("label", "evidence")
                ev_path = ev.get("path", "")
                ev_line = ev.get("line", "")
                excerpt = ev.get("excerpt", "")
                lines.append(f"**{ev_label}** (`{ev_path}:{ev_line}`)")
                if excerpt:
                    lines.append(f"```\n{excerpt}\n```")
                lines.append("")
            lines.append("</details>\n")

        # Remediation
        remediation = f.get("remediation", "")
        if remediation:
            lines.append(f"> **Remediation**: {remediation}\n")

        lines.append("---")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Full Hotspot List (not truncated)
# ---------------------------------------------------------------------------

def _full_hotspot_list(findings: list[dict[str, Any]]) -> str:
    hotspots = [
        f for f in findings
        if f.get("kind") == "hotspot" and not f.get("suppressed")
    ]
    if not hotspots:
        return ""

    lines = [f"## Hotspots ({len(hotspots)} requiring follow-up)\n"]
    for h in hotspots:
        title = h.get("title", "Unknown")
        loc = f"`{h.get('file', '?')}:{h.get('line', '?')}`"
        verdict = h.get("verdict", "unverified")
        lines.append(f"- **{title}** at {loc} -- {verdict}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Coverage Panel
# ---------------------------------------------------------------------------

def _coverage_panel(artifact: dict[str, Any]) -> str:
    coverage = artifact.get("coverage", {})
    if not coverage:
        return ""

    lines = ["## Coverage\n"]

    files_scanned = coverage.get("files_scanned")
    if files_scanned is not None:
        lines.append(f"**Files Scanned**: {files_scanned}  ")

    tools_used = coverage.get("tools_used", [])
    if tools_used:
        lines.append(f"**Tools Used**: {', '.join(tools_used)}  ")

    diff_aware = coverage.get("diff_aware")
    if diff_aware is not None:
        status = "Enabled" if diff_aware else "Disabled"
        lines.append(f"**Diff-Aware Scanning**: {status}  ")

    diff_ref = coverage.get("diff_ref", "")
    if diff_ref:
        lines.append(f"**Diff Reference**: `{diff_ref}`  ")

    languages = coverage.get("languages", {})
    if languages:
        lines.append("\n| Language | Files |")
        lines.append("|----------|------:|")
        for lang, count in sorted(languages.items(), key=lambda x: -x[1] if isinstance(x[1], int) else 0):
            lines.append(f"| {lang} | {count} |")

    return "\n".join(lines)


def _next_actions(artifact: dict[str, Any]) -> str:
    findings = [f for f in artifact.get("findings", []) if f.get("kind") == "finding" and not f.get("suppressed")]
    if not findings:
        return "## Next Actions\n\nNo reportable findings remain. Keep the `.claude/findings.json` artifact for audit history."

    verified = [f for f in findings if f.get("verdict") == "verified"]
    blocking = [f for f in findings if SEVERITY_PRIORITY.get(f.get("severity", "info"), 0) >= SEVERITY_PRIORITY["high"]]
    unverified = [f for f in findings if f.get("verdict") == "unverified"]

    actions = ["## Next Actions\n"]
    index = 1
    if verified:
        actions.append(f"{index}. Fix or explicitly suppress the {len(verified)} verified finding(s) first.")
        index += 1
    if blocking:
        actions.append(f"{index}. Use `--fail-on high` in CI until the {len(blocking)} high-or-higher finding(s) are resolved.")
        index += 1
    if unverified:
        actions.append(f"{index}. Run `/whitebox-pentest:verify` or the `deep` profile on the {len(unverified)} unverified finding(s).")
        index += 1
    actions.append(f"{index}. Re-render SARIF or HTML from the same `.claude/findings.json` artifact after triage.")
    return "\n".join(actions)
