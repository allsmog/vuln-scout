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
TRUST_BADGE_COLORS = {
    "provenance": "0e7490",
    "fp_risk": "6b7280",
    "exploitability": "ea580c",
}


def generate(artifact: dict[str, Any]) -> str:
    """Generate an enhanced markdown report from a findings artifact."""
    sections = [
        _header(artifact),
        _executive_summary(artifact),
        _diff_since_prior(artifact),
        _tool_status(artifact),
        _tool_maturity(artifact),
        _scan_diagnostics(artifact),
        _attack_chains(artifact),
        _all_findings((artifact.get("findings") or [])),
        _full_hotspot_list((artifact.get("findings") or [])),
        _coverage_panel(artifact),
        _trust_legend(),
        _next_actions(artifact),
    ]
    return "\n\n".join(s for s in sections if s)


def _scan_diagnostics(artifact: dict[str, Any]) -> str:
    """Render audit-trail failures from this scan.

    Surfaces:
      - chain pattern failures (`scan_metadata.chain_pattern_failures`)
      - sub-detector failures (`tool_statuses['vuln-class-detector'].detector_failures`)

    Returns "" when there's nothing to report. Operators reading the
    markdown report shouldn't have to grep the JSON to discover that
    a chain pattern or detector silently degraded.
    """
    meta = artifact.get("scan_metadata") or {}
    chain_failures = meta.get("chain_pattern_failures") or []
    tool_statuses = artifact.get("tool_statuses") or {}
    vcd_status = tool_statuses.get("vuln-class-detector") or {}
    detector_failures = vcd_status.get("detector_failures") or []
    if not chain_failures and not detector_failures:
        return ""
    lines: list[str] = ["## Scan Diagnostics\n"]
    if chain_failures:
        lines.append(
            f"_{len(chain_failures)} chain pattern(s) failed during detection. "
            "Remaining patterns ran normally; see audit log for details._\n"
        )
        for f in chain_failures:
            lines.append(f"- `{f.get('pattern', '?')}`: {f.get('error', '?')}")
        lines.append("")
    if detector_failures:
        lines.append(
            f"_{len(detector_failures)} sub-detector(s) raised during the scan. "
            "Remaining detectors ran normally; see audit log for details._\n"
        )
        for f in detector_failures:
            lines.append(f"- `{f.get('detector', '?')}`: {f.get('error', '?')}")
    return "\n".join(lines).rstrip()


def _diff_since_prior(artifact: dict[str, Any]) -> str:
    """Render the diff-against summary if the artifact carries one.

    Surfaces only the entries reviewers act on: new findings, gone findings,
    new chains, gone chains. The `kept` lists are large and uninteresting at
    review time — they stay in the JSON for tooling.
    """
    diff = artifact.get("diff")
    if not isinstance(diff, dict):
        return ""
    new_findings = diff.get("new") or []
    gone_findings = diff.get("gone") or []
    chains_diff = diff.get("chains") or {}
    new_chains = chains_diff.get("new") or []
    gone_chains = chains_diff.get("gone") or []
    kept_chains = chains_diff.get("kept") or []
    drift = chains_diff.get("severity_drift") or []
    if not (new_findings or gone_findings or new_chains or gone_chains or drift):
        # If `kept` is populated but nothing else, the scan is stable
        # vs prior — say so explicitly instead of returning an empty
        # section. Reviewers reading the report want a positive signal
        # that nothing regressed, not silence.
        kept_findings = diff.get("kept") or []
        if kept_findings or kept_chains:
            return (
                "## Changes since prior scan\n\n"
                f"_No changes vs prior scan — {len(kept_chains)} chain(s) and "
                f"{len(kept_findings)} finding(s) still present, none new or resolved._"
            )
        return ""
    lines: list[str] = ["## Changes since prior scan\n"]
    # Inline summary lines for at-a-glance read of all deltas.
    if any((new_chains, gone_chains, drift, kept_chains)):
        summary_bits = []
        if new_chains:
            summary_bits.append(f"{len(new_chains)} new")
        if gone_chains:
            summary_bits.append(f"{len(gone_chains)} resolved")
        if drift:
            summary_bits.append(f"{len(drift)} drift")
        if kept_chains:
            summary_bits.append(f"{len(kept_chains)} unchanged")
        if summary_bits:
            lines.append(f"_Chains: {', '.join(summary_bits)}._\n")
    # Same one-liner for findings — `kept` is large, the new/gone
    # counts are what the triager cares about.
    kept_findings = (diff.get("kept") or [])
    if any((new_findings, gone_findings, kept_findings)):
        bits = []
        if new_findings:
            bits.append(f"{len(new_findings)} new")
        if gone_findings:
            bits.append(f"{len(gone_findings)} resolved")
        if kept_findings:
            bits.append(f"{len(kept_findings)} unchanged")
        if bits:
            lines.append(f"_Findings: {', '.join(bits)}._\n")
    if new_chains:
        # Sort worst-first so the most-impactful new chain leads.
        # Stable secondary sort by stable_key keeps output byte-stable.
        _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sorted_new = sorted(
            new_chains,
            key=lambda c: (
                -_sev_rank.get(c.get("severity") or "info", 0),
                c.get("stable_key", ""),
            ),
        )
        lines.append(f"**New chains ({len(sorted_new)}):**\n")
        for c in sorted_new:
            sev = c.get("severity") or "?"
            label = c.get("pattern") or c.get("name") or "?"
            lines.append(f"- `[{sev}]` `{label}` (`{c.get('stable_key', '?')}`)")
        lines.append("")
    _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    if gone_chains:
        # Sort by stable_key only — `gone` entries don't carry severity
        # from the diff schema, just name + stable_key + pattern.
        sorted_gone = sorted(gone_chains, key=lambda c: c.get("stable_key", ""))
        lines.append(f"**Resolved chains ({len(sorted_gone)}):**\n")
        for c in sorted_gone:
            label = c.get("pattern") or c.get("name") or "?"
            lines.append(f"- `{label}` (`{c.get('stable_key', '?')}`)")
        lines.append("")
    if drift:
        # Sort escalations first, then by to_severity desc — escalations
        # are the urgent ones; within a direction, the worst lands first.
        sorted_drift = sorted(
            drift,
            key=lambda d: (
                0 if d.get("direction") == "escalated" else 1,
                -_sev_rank.get(d.get("to_severity") or "info", 0),
                d.get("stable_key", ""),
            ),
        )
        lines.append(f"**Chain severity drift ({len(sorted_drift)}):**\n")
        for d in sorted_drift:
            arrow = "↑" if d.get("direction") == "escalated" else "↓"
            label = d.get("pattern") or d.get("name") or "?"
            lines.append(
                f"- {arrow} `{label}`: "
                f"`{d.get('from_severity')}` → `{d.get('to_severity')}` "
                f"(`{d.get('stable_key', '?')}`)"
            )
        lines.append("")
    if new_findings:
        _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sorted_findings = sorted(
            new_findings,
            key=lambda f: (
                -_sev_rank.get(f.get("severity") or "info", 0),
                f.get("file", ""),
                f.get("line", 0),
            ),
        )
        lines.append(f"**New findings ({len(sorted_findings)}):**\n")
        for f in sorted_findings[:20]:
            sev = f.get("severity") or "?"
            lines.append(
                f"- `[{sev}]` {f.get('type', '?')} at `{f.get('file', '?')}:{f.get('line', '?')}`"
            )
        if len(sorted_findings) > 20:
            lines.append(f"- … and {len(sorted_findings) - 20} more")
        lines.append("")
    if gone_findings:
        lines.append(f"**Resolved findings ({len(gone_findings)}):** see `diff.gone` in artifact JSON.\n")
    return "\n".join(lines).rstrip()


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
    # Filter out suppressed chains so the exec summary matches the
    # Attack Chains section and the recomputed rollups in summary.
    # Use `or []` to tolerate an artifact where `chains`/`findings`
    # is explicitly None (vs absent) — common in hand-edited fixtures
    # and CI artifact passes that strip empty arrays.
    chains = [c for c in (artifact.get("chains") or []) if not c.get("suppressed")]
    coverage = artifact.get("coverage") or {}
    findings = artifact.get("findings") or []

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

    # Chain breakdown by severity (when the summary already ran the
    # rollup we did in mobile_scan; otherwise we recompute).
    chains_by_sev = summary.get("chains_by_severity") or {}
    if not chains_by_sev and chains:
        for c in chains:
            sev = c.get("severity") or "info"
            chains_by_sev[sev] = chains_by_sev.get(sev, 0) + 1
    if chains_by_sev:
        sev_bits = [
            f"{sev}: {chains_by_sev[sev]}"
            for sev in ("critical", "high", "medium", "low")
            if chains_by_sev.get(sev)
        ]
        if sev_bits:
            rows.append(f"**Chains by Severity**: {', '.join(sev_bits)}  ")

    # Most common chain patterns — useful for "what shape is this app
    # leaking" at-a-glance.
    chains_by_pat = summary.get("chains_by_pattern") or {}
    if not chains_by_pat and chains:
        for c in chains:
            pat = c.get("pattern") or "unknown"
            chains_by_pat[pat] = chains_by_pat.get(pat, 0) + 1
    if chains_by_pat:
        top = sorted(chains_by_pat.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        top_str = ", ".join(f"`{p}`={n}" for p, n in top)
        rows.append(f"**Top Chain Patterns**: {top_str}  ")

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


def _tool_maturity(artifact: dict[str, Any]) -> str:
    maturity = artifact.get("maturity", {})
    if not maturity:
        return ""

    profile = artifact.get("scan_profile")
    profile_maturity = maturity.get("profiles", {}).get(profile)
    # Use `or {}` rather than `get(K, {})` so an explicit None doesn't
    # crash the chained .get(). Same defensive pattern as bug 31.
    tools = (
        (artifact.get("tool_status") or {}).get("requested")
        or (artifact.get("coverage") or {}).get("tools_used")
        or []
    )
    if not tools:
        tools = sorted({f.get("source_tool") for f in (artifact.get("findings") or []) if f.get("source_tool")})
    analyzers = maturity.get("analyzers", {})
    commands = maturity.get("commands", {})

    lines = ["## Tool Maturity\n"]
    if profile and profile_maturity:
        lines.append(f"**Profile**: `{profile}` ({profile_maturity})  ")
    if tools:
        lines.extend(["", "| Tool | Maturity |", "|------|----------|"])
        for tool in tools:
            lines.append(f"| `{tool}` | {analyzers.get(tool) or commands.get(tool, 'unknown')} |")
    return "\n".join(lines)


def _badge(label: str, value: str, color: str) -> str:
    safe_label = label.replace("-", "--").replace("_", "__").replace(" ", "%20")
    safe_value = value.replace("-", "--").replace("_", "__").replace(" ", "%20")
    return f"![{label}: {value}](https://img.shields.io/badge/{safe_label}-{safe_value}-{color})"


def _trust_badge(finding: dict[str, Any]) -> str:
    trust = finding.get("trust_metadata") or {}
    provenance = (trust.get("provenance") or {}).get("origin", "unknown")
    fp_risk = (trust.get("false_positive_risk") or {}).get("level", "unknown")
    exploitability = trust.get("exploitability_status", "unknown")
    return " ".join([
        _badge("Trust", str(provenance), TRUST_BADGE_COLORS["provenance"]),
        _badge("FP-risk", str(fp_risk), TRUST_BADGE_COLORS["fp_risk"]),
        _badge("Exploitability", str(exploitability), TRUST_BADGE_COLORS["exploitability"]),
    ])


def _confidence_reason_block(finding: dict[str, Any]) -> str:
    trust = finding.get("trust_metadata") or {}
    reason = trust.get("confidence_reason")
    return f"*{reason}*" if reason else ""


def _trust_legend() -> str:
    return "\n".join([
        "## Trust Legend",
        "",
        "- **Trust** identifies provenance: deterministic tool, LLM analysis, dynamic verification, human review, or mixed.",
        "- **FP-risk** estimates false-positive likelihood from suppressions, semantic checks, and verification signals.",
        "- **Exploitability** states whether the issue is confirmed, plausible, blocked by a control, auth-gated, unreachable, or unknown.",
    ])


# ---------------------------------------------------------------------------
# Attack Chains (Mermaid diagrams)
# ---------------------------------------------------------------------------

def _attack_chains(artifact: dict[str, Any]) -> str:
    # Skip suppressed chains (every participant suppressed → chain.suppressed
    # set by artifact_utils.apply_suppressions). They stay in the JSON for
    # audit but don't belong in the reviewer-facing report.
    chains = [c for c in (artifact.get("chains") or []) if not c.get("suppressed")]
    if not chains:
        return ""

    findings_by_id = {}
    for f in (artifact.get("findings") or []):
        fid = f.get("id")
        if fid:
            findings_by_id[fid] = f

    lines = ["## Attack Chains\n"]

    for chain in chains:
        chain_name = chain.get("name", "Unnamed Chain")
        chain_id = chain.get("id", "")
        finding_ids = chain.get("finding_ids", [])
        flow_desc = chain.get("flow_description", "")
        impact = chain.get("impact", "")

        severity = chain.get("severity")
        confidence = chain.get("confidence")
        cvss_estimate = chain.get("cvss_estimate")
        sev_badge = f" `[{severity}]`" if severity else ""
        if cvss_estimate is not None:
            sev_badge += f" *(CVSS≈{cvss_estimate})*"
        if confidence and confidence != "high":
            sev_badge += f" *(confidence: {confidence})*"
        lines.append(f"### {chain_name}{sev_badge}")
        id_parts: list[str] = []
        if chain_id:
            id_parts.append(f"Chain ID: {chain_id}")
        stable_key = chain.get("stable_key")
        if stable_key:
            id_parts.append(f"stable_key: `{stable_key}`")
        if id_parts:
            lines.append(f"*{' • '.join(id_parts)}*\n")

        if impact:
            lines.append(f"**Impact:** {impact}\n")
        cwes = chain.get("cwes") or []
        if cwes:
            cwe_links = [
                f"[{c}](https://cwe.mitre.org/data/definitions/{c.split('-')[-1]}.html)"
                for c in cwes
            ]
            lines.append(f"**CWE:** {', '.join(cwe_links)}\n")
        if flow_desc:
            lines.append(f"**Flow:** {flow_desc}\n")

        # When there's only one participant (rare but possible — a
        # chain detector that matched only the precondition), Mermaid
        # can't render an edge. Surface the participant explicitly so
        # the chain section isn't a dead-end.
        if len(finding_ids) == 1:
            f = findings_by_id.get(finding_ids[0])
            if f:
                lines.append(
                    f"**Participant:** `{f.get('file', '?')}:{f.get('line', '?')}` "
                    f"({f.get('type', 'unknown')})\n"
                )
        # Build Mermaid diagram from linked findings. Labels prefer the
        # finding's role + short type + file:line — full titles would
        # blow out node width in markdown preview. The full title is
        # already in the Findings section.
        if len(finding_ids) >= 2:
            nodes = []
            for fid in finding_ids:
                f = findings_by_id.get(fid)
                if f:
                    # Find the role for this chain by looking up the
                    # participation entry matching the chain id.
                    role = ""
                    for p in (f.get("chain_participations") or []):
                        if p.get("chain_id") == chain_id:
                            role = p.get("role") or ""
                            break
                    role_prefix = f"[{role}] " if role else ""
                    type_str = f.get("type") or "finding"
                    loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
                    label = f"{role_prefix}{type_str}<br/>{loc}"
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
        f for f in (findings or [])
        if f.get("kind") == "finding" and not f.get("suppressed")
    ]
    # Sort by: chain membership (chains first), severity desc, CVSS desc. A
    # finding tagged with chain_id participates in an end-to-end primitive, so
    # triagers should see it before standalone findings of equal severity.
    reportable.sort(key=lambda f: (
        0 if f.get("chain_id") else 1,
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

        chain_id = f.get("chain_id")
        chain_role = f.get("chain_role")
        chain_pattern = f.get("chain_pattern")
        chain_marker = ""
        if chain_id:
            # If the finding participates in MULTIPLE chains, surface
            # every one — multi-chain findings are higher-priority
            # since they're load-bearing across primitives.
            participations = f.get("chain_participations") or []
            patterns_with_roles: list[str] = []
            for p in participations:
                if isinstance(p, dict) and p.get("pattern"):
                    role = p.get("role") or "?"
                    patterns_with_roles.append(f"`{p['pattern']}`:{role}")
            if len(patterns_with_roles) > 1:
                # Multi-chain: list every participation
                chain_marker = f" \\[chains {', '.join(patterns_with_roles)}\\]"
            else:
                # Single chain (back-compat): the canonical N+30 form
                role_str = f" — {chain_role}" if chain_role else ""
                chain_label = chain_pattern or chain_id
                chain_marker = f" \\[chain `{chain_label}`{role_str}\\]"
        lines.append(f"### {badge} {title}{chain_marker}")
        lines.append(f"**Location**: {file_loc}{cvss_str}{cwe_str}  ")
        confidence = f.get("confidence", "unknown")
        conf_extra = ""
        if (f.get("metadata") or {}).get("confidence_boosted_by_chain"):
            conf_extra = " (boosted by chain)"
        lines.append(
            f"**Verdict**: {verdict} | **Confidence**: {confidence}{conf_extra} | **ID**: `{f.get('id', '?')}`\n"
        )
        lines.append(f"{_trust_badge(f)}\n")
        confidence_reason = _confidence_reason_block(f)
        if confidence_reason:
            lines.append(f"{confidence_reason}\n")

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
        f for f in (findings or [])
        if f.get("kind") == "hotspot" and not f.get("suppressed")
    ]
    if not hotspots:
        return ""
    # Same ordering policy as the findings list: chain-tagged first,
    # then severity desc. A hotspot that participates in an end-to-end
    # primitive is more urgent than a standalone medium of equal sev.
    hotspots.sort(key=lambda f: (
        0 if f.get("chain_id") else 1,
        -SEVERITY_PRIORITY.get(f.get("severity", "info"), 0),
        f.get("file", ""),
    ))

    lines = [f"## Hotspots ({len(hotspots)} requiring follow-up)\n"]
    for h in hotspots:
        title = h.get("title", "Unknown")
        loc = f"`{h.get('file', '?')}:{h.get('line', '?')}`"
        verdict = h.get("verdict", "unverified")
        sev = h.get("severity", "info")
        chain_pattern = h.get("chain_pattern")
        chain_marker = f" \\[chain `{chain_pattern}`\\]" if chain_pattern else ""
        lines.append(
            f"- `[{sev}]` **{title}** at {loc} -- {verdict}{chain_marker}"
        )

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
    findings = [f for f in (artifact.get("findings") or []) if f.get("kind") == "finding" and not f.get("suppressed")]
    chains = [
        c for c in (artifact.get("chains", []) or [])
        if not c.get("suppressed")
    ]
    if not findings and not chains:
        return "## Next Actions\n\nNo reportable findings remain. Keep the `.claude/findings.json` artifact for audit history."

    verified = [f for f in findings if f.get("verdict") == "verified"]
    blocking = [f for f in findings if SEVERITY_PRIORITY.get(f.get("severity", "info"), 0) >= SEVERITY_PRIORITY["high"]]
    unverified = [f for f in findings if f.get("verdict") == "unverified"]
    # Chains are already sorted worst-first by the chain detector.
    high_chains = [
        c for c in chains
        if SEVERITY_PRIORITY.get(c.get("severity", "info"), 0) >= SEVERITY_PRIORITY["high"]
    ]

    actions = ["## Next Actions\n"]
    index = 1
    if high_chains:
        # Chains describe end-to-end primitives — triage them before
        # standalone findings of equal severity.
        worst = high_chains[0]
        actions.append(
            f"{index}. Triage the {len(high_chains)} high-or-critical chain(s) first — start with "
            f"`{worst.get('pattern') or worst.get('name')}` "
            f"(`{worst.get('stable_key', worst.get('id', '?'))}`)."
        )
        index += 1
        actions.append(
            f"{index}. Generate bug-bounty submissions: "
            f"`python3 vuln-scout/scripts/submission_template.py <findings.json>`"
        )
        index += 1
    if verified:
        actions.append(f"{index}. Fix or explicitly suppress the {len(verified)} verified finding(s).")
        index += 1
    if blocking:
        actions.append(f"{index}. Use `--fail-on high` in CI until the {len(blocking)} high-or-higher finding(s) are resolved.")
        index += 1
    if unverified:
        actions.append(f"{index}. Run `/vuln-scout:verify` or the `deep` profile on the {len(unverified)} unverified finding(s).")
        index += 1
    if chains:
        actions.append(
            f"{index}. If a chain class is a known false positive on this repo, add "
            f"`chain_pattern:<slug>  <reason>` to `.vuln-scout-ignore`."
        )
        index += 1
    actions.append(f"{index}. Re-render SARIF or HTML from the same `.claude/findings.json` artifact after triage.")
    return "\n".join(actions)
