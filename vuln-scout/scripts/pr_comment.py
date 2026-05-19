#!/usr/bin/env python3
"""Generate a compact GitHub PR comment from a VulnScout findings artifact.

Produces GitHub-flavored Markdown optimized for pull request comments:
- Severity summary table
- Diff-aware "New in this PR" section
- Attack chain summary
- Expandable full findings list via <details> tags
- 55 KB truncation guard for GitHub comment size limits
"""
from __future__ import annotations

from typing import Any

SEVERITY_PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# GitHub PR comment body limit is ~65535 chars; we truncate at 55 KB to leave room.
MAX_COMMENT_BYTES = 55 * 1024


def generate(artifact: dict[str, Any]) -> str:
    """Generate a compact PR comment from a findings artifact."""
    summary = artifact.get("summary", {})
    findings = artifact.get("findings", [])
    chains = artifact.get("chains", [])
    coverage = artifact.get("coverage", {})

    reportable = [
        f for f in findings
        if f.get("kind") == "finding" and not f.get("suppressed")
    ]

    # If no findings at all, produce a clean pass message
    if not reportable:
        return _empty_comment(artifact, coverage)

    sections = [
        _header_table(summary),
        _new_in_pr(reportable),
        _chain_summary(chains),
        _full_list(reportable),
        _footer(artifact, coverage),
    ]

    body = "\n\n".join(s for s in sections if s)
    return _truncate(body, reportable)


# ---------------------------------------------------------------------------
# Empty scan result
# ---------------------------------------------------------------------------

def _empty_comment(artifact: dict[str, Any], coverage: dict[str, Any]) -> str:
    lines = [
        "## VulnScout Security Scan",
        "",
        "No security issues found.",
        "",
        _footer(artifact, coverage),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Header with severity table
# ---------------------------------------------------------------------------

def _header_table(summary: dict[str, Any]) -> str:
    c = summary.get("critical", 0)
    h = summary.get("high", 0)
    m = summary.get("medium", 0)
    lo = summary.get("low", 0)

    lines = [
        "## VulnScout Security Scan",
        "",
        "| | Critical | High | Medium | Low |",
        "|---|---|---|---|---|",
        f"| Findings | {c} | {h} | {m} | {lo} |",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# New in this PR (diff-aware findings)
# ---------------------------------------------------------------------------

def _new_in_pr(reportable: list[dict[str, Any]]) -> str:
    diff_findings = [f for f in reportable if f.get("in_diff")]
    if not diff_findings:
        return ""

    diff_findings.sort(key=lambda f: (
        -SEVERITY_PRIORITY.get(f.get("severity", "info"), 0),
        -(f.get("cvss_score") or 0),
    ))

    lines = ["### New in this PR"]
    for f in diff_findings:
        sev = f.get("severity", "info").upper()
        title = f.get("title", "Unknown")
        loc = f"`{f.get('file', '?')}:{f.get('line', '?')}`"
        verdict = f.get("verdict", "needs review")
        lines.append(f"- **[{sev}]** {title} in {loc} -- {verdict}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Attack chain summary
# ---------------------------------------------------------------------------

def _chain_summary(chains: list[dict[str, Any]]) -> str:
    if not chains:
        return ""

    lines = ["### Attack Chains Detected"]
    for chain in chains:
        name = chain.get("name", "Unnamed")
        finding_ids = chain.get("finding_ids", [])
        count = len(finding_ids)
        lines.append(f"- {name} ({count} finding{'s' if count != 1 else ''} linked)")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Full expandable list
# ---------------------------------------------------------------------------

def _full_list(reportable: list[dict[str, Any]]) -> str:
    sorted_findings = sorted(reportable, key=lambda f: (
        -SEVERITY_PRIORITY.get(f.get("severity", "info"), 0),
        -(f.get("cvss_score") or 0),
    ))

    lines = [
        "<details>",
        f"<summary>All findings ({len(sorted_findings)} total)</summary>",
        "",
    ]

    for f in sorted_findings:
        sev = f.get("severity", "info").upper()
        title = f.get("title", "Unknown")
        loc = f"`{f.get('file', '?')}:{f.get('line', '?')}`"
        verdict = f.get("verdict", "unverified")
        cvss = f.get("cvss_score")
        cvss_str = f" (CVSS {cvss:.1f})" if cvss else ""
        in_diff = " :new:" if f.get("in_diff") else ""
        lines.append(f"- **[{sev}]** {title} at {loc} -- {verdict}{cvss_str}{in_diff}")

    lines.append("")
    lines.append("</details>")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

def _footer(artifact: dict[str, Any], coverage: dict[str, Any]) -> str:
    files_scanned = coverage.get("files_scanned", "?")
    elapsed = coverage.get("elapsed_seconds", "?")

    parts = [f"{files_scanned} files"]
    if elapsed != "?":
        parts.append(f"{elapsed}s")

    return (
        "---\n"
        f"*Scanned by [VulnScout](https://github.com/allsmog/vuln-scout) | "
        f"{' | '.join(parts)}*"
    )


# ---------------------------------------------------------------------------
# Truncation guard
# ---------------------------------------------------------------------------

def _truncate(body: str, reportable: list[dict[str, Any]]) -> str:
    """If the comment exceeds 55 KB, truncate the details section."""
    if len(body.encode("utf-8")) <= MAX_COMMENT_BYTES:
        return body

    # Find the <details> block and trim it
    details_start = body.find("<details>")
    details_end = body.find("</details>")
    if details_start == -1 or details_end == -1:
        # No details block to trim; hard-truncate
        return body[:MAX_COMMENT_BYTES] + "\n\n*Output truncated.*"

    before = body[:details_start]
    after = body[details_end + len("</details>"):]

    # Count how many findings we can keep
    total = len(reportable)
    kept = 0
    trimmed_details_lines = [
        "<details>",
        f"<summary>All findings ({total} total -- truncated)</summary>",
        "",
    ]

    for f in sorted(reportable, key=lambda f: (
        -SEVERITY_PRIORITY.get(f.get("severity", "info"), 0),
        -(f.get("cvss_score") or 0),
    )):
        sev = f.get("severity", "info").upper()
        title = f.get("title", "Unknown")
        loc = f"`{f.get('file', '?')}:{f.get('line', '?')}`"
        verdict = f.get("verdict", "unverified")
        line = f"- **[{sev}]** {title} at {loc} -- {verdict}"
        trimmed_details_lines.append(line)
        kept += 1

        candidate = before + "\n".join(trimmed_details_lines) + f"\n\n*{total - kept} more findings omitted -- see full report*\n\n</details>" + after
        if len(candidate.encode("utf-8")) > MAX_COMMENT_BYTES:
            # Remove the last added line
            trimmed_details_lines.pop()
            kept -= 1
            break

    omitted = total - kept
    if omitted > 0:
        trimmed_details_lines.append(f"\n*{omitted} more findings omitted -- see full report*")

    trimmed_details_lines.append("")
    trimmed_details_lines.append("</details>")

    return before + "\n".join(trimmed_details_lines) + after
