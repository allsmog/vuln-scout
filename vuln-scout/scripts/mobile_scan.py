#!/usr/bin/env python3
"""Mobile audit driver: scan jadx_out + apktool_out together.

Most Android targets are decompiled into two side-by-side directories:

* ``<target>/jadx_out/sources/`` — Java/Kotlin pseudocode that we scan with the
  code-side detectors (WebView JS injection, remote-controlled URLs, insecure
  crypto, etc.).
* ``<target>/apktool_out/`` — resources, manifest, native libs that hold the
  AndroidManifest + ``res/xml/network_security_config.xml`` we scan for
  exported components, pinning gaps, debuggable builds.

Pointing the regular scanner at the *target root* loses one or the other.
This driver auto-discovers both, runs ``scan_orchestrator`` on each, and
merges the artifacts into a single ``findings.json`` under the target root.

Usage:
    python3 mobile_scan.py <target_root> [--output FILE]
                                         [--profile quick|deep|audit]
                                         [--extra-arg ...]

If the target is *itself* a jadx_out/sources or apktool_out directory the
driver scans just that location and exits.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCRIPTS_DIR = Path(__file__).resolve().parent
ORCHESTRATOR = SCRIPTS_DIR / "scan_orchestrator.py"

log = logging.getLogger("vuln-scout-mobile")


# Directory names we look for. Order matters: the earlier match in the list is
# treated as the primary "code" target and gets the canonical findings output.
CODE_SUBPATHS: tuple[tuple[str, ...], ...] = (
    ("jadx_out", "sources"),
    ("jadx_out2", "sources"),
    ("jadx", "sources"),
    ("decompiled", "sources"),
    ("android-decompiled", "sources"),
    ("sources",),
    ("src", "main", "java"),
    # iOS / Swift project layouts
    ("Sources",),
    ("Source",),
    ("App",),
    ("Application",),
)
RESOURCE_SUBPATHS: tuple[tuple[str, ...], ...] = (
    ("apktool_out",),
    ("apktool",),
    ("res",),
    # iOS extracted IPA: Payload contains the .app bundle with Info.plist
    ("Payload",),
    ("Resources",),
)


def _exists(root: Path, parts: tuple[str, ...]) -> Path | None:
    p = root
    for part in parts:
        p = p / part
    return p if p.is_dir() else None


def discover_mobile_targets(root: Path) -> list[Path]:
    """Return a list of distinct directories to scan."""
    targets: list[Path] = []

    # If `root` itself is a known sub-target, use it directly.
    if root.name == "sources" and (root.parent / "sources" == root):
        return [root]
    if root.name == "apktool_out":
        return [root]

    for parts in CODE_SUBPATHS:
        found = _exists(root, parts)
        if found:
            targets.append(found)
            break  # only the first code root

    for parts in RESOURCE_SUBPATHS:
        found = _exists(root, parts)
        if found and found not in targets:
            targets.append(found)
            break  # only the first resource root

    # If nothing matched, fall back to root itself.
    if not targets:
        targets.append(root)
    return targets


def _run_orchestrator(
    target: Path,
    extra_args: list[str],
    output_path: Path,
    profile: str,
    suppressions: Path | None = None,
) -> int:
    cmd = [
        sys.executable,
        str(ORCHESTRATOR),
        str(target),
        "--profile",
        profile,
        "--extended-detectors",
        "--tools",
        "api-spec",  # api-spec is cheap and useful even when not the main goal
        "--format",
        "json",
        "--output",
        str(output_path),
    ]
    if suppressions:
        cmd.extend(["--suppressions", str(suppressions)])
    cmd.extend(extra_args)
    log.info("Scanning %s -> %s", target, output_path)
    result = subprocess.run(cmd)
    return result.returncode


def merge_findings(artifacts: list[Path], *, skip_chains: bool = False) -> dict[str, Any]:
    """Merge several findings.json artifacts into one.

    De-duplicates findings by ``stable_key`` when present, falling back to
    ``file:line:type``. Sums summary counters, concatenates evidence, and
    re-runs the chain detector on the combined finding set so
    cross-tree chains (e.g. a manifest-side NSC gap + a code-side
    remote-controlled URL) actually get linked.
    """
    out: dict[str, Any] = {
        "schema_version": "1.2.0",
        "scan_id": None,
        "project_path": None,
        "completed_at": None,
        "source_tool": "vuln-scout-mobile",
        "summary": {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "total_findings": 0, "total_hotspots": 0,
        },
        "findings": [],
        "chains": [],
        "merged_from": [],
    }
    seen: dict[str, dict[str, Any]] = {}
    for art in artifacts:
        if not art.is_file():
            continue
        try:
            data = json.loads(art.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Skipping unreadable artifact %s: %s", art, exc)
            continue
        out["merged_from"].append(str(art))
        if not out["scan_id"]:
            out["scan_id"] = data.get("scan_id")
        if not out["project_path"]:
            out["project_path"] = data.get("project_path")
        out["completed_at"] = data.get("completed_at") or out["completed_at"]
        for finding in (data.get("findings") or []):
            # Use the same key-derivation as the diff path so an
            # anonymous finding doesn't collapse two distinct findings
            # into one merged entry. See bug 19.
            key = _finding_key(finding)
            if key in seen:
                # Merge evidence
                existing = seen[key]
                existing_ev = existing.get("evidence", []) or []
                new_ev = finding.get("evidence", []) or []
                # de-dup by repr to keep payload small
                ev_seen = {repr(e) for e in existing_ev}
                for e in new_ev:
                    if repr(e) not in ev_seen:
                        existing_ev.append(e)
                        ev_seen.add(repr(e))
                existing["evidence"] = existing_ev
                # Take the WORST severity across duplicates — without
                # this, a "critical" finding from artifact 2 would get
                # silently downgraded to whatever artifact 1 reported.
                # Same idea for confidence: keep the strongest signal.
                _sev_rank = {"critical": 4, "high": 3, "medium": 2,
                             "low": 1, "info": 0}
                _conf_rank = {"verified": 4, "high": 3, "medium": 2,
                              "low": 1, "unknown": 0}
                if _sev_rank.get(finding.get("severity", "info"), 0) > \
                   _sev_rank.get(existing.get("severity", "info"), 0):
                    existing["severity"] = finding.get("severity")
                if _conf_rank.get(finding.get("confidence", "unknown"), 0) > \
                   _conf_rank.get(existing.get("confidence", "unknown"), 0):
                    existing["confidence"] = finding.get("confidence")
                continue
            # Clear any previously-tagged chain ids — we re-run chain
            # detection on the unified set after merging so per-target
            # chain ids would otherwise collide.
            finding.pop("chain_id", None)
            finding.pop("chain_role", None)
            seen[key] = finding
    out["findings"] = list(seen.values())

    # Re-run chain detection over the merged set. Operators can pass
    # --no-chains to skip this stage entirely for ultra-quick smoke
    # scans; chain rollups below become naturally empty.
    if skip_chains:
        out["chains"] = []
        log.info("Chain detection skipped (--no-chains).")
    else:
        # Lazy import because mobile_scan is sometimes invoked from
        # contexts where the scripts dir isn't on the path.
        try:
            sys.path.insert(0, str(SCRIPTS_DIR))
            import chain_detector  # type: ignore
            out["findings"], out["chains"] = chain_detector.detect_chains(
                out["findings"], service_graph=None
            )
            # If any individual chain pattern raised (caught by chain_detector's
            # per-pattern _safe wrapper), surface them in scan_metadata so
            # operators can spot regressions without grepping logs.
            pattern_failures = list(getattr(chain_detector, "LAST_PATTERN_FAILURES", []) or [])
            if pattern_failures:
                # setdefault doesn't replace an existing None value with
                # the default — guard explicitly so we don't crash with
                # "NoneType doesn't support item assignment" if a
                # caller wrote scan_metadata: null.
                if not isinstance(out.get("scan_metadata"), dict):
                    out["scan_metadata"] = {}
                out["scan_metadata"]["chain_pattern_failures"] = pattern_failures
                log.warning(
                    "Chain detection completed with %d pattern failure(s); see scan_metadata.chain_pattern_failures",
                    len(pattern_failures),
                )
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("Chain re-detection skipped: %s", exc)

    # Recompute summary
    summary = out["summary"]
    for f in out["findings"]:
        if f.get("kind") == "hotspot":
            summary["total_hotspots"] += 1
        else:
            sev = (f.get("severity") or "low").lower()
            summary[sev] = summary.get(sev, 0) + 1
            summary["total_findings"] += 1
    # Roll up chains by pattern + by severity. Dashboards and SLO
    # reports want counts they can chart without re-reading chains.
    # Keys are sorted (pattern alphabetically, severity by canonical
    # priority) so the merged JSON byte-diffs stably across runs.
    chain_pattern_counts: dict[str, int] = {}
    chain_severity_counts: dict[str, int] = {}
    for c in out.get("chains", []):
        pat = c.get("pattern") or "unknown"
        chain_pattern_counts[pat] = chain_pattern_counts.get(pat, 0) + 1
        sev = c.get("severity") or "info"
        chain_severity_counts[sev] = chain_severity_counts.get(sev, 0) + 1
    # Local copy of artifact_utils.SEVERITY_ORDER. Kept literal because
    # this function fires before mobile_scan's lazy artifact_utils
    # import (line ~470, inside --validate-suppressions). Keep in sync
    # with the public constant if the tier list ever changes.
    _SEV_ORDER = ["critical", "high", "medium", "low", "info"]
    summary["total_chains"] = len(out.get("chains", []))
    summary["chains_by_pattern"] = {
        k: chain_pattern_counts[k] for k in sorted(chain_pattern_counts)
    }
    summary["chains_by_severity"] = {
        sev: chain_severity_counts[sev]
        for sev in _SEV_ORDER
        if sev in chain_severity_counts
    }
    return out


_URL_HOST_RE = re.compile(r"""["']https?://([a-zA-Z0-9.\-]+)""")
_PINNED_DOMAINS_RE = re.compile(r"network_security_config pins only: (.+)")


def _collect_hosts_across(targets: list[Path], max_files: int = 8000) -> list[str]:
    """Walk Java/Kotlin sources across every discovered target.

    Per-target detectors (e.g. ``detect_network_security_config_gaps``) only
    see files under their own root, so the NSC narrow-pinning finding —
    which fires on ``apktool_out/res/xml/...`` — never gets to learn which
    hosts the *jadx_out* code actually reaches. We do that join here.
    """
    hosts: set[str] = set()
    seen_files = 0
    for tgt in targets:
        if not tgt.is_dir():
            continue
        for p in tgt.rglob("*"):
            if seen_files >= max_files:
                break
            if p.suffix not in {".java", ".kt"}:
                continue
            seen_files += 1
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            for h in _URL_HOST_RE.findall(text):
                if "." in h and "%" not in h:
                    hosts.add(h)
    return sorted(hosts)


def _enrich_nsc_finding(merged: dict[str, Any], targets: list[Path]) -> None:
    """Augment ``mobile-nsc-narrow-pinning`` with cross-target unpinned hosts.

    Mutates ``merged`` in place. No-op when the finding doesn't exist or is
    already enriched (idempotent for repeat runs).
    """
    nsc = None
    for f in merged.get("findings", []):
        if f.get("type") == "mobile-nsc-narrow-pinning":
            nsc = f
            break
    if not nsc:
        return
    message = nsc.get("message", "")
    if "App code references" in message:
        return  # already enriched (e.g. when both sides see Java)
    title = nsc.get("title") or nsc.get("description") or ""
    m = _PINNED_DOMAINS_RE.search(title) or _PINNED_DOMAINS_RE.search(message)
    pinned: list[str] = []
    if m:
        pinned = [d.strip() for d in m.group(1).split(",") if d.strip()]
    else:
        # Fall back to evidence
        for e in nsc.get("evidence", []) or []:
            if isinstance(e, dict):
                snippet = e.get("snippet") or e.get("text") or ""
                if snippet:
                    pinned.extend([d.strip() for d in snippet.split(",") if d.strip()])
    app_hosts = _collect_hosts_across(targets)
    if not app_hosts:
        return
    unpinned = [
        h for h in app_hosts
        if not any(pd == h or h.endswith("." + pd) for pd in pinned)
    ]
    if not unpinned:
        return
    sample = ", ".join(unpinned[:5])
    nsc["message"] = (
        message.rstrip()
        + f" App code references {len(unpinned)} other host(s) "
        + f"(sample: {sample}) that fall back to system CA trust."
    )
    nsc.setdefault("metadata", {})["unpinned_hosts"] = unpinned[:50]


def _finding_key(finding: dict[str, Any]) -> str:
    if finding.get("stable_key"):
        return finding["stable_key"]
    # Fallback to file:line:type — but only if at least one component
    # is non-empty. Without that guard, every finding lacking all three
    # fields collapses to "None:None:None" and gets deduped into one
    # bucket by the diff. Final fallback is the finding's own `id`.
    f, l, t = finding.get("file"), finding.get("line"), finding.get("type")
    if f or l or t:
        return f"{f}:{l}:{t}"
    return finding.get("id") or "anon"


def _trim_to_top_chains(merged: dict[str, Any], top_n: int) -> None:
    """Keep only the top-N chains by severity; clear orphan finding tags.

    Mutates `merged` in place. Chains are already sorted worst-first by
    the chain detector, so slicing preserves the priority order. Findings
    that were tagged with a dropped chain get their `chain_id`,
    `chain_role`, and `chain_pattern` cleared so downstream tools don't
    dangle references to chains that aren't in the output.
    """
    chains = merged.get("chains") or []
    if len(chains) <= top_n:
        return
    kept = chains[:top_n]
    kept_ids = {c.get("id") for c in kept if c.get("id")}
    merged["chains"] = kept
    for f in merged.get("findings", []):
        cid = f.get("chain_id")
        if cid and cid not in kept_ids:
            f.pop("chain_id", None)
            f.pop("chain_role", None)
            f.pop("chain_pattern", None)
        # Drop dangling chain_participations entries for chains that got
        # trimmed — otherwise downstream renderers (markdown, submission
        # template) reference a chain that's not in `merged["chains"]`.
        participations = f.get("chain_participations") or []
        if participations:
            kept = [
                p for p in participations
                if isinstance(p, dict) and p.get("chain_id") in kept_ids
            ]
            if kept:
                f["chain_participations"] = kept
            else:
                f.pop("chain_participations", None)


def _compute_diff(prior: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    # `dict.get("findings", [])` returns the default only when the key
    # is absent — if the key is present but explicitly None, the get()
    # returns None and iteration crashes. Add `or []` for robustness.
    # Skip suppressed findings — mirror the chain-diff logic at line ~421.
    # A finding the operator silenced via suppression rules shouldn't
    # surface in the new/gone/kept diff buckets, otherwise it leaks
    # back into dashboards the suppression was meant to clean up.
    prior_keys = {
        _finding_key(f) for f in (prior.get("findings") or [])
        if not f.get("suppressed")
    }
    cur_by_key = {
        _finding_key(f): f for f in (current.get("findings") or [])
        if not f.get("suppressed")
    }
    cur_keys = set(cur_by_key.keys())
    new_keys = sorted(cur_keys - prior_keys)
    gone_keys = sorted(prior_keys - cur_keys)
    kept_keys = sorted(cur_keys & prior_keys)
    diff: dict[str, Any] = {
        "new": [
            {"key": k, "type": cur_by_key[k].get("type"), "severity": cur_by_key[k].get("severity"),
             "file": cur_by_key[k].get("file"), "line": cur_by_key[k].get("line")}
            for k in new_keys
        ],
        "gone": [{"key": k} for k in gone_keys],
        "kept": [{"key": k} for k in kept_keys],
    }
    # Chain-level diff: same shape, keyed by chain stable_key (deterministic
    # across scans). Reviewers can see "the deeplink→WebView chain went away"
    # without having to compare individual findings.
    # Exclude suppressed chains from the diff. A chain the operator
    # silenced via chain_pattern: rules shouldn't appear in new/gone/kept
    # buckets — that would resurface it in dashboards the suppression
    # is meant to clean up.
    prior_chains = {
        c.get("stable_key"): c for c in (prior.get("chains") or [])
        if c.get("stable_key") and not c.get("suppressed")
    }
    cur_chains = {
        c.get("stable_key"): c for c in (current.get("chains") or [])
        if c.get("stable_key") and not c.get("suppressed")
    }
    new_chain_keys = sorted(set(cur_chains) - set(prior_chains))
    gone_chain_keys = sorted(set(prior_chains) - set(cur_chains))
    kept_chain_keys = sorted(set(cur_chains) & set(prior_chains))
    # Detect chain severity drift: a chain that survived but escalated or
    # de-escalated is reviewer-actionable in a different way than new/gone
    # chains, so we surface it as its own bucket.
    # Local copy of artifact_utils.SEVERITY_RANK — see merge_findings()
    # for the why (lazy import ordering). Keep in sync with the public
    # constant in artifact_utils.
    _SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    escalated: list[dict[str, Any]] = []
    for k in kept_chain_keys:
        prior_sev = prior_chains[k].get("severity") or "info"
        cur_sev = cur_chains[k].get("severity") or "info"
        if prior_sev == cur_sev:
            continue
        direction = (
            "escalated" if _SEV_RANK.get(cur_sev, 0) > _SEV_RANK.get(prior_sev, 0)
            else "de-escalated"
        )
        escalated.append({
            "stable_key": k,
            "name": cur_chains[k].get("name"),
            "pattern": cur_chains[k].get("pattern"),
            "from_severity": prior_sev,
            "to_severity": cur_sev,
            "direction": direction,
        })
    diff["chains"] = {
        "new": [
            {"stable_key": k, "name": cur_chains[k].get("name"),
             "pattern": cur_chains[k].get("pattern"),
             "severity": cur_chains[k].get("severity")}
            for k in new_chain_keys
        ],
        "gone": [
            {"stable_key": k, "name": prior_chains[k].get("name"),
             "pattern": prior_chains[k].get("pattern")}
            for k in gone_chain_keys
        ],
        "kept": [{"stable_key": k} for k in kept_chain_keys],
        "severity_drift": escalated,
    }
    return diff


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnScout mobile audit driver")
    # --validate-suppressions short-circuits before requiring `path`,
    # acting as a lint pass for .vuln-scout-ignore files. Reports
    # unknown chain_pattern slugs, invalid severity levels, and empty
    # patterns. Exits non-zero if any issues found.
    if "--validate-suppressions" in sys.argv[1:]:
        try:
            idx = sys.argv.index("--validate-suppressions")
            if idx + 1 >= len(sys.argv):
                log.error("--validate-suppressions requires a file path")
                return 1
            supp_path = Path(sys.argv[idx + 1])
            # Convenience: if the operator passes a directory, look for
            # `.vuln-scout-ignore` inside it. Matches the auto-discovery
            # behavior of --suppressions during a normal scan.
            if supp_path.is_dir():
                candidate = supp_path / ".vuln-scout-ignore"
                if candidate.is_file():
                    log.info("Validating %s (auto-resolved from %s)", candidate, supp_path)
                    supp_path = candidate
            if not supp_path.is_file():
                log.error("Suppressions file not found: %s", supp_path)
                return 1
            sys.path.insert(0, str(SCRIPTS_DIR))
            import artifact_utils as _au  # type: ignore
            import chain_detector as _cd  # type: ignore
            rules = _au.parse_suppressions(supp_path)
            known_slugs = set(_cd._CHAIN_NAME_TO_PATTERN.values())
            # Pull from artifact_utils so a future severity-tier change
            # is picked up automatically by the linter.
            known_severities = _au.VALID_SEVERITIES
            # Canonical stable_key shape: `vscout:<12-hex>`. Operator
            # typos like `vscout:legacy_accepted` are common after a
            # copy/paste accident.
            stable_key_shape = re.compile(r"^vscout:[0-9a-f]{12}$")
            # Collect all warnings with their line numbers, then sort
            # by line before printing so the output reads top-to-bottom
            # of the file (like a normal linter).
            warnings: list[tuple[int, str]] = []
            seen_keys: dict[str, int] = {}
            rule_lines: dict[str, int] = {}
            # Use explicit UTF-8 with replace for robustness — operators
            # on Windows / older Linux systems may have locales that
            # default to something else, and we'd rather lint a slightly
            # munged file than crash.
            ignore_text = supp_path.read_text(encoding="utf-8", errors="replace")
            for line_num, raw_line in enumerate(ignore_text.splitlines(), 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                key = stripped.split(maxsplit=1)[0]
                if key in seen_keys:
                    warnings.append((
                        line_num,
                        f"{supp_path}:{line_num}: warn: duplicate rule key {key!r} (first at line {seen_keys[key]})",
                    ))
                else:
                    seen_keys[key] = line_num
                    rule_lines.setdefault(key, line_num)
            for key, _reason in rules.items():
                ln = rule_lines.get(key, 0)
                loc = f"{supp_path}:{ln}: " if ln else ""
                if key.startswith("vscout:"):
                    if not stable_key_shape.match(key):
                        warnings.append((ln, f"{loc}warn: stable_key doesn't match `vscout:<12-hex>` shape: {key!r}"))
                    continue
                if key.startswith(_au.SUPP_PREFIX_CHAIN_PATTERN):
                    slug = key[len(_au.SUPP_PREFIX_CHAIN_PATTERN):].lstrip()
                    if not slug:
                        warnings.append((ln, f"{loc}warn: empty chain_pattern slug"))
                    elif "*" in slug or "?" in slug:
                        # Best-effort wildcard check: if the glob matches
                        # ZERO known static slugs, the operator likely
                        # typo'd (e.g., `mobile-debugable-*` missing g).
                        # Don't warn on patterns that could match a
                        # dynamic web/service slug (ssrf-to-*, etc).
                        matches_dynamic = any(
                            slug.startswith(p) for p in ("ssrf-", "auth-bypass-", "path-traversal-")
                        )
                        if not matches_dynamic and not any(
                            fnmatch.fnmatch(s, slug) for s in known_slugs
                        ):
                            warnings.append((ln,
                                f"{loc}warn: chain_pattern glob {slug!r} matches no known slug "
                                "(run --list-chain-patterns)"
                            ))
                    elif slug not in known_slugs:
                        warnings.append((ln, f"{loc}warn: unknown chain_pattern slug: {slug!r} (run --list-chain-patterns)"))
                elif key.startswith(_au.SUPP_PREFIX_SEVERITY):
                    lvl = key[len(_au.SUPP_PREFIX_SEVERITY):].strip().lower()
                    if lvl not in known_severities:
                        warnings.append((ln, f"{loc}warn: unknown severity level: {lvl!r} (expected: {', '.join(sorted(known_severities))})"))
                elif key.startswith(_au.SUPP_PREFIX_FILE):
                    pat = key[len(_au.SUPP_PREFIX_FILE):].strip()
                    if not pat:
                        warnings.append((ln, f"{loc}warn: empty file: glob"))
                else:
                    # Unknown rule prefix: not vscout:, chain_pattern:,
                    # severity:, or file:. apply_suppressions silently
                    # ignores it, so the operator's rule never fires.
                    # Flag so they know to fix the prefix.
                    warnings.append((ln,
                        f"{loc}warn: unknown rule prefix in {key!r} "
                        "(expected vscout:, chain_pattern:, severity:, or file:)"
                    ))
            # Emit warnings sorted by line number — reads top-to-bottom
            # of the file, easier to scan and fix.
            warnings.sort(key=lambda w: (w[0], w[1]))
            for _, msg in warnings:
                print(msg)
            issues = len(warnings)
            if issues:
                print(f"\n{issues} issue(s) found in {supp_path}", file=sys.stderr)
                return 1
            # Break the count down by rule type so operators can verify
            # their .vuln-scout-ignore mix matches expectations.
            by_type = {"stable_key": 0, "chain_pattern": 0,
                       "file_glob": 0, "severity_floor": 0}
            for key in rules:
                if key.startswith("vscout:"):
                    by_type["stable_key"] += 1
                elif key.startswith(_au.SUPP_PREFIX_CHAIN_PATTERN):
                    by_type["chain_pattern"] += 1
                elif key.startswith(_au.SUPP_PREFIX_FILE):
                    by_type["file_glob"] += 1
                elif key.startswith(_au.SUPP_PREFIX_SEVERITY):
                    by_type["severity_floor"] += 1
            bits = [f"{count} {name}" for name, count in by_type.items() if count]
            breakdown = " (" + ", ".join(bits) + ")" if bits else ""
            print(f"ok: {supp_path} ({len(rules)} rules{breakdown})")
            return 0
        except Exception as exc:
            log.error("Validation failed: %s", exc)
            return 1
    # --list-chain-patterns short-circuits before requiring `path`, so it
    # works as a quick reference command for `.vuln-scout-ignore` authors.
    # Pair with `--list-chain-patterns-format json` for tooling.
    if "--list-chain-patterns" in sys.argv[1:]:
        try:
            sys.path.insert(0, str(SCRIPTS_DIR))
            import chain_detector as _cd  # type: ignore
            entries = _cd.list_chain_patterns()
            as_json = "--list-chain-patterns-format" in sys.argv[1:] and (
                sys.argv[sys.argv.index("--list-chain-patterns-format") + 1] == "json"
                if sys.argv.index("--list-chain-patterns-format") + 1 < len(sys.argv)
                else False
            )
            if as_json:
                print(json.dumps(entries, indent=2))
            else:
                # Usage hint at the top makes the output self-documenting:
                # operators don't have to cross-reference docs to know how
                # to use these slugs.
                print("# Known chain pattern slugs for .vuln-scout-ignore rules.")
                print("# Usage: chain_pattern:<slug>  optional reason text")
                print("# Wildcards (fnmatch) supported: chain_pattern:*-webview-*")
                print()
                for entry in entries:
                    print(f"{entry['pattern']:35s}  {entry['name']}")
            return 0
        except Exception as exc:
            log.error("Failed to load chain patterns: %s", exc)
            return 1
    parser.add_argument("path", help="Mobile target root (containing jadx_out/apktool_out)")
    parser.add_argument(
        "--profile", default="quick", choices=["quick", "deep", "audit"],
        help="Scan profile (default: quick). `quick` uses local Semgrep rules "
             "only; `deep` adds the Semgrep registry + installed analyzers; "
             "`audit` runs the deterministic baseline (semgrep + joern + "
             "codeql + secrets, offline).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to merged findings.json (default: <target>/.claude/findings.json)",
    )
    parser.add_argument(
        "--orchestrator-arg",
        action="append",
        default=[],
        metavar="ARG",
        help="Extra argument to pass through to scan_orchestrator. Repeatable. "
             "Example: --orchestrator-arg --tools --orchestrator-arg semgrep,joern "
             "(prepends both tokens to the inner scan_orchestrator invocation).",
    )
    parser.add_argument(
        "--suppressions",
        default=None,
        help="Path to a .vuln-scout-ignore file. If omitted, the driver looks for "
             "<target>/.vuln-scout-ignore.",
    )
    parser.add_argument(
        "--format",
        default="json",
        choices=["json", "md"],
        help="Output format: json (default) writes the merged findings artifact; "
             "md additionally emits a markdown report next to the JSON output.",
    )
    parser.add_argument(
        "--diff-against",
        default=None,
        help="Path to a prior findings.json. If provided, the merged output gets "
             "a `diff` block listing keys that are new (added since the prior "
             "scan), gone (resolved or no-longer-detected), and kept.",
    )
    parser.add_argument(
        "--list-chain-patterns",
        action="store_true",
        help="Print the known chain pattern slugs (e.g. mobile-token-replay) "
             "with their human names and exit. Use this to discover slugs "
             "for `chain_pattern:<slug>` rules in .vuln-scout-ignore.",
    )
    parser.add_argument(
        "--validate-suppressions",
        metavar="PATH",
        default=None,
        help="Lint a .vuln-scout-ignore file: warn on unknown chain_pattern "
             "slugs, invalid severity levels, and empty patterns. Exits "
             "non-zero if issues found. Short-circuits before requiring a "
             "target path.",
    )
    parser.add_argument(
        "--list-chain-patterns-format",
        default="text",
        choices=["text", "json"],
        help="Output format for --list-chain-patterns (default: text).",
    )
    parser.add_argument(
        "--no-chains",
        action="store_true",
        help="Skip chain detection. Output contains findings but `chains: []` "
             "and no chain-aware enrichments. Useful for ultra-quick smoke "
             "scans where the operator only wants the raw finding list.",
    )
    parser.add_argument(
        "--top-chains",
        type=int,
        default=None,
        metavar="N",
        help="Keep only the top N chains by severity in the output (chains are "
             "already sorted worst-first). Dropped chains are removed from the "
             "`chains` array; participant findings stay in `findings` but lose "
             "their chain_id/chain_role/chain_pattern tags so reports don't "
             "dangle. Useful for triagers who only want the highest-impact "
             "primitives in CI noise.",
    )
    args = parser.parse_args()
    # Flag-compatibility validation. --no-chains disables chain detection
    # entirely, so any chain-shaping flag is incoherent. Refuse the
    # combination explicitly rather than silently no-op'ing.
    if args.no_chains and args.top_chains is not None:
        parser.error("--no-chains is incompatible with --top-chains (no chains to trim)")
    if args.top_chains is not None and args.top_chains < 0:
        parser.error(
            f"--top-chains must be >= 0 (got {args.top_chains}). "
            "Use 0 to drop all chains, --no-chains to skip detection entirely."
        )
    if args.no_chains and args.diff_against:
        log.warning(
            "--no-chains + --diff-against: chain-level diff fields will be empty "
            "(finding-level diff still produced).",
        )

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)

    root = Path(args.path).resolve()
    if not root.is_dir():
        log.error("Target path is not a directory: %s", root)
        return 1

    targets = discover_mobile_targets(root)
    log.info("Discovered %d mobile target(s):", len(targets))
    for t in targets:
        log.info("  - %s", t)

    # Resolve suppressions: explicit flag wins, else look at <target>/.vuln-scout-ignore
    suppressions_path: Path | None = None
    if args.suppressions:
        suppressions_path = Path(args.suppressions).resolve()
        if not suppressions_path.is_file():
            log.warning("Suppressions file not found: %s", suppressions_path)
            suppressions_path = None
    else:
        default_supp = root / ".vuln-scout-ignore"
        if default_supp.is_file():
            suppressions_path = default_supp
            log.info("Using suppressions from %s", suppressions_path)

    artifacts: list[Path] = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for i, target in enumerate(targets):
            out_path = tmp_dir / f"target-{i}.json"
            rc = _run_orchestrator(
                target, args.orchestrator_arg, out_path, args.profile,
                suppressions=suppressions_path,
            )
            if rc != 0:
                log.warning("Scan returned non-zero exit for %s (rc=%d) — continuing", target, rc)
            if out_path.is_file():
                artifacts.append(out_path)

        merged = merge_findings(artifacts, skip_chains=args.no_chains)
        _enrich_nsc_finding(merged, targets)
        if args.top_chains is not None and args.top_chains >= 0:
            _trim_to_top_chains(merged, args.top_chains)

    output = (
        Path(args.output).resolve()
        if args.output
        else (root / ".claude" / "findings.json")
    )
    # Optional diff against a prior scan
    if args.diff_against:
        prior_path = Path(args.diff_against).resolve()
        if prior_path.is_file():
            try:
                prior = json.loads(prior_path.read_text())
                merged["diff"] = _compute_diff(prior, merged)
                log.info(
                    "Diff vs %s: +%d new, -%d gone, =%d kept",
                    prior_path,
                    len(merged["diff"]["new"]),
                    len(merged["diff"]["gone"]),
                    len(merged["diff"]["kept"]),
                )
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("Failed to read prior artifact %s: %s", prior_path, exc)
        else:
            log.warning("Prior artifact not found: %s", prior_path)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(merged, indent=2, sort_keys=False))
    log.info(
        "Merged %d findings (%d hotspots) across %d targets -> %s",
        merged["summary"]["total_findings"],
        merged["summary"]["total_hotspots"],
        len(targets),
        output,
    )

    if args.format == "md":
        md_output = output.with_suffix(".md")
        try:
            sys.path.insert(0, str(SCRIPTS_DIR))
            import markdown_report  # type: ignore
            md_output.write_text(markdown_report.generate(merged))
            log.info("Markdown report -> %s", md_output)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("Markdown rendering failed: %s", exc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
