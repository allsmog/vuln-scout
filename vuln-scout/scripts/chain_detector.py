#!/usr/bin/env python3
"""Automated attack chain detection.

Analyzes findings and service topology to automatically populate the
``chains`` array and ``chain_id``/``chain_role`` fields in findings.json.

Chain patterns detected (web/service):
  - Pattern 1: SSRF → internal service sink (RCE/SSTI/SQLi)
  - Pattern 2: SSRF → cloud metadata (169.254.169.254)
  - Pattern 3: Auth bypass → admin-only vulnerability
  - Pattern 4: Path traversal → secret/config read
  - Pattern 5: Same-file vulnerability stacking

Chain patterns detected (mobile):
  - Pattern 6: WebView dispatch (remote URL + JS literal + bridge)
  - Pattern 7: MITM precondition + remote-influenced flow (Android + iOS)
  - Pattern 8: Backup-extractable token chain (allowBackup + plain prefs)
  - Pattern 9: Deeplink → in-WebView dispatch chain
  - Pattern 10: Permission-relay (exported component + intent-redirection)
  - Pattern 11: Token-replay (plain-prefs token + bundled GraphQL mutation)
  - Pattern 12: Gadget-landing (exported entry + Java deserialization sink)
  - Pattern 13: iOS WebView injection (HTML/JS concat + ATS gap)
  - Pattern 14: iOS credential-at-rest + transport gap (kSecAttrAccessibleAlways + ATS off)
  - Pattern 15: Debuggable + in-memory secret (debuggable=true + plain prefs / hardcoded JWT / log-sensitive)
  - Pattern 16: Token double-exposure (plain-prefs storage + log of the same token name)
  - Pattern 17: Predictable-token (insecure RNG + plain-prefs storage)

Each chain carries:
  - ``id``: sequential ``chain-NNN`` within this scan
  - ``stable_key``: deterministic SHA1 of name + sorted participant stable_keys
    (same chain → same key across scans; enables diff-against workflows)
  - ``pattern``: programmatic slug for filtering / suppression rules
  - ``severity``: max participant severity
  - ``confidence``: min participant confidence (post-chain-context boost)
  - ``cvss_estimate``: severity-band midpoint (numeric, 0.0–9.5)
  - ``cwes``: sorted CWE-NNN array aggregated from impact + participants
  - ``finding_ids``: list of contributing findings
  - ``impact`` / ``flow_description``: human-readable narrative

Findings inside chains carry ``chain_id``, ``chain_role``, ``chain_pattern``,
and ``chain_cwes`` (single-valued, primary chain), plus a
``chain_participations[{chain_id, role, pattern}, ...]`` list for findings
in multiple chains. Low-confidence findings get promoted to medium when
chain context corroborates them (``metadata.confidence_boosted_by_chain``).

Per-pattern failures during ``detect_chains`` are caught (``_safe`` wrapper)
and recorded on ``LAST_PATTERN_FAILURES`` for the calling module to surface
in ``scan_metadata.chain_pattern_failures``.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from artifact_utils import SEVERITY_RANK as _SEVERITY_RANK
from service_graph import ServiceGraph

_CWE_RE = re.compile(r"\bCWE-(\d{1,5})\b")

# Populated by detect_chains with any per-pattern exceptions caught
# during the last invocation. Consumers (mobile_scan, scan_orchestrator)
# read this after the call to surface failures in scan_metadata.
LAST_PATTERN_FAILURES: list[dict[str, str]] = []

# Public API surface — everything else (`_safe`, `_stamp_*`, `_detect_*`,
# `_CHAIN_NAME_TO_PATTERN`) is implementation detail. External callers
# should only import these names.
__all__ = [
    "detect_chains",
    "list_chain_patterns",
    "LAST_PATTERN_FAILURES",
]

log = logging.getLogger("vuln-scout")

# Vulnerability types that serve as chain entry points (enable reaching other services)
ENTRY_TYPES = {"ssrf", "open-redirect", "path-traversal"}

# Vulnerability types that serve as high-impact chain sinks
SINK_TYPES = {
    "sql-injection", "command-injection", "ssti", "deserialization",
    "code-injection", "xxe", "reentrancy",
}

# Types that serve as pivot points (enable escalation but aren't final impact)
PIVOT_TYPES = {"ssrf", "path-traversal", "idor", "auth-bypass"}

# Cloud metadata IP patterns
CLOUD_METADATA_INDICATORS = {"169.254.169.254", "metadata.google", "metadata.azure"}


def detect_chains(
    findings: list[dict[str, Any]],
    service_graph: ServiceGraph | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Detect attack chains in the findings list.

    Args:
        findings: List of normalized findings.
        service_graph: Optional service topology for cross-service chains.

    Returns:
        Tuple of (updated_findings, chains) where chains is the list to put
        in artifact["chains"].
    """
    # Reset in place via .clear() — if a caller did
    # `from chain_detector import LAST_PATTERN_FAILURES`, they hold a
    # reference to the original list and a rebind (`= []`) would orphan
    # their view. .clear() mutates the same list so every reader sees
    # the reset.
    LAST_PATTERN_FAILURES.clear()

    chains: list[dict[str, Any]] = []
    chain_counter = 0

    # Each pattern runs in isolation — a buggy or in-development pattern
    # detector shouldn't kill the whole chain pipeline. Failures are
    # logged, recorded on LAST_PATTERN_FAILURES, and skipped so the
    # remaining patterns still produce chains.
    def _safe(name: str, fn, *args):
        nonlocal chain_counter
        try:
            result = fn(*args, chains, chain_counter)
            # Defend against a pattern function that forgets to return
            # the incremented counter (returns None) — keep the old
            # value so subsequent patterns get a valid int rather than
            # crashing with `chain-NoneType` formatting. Reject bool
            # explicitly: isinstance(True, int) is True in Python
            # because bool subclasses int, so without the bool guard a
            # function returning True/False would reset the counter
            # to 1/0 and clobber subsequent chain IDs.
            if isinstance(result, int) and not isinstance(result, bool):
                chain_counter = result
            else:
                log.warning(
                    "[chain-pattern-failure] pattern=%s error=non-int-counter: returned %r",
                    name, result,
                )
                LAST_PATTERN_FAILURES.append({
                    "pattern": name,
                    "error": f"non-int counter return: {type(result).__name__}",
                })
        except Exception as exc:
            # Stable marker `[chain-pattern-failure]` for greppable
            # log analysis across multi-target / CI runs.
            log.warning(
                "[chain-pattern-failure] pattern=%s error=%s: %s",
                name, type(exc).__name__, exc,
            )
            LAST_PATTERN_FAILURES.append({
                "pattern": name,
                "error": f"{type(exc).__name__}: {exc}",
            })

    # --- Pattern 1: SSRF → internal service sink ---
    _safe("ssrf-to-sink", _detect_ssrf_to_sink, findings, service_graph)

    # --- Pattern 2: SSRF → cloud metadata ---
    _safe("ssrf-to-metadata", _detect_ssrf_to_metadata, findings)

    # --- Pattern 3: Auth bypass → privileged vuln ---
    _safe("auth-bypass", _detect_auth_bypass_escalation, findings)

    # --- Pattern 4: Path traversal → credential/config read ---
    _safe("path-traversal-secrets", _detect_path_traversal_to_secrets, findings)

    # --- Pattern 5: Same-file vulnerability stacking ---
    _safe("same-file-stack", _detect_same_file_chains, findings)

    # --- Pattern 6: Mobile WebView dispatch chains (tokenization-WebView shape) ---
    _safe("mobile-webview-dispatch", _detect_mobile_webview_chains, findings)

    # --- Pattern 7: Mobile MITM precondition chains (no pinning + sensitive flow) ---
    _safe("mobile-mitm-precondition", _detect_mobile_mitm_chains, findings)

    # --- Pattern 8: Mobile backup exfil chain (allowBackup + plain prefs token) ---
    _safe("mobile-backup-exfil", _detect_mobile_backup_exfil_chain, findings)

    # --- Pattern 9: Mobile deeplink → WebView intent-redirection chain ---
    _safe("mobile-deeplink-webview", _detect_mobile_deeplink_webview_chain, findings)

    # --- Pattern 10: Mobile permission-relay (exported-component + intent-redirection) ---
    _safe("mobile-permission-relay", _detect_mobile_permission_relay_chain, findings)

    # --- Pattern 11: Token-extraction + sensitive GraphQL mutation replay chain ---
    _safe("mobile-token-replay", _detect_mobile_token_replay_chain, findings)

    # --- Pattern 12: Mobile gadget-landing (exported entry + Java deserialization) ---
    _safe("mobile-gadget-landing", _detect_mobile_gadget_landing_chain, findings)

    # --- Pattern 13: iOS WebView injection chain (HTML/JS concat + ATS / trust-all) ---
    _safe("ios-webview-injection", _detect_ios_webview_injection_chain, findings)

    # --- Pattern 14: iOS credential-at-rest exfil chain (keychain always-accessible + ATS off) ---
    _safe("ios-credential-at-rest", _detect_ios_credential_at_rest_chain, findings)

    # --- Pattern 15: Mobile debuggable + sensitive secret-in-memory chain ---
    _safe("mobile-debuggable-secret", _detect_mobile_debuggable_secret_chain, findings)

    # --- Pattern 16: Mobile token double-exposure (plain prefs + log of same token) ---
    _safe("mobile-token-double-exposure", _detect_mobile_token_double_exposure_chain, findings)

    # --- Pattern 17: Mobile predictable-token chain (insecure RNG + plain prefs) ---
    _safe("mobile-predictable-token", _detect_mobile_predictable_token_chain, findings)

    # Annotate each chain with a programmatic `pattern` slug derived from
    # its name. Downstream filters can pivot on `pattern == "mobile-token-replay"`
    # rather than substring-matching the human-readable name.
    _stamp_chain_pattern_slugs(chains)

    # Annotate each chain with a stable_key derived from its participants'
    # stable_keys (or finding IDs / file:line as fallback). The same chain
    # re-appearing in a later scan should hash to the same key so reviewers
    # can diff chains across runs.
    _stamp_chain_stable_keys(findings, chains)

    # Rank each chain by the max severity of its participants. Reviewers
    # should see the worst chain first, not the first-detected one.
    _rank_chains_by_max_severity(findings, chains)

    # Aggregate CWE IDs from the chain's own impact string AND from
    # each participant finding's message. Stored as chain.cwes (a sorted
    # list of "CWE-NNN" strings) for compliance/dashboard tooling.
    _stamp_chain_cwes(findings, chains)

    # Propagate the chain's pattern slug onto each member finding so
    # downstream filters (`chain_pattern == "mobile-token-replay"`) work
    # without joining the chains array. Done before confidence boost so
    # boost-audit dumps include the pattern.
    _propagate_chain_pattern_to_findings(findings, chains)

    # A finding that's `confidence=low` in isolation but participates in a
    # chain has its concern corroborated by cross-finding context — the
    # dispatch path / precondition / payload site lives elsewhere in the
    # scan. Bump such findings to `medium` and record the reason so the
    # boost is auditable. Runs BEFORE chain confidence aggregation so
    # the chain reflects post-boost participant confidences.
    _boost_chain_member_confidence(findings)

    # Aggregate participant confidences into a chain-level confidence so
    # triagers can rank "all-high-confidence chain" above "mixed/low
    # chain" of the same severity. Uses post-boost participant
    # confidences so the chain reflects the final state.
    _stamp_chain_confidence(findings, chains)

    # Derive a numeric CVSS estimate from severity for SARIF
    # security-severity, dashboards, and CI gates that compare against
    # numeric thresholds.
    _stamp_chain_cvss_estimate(chains)

    if chains:
        log.info("Detected %d attack chains across %d findings",
                 len(chains),
                 sum(1 for f in findings if f.get("chain_id")))

    return findings, chains


# _SEVERITY_RANK is imported from artifact_utils at the top of the file
# so the dozens of downstream `_SEVERITY_RANK.get(...)` callsites stay
# unchanged. A future severity-tier addition only requires editing
# artifact_utils.SEVERITY_RANK.

# Maps chain names to programmatic pattern slugs. Downstream consumers
# (suppressions, alert routers, dashboards) can pivot on pattern instead
# of substring-matching the human-readable name, which is prose and may
# change wording.
def list_chain_patterns() -> list[dict[str, str]]:
    """Return every known chain pattern slug with its human-readable name.

    Authors of `.vuln-scout-ignore` files can use this to discover
    which `chain_pattern:<slug>` rules are available. Includes both
    the statically-mapped mobile/iOS slugs and the dynamic web/service
    slug prefixes (with explanatory text so users know to use a
    wildcard like `chain_pattern:ssrf-to-*`).
    """
    out: list[dict[str, str]] = [
        {"pattern": slug, "name": name}
        for name, slug in sorted(_CHAIN_NAME_TO_PATTERN.items(), key=lambda kv: kv[1])
    ]
    # Web/service chain slugs are derived from the dynamic chain name
    # (e.g., "SSRF → command-injection" → "ssrf-to-command-injection"),
    # so they vary per scan. Surface the prefixes so operators know
    # they can suppress with a wildcard.
    out.extend([
        {"pattern": "ssrf-to-*", "name": "SSRF → internal sink chains (dynamic)"},
        {"pattern": "auth-bypass-to-*", "name": "Auth bypass → privileged vuln chains (dynamic)"},
        {"pattern": "path-traversal-to-*", "name": "Path traversal → secret/credential chains (dynamic)"},
    ])
    return out


_CHAIN_NAME_TO_PATTERN = {
    "Mobile WebView dispatch chain": "mobile-webview-dispatch",
    "Mobile MITM precondition + remote-influenced flow": "mobile-mitm-precondition",
    "Mobile backup-extractable token chain": "mobile-backup-exfil",
    "Mobile deeplink → in-WebView dispatch chain": "mobile-deeplink-webview",
    "Mobile permission-relay chain": "mobile-permission-relay",
    "Mobile token-replay chain": "mobile-token-replay",
    "Mobile gadget-landing chain": "mobile-gadget-landing",
    "Mobile debuggable + in-memory secret chain": "mobile-debuggable-secret",
    "Mobile token double-exposure chain": "mobile-token-double-exposure",
    "Mobile predictable-token chain": "mobile-predictable-token",
    "iOS WebView injection chain": "ios-webview-injection",
    "iOS credential-at-rest + transport gap chain": "ios-credential-at-rest",
}


def _stamp_chain_pattern_slugs(chains: list[dict[str, Any]]) -> None:
    """Set chain['pattern'] from chain['name'] using the known mapping.

    Chains whose name isn't in the map get pattern derived from the name
    (lowercase, spaces→dashes) so newly-added chain detectors don't need
    to register here to get a usable slug.
    """
    for c in chains:
        name = c.get("name") or ""
        slug = _CHAIN_NAME_TO_PATTERN.get(name)
        if slug is None:
            slug = name.lower().replace(" ", "-").replace("→", "to").replace("+", "and")
            slug = "".join(ch for ch in slug if ch.isalnum() or ch == "-")
            slug = "-".join(s for s in slug.split("-") if s)  # collapse repeats
        c["pattern"] = slug


# Confidence priority used for chain.confidence stamping.
# "verified" is the strongest (the finding has a generated PoC or
# similar concrete evidence). "high" / "medium" / "low" are the rest of
# the VALID_CONFIDENCE vocabulary from artifact_utils. "unknown" is the
# fallback for findings missing a confidence field.
_CONFIDENCE_RANK = {"verified": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

# Conservative CVSS-3.1 midpoints per severity band. Chains aren't
# individually scored, so we use the band centroid; downstream tooling
# that wants exact CVSS should recompute from the participating
# findings.
_SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 0.0,
}


def _stamp_chain_cvss_estimate(chains: list[dict[str, Any]]) -> None:
    """Annotate each chain with a `cvss_estimate` numeric score.

    Uses the canonical CVSS-3.1 band midpoint for the chain's severity.
    Marked as `cvss_estimate` (not `cvss_score`) so consumers know it's
    a derived band midpoint rather than a per-vector calculation.
    """
    for c in chains:
        sev = c.get("severity") or "info"
        score = _SEVERITY_TO_CVSS.get(sev)
        if score is not None:
            c["cvss_estimate"] = score


def _stamp_chain_confidence(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
) -> None:
    """Set chain.confidence to the minimum confidence across its participants.

    A chain is only as confident as its weakest link — if even one
    participant is `low`, the chain's overall confidence is `low`. This
    is more conservative than "max" but better matches the triage
    intuition: a chain that depends on a low-confidence finding to fire
    is itself uncertain.
    """
    by_id = {f.get("id"): f for f in findings if f.get("id")}
    for c in chains:
        weakest = None
        weakest_rank = 999
        for fid in c.get("finding_ids") or []:
            f = by_id.get(fid)
            if not f:
                continue
            conf = f.get("confidence", "unknown")
            rank = _CONFIDENCE_RANK.get(conf, 0)
            if rank < weakest_rank:
                weakest_rank = rank
                weakest = conf
        if weakest:
            c["confidence"] = weakest


def _stamp_chain_cwes(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
) -> None:
    """Aggregate CWE IDs onto each chain.

    Sources: the chain's own `impact` string (where chain detectors
    already cite CWEs in prose), and each participating finding's
    `message` (where individual detectors do the same). Stored as a
    sorted list of `"CWE-NNN"` strings on `chain.cwes`.
    """
    by_id = {f.get("id"): f for f in findings if f.get("id")}
    for c in chains:
        cwes: set[str] = set()
        for m in _CWE_RE.findall(c.get("impact") or ""):
            cwes.add(f"CWE-{m}")
        for fid in c.get("finding_ids") or []:
            f = by_id.get(fid) or {}
            for m in _CWE_RE.findall(f.get("message") or ""):
                cwes.add(f"CWE-{m}")
        if cwes:
            c["cwes"] = sorted(cwes, key=lambda s: int(s.split("-")[1]))


def _propagate_chain_pattern_to_findings(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
) -> None:
    """Propagate chain.pattern + chain.cwes onto each member finding.

    Findings already carry `chain_id` and `chain_role`; adding the pattern
    slug means downstream filters (e.g. "ignore all findings in any
    mobile-debuggable-secret chain") don't need to join the chains array.
    Also stamps the pattern onto every entry in `chain_participations`
    so multi-chain findings can be filtered by any participation.

    Additionally aggregates `chain_cwes` across every chain the finding
    participates in — compliance dashboards can pivot on per-finding
    CWE lists without re-walking chains.
    """
    pattern_by_id = {
        c.get("id"): c.get("pattern")
        for c in chains
        if c.get("id") and c.get("pattern")
    }
    cwes_by_id = {
        c.get("id"): list(c.get("cwes") or [])
        for c in chains
        if c.get("id")
    }
    for f in findings:
        cid = f.get("chain_id")
        if cid and pattern_by_id.get(cid):
            f["chain_pattern"] = pattern_by_id[cid]
        # Backfill pattern slug on every participation entry. Skip
        # malformed entries (a hand-edited artifact may contain None
        # or non-dict items — we don't want to crash on those).
        for p in f.get("chain_participations") or []:
            if not isinstance(p, dict):
                continue
            pcid = p.get("chain_id")
            if pcid and pattern_by_id.get(pcid):
                p["pattern"] = pattern_by_id[pcid]
        # Aggregate CWEs from every chain this finding participates in.
        accumulated: set[str] = set()
        participation_ids: list[str] = []
        if cid:
            participation_ids.append(cid)
        for p in f.get("chain_participations") or []:
            if not isinstance(p, dict):
                continue
            pcid = p.get("chain_id")
            if pcid and pcid not in participation_ids:
                participation_ids.append(pcid)
        for pcid in participation_ids:
            for cwe in cwes_by_id.get(pcid) or []:
                accumulated.add(cwe)
        if accumulated:
            f["chain_cwes"] = sorted(
                accumulated, key=lambda s: int(s.split("-")[1])
            )


def _boost_chain_member_confidence(findings: list[dict[str, Any]]) -> None:
    """Promote `confidence=low` findings that ended up inside a chain.

    The reasoning: a `confidence=low` shared-prefs / WebView-JS / etc.
    finding is hedged because its dispatch path wasn't visible in the
    same file. Chain membership demonstrates that dispatch path exists
    elsewhere in the same scan — the hedge no longer applies.

    Records the bump on `metadata.confidence_boosted_by_chain = chain_id`
    so the escalation is auditable and reversible by downstream tooling.
    """
    for f in findings:
        if f.get("chain_id") and f.get("confidence") == "low":
            f["confidence"] = "medium"
            meta = f.setdefault("metadata", {})
            meta["confidence_boosted_by_chain"] = f.get("chain_id")


def _stamp_chain_stable_keys(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
) -> None:
    """Set chain['stable_key'] to a hash of its participants' stable_keys.

    The same chain in a later scan should hash to the same key — enabling
    diff-against workflows to recognize "this chain re-appeared / went away".
    """
    by_id = {f.get("id"): f for f in findings if f.get("id")}
    for c in chains:
        parts: list[str] = []
        for fid in c.get("finding_ids") or []:
            f = by_id.get(fid)
            if f and f.get("stable_key"):
                parts.append(str(f["stable_key"]))
            elif f:
                # Avoid the ":::" collapse — fall through to the finding
                # id if every component is empty.
                file_str = f.get("file", "") or ""
                line_str = str(f.get("line", "") or "")
                type_str = f.get("type", "") or ""
                if file_str or line_str or type_str:
                    parts.append(f"{file_str}:{line_str}:{type_str}")
                else:
                    parts.append(str(fid))
            else:
                parts.append(str(fid))
        parts.sort()
        h = hashlib.sha1(("|".join([c.get("name", "")] + parts)).encode("utf-8")).hexdigest()
        c["stable_key"] = f"chain-{h[:12]}"


def _rank_chains_by_max_severity(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
) -> None:
    """Annotate each chain with `severity` (= max participant severity) and
    sort the chain list so the worst chain comes first."""
    by_id = {f.get("id"): f for f in findings if f.get("id")}
    for c in chains:
        worst = 0
        worst_name = "info"
        for fid in c.get("finding_ids") or []:
            sev = (by_id.get(fid) or {}).get("severity") or "info"
            rank = _SEVERITY_RANK.get(sev, 0)
            if rank > worst:
                worst = rank
                worst_name = sev
        c["severity"] = worst_name
    # Primary: severity desc. Secondary: stable_key asc (deterministic
    # tie-breaker across runs — same chains in the same order). The
    # stable_key was just stamped by _stamp_chain_stable_keys above so
    # it's guaranteed present.
    chains.sort(
        key=lambda c: (
            -_SEVERITY_RANK.get(c.get("severity", "info"), 0),
            c.get("stable_key", ""),
        )
    )


def _detect_ssrf_to_sink(
    findings: list[dict[str, Any]],
    graph: ServiceGraph | None,
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """SSRF in external service + high-impact vuln in reachable internal service."""
    ssrf_findings = [f for f in findings if f.get("type") == "ssrf"]
    sink_findings = [f for f in findings if f.get("type") in SINK_TYPES]

    if not ssrf_findings or not sink_findings:
        return counter

    for ssrf in ssrf_findings:
        for sink in sink_findings:
            # Same-service SSRF→sink (e.g., SSRF to internal admin endpoint)
            if ssrf.get("file") == sink.get("file"):
                continue  # Skip same-file, handled by pattern 5

            # Different service -- if we have a service graph, check reachability
            connected = True
            if graph and graph.services:
                ssrf_svc = _file_to_service(ssrf.get("file", ""), graph)
                sink_svc = _file_to_service(sink.get("file", ""), graph)
                if ssrf_svc and sink_svc and ssrf_svc != sink_svc:
                    connected = sink_svc in graph.get_reachable_services(ssrf_svc)
                elif ssrf_svc == sink_svc:
                    connected = True

            if connected:
                counter += 1
                chain_id = f"chain-{counter:03d}"
                chain = {
                    "id": chain_id,
                    "name": f"SSRF → {sink.get('type', 'unknown')}",
                    "impact": f"SSRF at {ssrf.get('file')}:{ssrf.get('line')} enables reaching {sink.get('type')} at {sink.get('file')}:{sink.get('line')}",
                    "finding_ids": [ssrf.get("id", ""), sink.get("id", "")],
                    "flow_description": f"Attacker exploits SSRF to reach internal service, then exploits {sink.get('type')} for full compromise",
                }
                chains.append(chain)
                _tag_finding(ssrf, chain_id, "entry")
                _tag_finding(sink, chain_id, "sink")

    return counter


def _detect_ssrf_to_metadata(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """SSRF with cloud metadata access pattern."""
    for f in findings:
        if f.get("type") != "ssrf":
            continue
        # Check evidence for cloud metadata indicators
        evidence_text = " ".join(
            e.get("excerpt", "") for e in f.get("evidence", [])
        )
        for indicator in CLOUD_METADATA_INDICATORS:
            if indicator in evidence_text:
                counter += 1
                chain_id = f"chain-{counter:03d}"
                chain = {
                    "id": chain_id,
                    "name": "SSRF → Cloud Metadata",
                    "impact": f"SSRF at {f.get('file')}:{f.get('line')} can access cloud instance metadata for credential theft",
                    "finding_ids": [f.get("id", "")],
                    "flow_description": "Attacker exploits SSRF to access cloud metadata service (169.254.169.254), potentially stealing IAM credentials or service account tokens",
                }
                chains.append(chain)
                _tag_finding(f, chain_id, "entry")
                break

    return counter


def _detect_auth_bypass_escalation(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Auth bypass + any high-severity vulnerability in protected area."""
    auth_findings = [f for f in findings if f.get("type") in ("auth-bypass", "idor", "broken-authentication")]
    high_severity = [f for f in findings if f.get("severity") in ("critical", "high")
                     and f.get("type") not in ("auth-bypass", "idor", "broken-authentication")]

    for auth in auth_findings:
        for vuln in high_severity:
            counter += 1
            chain_id = f"chain-{counter:03d}"
            chain = {
                "id": chain_id,
                "name": f"Auth Bypass → {vuln.get('type', 'unknown')}",
                "impact": f"Authentication bypass enables access to {vuln.get('type')} that would otherwise require privileges",
                "finding_ids": [auth.get("id", ""), vuln.get("id", "")],
                "flow_description": f"Attacker bypasses authentication at {auth.get('file')}:{auth.get('line')}, then exploits {vuln.get('type')} at {vuln.get('file')}:{vuln.get('line')}",
            }
            chains.append(chain)
            _tag_finding(auth, chain_id, "entry")
            _tag_finding(vuln, chain_id, "sink")

    return counter


def _detect_path_traversal_to_secrets(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Path traversal that could read sensitive config files."""
    pt_findings = [f for f in findings if f.get("type") == "path-traversal"]
    secret_findings = [f for f in findings if f.get("type") in ("hardcoded-secret", "sensitive-data-exposure")]

    for pt in pt_findings:
        # Path traversal on its own can read secrets
        if not secret_findings:
            counter += 1
            chain_id = f"chain-{counter:03d}"
            chain = {
                "id": chain_id,
                "name": "Path Traversal → Credential Read",
                "impact": f"Path traversal at {pt.get('file')}:{pt.get('line')} enables reading /etc/passwd, .env, config files with secrets",
                "finding_ids": [pt.get("id", "")],
                "flow_description": "Attacker exploits path traversal to read sensitive configuration files containing credentials or API keys",
            }
            chains.append(chain)
            _tag_finding(pt, chain_id, "entry")
        else:
            # Path traversal + known hardcoded secrets = confirmed credential theft
            for secret in secret_findings:
                counter += 1
                chain_id = f"chain-{counter:03d}"
                chain = {
                    "id": chain_id,
                    "name": "Path Traversal → Secret Exposure",
                    "impact": f"Path traversal can read file containing {secret.get('type')} at {secret.get('file')}",
                    "finding_ids": [pt.get("id", ""), secret.get("id", "")],
                    "flow_description": f"Attacker exploits path traversal at {pt.get('file')}:{pt.get('line')} to read secrets in {secret.get('file')}",
                }
                chains.append(chain)
                _tag_finding(pt, chain_id, "entry")
                _tag_finding(secret, chain_id, "sink")

    return counter


def _detect_same_file_chains(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Multiple vulnerabilities in the same file that can be chained."""
    # Group findings by file
    by_file: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        if f.get("kind") != "finding":
            continue
        by_file.setdefault(f.get("file", ""), []).append(f)

    for file_path, file_findings in by_file.items():
        if len(file_findings) < 2:
            continue

        entries = [f for f in file_findings if f.get("type") in ENTRY_TYPES]
        sinks = [f for f in file_findings if f.get("type") in SINK_TYPES]

        for entry in entries:
            for sink in sinks:
                if entry.get("id") == sink.get("id"):
                    continue
                # Don't duplicate chains already created by other patterns
                if entry.get("chain_id") and sink.get("chain_id"):
                    continue
                counter += 1
                chain_id = f"chain-{counter:03d}"
                chain = {
                    "id": chain_id,
                    "name": f"{entry.get('type')} → {sink.get('type')} (same file)",
                    "impact": f"Vulnerabilities in {file_path} can be chained for greater impact",
                    "finding_ids": [entry.get("id", ""), sink.get("id", "")],
                    "flow_description": f"Chain in {file_path}: {entry.get('type')} at line {entry.get('line')} enables {sink.get('type')} at line {sink.get('line')}",
                }
                chains.append(chain)
                _tag_finding(entry, chain_id, "entry")
                _tag_finding(sink, chain_id, "sink")

    return counter


def _detect_mobile_webview_chains(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain a remote-controlled URL with WebView JS dispatch in the same package.

    Reproduces the classic mobile tokenization-WebView primitive: the network
    endpoint serving a JS payload is server-controllable AND there's a
    Java/Kotlin file in the same package that interpolates native values into
    a JS literal sent to a WebView. Both alone are mediocre findings; the
    chain elevates them to a complete redirection → JS injection →
    @JavascriptInterface pivot.
    """
    def _pkg(file_path: str) -> str:
        # Group by the directory containing the file (typically the Java
        # package). Strip the basename.
        idx = file_path.rfind("/")
        return file_path[:idx] if idx > 0 else file_path

    def _parent(pkg: str) -> str:
        idx = pkg.rfind("/")
        return pkg[:idx] if idx > 0 else pkg

    url_findings_all = [f for f in findings if f.get("type") == "mobile-remote-controlled-endpoint"]
    iface_findings_all = [
        f for f in findings if f.get("type") in ("mobile-webview-js-interface", "mobile-js-bridge-payment-token")
    ]
    js_findings_all = [f for f in findings if f.get("type") == "mobile-webview-js-injection"]

    # Find JS injection findings whose package shares a parent with a remote
    # URL finding (same package OR sibling) — that's the WebView dispatch shape.
    for js in js_findings_all:
        js_pkg = _pkg(js.get("file", ""))
        js_parent = _parent(js_pkg)
        url_findings = [
            f for f in url_findings_all
            if _pkg(f.get("file", "")) == js_pkg
            or _parent(_pkg(f.get("file", ""))) == js_parent
        ]
        iface_findings = [
            f for f in iface_findings_all
            if _pkg(f.get("file", "")) == js_pkg
            or _parent(_pkg(f.get("file", ""))) == js_parent
        ]
        if not (url_findings or iface_findings):
            continue
        counter += 1
        chain_id = f"chain-{counter:03d}"
        participants = [js]
        participants.extend(url_findings[:1])
        participants.extend(iface_findings[:1])
        pkg = js_pkg
        if True:
            chain = {
                "id": chain_id,
                "name": "Mobile WebView dispatch chain",
                "impact": (
                    "End-to-end primitive: a remotely-influenced value reaches a "
                    "WebView JS literal that's bridged back into native code "
                    "(@JavascriptInterface). Classic mobile card-data exfiltration "
                    "shape — server controls the URL, server-supplied key material "
                    "lands in a JS payload, JS-side bridge ships the token back. "
                    "(CWE-94 + CWE-749 + CWE-829)"
                ),
                "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
                "flow_description": (
                    f"In package {pkg}: a config-controlled URL feeds a JS payload "
                    "assembled at line "
                    f"{js.get('line')} ({js.get('file')}) and dispatched to a "
                    "WebView whose JavascriptInterface bridges values back into "
                    "native code."
                ),
            }
            chains.append(chain)
            _tag_finding(js, chain_id, "sink")
            for p in url_findings[:1]:
                _tag_finding(p, chain_id, "entry")
            for p in iface_findings[:1]:
                _tag_finding(p, chain_id, "pivot")

    return counter


def _detect_mobile_mitm_chains(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain a no/partial-pinning NSC with any remote-controlled endpoint.

    A `mobile-nsc-no-pinning` or `mobile-nsc-narrow-pinning` finding on its
    own is "audit later". Combined with even one `mobile-remote-controlled-endpoint`,
    `mobile-insecure-tls`, or `mobile-webview-js-injection`, it becomes a
    MITM-enables-remote-attack chain.
    """
    nsc = [f for f in findings if f.get("type") in {
        # Android preconditions
        "mobile-nsc-no-pinning", "mobile-nsc-narrow-pinning", "mobile-nsc-cleartext",
        "mobile-cleartext-traffic-allowed", "mobile-insecure-tls",
        # iOS preconditions (ATS disabled / trust-all delegate)
        "ios-ats-arbitrary-loads", "ios-ats-partial-exemption", "ios-trust-all-ssl",
    }]
    dependents = [f for f in findings if f.get("type") in {
        "mobile-remote-controlled-endpoint",
        "mobile-webview-js-injection",
        "mobile-webview-mixed-content",
    }]
    if not nsc or not dependents:
        return counter

    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = nsc[:1] + dependents[:3]
    chain = {
        "id": chain_id,
        "name": "Mobile MITM precondition + remote-influenced flow",
        "impact": (
            "Transport-layer protection is missing or narrow (no/narrow pinning, "
            "cleartext allowed, or trust-all manager) AND at least one finding "
            "depends on a remotely-supplied value reaching a sensitive sink. An "
            "attacker that can MITM HTTPS to the affected hosts can trigger the "
            "dependent finding at will. (CWE-295 + CWE-319)"
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            "Cert pinning gap " + nsc[0].get("file", "") +
            " enables MITM of " + ", ".join(
                f"{p.get('file', '')}:{p.get('line', '')}" for p in dependents[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(nsc[0], chain_id, "entry")
    for d in dependents[:3]:
        _tag_finding(d, chain_id, "sink")
    return counter


def _detect_mobile_backup_exfil_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain `allowBackup=true` with any plain-SharedPreferences-sensitive finding.

    Either finding alone is a "medium / audit later". Together they form a
    complete exfiltration primitive: any user-installed adb backup tool (or
    Google Auto Backup if the device is restored from cloud) walks off with
    the named tokens. Surfaces as a chain so the report sorts both up.
    """
    backup = [f for f in findings if f.get("type") == "mobile-allow-backup-true"]
    prefs = [f for f in findings if f.get("type") == "mobile-shared-prefs-sensitive"]
    if not backup or not prefs:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = backup[:1] + prefs[:3]
    # Pull the actual key names out of the prefs findings (enriched by the
    # detector). Naming the keys in the chain impact turns the chain from
    # "they leak something" into "they leak `access_token`, `refresh_token`,
    # `user_pin`" — instantly reportable to a triager.
    pref_keys: list[str] = []
    for p in prefs:
        for k in (p.get("metadata") or {}).get("pref_keys") or []:
            if k not in pref_keys:
                pref_keys.append(k)
    key_extra = ""
    if pref_keys:
        head = ",".join(pref_keys[:5])
        tail = "" if len(pref_keys) <= 5 else f" (+{len(pref_keys) - 5} more)"
        key_extra = f" Exposed key(s): {head}{tail}."
    chain = {
        "id": chain_id,
        "name": "Mobile backup-extractable token chain",
        "impact": (
            "AndroidManifest sets allowBackup=true while app code writes "
            "tokens/PINs/PANs to plain SharedPreferences. Anyone with adb "
            "access (or a cloud-restore replay) walks off with the named "
            "credentials — no root, no MITM, no exploit required. "
            "(CWE-200 + CWE-312)"
            f"{key_extra}"
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            "allowBackup=true at " + backup[0].get("file", "") +
            " exposes plain prefs at " + ", ".join(
                f"{p.get('file', '')}:{p.get('line', '')}" for p in prefs[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(backup[0], chain_id, "entry")
    for p in prefs[:3]:
        _tag_finding(p, chain_id, "sink")
    return counter


def _detect_mobile_deeplink_webview_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain an exported-deeplink activity with any in-WebView dispatch finding.

    The shape we surface: an activity exported to the world (custom-scheme
    deeplink, no host/path restriction OR an exported manifest component that
    advertises non-http schemes) AND somewhere in the same app a WebView
    runs JS pulled from native code with JS enabled / bridges exposed.

    The attacker's primitive: craft a deeplink URL whose parameter the
    activity hands to its WebView. The WebView either evaluates the
    parameter as JS, loads it as a URL, or exposes its @JavascriptInterface
    bridge to JS running inside the loaded page.

    Either finding alone is a hotspot. Together they're a complete intent-
    redirection-to-in-WebView-XSS chain.
    """
    deeplinks = [
        f for f in findings
        if f.get("type") in {
            "mobile-deeplink-unrestricted",
            "mobile-deeplink-host-wildcard",
        }
        or (
            f.get("type") == "mobile-exported-component-no-permission"
            and (f.get("metadata") or {}).get("intent_schemes")
        )
    ]
    webviews = [
        f for f in findings
        if f.get("type") in {
            "mobile-webview-js-injection",
            "mobile-webview-mixed-content",
            "mobile-webview-js-interface",
            "mobile-webview-file-access",
        }
    ]
    if not deeplinks or not webviews:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = deeplinks[:1] + webviews[:3]
    schemes = (deeplinks[0].get("metadata") or {}).get("intent_schemes") or []
    component = (deeplinks[0].get("metadata") or {}).get("component_name") or "(unnamed)"
    chain = {
        "id": chain_id,
        "name": "Mobile deeplink → in-WebView dispatch chain",
        "impact": (
            "An exported deeplink activity routes attacker-influenced URI data into "
            "an in-app WebView whose JavaScript is enabled and whose code already "
            "splices native values into JS payloads. An attacker who can land any "
            "deeplink URL (via browser, another app, or a notification preview) can "
            "drive the WebView into running attacker-chosen JavaScript inside a "
            "privileged native context. (CWE-94 + CWE-939)"
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            f"Deeplink entry: {component} (scheme(s): {','.join(schemes[:3])}) "
            f"→ WebView dispatch: " + ", ".join(
                f"{p.get('file', '')}:{p.get('line', '')}" for p in webviews[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(deeplinks[0], chain_id, "entry")
    for w in webviews[:3]:
        _tag_finding(w, chain_id, "sink")
    return counter


def _detect_mobile_predictable_token_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain insecure RNG with sensitive-prefs storage.

    Shape: the app uses `Math.random()` / `new Random()` in a security
    context (token, nonce, salt, IV, key, secret, password) AND persists
    a similarly-named value to plain SharedPreferences. The token is
    doubly-broken: predictable (attacker can brute-force) AND
    extractable (adb backup walks off with the storage). Together they
    describe a complete "guess + replay" primitive.
    """
    rng = [f for f in findings if f.get("type") == "mobile-insecure-random"]
    prefs = [f for f in findings if f.get("type") == "mobile-shared-prefs-sensitive"]
    if not rng or not prefs:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = rng[:1] + prefs[:3]
    pref_keys: list[str] = []
    for p in prefs:
        for k in (p.get("metadata") or {}).get("pref_keys") or []:
            if k not in pref_keys:
                pref_keys.append(k)
    key_extra = ""
    if pref_keys:
        head = ",".join(pref_keys[:5])
        tail = "" if len(pref_keys) <= 5 else f" (+{len(pref_keys) - 5} more)"
        key_extra = f" At-risk key(s): {head}{tail}."
    chain = {
        "id": chain_id,
        "name": "Mobile predictable-token chain",
        "impact": (
            "App generates a security-context value (token/nonce/salt/key) "
            "using Math.random() or new Random() — not SecureRandom — AND "
            "persists that value to plain SharedPreferences. The token is "
            "doubly broken: an attacker can brute-force candidate values "
            "from the seeded PRNG AND extract any actual stored token via "
            "adb backup. (CWE-330 + CWE-312)" + key_extra
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            "Insecure RNG at " + rng[0].get("file", "") +
            " feeds plain prefs at " + ", ".join(
                f"{p.get('file', '')}:{p.get('line', '')}" for p in prefs[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(rng[0], chain_id, "source")
    for p in prefs[:3]:
        _tag_finding(p, chain_id, "sink")
    return counter


def _detect_mobile_token_double_exposure_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain plain-prefs sensitive storage with a log of the same identifier.

    Shape: the app stores a token (`access_token`, `refresh_token`, …) to
    plain SharedPreferences AND a Log call elsewhere interpolates an
    identifier with the *same name*. Two complementary exposures of the
    same secret material: disk-readable AND logcat-leaked.

    Logcat collection is common on enterprise-managed devices and was
    world-readable before Android 4.1; combined with adb-backup-readable
    plain prefs, the same secret is recoverable through two independent
    channels — defense-in-depth fails twice.
    """
    prefs = [
        f for f in findings
        if f.get("type") == "mobile-shared-prefs-sensitive"
    ]
    logs = [
        f for f in findings
        if f.get("type") == "mobile-log-sensitive"
    ]
    if not prefs or not logs:
        return counter
    # Normalize: drop separators and lowercase so `access_token`,
    # `accessToken`, and `access-token` all collapse to `accesstoken`.
    def _norm(s: str) -> str:
        return "".join(ch for ch in s.lower() if ch.isalnum())
    pref_keys: dict[str, str] = {}
    for p in prefs:
        for k in (p.get("metadata") or {}).get("pref_keys") or []:
            pref_keys[_norm(k)] = k
    log_idents: dict[str, str] = {}
    for l in logs:
        for ident in (l.get("metadata") or {}).get("sensitive_idents") or []:
            log_idents[_norm(ident)] = ident
    # Match on substring/shared root after normalization, so
    # `access_token` (prefs) links to `accessToken` (log).
    overlapping: list[str] = []
    for npk, original_pk in pref_keys.items():
        for nli in log_idents.keys():
            if npk in nli or nli in npk:
                overlapping.append(original_pk)
                break
    if not overlapping:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = prefs[:1] + logs[:3]
    name_extra = ""
    if overlapping:
        head = ",".join(sorted(set(overlapping))[:3])
        name_extra = f" Shared identifier(s): {head}."
    chain = {
        "id": chain_id,
        "name": "Mobile token double-exposure chain",
        "impact": (
            "The app stores a secret in plain SharedPreferences AND logs "
            "an identifier with the same name elsewhere — the same secret "
            "material is recoverable through two independent channels "
            "(disk via adb backup OR logcat via enterprise MDM agents "
            "and pre-Android-4.1 world-readable logs). Defense-in-depth "
            "fails twice. (CWE-312 + CWE-532)" + (f" {name_extra}" if name_extra else "")
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            "Plain prefs at " + prefs[0].get("file", "") +
            " + log leak at " + ", ".join(
                f"{l.get('file', '')}:{l.get('line', '')}" for l in logs[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(prefs[0], chain_id, "storage")
    for l in logs[:3]:
        _tag_finding(l, chain_id, "log")
    return counter


def _detect_mobile_debuggable_secret_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain `android:debuggable=true` with any sensitive-data finding.

    Shape: a release manifest sets `android:debuggable=true` AND the app
    stores sensitive material (tokens in SharedPreferences, hardcoded
    JWTs/secrets, sensitive material being logged). Once debuggable is on,
    anyone with adb access can attach JDWP and read process memory —
    even decrypted EncryptedSharedPreferences, even keychain-backed
    secrets that the app pulled into a String. This is qualitatively
    different from the backup chain because process-memory exposure
    defeats encryption-at-rest.

    Either finding alone is "audit later". Together they form a complete
    "attach debugger, dump tokens" primitive worth surfacing as a chain.
    """
    debuggable = [f for f in findings if f.get("type") == "mobile-debuggable-build"]
    secrets = [
        f for f in findings
        if f.get("type") in {
            "mobile-shared-prefs-sensitive",
            "mobile-log-sensitive",
            "mobile-hardcoded-jwt",
            "hardcoded-secret",
        }
    ]
    if not debuggable or not secrets:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = debuggable[:1] + secrets[:3]
    pref_keys: list[str] = []
    for s in secrets:
        for k in (s.get("metadata") or {}).get("pref_keys") or []:
            if k not in pref_keys:
                pref_keys.append(k)
        for k in (s.get("metadata") or {}).get("sensitive_idents") or []:
            if k not in pref_keys:
                pref_keys.append(k)
    key_extra = ""
    if pref_keys:
        head = ",".join(pref_keys[:5])
        tail = "" if len(pref_keys) <= 5 else f" (+{len(pref_keys) - 5} more)"
        key_extra = f" In-memory secret(s) at risk: {head}{tail}."
    chain = {
        "id": chain_id,
        "name": "Mobile debuggable + in-memory secret chain",
        "impact": (
            "A release manifest sets `android:debuggable=true` while app "
            "code holds sensitive material (tokens, JWTs, secrets) in "
            "process memory. Anyone with adb access can attach JDWP and "
            "dump the live process — exposing secrets even if they're "
            "stored encrypted at rest (the decrypted plaintext sits in "
            "memory as soon as the app reads it). This defeats "
            "EncryptedSharedPreferences and keychain protections. "
            "(CWE-489 + CWE-200)" + key_extra
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            "debuggable=true at " + debuggable[0].get("file", "") +
            " exposes in-memory secrets at " + ", ".join(
                f"{s.get('file', '')}:{s.get('line', '')}" for s in secrets[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(debuggable[0], chain_id, "entry")
    for s in secrets[:3]:
        _tag_finding(s, chain_id, "exposed")
    return counter


def _detect_ios_webview_injection_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain iOS WebView HTML/JS concat with a transport gap.

    Shape: an iOS WebView call interpolates Swift values into the JS/HTML
    string (`loadHTMLString` / `evaluateJavaScript`) AND the app has either
    `NSAllowsArbitraryLoads=true` (ATS disabled) or a trust-all
    URLSessionDelegate. Combined, a network MITM can swap in attacker-
    controlled content that the WebView then renders, and the WKWebView
    JS context has direct access to whatever native bridges are exposed.

    Either finding alone is a hotspot. Together they're a complete
    "MITM → JS execution inside WKWebView" primitive.
    """
    webview = [
        f for f in findings
        if f.get("type") in {
            "ios-webview-html-concat",
            "ios-webview-evaljs-concat",
            "ios-uiwebview-deprecated",
        }
    ]
    transport = [
        f for f in findings
        if f.get("type") in {
            "ios-ats-arbitrary-loads",
            "ios-ats-partial-exemption",
            "ios-trust-all-ssl",
        }
    ]
    if not webview or not transport:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = transport[:1] + webview[:3]
    chain = {
        "id": chain_id,
        "name": "iOS WebView injection chain",
        "impact": (
            "App disables/relaxes ATS (or installs a trust-all URLSession "
            "delegate) AND splices Swift values into a WKWebView/UIWebView "
            "HTML or evaluateJavaScript call. An on-path attacker can swap "
            "remote content the WebView then evaluates, executing attacker "
            "JS inside the app's WebView context — straight access to any "
            "exposed WKScriptMessageHandler bridges and to PII the same "
            "payload happens to be interpolating. (CWE-295 + CWE-94)"
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            "Transport gap at " + transport[0].get("file", "") +
            " enables MITM of WebView sites at " + ", ".join(
                f"{w.get('file', '')}:{w.get('line', '')}" for w in webview[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(transport[0], chain_id, "precondition")
    for w in webview[:3]:
        _tag_finding(w, chain_id, "sink")
    return counter


def _detect_ios_credential_at_rest_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain iOS keychain misuse with ATS gap.

    Shape: the app stores credentials in the keychain with
    `kSecAttrAccessibleAlways` (lifetime persistent, not protected by
    device unlock) AND ATS is disabled / partially exempted. The keychain
    item survives device backups; combined with cleartext-permitted
    network traffic, a credential captured at rest can be replayed against
    cleartext endpoints the app continues to talk to. Less common than the
    Android backup-extractable chain but real on iOS targets.
    """
    keychain = [f for f in findings if f.get("type") == "ios-keychain-accessible-always"]
    ats = [
        f for f in findings
        if f.get("type") in {"ios-ats-arbitrary-loads", "ios-ats-partial-exemption"}
    ]
    if not keychain or not ats:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = keychain[:1] + ats[:1]
    chain = {
        "id": chain_id,
        "name": "iOS credential-at-rest + transport gap chain",
        "impact": (
            "iOS keychain items declared kSecAttrAccessibleAlways persist "
            "through device backups and across reboots without requiring "
            "device unlock. Combined with ATS being disabled / partially "
            "exempted, a credential captured at rest can be replayed against "
            "cleartext endpoints the app still talks to. (CWE-312 + CWE-319)"
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            "Always-accessible keychain item at " + keychain[0].get("file", "") +
            " + ATS gap at " + ats[0].get("file", "")
        ),
    }
    chains.append(chain)
    _tag_finding(keychain[0], chain_id, "credential")
    _tag_finding(ats[0], chain_id, "precondition")
    return counter


def _detect_mobile_gadget_landing_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain an exported entry point with a Java deserialization sink.

    Shape: a component is exported with no permission guard AND somewhere in
    the same app, `ObjectInputStream` / `readObject` is called. If any
    attacker-supplied byte stream from the exported entry reaches the
    deserialization call, the attacker can land a gadget chain — the
    classic Java native-serialization RCE vector applied to Android Intent
    extras.

    Either finding alone is a hotspot. Together they form a complete
    "land bytes → deserialize → gadget" primitive worth chaining.
    """
    exported = [
        f for f in findings
        if f.get("type") == "mobile-exported-component-no-permission"
    ]
    deserial = [
        f for f in findings
        if f.get("type") == "mobile-insecure-deserialization"
    ]
    if not exported or not deserial:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = exported[:1] + deserial[:3]
    component = (exported[0].get("metadata") or {}).get("component_name") or "(unnamed)"
    kind = (exported[0].get("metadata") or {}).get("component_kind") or "component"
    chain = {
        "id": chain_id,
        "name": "Mobile gadget-landing chain",
        "impact": (
            "An exported component with no permission guard coexists with a "
            "Java native-deserialization sink (ObjectInputStream / readObject). "
            "Any installed app can dispatch an Intent to the exported entry "
            "carrying a Parcelable/byte-array payload, and if the host app "
            "feeds that payload to the deserialization sink, a gadget chain "
            "fires with the host app's classloader — code execution inside "
            "the host process. (CWE-502 + CWE-926)"
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            f"Exported {kind} `{component}` → deserialization sink at "
            + ", ".join(
                f"{d.get('file', '')}:{d.get('line', '')}" for d in deserial[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(exported[0], chain_id, "entry")
    for d in deserial[:3]:
        _tag_finding(d, chain_id, "sink")
    return counter


def _detect_mobile_token_replay_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain a token-extraction primitive with a sensitive client mutation.

    Shape: app code writes tokens to plain SharedPreferences AND the client
    ships a sensitive GraphQL mutation in its bundled resources. An attacker
    who extracts the token (via rooted device, adb backup if allowBackup is
    on, or a memory-dump primitive) can mount the bundled mutation against
    the backend with the stolen token. The mutation shape is already in
    the APK — the attacker doesn't need to reverse-engineer it.

    Either finding alone is moderate. Together they describe a replay
    primitive worth surfacing as a chain.
    """
    token_sources = [
        f for f in findings
        if f.get("type") == "mobile-shared-prefs-sensitive"
    ]
    mutations = [
        f for f in findings
        if f.get("type") == "graphql-sensitive-client-mutation"
    ]
    if not token_sources or not mutations:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = token_sources[:1] + mutations[:3]
    # Pull mutation names from titles ("Sensitive GraphQL mutation shipped in
    # client resources: NameHere") so the chain impact names what the attacker
    # would actually call.
    mutation_names: list[str] = []
    for m in mutations:
        title = m.get("title") or ""
        sep = ": "
        if sep in title:
            name = title.split(sep, 1)[1].strip()
            if name and name not in mutation_names:
                mutation_names.append(name)
    mut_extra = ""
    if mutation_names:
        head = ",".join(mutation_names[:3])
        tail = "" if len(mutation_names) <= 3 else f" (+{len(mutation_names) - 3} more)"
        mut_extra = f" Bundled mutation(s) at risk: {head}{tail}."
    pref_keys: list[str] = []
    for p in token_sources:
        for k in (p.get("metadata") or {}).get("pref_keys") or []:
            if k not in pref_keys:
                pref_keys.append(k)
    key_extra = ""
    if pref_keys:
        head = ",".join(pref_keys[:5])
        tail = "" if len(pref_keys) <= 5 else f" (+{len(pref_keys) - 5} more)"
        key_extra = f" Exposed token key(s): {head}{tail}."
    chain = {
        "id": chain_id,
        "name": "Mobile token-replay chain",
        "impact": (
            "App code persists auth tokens in plain SharedPreferences while "
            "the client ships sensitive GraphQL mutations in bundled resources. "
            "Once an attacker extracts a token (rooted device, adb backup if "
            "allowBackup is enabled, or a memory-dump primitive), they can "
            "replay the bundled mutation shape against the backend — no "
            "reverse engineering required since the mutation lives in the APK. "
            "(CWE-312 + CWE-639)"
            f"{key_extra}{mut_extra}"
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            "Token storage at " + token_sources[0].get("file", "") +
            " feeds replay of " + ", ".join(
                f"{m.get('file', '')}:{m.get('line', '')}" for m in mutations[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(token_sources[0], chain_id, "source")
    for m in mutations[:3]:
        _tag_finding(m, chain_id, "sink")
    return counter


def _detect_mobile_permission_relay_chain(
    findings: list[dict[str, Any]],
    chains: list[dict[str, Any]],
    counter: int,
) -> int:
    """Chain an exported component with an intent-redirection sink.

    The shape: a component exported to the world (no permission guard) AND
    somewhere in the same app, a code path unpacks an Intent extra and
    re-launches it via startActivity / startActivityForResult.

    The attacker's primitive: any installed app sends an Intent to the
    exported entry with an attacker-supplied inner Intent as a Parcelable
    extra. The trampoline activity dispatches the inner Intent, granting
    the attacker access to private (non-exported) components or to URI
    permissions held by the host app. StrandHogg / Pulse-style permission
    relay.

    Either finding alone is a hotspot. Together they form a complete
    permission-relay primitive worth surfacing.
    """
    exported = [
        f for f in findings
        if f.get("type") == "mobile-exported-component-no-permission"
    ]
    redirections = [
        f for f in findings
        if f.get("type") == "mobile-intent-redirection"
    ]
    if not exported or not redirections:
        return counter
    counter += 1
    chain_id = f"chain-{counter:03d}"
    participants = exported[:1] + redirections[:3]
    component = (exported[0].get("metadata") or {}).get("component_name") or "(unnamed)"
    kind = (exported[0].get("metadata") or {}).get("component_kind") or "component"
    chain = {
        "id": chain_id,
        "name": "Mobile permission-relay chain",
        "impact": (
            "An exported component with no permission guard coexists with an "
            "intent-redirection sink. An installed app can target the exported "
            "entry, pass an attacker-crafted Intent as a Parcelable extra, and "
            "have the host app dispatch it with its own permissions — reaching "
            "private activities, signature-protected actions, or content URIs "
            "the attacker could not reach directly. This is the StrandHogg / "
            "Pulse permission-relay primitive. (CWE-926 + CWE-940)"
        ),
        "finding_ids": [p.get("id", "") for p in participants if p.get("id")],
        "flow_description": (
            f"Exported {kind} `{component}` → intent-redirection sink at "
            + ", ".join(
                f"{r.get('file', '')}:{r.get('line', '')}" for r in redirections[:3]
            )
        ),
    }
    chains.append(chain)
    _tag_finding(exported[0], chain_id, "entry")
    for r in redirections[:3]:
        _tag_finding(r, chain_id, "sink")
    return counter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tag_finding(finding: dict[str, Any], chain_id: str, role: str) -> None:
    """Tag a finding with chain membership.

    `chain_id` / `chain_role` capture the *first* chain that claimed this
    finding (preserved for backwards compatibility with downstream tooling
    that expects single-valued fields). All chain memberships — including
    additional ones added by later patterns — accumulate on the
    `chain_participations` list as `{chain_id, role}` entries.
    """
    if not finding.get("chain_id"):
        finding["chain_id"] = chain_id
        finding["chain_role"] = role
    # `setdefault` returns the existing value, so a key set to explicit
    # None (vs absent) returns None — `for p in None` crashes. Replace
    # None with [] explicitly before mutating.
    parts = finding.get("chain_participations")
    if not isinstance(parts, list):
        parts = []
        finding["chain_participations"] = parts
    if not any(isinstance(p, dict) and p.get("chain_id") == chain_id for p in parts):
        parts.append({"chain_id": chain_id, "role": role})


def _file_to_service(file_path: str, graph: ServiceGraph) -> str | None:
    """Map a file path to the service that owns it."""
    for svc in graph.services:
        if svc.path and file_path.startswith(svc.path):
            return svc.name
    return None
