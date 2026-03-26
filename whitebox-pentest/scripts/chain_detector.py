#!/usr/bin/env python3
"""Automated attack chain detection.

Analyzes findings and service topology to automatically populate the
``chains`` array and ``chain_id``/``chain_role`` fields in findings.json.

Known chain patterns detected:
  - SSRF → internal service RCE/SSTI/SQLi
  - SSRF → cloud metadata (169.254.169.254)
  - Auth bypass → admin-only vulnerability
  - Path traversal → config/credential read
  - SQLi → file read (LOAD_FILE / xp_cmdshell)
  - Open redirect → phishing / token theft
"""
from __future__ import annotations

import logging
from typing import Any

from service_graph import ServiceGraph

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
    chains: list[dict[str, Any]] = []
    chain_counter = 0

    # --- Pattern 1: SSRF → internal service sink ---
    chain_counter = _detect_ssrf_to_sink(findings, service_graph, chains, chain_counter)

    # --- Pattern 2: SSRF → cloud metadata ---
    chain_counter = _detect_ssrf_to_metadata(findings, chains, chain_counter)

    # --- Pattern 3: Auth bypass → privileged vuln ---
    chain_counter = _detect_auth_bypass_escalation(findings, chains, chain_counter)

    # --- Pattern 4: Path traversal → credential/config read ---
    chain_counter = _detect_path_traversal_to_secrets(findings, chains, chain_counter)

    # --- Pattern 5: Same-file vulnerability stacking ---
    chain_counter = _detect_same_file_chains(findings, chains, chain_counter)

    if chains:
        log.info("Detected %d attack chains across %d findings",
                 len(chains),
                 sum(1 for f in findings if f.get("chain_id")))

    return findings, chains


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tag_finding(finding: dict[str, Any], chain_id: str, role: str) -> None:
    """Tag a finding with chain membership (only if not already tagged)."""
    if not finding.get("chain_id"):
        finding["chain_id"] = chain_id
        finding["chain_role"] = role


def _file_to_service(file_path: str, graph: ServiceGraph) -> str | None:
    """Map a file path to the service that owns it."""
    for svc in graph.services:
        if svc.path and file_path.startswith(svc.path):
            return svc.name
    return None
