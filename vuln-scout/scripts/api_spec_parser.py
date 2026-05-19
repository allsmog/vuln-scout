#!/usr/bin/env python3
"""API specification parser for security analysis.

Parses OpenAPI/Swagger specs and GraphQL schemas to find:
- Undocumented endpoints (in code but not spec)
- Missing auth on documented endpoints
- PII in query parameters
- Missing rate limiting on state-changing endpoints
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from safe_paths import safe_read_text, safe_walk_files

log = logging.getLogger("vuln-scout")

_EXCLUDED_DIRS = frozenset({
    "node_modules", "vendor", "dist", "build", ".git",
    "__pycache__", ".joern", ".claude",
})

# Parameter names that suggest PII -- should not appear in query strings
_PII_PARAM_NAMES = re.compile(
    r"""(?i)^(email|phone|ssn|social_security|password|passwd|secret|token|
    api_key|apikey|credit_card|card_number|cvv|dob|date_of_birth|
    national_id|passport|driver_license|bank_account|routing_number|
    first_name|last_name|full_name|address|zip_code|postal_code)$""",
    re.VERBOSE,
)

# HTTP methods that are state-changing and should have rate limiting
_STATE_CHANGING_METHODS = {"post", "put", "patch", "delete"}
_SPEC_EXTENSIONS = {".json", ".yaml", ".yml", ".graphql", ".graphqls", ".gql"}


def _is_excluded(path: Path) -> bool:
    return any(part in _EXCLUDED_DIRS for part in path.parts)


# ---------------------------------------------------------------------------
# OpenAPI / Swagger parsing
# ---------------------------------------------------------------------------

def discover_specs(target_path: str) -> list[dict[str, Any]]:
    """Find API specification files in the target directory."""
    root = Path(target_path).resolve()
    if not root.is_dir():
        return []
    specs: list[dict[str, Any]] = []

    for f in safe_walk_files(root, extensions=_SPEC_EXTENSIONS, excluded_dirs=_EXCLUDED_DIRS):
        if _is_excluded(f):
            continue
        lower_name = f.name.lower()
        if (
            (lower_name.startswith("openapi") or lower_name.startswith("swagger"))
            and f.suffix.lower() in {".json", ".yaml", ".yml"}
        ):
            specs.append({"path": str(f), "type": "openapi", "rel": str(f.relative_to(root))})
            continue

        if f.suffix.lower() in {".graphql", ".graphqls"} or lower_name == "schema.gql":
            specs.append({"path": str(f), "type": "graphql", "rel": str(f.relative_to(root))})

    if specs:
        log.info("Discovered %d API spec files", len(specs))
    return specs


def parse_openapi(spec_path: str) -> dict[str, Any] | None:
    """Parse an OpenAPI/Swagger spec and extract security-relevant info."""
    path = Path(spec_path)
    text = safe_read_text(path.parent, path, errors="replace")
    if text is None:
        return None

    # Try JSON first
    data = None
    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
    else:
        # Try PyYAML, fall back to basic regex extraction
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:
            data = _basic_yaml_parse(text)
        except Exception:
            return None

    if not isinstance(data, dict):
        return None

    # Extract endpoints
    endpoints: list[dict[str, Any]] = []
    paths = data.get("paths", {})
    global_security = data.get("security", [])

    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue

            # Security can be defined per-operation or globally
            security = operation.get("security", global_security)
            has_auth = bool(security) and security != [{}]

            # Extract parameters
            params = operation.get("parameters", []) + path_item.get("parameters", [])

            endpoints.append({
                "method": method.upper(),
                "path": path_str,
                "has_auth": has_auth,
                "security_schemes": [list(s.keys())[0] for s in security if isinstance(s, dict) and s] if security else [],
                "parameters": [
                    {
                        "name": p.get("name", ""),
                        "in": p.get("in", ""),
                        "required": p.get("required", False),
                    }
                    for p in params if isinstance(p, dict)
                ],
                "operation_id": operation.get("operationId", ""),
                "responses": list(operation.get("responses", {}).keys()),
                "tags": operation.get("tags", []),
            })

    return {
        "version": data.get("openapi", data.get("swagger", "unknown")),
        "title": data.get("info", {}).get("title", ""),
        "endpoints": endpoints,
        "security_definitions": list(
            data.get("securityDefinitions", data.get("components", {}).get("securitySchemes", {})).keys()
        ),
    }


def _basic_yaml_parse(text: str) -> dict | None:
    """Very basic YAML key extraction when PyYAML is unavailable."""
    # Only handles flat structure -- enough to detect openapi version
    if "openapi:" in text or "swagger:" in text:
        return {"paths": {}}  # Signal that it's an API spec but parsing is limited
    return None


# ---------------------------------------------------------------------------
# GraphQL schema parsing
# ---------------------------------------------------------------------------

def parse_graphql_schema(schema_path: str) -> dict[str, Any] | None:
    """Parse a GraphQL schema file for security-relevant info."""
    path = Path(schema_path)
    text = safe_read_text(path.parent, path, errors="replace")
    if text is None:
        return None

    # Extract type definitions
    types: list[dict[str, Any]] = []
    type_pattern = re.compile(r'type\s+(\w+)\s*(?:@\w+(?:\([^)]*\))?\s*)*\{([^}]+)\}', re.DOTALL)

    for m in type_pattern.finditer(text):
        type_name = m.group(1)
        body = m.group(2)

        fields: list[dict[str, Any]] = []
        field_pattern = re.compile(r'(\w+)\s*(?:\([^)]*\))?\s*:\s*([^\n!]+!?)')
        for fm in field_pattern.finditer(body):
            field_name = fm.group(1)
            field_type = fm.group(2).strip()
            # Check for auth directives
            has_auth = bool(re.search(r'@(?:auth|hasRole|requireAuth|authenticated)', body))
            fields.append({"name": field_name, "type": field_type})

        types.append({
            "name": type_name,
            "fields": fields,
            "has_auth_directive": bool(re.search(r'@(?:auth|hasRole|requireAuth)', text[:m.start()] + body)),
        })

    # Check for introspection disabling
    has_introspection_disabled = "__schema" in text and "false" in text.lower()

    # Check for depth/complexity limits (often in comments or directives)
    has_depth_limit = bool(re.search(r'(?:depthLimit|maxDepth|depth\s*:\s*\d+)', text, re.IGNORECASE))
    has_complexity_limit = bool(re.search(r'(?:complexityLimit|maxComplexity|cost\s*:\s*\d+)', text, re.IGNORECASE))

    return {
        "types": types,
        "query_type": next((t for t in types if t["name"] == "Query"), None),
        "mutation_type": next((t for t in types if t["name"] == "Mutation"), None),
        "has_introspection_disabled": has_introspection_disabled,
        "has_depth_limit": has_depth_limit,
        "has_complexity_limit": has_complexity_limit,
    }


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------

def check_missing_auth(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Find endpoints without authentication requirements."""
    findings: list[dict[str, Any]] = []
    for ep in spec.get("endpoints", []):
        if not ep.get("has_auth") and ep["method"] in ("POST", "PUT", "PATCH", "DELETE"):
            findings.append(_make_finding(
                "missing-auth-spec", "high",
                f"API endpoint {ep['method']} {ep['path']} has no authentication requirement",
                f"State-changing endpoint without security definition in API spec",
                ep.get("path", ""), 0,
            ))
    return findings


def check_pii_in_params(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Find PII-suggestive parameter names in query strings."""
    findings: list[dict[str, Any]] = []
    for ep in spec.get("endpoints", []):
        for param in ep.get("parameters", []):
            if param.get("in") == "query" and _PII_PARAM_NAMES.match(param.get("name", "")):
                findings.append(_make_finding(
                    "pii-in-query-param", "medium",
                    f"PII parameter '{param['name']}' exposed in query string at {ep['method']} {ep['path']}",
                    f"Sensitive parameter in URL query string may be logged or leaked via Referer header (CWE-598)",
                    ep.get("path", ""), 0,
                ))
    return findings


def check_rate_limiting(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Check for missing rate limiting on state-changing endpoints."""
    findings: list[dict[str, Any]] = []
    for ep in spec.get("endpoints", []):
        if ep["method"].lower() in _STATE_CHANGING_METHODS:
            responses = ep.get("responses", [])
            if "429" not in responses:
                finding = _make_finding(
                    "missing-rate-limit", "low",
                    f"No rate limiting (429 response) on {ep['method']} {ep['path']}",
                    f"State-changing endpoint without rate limiting may be vulnerable to abuse",
                    ep.get("path", ""), 0,
                )
                finding["kind"] = "hotspot"
                findings.append(finding)
    return findings


def check_graphql_security(schema: dict[str, Any], spec_file: str) -> list[dict[str, Any]]:
    """Check GraphQL schema for security issues."""
    findings: list[dict[str, Any]] = []

    if not schema.get("has_depth_limit"):
        findings.append(_make_finding(
            "graphql-no-depth-limit", "medium",
            "GraphQL schema has no depth limit configured",
            "Missing query depth limit enables DoS via deeply nested queries",
            spec_file, 0,
        ))

    if not schema.get("has_complexity_limit"):
        findings.append(_make_finding(
            "graphql-no-complexity-limit", "medium",
            "GraphQL schema has no complexity limit configured",
            "Missing query complexity limit enables DoS via expensive queries",
            spec_file, 0,
        ))

    # Check mutations without auth
    mutation_type = schema.get("mutation_type")
    if mutation_type and not mutation_type.get("has_auth_directive"):
        findings.append(_make_finding(
            "graphql-mutation-no-auth", "high",
            "GraphQL Mutation type has no auth directive",
            "Mutations may be accessible without authentication",
            spec_file, 0,
        ))

    return findings


def cross_reference_endpoints(
    spec_endpoints: list[dict[str, Any]],
    code_endpoints: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Compare API spec endpoints against code entry points."""
    findings: list[dict[str, Any]] = []
    if not code_endpoints:
        return findings

    # Normalize paths for comparison
    spec_paths = {(ep["method"], _normalize_path(ep["path"])) for ep in spec_endpoints}
    code_paths = {(ep.get("method", "ALL"), _normalize_path(ep.get("path", ""))) for ep in code_endpoints}

    # Shadow API: in code but not spec -- audit point, not confirmed vuln
    for method, path in code_paths - spec_paths:
        # Skip if method is ALL (code uses catch-all, spec is method-specific)
        if method == "ALL":
            continue
        finding = _make_finding(
            "undocumented-endpoint", "low",
            f"Undocumented endpoint: {method} {path}",
            f"Endpoint exists in code but not in API specification (shadow API)",
            path, 0,
        )
        finding["kind"] = "hotspot"
        findings.append(finding)

    return findings


def _normalize_path(path: str) -> str:
    """Normalize API path for comparison (remove param names, keep structure)."""
    # /users/{id} -> /users/:param, /users/:id -> /users/:param
    normalized = re.sub(r'\{[^}]+\}', ':param', path)
    normalized = re.sub(r':\w+', ':param', normalized)
    return normalized.rstrip("/") or "/"


def _make_finding(vuln_type: str, severity: str, title: str,
                  message: str, file: str, line: int) -> dict[str, Any]:
    return {
        "id": "",
        "stable_key": "",
        "kind": "finding",
        "severity": severity,
        "type": vuln_type,
        "title": title,
        "file": file,
        "line": line,
        "verdict": "unverified",
        "confidence": "medium",
        "source_tool": "api-spec-parser",
        "message": message,
        "evidence": [{
            "type": "api-spec",
            "label": vuln_type,
            "path": file,
            "line": line,
            "excerpt": title,
        }],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(
    target_path: str,
    entry_points: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Parse API specs and run all security checks.

    Args:
        target_path: Root directory of the project.
        entry_points: Entry points from entry_point_mapper (for cross-reference).

    Returns:
        List of findings in the standard schema format.
    """
    specs = discover_specs(target_path)
    if not specs:
        return []

    all_findings: list[dict[str, Any]] = []

    for spec_info in specs:
        spec_path = spec_info["path"]
        spec_type = spec_info["type"]

        if spec_type == "openapi":
            parsed = parse_openapi(spec_path)
            if not parsed:
                continue
            log.info("Parsed OpenAPI spec: %s (%d endpoints)",
                     spec_info["rel"], len(parsed.get("endpoints", [])))

            all_findings.extend(check_missing_auth(parsed))
            all_findings.extend(check_pii_in_params(parsed))
            all_findings.extend(check_rate_limiting(parsed))
            all_findings.extend(cross_reference_endpoints(
                parsed.get("endpoints", []), entry_points
            ))

        elif spec_type == "graphql":
            parsed = parse_graphql_schema(spec_path)
            if not parsed:
                continue
            log.info("Parsed GraphQL schema: %s (%d types)",
                     spec_info["rel"], len(parsed.get("types", [])))
            all_findings.extend(check_graphql_security(parsed, spec_info["rel"]))

    if all_findings:
        log.info("API spec analysis: %d findings", len(all_findings))
    return all_findings
