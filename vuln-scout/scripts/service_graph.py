#!/usr/bin/env python3
"""Service topology mapper for multi-service applications.

Parses docker-compose, Kubernetes manifests, and code-level HTTP client
calls to build a service graph.  Used by the chain detector to determine
which services can reach which, enabling automated attack chain detection.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from safe_paths import safe_read_text, safe_walk_files

log = logging.getLogger("vuln-scout")


@dataclass
class Service:
    """A service or component in the application topology."""
    name: str
    path: str = ""                   # Relative path to service root
    language: str = ""               # Primary language
    exposure: str = "internal"       # "external" or "internal"
    ports: list[int] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)


@dataclass
class ServiceGraph:
    """Directed graph of services and their connectivity."""
    services: list[Service] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)  # (from, to)

    def is_externally_reachable(self, service_name: str) -> bool:
        for svc in self.services:
            if svc.name == service_name:
                return svc.exposure == "external"
        return False

    def get_reachable_services(self, from_service: str) -> set[str]:
        """BFS from a service to find all reachable services."""
        reachable: set[str] = set()
        queue = [from_service]
        while queue:
            current = queue.pop(0)
            for src, dst in self.edges:
                if src == current and dst not in reachable:
                    reachable.add(dst)
                    queue.append(dst)
        return reachable

    def to_dict(self) -> dict[str, Any]:
        return {
            "services": [asdict(s) for s in self.services],
            "edges": [{"from": src, "to": dst} for src, dst in self.edges],
        }


# ---------------------------------------------------------------------------
# Docker Compose parser
# ---------------------------------------------------------------------------

def _parse_docker_compose(path: Path) -> ServiceGraph:
    """Parse docker-compose.yml for service topology."""
    graph = ServiceGraph()

    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        compose_path = path / name
        text = safe_read_text(path, compose_path, errors="replace")
        if text is not None:
            break
    else:
        return graph

    # Try to use PyYAML if available, fall back to regex parsing
    try:
        import yaml
        data = yaml.safe_load(text)
    except ImportError:
        data = _simple_compose_parse(text)

    if not isinstance(data, dict):
        return graph

    services_data = data.get("services", {})
    if not isinstance(services_data, dict):
        return graph

    for svc_name, svc_config in services_data.items():
        if not isinstance(svc_config, dict):
            continue

        ports = []
        exposure = "internal"
        for p in svc_config.get("ports", []):
            p_str = str(p)
            # "8080:80" or "80" -- first number is host port
            nums = re.findall(r"\d+", p_str)
            if nums:
                ports.append(int(nums[0]))
                exposure = "external"  # Published port = externally reachable

        depends = svc_config.get("depends_on", [])
        if isinstance(depends, dict):
            depends = list(depends.keys())

        networks = list(svc_config.get("networks", {}).keys()) if isinstance(svc_config.get("networks"), dict) else svc_config.get("networks", [])

        build_ctx = svc_config.get("build", "")
        svc_path = ""
        if isinstance(build_ctx, str):
            svc_path = build_ctx
        elif isinstance(build_ctx, dict):
            svc_path = build_ctx.get("context", "")

        graph.services.append(Service(
            name=svc_name,
            path=svc_path,
            exposure=exposure,
            ports=ports,
            depends_on=depends if isinstance(depends, list) else [],
            networks=networks if isinstance(networks, list) else [],
        ))

    # Build edges from depends_on
    svc_names = {s.name for s in graph.services}
    for svc in graph.services:
        for dep in svc.depends_on:
            if dep in svc_names:
                graph.edges.append((svc.name, dep))

    # Build edges from shared networks (bidirectional connectivity)
    network_members: dict[str, list[str]] = {}
    for svc in graph.services:
        for net in svc.networks:
            network_members.setdefault(net, []).append(svc.name)
    for net, members in network_members.items():
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                if (a, b) not in graph.edges:
                    graph.edges.append((a, b))
                if (b, a) not in graph.edges:
                    graph.edges.append((b, a))

    return graph


def _simple_compose_parse(text: str) -> dict:
    """Very basic YAML-like parser for docker-compose when PyYAML isn't available."""
    # This is intentionally simplistic -- just extract service names and ports
    result: dict[str, Any] = {"services": {}}
    current_service = None
    in_services = False

    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "services:":
            in_services = True
            continue
        if in_services and not line.startswith(" ") and not line.startswith("\t") and stripped:
            in_services = False

        if in_services:
            # Service name (2-space indent, no further indent)
            svc_match = re.match(r"^  (\w[\w-]*):", line)
            if svc_match:
                current_service = svc_match.group(1)
                result["services"][current_service] = {"ports": [], "depends_on": []}
                continue

            if current_service:
                # Port mapping
                port_match = re.search(r'["\']?(\d+:\d+|\d+)["\']?', stripped)
                if stripped.startswith("- ") and port_match and "port" in text[max(0, text.index(stripped) - 30):text.index(stripped)].lower():
                    result["services"][current_service]["ports"].append(port_match.group(1))

    return result


# ---------------------------------------------------------------------------
# Kubernetes manifest parser
# ---------------------------------------------------------------------------

def _parse_kubernetes(path: Path) -> ServiceGraph:
    """Parse Kubernetes manifests for service topology."""
    graph = ServiceGraph()

    k8s_dirs = [path, path / "k8s", path / "kubernetes", path / "deploy", path / "manifests"]
    for d in k8s_dirs:
        if not d.is_dir():
            continue
        for f in safe_walk_files(
            path,
            start=d,
            excluded_dirs={"node_modules", "vendor", "dist", ".git", "__pycache__", ".joern", ".claude"},
            include_patterns=("**/*.yaml", "**/*.yml", "*.yaml", "*.yml"),
        ):
            _parse_k8s_file(f, path, graph)

    return graph


def _parse_k8s_file(f: Path, root: Path, graph: ServiceGraph) -> None:
    """Parse a single k8s YAML file and add to graph."""
    text = safe_read_text(root, f, errors="replace")
    if text is None:
        return

    # Look for Service kind with type: LoadBalancer or NodePort
    if "kind: Service" in text:
        name_match = re.search(r"name:\s*(\S+)", text)
        type_match = re.search(r"type:\s*(LoadBalancer|NodePort|ClusterIP)", text)
        if name_match:
            svc_name = name_match.group(1)
            exposure = "external" if type_match and type_match.group(1) in ("LoadBalancer", "NodePort") else "internal"

            port_matches = re.findall(r"port:\s*(\d+)", text)
            ports = [int(p) for p in port_matches]

            existing = next((s for s in graph.services if s.name == svc_name), None)
            if existing:
                existing.exposure = exposure
                existing.ports = ports
            else:
                graph.services.append(Service(
                    name=svc_name, exposure=exposure, ports=ports,
                ))

    # Look for Ingress kind (external exposure)
    if "kind: Ingress" in text:
        backend_matches = re.findall(r"serviceName:\s*(\S+)|name:\s*(\S+)", text)
        for match in backend_matches:
            svc_name = match[0] or match[1]
            if svc_name:
                existing = next((s for s in graph.services if s.name == svc_name), None)
                if existing:
                    existing.exposure = "external"


# ---------------------------------------------------------------------------
# Code-level HTTP client call detection
# ---------------------------------------------------------------------------

def _detect_internal_calls(path: Path) -> list[tuple[str, str]]:
    """Detect internal service-to-service HTTP calls in source code.

    Returns list of (caller_file, target_service_hint) tuples.
    """
    calls: list[tuple[str, str]] = []
    # Patterns that suggest internal HTTP calls
    internal_patterns = [
        re.compile(r"""(?:fetch|axios|requests?\.(?:get|post)|http\.(?:Get|Post)|HttpClient)\s*\(\s*['"f`](?:https?://)?(?:localhost|127\.0\.0\.1|(?:[\w-]+):\d+)"""),
        re.compile(r"""(?:fetch|axios|requests?\.(?:get|post))\s*\(\s*['"f`](?:https?://)?(\w[\w-]*)(?::\d+)?/"""),
    ]

    for f in safe_walk_files(
        path,
        extensions={".ts", ".js", ".py", ".go", ".java", ".rb", ".php"},
        excluded_dirs={"node_modules", "vendor", "dist", ".git", "__pycache__", ".joern", ".claude"},
    ):
        text = safe_read_text(path, f, errors="replace")
        if text is None:
            continue
        rel = str(f.relative_to(path))
        for pattern in internal_patterns:
            for m in pattern.finditer(text):
                target = m.group(1) if m.lastindex else "internal-service"
                calls.append((rel, target))

    return calls


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_service_graph(target_path: str) -> ServiceGraph:
    """Build a service graph from all available sources.

    Combines docker-compose, Kubernetes manifests, and code-level HTTP
    client detection into a unified service topology.
    """
    path = Path(target_path).resolve()
    if not path.is_dir():
        return ServiceGraph()

    # Start with docker-compose (most common)
    graph = _parse_docker_compose(path)

    # Merge Kubernetes info
    k8s_graph = _parse_kubernetes(path)
    existing_names = {s.name for s in graph.services}
    for svc in k8s_graph.services:
        if svc.name not in existing_names:
            graph.services.append(svc)
        else:
            # Update exposure from k8s
            existing = next(s for s in graph.services if s.name == svc.name)
            if svc.exposure == "external":
                existing.exposure = "external"
    graph.edges.extend(k8s_graph.edges)

    # Add code-level internal calls as edges
    internal_calls = _detect_internal_calls(path)
    svc_names = {s.name for s in graph.services}
    for caller_file, target in internal_calls:
        # Try to match target to a known service
        if target in svc_names:
            # Find which service owns the caller file
            for svc in graph.services:
                if svc.path and caller_file.startswith(svc.path):
                    if (svc.name, target) not in graph.edges:
                        graph.edges.append((svc.name, target))
                    break

    if graph.services:
        log.info("Service graph: %d services, %d edges, %d external",
                 len(graph.services), len(graph.edges),
                 sum(1 for s in graph.services if s.exposure == "external"))

    return graph


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    graph = build_service_graph(target)
    print(json.dumps(graph.to_dict(), indent=2))
