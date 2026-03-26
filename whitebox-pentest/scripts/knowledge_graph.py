#!/usr/bin/env python3
"""Security knowledge graph.

Connects code entities, data flows, findings, dependencies, and business
context in a queryable graph.  No external dependencies -- uses adjacency
lists and dicts.

Graph entities:
  - function: functions/methods in the codebase
  - endpoint: HTTP endpoints from entry_point_mapper
  - finding: vulnerability findings
  - dependency: external packages
  - file: source files

Relationships:
  - CONTAINS: file -> function/endpoint
  - AFFECTS: finding -> function/file
  - REACHES: endpoint -> function (call graph)
  - IMPORTS: file -> dependency
  - CHAINS_TO: finding -> finding (attack chain)
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")


@dataclass
class Entity:
    id: str
    kind: str          # function, endpoint, finding, dependency, file
    name: str
    file: str = ""
    line: int = 0
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class Relationship:
    source_id: str
    target_id: str
    kind: str          # CONTAINS, AFFECTS, REACHES, IMPORTS, CHAINS_TO
    properties: dict[str, Any] = field(default_factory=dict)


class KnowledgeGraph:
    """In-memory security knowledge graph."""

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._relationships: list[Relationship] = []
        self._adjacency: dict[str, list[str]] = {}  # Forward edges
        self._reverse: dict[str, list[str]] = {}     # Reverse edges

    def add_entity(self, entity: Entity) -> None:
        self._entities[entity.id] = entity

    def add_relationship(self, rel: Relationship) -> None:
        self._relationships.append(rel)
        self._adjacency.setdefault(rel.source_id, []).append(rel.target_id)
        self._reverse.setdefault(rel.target_id, []).append(rel.source_id)

    def get_entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def get_neighbors(self, entity_id: str, direction: str = "forward") -> list[Entity]:
        """Get neighboring entities in the graph."""
        adj = self._adjacency if direction == "forward" else self._reverse
        neighbor_ids = adj.get(entity_id, [])
        return [self._entities[nid] for nid in neighbor_ids if nid in self._entities]

    def get_entities_by_kind(self, kind: str) -> list[Entity]:
        return [e for e in self._entities.values() if e.kind == kind]

    def get_blast_radius(self, finding_id: str) -> dict[str, Any]:
        """Calculate blast radius for a finding via BFS."""
        visited: set[str] = set()
        queue = [finding_id]
        affected_files: set[str] = set()
        affected_functions: set[str] = set()
        affected_endpoints: set[str] = set()

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            entity = self._entities.get(current)
            if not entity:
                continue

            if entity.kind == "file":
                affected_files.add(entity.name)
            elif entity.kind == "function":
                affected_functions.add(entity.name)
            elif entity.kind == "endpoint":
                affected_endpoints.add(entity.name)

            # Traverse forward and reverse edges
            for neighbor_id in self._adjacency.get(current, []):
                if neighbor_id not in visited:
                    queue.append(neighbor_id)
            for neighbor_id in self._reverse.get(current, []):
                if neighbor_id not in visited:
                    queue.append(neighbor_id)

        return {
            "finding_id": finding_id,
            "affected_files": sorted(affected_files),
            "affected_functions": sorted(affected_functions),
            "affected_endpoints": sorted(affected_endpoints),
            "total_reachable": len(visited) - 1,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": [asdict(e) for e in self._entities.values()],
            "relationships": [asdict(r) for r in self._relationships],
            "stats": {
                "total_entities": len(self._entities),
                "total_relationships": len(self._relationships),
                "by_kind": {
                    kind: len(self.get_entities_by_kind(kind))
                    for kind in {"file", "function", "endpoint", "finding", "dependency"}
                },
            },
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: str | Path) -> KnowledgeGraph:
        data = json.loads(Path(path).read_text())
        graph = cls()
        for e_data in data.get("entities", []):
            graph.add_entity(Entity(**e_data))
        for r_data in data.get("relationships", []):
            graph.add_relationship(Relationship(**r_data))
        return graph


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_knowledge_graph(
    findings: list[dict[str, Any]],
    entry_points: list[dict[str, Any]] | None = None,
    chains: list[dict[str, Any]] | None = None,
) -> KnowledgeGraph:
    """Build a knowledge graph from scan results.

    Args:
        findings: Normalized findings list.
        entry_points: Entry points from entry_point_mapper.
        chains: Attack chains from chain_detector.

    Returns:
        Populated KnowledgeGraph.
    """
    graph = KnowledgeGraph()

    # Add file entities and finding entities
    files_seen: set[str] = set()
    for f in findings:
        # File entity
        file_path = f.get("file", "")
        if file_path and file_path not in files_seen:
            files_seen.add(file_path)
            graph.add_entity(Entity(
                id=f"file:{file_path}",
                kind="file",
                name=file_path,
                file=file_path,
            ))

        # Finding entity
        finding_id = f.get("id", "")
        if finding_id:
            graph.add_entity(Entity(
                id=f"finding:{finding_id}",
                kind="finding",
                name=f.get("title", f.get("type", "")),
                file=file_path,
                line=f.get("line", 0),
                properties={
                    "type": f.get("type"),
                    "severity": f.get("severity"),
                    "verdict": f.get("verdict"),
                    "confidence": f.get("confidence"),
                },
            ))
            # Link finding to file
            if file_path:
                graph.add_relationship(Relationship(
                    source_id=f"finding:{finding_id}",
                    target_id=f"file:{file_path}",
                    kind="AFFECTS",
                ))

    # Add endpoint entities
    if entry_points:
        for ep in entry_points:
            ep_id = f"endpoint:{ep.get('method', 'ALL')}:{ep.get('path', '/')}"
            graph.add_entity(Entity(
                id=ep_id,
                kind="endpoint",
                name=f"{ep.get('method', 'ALL')} {ep.get('path', '/')}",
                file=ep.get("file", ""),
                line=ep.get("line", 0),
                properties={
                    "framework": ep.get("framework"),
                    "has_auth": ep.get("has_auth"),
                },
            ))
            # Link endpoint to file
            file_path = ep.get("file", "")
            if file_path:
                file_id = f"file:{file_path}"
                if file_id not in {e.id for e in graph.get_entities_by_kind("file")}:
                    graph.add_entity(Entity(id=file_id, kind="file", name=file_path, file=file_path))
                graph.add_relationship(Relationship(
                    source_id=file_id, target_id=ep_id, kind="CONTAINS",
                ))

    # Add chain relationships
    if chains:
        for chain in chains:
            finding_ids = chain.get("finding_ids", [])
            for i in range(len(finding_ids) - 1):
                graph.add_relationship(Relationship(
                    source_id=f"finding:{finding_ids[i]}",
                    target_id=f"finding:{finding_ids[i + 1]}",
                    kind="CHAINS_TO",
                    properties={"chain_id": chain.get("id")},
                ))

    log.info("Knowledge graph: %d entities, %d relationships",
             len(graph._entities), len(graph._relationships))
    return graph
