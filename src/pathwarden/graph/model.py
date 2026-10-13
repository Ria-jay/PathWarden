"""Typed, deterministic security graph.

The graph is a :class:`networkx.MultiDiGraph` so that several typed edges (for
example ``reads`` and ``writes``) can connect the same pair of nodes. Node and
edge identifiers are the real configuration identifiers; attribution is kept in
node/edge attributes so exports can explain every element.

Graph construction is deterministic: identical configuration produces identical
node and edge sets, and exports sort their output.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import networkx as nx

__all__ = ["EdgeType", "NodeType", "SecurityGraph"]


class NodeType(StrEnum):
    """Node kinds in the security graph."""

    INPUT_SOURCE = "input_source"
    AGENT = "agent"
    TOOL = "tool"
    RESOURCE = "resource"
    IDENTITY = "identity"
    EXTERNAL_DESTINATION = "external_destination"


class EdgeType(StrEnum):
    """Edge kinds in the security graph."""

    FEEDS_CONTEXT = "feeds_context"
    CAN_INVOKE = "can_invoke"
    READS = "reads"
    WRITES = "writes"
    USES_IDENTITY = "uses_identity"
    OUTBOUND_TO = "outbound_to"
    FLOWS_TO = "flows_to"


class SecurityGraph:
    """A typed, permission-aware view of an agent configuration.

    Nodes and edges are added by :mod:`pathwarden.graph.build`. This class only
    stores them and provides deterministic, sorted accessors plus export
    metadata.
    """

    def __init__(self, *, schema_version: str, agent_id: str) -> None:
        self.schema_version = schema_version
        self.agent_id = agent_id
        self.graph: nx.MultiDiGraph[Any] = nx.MultiDiGraph()

    # -- mutation ---------------------------------------------------------- #

    def add_node(self, node_id: str, node_type: NodeType, **attributes: Any) -> None:
        """Add a typed node. Attributes explain the node in exports."""

        self.graph.add_node(node_id, node_type=node_type.value, **attributes)

    def add_edge(self, source: str, target: str, edge_type: EdgeType, **attributes: Any) -> None:
        """Add a typed edge keyed by its type."""

        self.graph.add_edge(
            source, target, key=edge_type.value, edge_type=edge_type.value, **attributes
        )

    # -- deterministic accessors ------------------------------------------- #

    def node_count(self) -> int:
        return int(self.graph.number_of_nodes())

    def edge_count(self) -> int:
        return int(self.graph.number_of_edges())

    def nodes(self) -> list[tuple[str, dict[str, Any]]]:
        """Return ``(id, attributes)`` pairs sorted by type then id."""

        items = list(self.graph.nodes(data=True))
        items.sort(key=lambda item: (str(item[1].get("node_type", "")), item[0]))
        return items

    def edges(self) -> list[tuple[str, str, str, dict[str, Any]]]:
        """Return ``(source, target, edge_type, attributes)`` sorted deterministically."""

        items = list(self.graph.edges(data=True, keys=True))
        ordered = [
            (source, target, str(attrs.get("edge_type", key)), attrs)
            for source, target, key, attrs in items
        ]
        ordered.sort(key=lambda item: (item[0], item[1], item[2]))
        return ordered

    def grouped_node_ids(self) -> dict[str, list[str]]:
        """Node ids grouped by node type, each list sorted."""

        groups: dict[str, list[str]] = {}
        for node_id, attrs in self.nodes():
            groups.setdefault(str(attrs.get("node_type", "")), []).append(node_id)
        return groups
