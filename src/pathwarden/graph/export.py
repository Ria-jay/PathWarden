"""Deterministic graph exports: JSON, Mermaid, and Graphviz DOT.

All exporters sort nodes and edges so that identical input produces identical
output. Node and edge identifiers are the real configuration identifiers.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pathwarden.graph.model import SecurityGraph

__all__ = ["graph_to_dict", "graph_to_dot", "graph_to_json", "graph_to_mermaid"]

_SAFE_ID = re.compile(r"[^0-9A-Za-z_]")


def graph_to_dict(graph: SecurityGraph) -> dict[str, Any]:
    """Return a JSON-serializable, deterministically ordered representation."""

    nodes = [
        {"id": node_id, "type": str(attrs.get("node_type", "")), "attributes": dict(attrs)}
        for node_id, attrs in graph.nodes()
    ]
    edges = [
        {
            "source": source,
            "target": target,
            "type": edge_type,
            "attributes": dict(attrs),
        }
        for source, target, edge_type, attrs in graph.edges()
    ]
    return {
        "agent": graph.agent_id,
        "schema_version": graph.schema_version,
        "nodes": nodes,
        "edges": edges,
    }


def graph_to_json(graph: SecurityGraph, *, indent: int = 2) -> str:
    """Return the graph as canonical JSON (sorted keys, stable ordering)."""

    return json.dumps(graph_to_dict(graph), indent=indent, sort_keys=True) + "\n"


def _mermaid_id_map(graph: SecurityGraph) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for node_id, _ in graph.nodes():
        safe = _SAFE_ID.sub("_", node_id)
        if not safe or safe[0].isdigit():
            safe = f"n_{safe}"
        mapping[node_id] = safe
    return mapping


def _edge_label(edge_type: str, attrs: dict[str, Any]) -> str:
    operations = attrs.get("operations")
    if isinstance(operations, list) and operations:
        return f"{edge_type}: {', '.join(str(op) for op in operations)}"
    if edge_type == "outbound_to" and attrs.get("declared") is False:
        return "outbound_to: undeclared destination"
    return edge_type


def graph_to_mermaid(graph: SecurityGraph, *, direction: str = "LR") -> str:
    """Return a Mermaid ``graph`` definition with typed, labelled edges."""

    ids = _mermaid_id_map(graph)
    lines = [f"graph {direction}"]
    for node_id, attrs in graph.nodes():
        node_type = str(attrs.get("node_type", ""))
        label = f"{node_id}<br/>{node_type}"
        lines.append(f'    {ids[node_id]}["{label}"]')
    for source, target, edge_type, attrs in graph.edges():
        label = _edge_label(edge_type, attrs)
        lines.append(f"    {ids[source]} -->|{label}| {ids[target]}")
    return "\n".join(lines) + "\n"


def _dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def graph_to_dot(graph: SecurityGraph) -> str:
    """Return a Graphviz DOT digraph with typed edges and node attributes."""

    lines = ["digraph pathwarden {", "    rankdir=LR;"]
    for node_id, attrs in graph.nodes():
        node_type = str(attrs.get("node_type", ""))
        extra = ""
        sensitivity = attrs.get("sensitivity")
        if sensitivity is not None:
            extra = f"\\nsensitivity={sensitivity}"
        label = _dot_escape(f"{node_id}\\n{node_type}{extra}")
        lines.append(f'    "{_dot_escape(node_id)}" [label="{label}", node_type="{node_type}"];')
    for source, target, edge_type, attrs in graph.edges():
        label = _edge_label(edge_type, attrs)
        lines.append(
            f'    "{_dot_escape(source)}" -> "{_dot_escape(target)}" '
            f'[label="{_dot_escape(label)}", edge_type="{edge_type}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"
