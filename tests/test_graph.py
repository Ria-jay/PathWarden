"""Graph construction, determinism, exports, and permission-aware reachability."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from pathwarden.config.loader import load_config, load_config_from_text
from pathwarden.graph import NodeType, build_graph, graph_to_dot, graph_to_json, graph_to_mermaid
from pathwarden.graph.permissions import evaluate_access
from pathwarden.models.enums import Operation, PermissionStatus

Fixture = Callable[[str], Path]


def _node_types(graph: Any) -> dict[str, str]:
    return {node_id: str(attrs["node_type"]) for node_id, attrs in graph.nodes()}


def _edge_types(graph: Any) -> set[tuple[str, str, str]]:
    return {(source, target, edge_type) for source, target, edge_type, _ in graph.edges()}


def test_build_graph_from_hr_fixture(fixture: Fixture) -> None:
    config = load_config(fixture("valid_hr.yaml")).config
    graph = build_graph(config)

    types = _node_types(graph)
    assert types["hr-assistant"] == NodeType.AGENT
    assert types["cv-upload"] == NodeType.INPUT_SOURCE
    assert types["hr-agent-identity"] == NodeType.IDENTITY
    assert types["hr-database"] == NodeType.TOOL
    assert types["employee-db"] == NodeType.RESOURCE
    assert types["external:unspecified"] == NodeType.EXTERNAL_DESTINATION

    edges = _edge_types(graph)
    assert ("cv-upload", "hr-assistant", "feeds_context") in edges
    assert ("hr-assistant", "hr-database", "can_invoke") in edges
    assert ("hr-database", "hr-agent-identity", "uses_identity") in edges
    assert ("hr-database", "employee-db", "reads") in edges
    assert ("email-sender", "external:unspecified", "outbound_to") in edges


def test_read_edge_records_operations(fixture: Fixture) -> None:
    config = load_config(fixture("valid_hr.yaml")).config
    graph = build_graph(config)
    read_edges = [
        attrs
        for source, target, edge_type, attrs in graph.edges()
        if source == "hr-database" and target == "employee-db" and edge_type == "reads"
    ]
    assert len(read_edges) == 1
    assert read_edges[0]["operations"] == ["read"]
    assert read_edges[0]["restriction_basis"] == "undeclared"


def test_graph_is_deterministic(fixture: Fixture) -> None:
    config = load_config(fixture("valid_hr.yaml")).config
    first = graph_to_json(build_graph(config))
    second = graph_to_json(build_graph(config))
    assert first == second


def test_exports_contain_identifiers(fixture: Fixture) -> None:
    config = load_config(fixture("valid_hr.yaml")).config
    graph = build_graph(config)

    mermaid = graph_to_mermaid(graph)
    assert "graph LR" in mermaid
    assert "hr-assistant" in mermaid
    assert "reads: read" in mermaid
    assert "outbound_to: undeclared destination" in mermaid

    dot = graph_to_dot(graph)
    assert "digraph pathwarden" in dot
    assert '"hr-database"' in dot
    assert 'edge_type="reads"' in dot


def test_declared_restrictions_limit_edges() -> None:
    config = load_config_from_text(
        """
schema_version: "1.0"
agent: {id: a, name: A, execution_identity: idn}
identities:
  - {id: idn, type: service_account, granted_scopes: [db:read], tenants: [acme]}
tools:
  - id: t
    name: T
    operations: [read]
    identity: idn
    required_scopes: [db:read]
    resource_restrictions: ["db/*"]
resources:
  - id: db/employees
    type: database
    sensitivity: confidential
    tenant: acme
    permitted_operations: [read]
  - id: secrets/vault
    type: secret_store
    sensitivity: restricted
    tenant: acme
    permitted_operations: [read]
"""
    ).config
    graph = build_graph(config)
    edges = _edge_types(graph)
    assert ("t", "db/employees", "reads") in edges
    assert ("t", "secrets/vault", "reads") not in edges


def test_empty_restrictions_produce_no_resource_edges() -> None:
    config = load_config_from_text(
        """
schema_version: "1.0"
agent: {id: a, name: A, execution_identity: idn}
identities:
  - {id: idn, type: service_account}
tools:
  - id: t
    name: T
    operations: [read]
    identity: idn
    resource_restrictions: []
resources:
  - {id: r, type: database, sensitivity: internal, tenant: acme}
"""
    ).config
    graph = build_graph(config)
    assert ("t", "r", "reads") not in _edge_types(graph)


def test_structurally_connected_but_not_permission_reachable() -> None:
    """An edge can exist while the permission engine denies the operation."""

    config = load_config_from_text(
        """
schema_version: "1.0"
agent: {id: a, name: A, execution_identity: idn}
identities:
  - {id: idn, type: service_account, granted_scopes: [db:read], tenants: [globex]}
tools:
  - id: t
    name: T
    operations: [read]
    identity: idn
    required_scopes: [db:read]
resources:
  - {id: r, type: database, sensitivity: confidential, tenant: acme, permitted_operations: [read]}
"""
    ).config
    graph = build_graph(config)

    # The edge exists (structure) ...
    assert ("t", "r", "reads") in _edge_types(graph)
    # ... but the tenant check denies the operation (permission).
    result = evaluate_access(
        config, tool=config.tools[0], operation=Operation.READ, resource=config.resources[0]
    )
    assert result.status is PermissionStatus.DENIED
    assert result.deciding_step is not None
    assert result.deciding_step.name == "tenant"


def test_flows_to_edges_between_tools() -> None:
    config = load_config_from_text(
        """
schema_version: "1.0"
agent: {id: a, name: A, execution_identity: idn}
identities:
  - {id: idn, type: service_account}
tools:
  - {id: reader, name: Reader, operations: [read], identity: idn, output_flows_to: [summarizer]}
  - {id: summarizer, name: Summarizer, operations: [read], identity: idn}
"""
    ).config
    graph = build_graph(config)
    assert ("reader", "summarizer", "flows_to") in _edge_types(graph)


def test_send_operation_produces_writes_edge() -> None:
    config = load_config_from_text(
        """
schema_version: "1.0"
agent: {id: a, name: A, execution_identity: idn}
identities:
  - {id: idn, type: service_account}
tools:
  - id: mailer
    name: Mailer
    operations: [send]
    identity: idn
    outbound: true
resources:
  - id: mailbox
    type: messaging
    sensitivity: internal
    tenant: acme
    permitted_operations: [send]
"""
    ).config
    graph = build_graph(config)
    edges = _edge_types(graph)
    assert ("mailer", "mailbox", "writes") in edges
    assert ("mailer", "external:unspecified", "outbound_to") in edges
    write_edge = next(
        attrs
        for source, target, edge_type, attrs in graph.edges()
        if source == "mailer" and target == "mailbox" and edge_type == "writes"
    )
    assert write_edge["operations"] == ["send"]
