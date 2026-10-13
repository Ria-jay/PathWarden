"""Shared helpers used by the static rules."""

from __future__ import annotations

from dataclasses import dataclass

from pathwarden.finding import PathEdge
from pathwarden.graph.model import SecurityGraph
from pathwarden.graph.permissions import (
    ApprovalAssessmentStatus,
    PermissionResult,
    assess_approval,
    evaluate_access,
)
from pathwarden.models.config import AgentConfig
from pathwarden.models.entities import InputSource, Resource, Tool
from pathwarden.models.enums import Operation, PermissionStatus, Sensitivity, Trust

__all__ = [
    "MUTATING_OPERATIONS",
    "SENSITIVE_LEVELS",
    "ToolResourceAccess",
    "approval_is_declared",
    "most_sensitive",
    "path_edge",
    "resource_operations",
    "unknown_constraints",
    "untrusted_sources",
]

#: Sensitivity levels that PW-001/005/007 treat as sensitive.
SENSITIVE_LEVELS = frozenset({Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED})

#: Operations other than read that PW-001 treats as sensitive by themselves.
MUTATING_OPERATIONS = frozenset(
    {Operation.WRITE, Operation.DELETE, Operation.EXECUTE, Operation.SEND}
)


@dataclass(frozen=True)
class ToolResourceAccess:
    """A declared tool operation on a resource, with its permission result."""

    tool: Tool
    operation: Operation
    resource: Resource
    result: PermissionResult


def resource_operations(config: AgentConfig, graph: SecurityGraph) -> list[ToolResourceAccess]:
    """Enumerate declared (tool, operation, resource) triples with permissions."""

    accesses: list[ToolResourceAccess] = []
    for source, target, edge_type, attrs in graph.edges():
        if edge_type not in ("reads", "writes"):
            continue
        tool = config.tool_by_id(source)
        resource = config.resource_by_id(target)
        if tool is None or resource is None:
            continue
        for value in attrs.get("operations", []):
            operation = Operation(value)
            result = evaluate_access(config, tool=tool, operation=operation, resource=resource)
            accesses.append(ToolResourceAccess(tool, operation, resource, result))
    return accesses


def untrusted_sources(config: AgentConfig) -> list[InputSource]:
    """Input sources that are untrusted or flagged as attacker-controlled."""

    return [
        source
        for source in config.input_sources
        if source.trust is Trust.UNTRUSTED or source.may_contain_attacker_content
    ]


def approval_is_declared(
    config: AgentConfig, *, tool: Tool, operation: Operation, resource: Resource | None
) -> bool:
    """Whether policy requires approval and the tool declares it required."""

    sensitive = resource is not None and resource.sensitivity in config.policy.approval_sensitivity
    assessment = assess_approval(config.policy, tool=tool, operation=operation, sensitive=sensitive)
    return assessment.status is ApprovalAssessmentStatus.DECLARED


def unknown_constraints(result: PermissionResult) -> tuple[str, ...]:
    """Return human-readable descriptions of unknown permission steps."""

    return tuple(
        f"{step.name}: {step.detail}"
        for step in result.steps
        if step.status is PermissionStatus.UNKNOWN
    )


def status_label(result: PermissionResult) -> str:
    """Return the permission status value for a result."""

    return result.status.value


def most_sensitive(resources: list[Resource]) -> Sensitivity:
    """Return the most sensitive level among ``resources`` (default internal)."""

    order = {
        Sensitivity.PUBLIC: 0,
        Sensitivity.INTERNAL: 1,
        Sensitivity.CONFIDENTIAL: 2,
        Sensitivity.RESTRICTED: 3,
    }
    if not resources:
        return Sensitivity.INTERNAL
    return max(resources, key=lambda resource: order[resource.sensitivity]).sensitivity


def path_edge(graph: SecurityGraph, source: str, target: str, edge_type: str) -> PathEdge:
    """Return a :class:`PathEdge` carrying the real graph attributes, if any."""

    attributes: dict[str, object] = {}
    data = graph.graph.get_edge_data(source, target)
    if data:
        for key, value in data.items():
            if key == edge_type:
                attributes = dict(value)
    return PathEdge(source=source, target=target, edge_type=edge_type, attributes=attributes)
