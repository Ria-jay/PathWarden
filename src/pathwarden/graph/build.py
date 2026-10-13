"""Build a :class:`~pathwarden.graph.model.SecurityGraph` from a configuration.

Edges are added based on declared capabilities, not on assumption:

* ``feeds_context``  input source → agent
* ``can_invoke``     agent → tool
* ``uses_identity``  tool → identity (and agent → identity for the execution identity)
* ``reads``          tool → resource (read operations)
* ``writes``         tool → resource (write/delete/execute/send operations)
* ``outbound_to``    tool → external destination
* ``flows_to``       tool → tool

A tool with *undeclared* resource restrictions is connected to every resource
with the restriction recorded as undeclared. The edge existing does **not** mean
the operation is permitted; that is decided by the permission engine at query
time. Conversely, a tool with declared restrictions is only connected to the
resources those restrictions admit.
"""

from __future__ import annotations

from typing import Any

from pathwarden.graph.model import EdgeType, NodeType, SecurityGraph
from pathwarden.models.config import AgentConfig
from pathwarden.models.entities import Resource, Tool
from pathwarden.models.enums import Operation

__all__ = ["UNDECLARED_DESTINATION_ID", "build_graph"]

#: Node id used when an outbound tool declares no usable destinations.
UNDECLARED_DESTINATION_ID = "external:unspecified"

_READ_OPERATIONS = {Operation.READ}


def _jsonable(value: Any) -> Any:
    """Convert model values to JSON-friendly primitives, preserving unknowns."""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if hasattr(value, "value"):  # StrEnum
        return value.value
    if isinstance(value, dict):
        return {_jsonable(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return str(value)


def _is_deny(pattern: str) -> bool:
    return pattern.startswith("!") and len(pattern) > 1


def _bare(pattern: str) -> str:
    return pattern[1:] if _is_deny(pattern) else pattern


def _matches(patterns: tuple[str, ...], value: str) -> bool:
    import fnmatch

    return any(fnmatch.fnmatchcase(value, _bare(pattern)) for pattern in patterns)


def _tool_resources(tool: Tool, resources: tuple[Resource, ...]) -> tuple[list[Resource], str]:
    """Return the resources a tool can plausibly reach and the basis for it."""

    restrictions = tool.resource_restrictions
    if restrictions is None:
        return list(resources), "undeclared"
    if len(restrictions) == 0:
        return [], "empty"

    denies = tuple(pattern for pattern in restrictions if _is_deny(pattern))
    allows = tuple(pattern for pattern in restrictions if not _is_deny(pattern))

    selected: list[Resource] = []
    for resource in resources:
        if _matches(denies, resource.id):
            continue
        if allows and not _matches(allows, resource.id):
            continue
        selected.append(resource)
    return selected, "declared"


def _shared_operations(tool: Tool, resource: Resource) -> list[Operation]:
    permitted = resource.permitted_operations
    if permitted is None:
        return list(tool.operations)
    return [operation for operation in tool.operations if operation in permitted]


def build_graph(config: AgentConfig) -> SecurityGraph:
    """Construct the deterministic, permission-aware graph for ``config``."""

    graph = SecurityGraph(schema_version=config.schema_version, agent_id=config.agent.id)

    # Nodes -----------------------------------------------------------------
    graph.add_node(
        config.agent.id,
        NodeType.AGENT,
        name=config.agent.name,
        description=config.agent.description,
        execution_identity=config.agent.execution_identity,
    )
    for identity in config.identities:
        graph.add_node(
            identity.id,
            NodeType.IDENTITY,
            name=identity.name,
            identity_type=identity.type.value,
            granted_scopes=_jsonable(identity.granted_scopes),
            resource_restrictions=_jsonable(identity.resource_restrictions),
            tenants=_jsonable(identity.tenants),
            acts_as_requester=identity.acts_as_requester,
            credential_ref=identity.credential_ref,
        )
    for source in config.input_sources:
        graph.add_node(
            source.id,
            NodeType.INPUT_SOURCE,
            name=source.name,
            input_type=source.type.value,
            trust=source.trust.value,
            may_contain_attacker_content=source.may_contain_attacker_content,
            requesting_principal=source.requesting_principal,
        )
    for tool in config.tools:
        graph.add_node(
            tool.id,
            NodeType.TOOL,
            name=tool.name,
            description=tool.description,
            operations=[operation.value for operation in tool.operations],
            identity=tool.identity,
            required_scopes=_jsonable(tool.required_scopes),
            resource_restrictions=_jsonable(tool.resource_restrictions),
            approval=_jsonable(tool.approval),
            outbound=tool.outbound,
            allowed_destinations=_jsonable(tool.allowed_destinations),
            authorization_check=(
                tool.authorization_check.type.value if tool.authorization_check else None
            ),
            declared_purpose=tool.declared_purpose,
        )
    for resource in config.resources:
        graph.add_node(
            resource.id,
            NodeType.RESOURCE,
            name=resource.name,
            resource_type=resource.type,
            sensitivity=resource.sensitivity.value,
            owner=resource.owner,
            tenant=resource.tenant,
            permitted_operations=_jsonable(resource.permitted_operations),
            access_restrictions=_jsonable(resource.access_restrictions),
        )

    # Edges -----------------------------------------------------------------
    for source in config.input_sources:
        graph.add_edge(
            source.id,
            config.agent.id,
            EdgeType.FEEDS_CONTEXT,
            trust=source.trust.value,
            may_contain_attacker_content=source.may_contain_attacker_content,
        )

    for tool in config.tools:
        graph.add_edge(config.agent.id, tool.id, EdgeType.CAN_INVOKE)

    execution_identity = config.identity_by_id(config.agent.execution_identity)
    if execution_identity is not None:
        graph.add_edge(
            config.agent.id,
            execution_identity.id,
            EdgeType.USES_IDENTITY,
            role="execution_identity",
        )

    for tool in config.tools:
        graph.add_edge(tool.id, tool.identity, EdgeType.USES_IDENTITY, role="tool_identity")

        selected, basis = _tool_resources(tool, config.resources)
        for resource in selected:
            operations = _shared_operations(tool, resource)
            read_ops = sorted(op.value for op in operations if op in _READ_OPERATIONS)
            write_ops = sorted(op.value for op in operations if op not in _READ_OPERATIONS)
            if read_ops:
                graph.add_edge(
                    tool.id,
                    resource.id,
                    EdgeType.READS,
                    operations=read_ops,
                    restriction_basis=basis,
                )
            if write_ops:
                graph.add_edge(
                    tool.id,
                    resource.id,
                    EdgeType.WRITES,
                    operations=write_ops,
                    restriction_basis=basis,
                )

        for target in tool.output_flows_to:
            graph.add_edge(tool.id, target, EdgeType.FLOWS_TO)

        if tool.outbound:
            destinations = tool.allowed_destinations
            if not destinations:
                graph.add_node(
                    UNDECLARED_DESTINATION_ID,
                    NodeType.EXTERNAL_DESTINATION,
                    declared=False,
                    reason="tool declares no allowed destinations"
                    if destinations is None
                    else "tool declares an empty destination allowlist",
                )
                graph.add_edge(
                    tool.id,
                    UNDECLARED_DESTINATION_ID,
                    EdgeType.OUTBOUND_TO,
                    declared=False,
                    policy_allowed_destinations=_jsonable(
                        config.policy.allowed_outbound_destinations
                    ),
                )
            else:
                for pattern in destinations:
                    if _is_deny(pattern):
                        continue
                    destination_id = f"external:{pattern}"
                    graph.add_node(
                        destination_id,
                        NodeType.EXTERNAL_DESTINATION,
                        declared=True,
                        pattern=pattern,
                    )
                    graph.add_edge(
                        tool.id,
                        destination_id,
                        EdgeType.OUTBOUND_TO,
                        declared=True,
                        destination=pattern,
                        policy_allowed_destinations=_jsonable(
                            config.policy.allowed_outbound_destinations
                        ),
                    )

    return graph
