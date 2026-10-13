"""PW-007 — Privilege chain."""

from __future__ import annotations

import networkx as nx

from pathwarden.finding import (
    Confidence,
    Finding,
    FindingPath,
    FindingStatus,
    make_finding_id,
)
from pathwarden.graph.model import SecurityGraph
from pathwarden.graph.permissions import check_destinations
from pathwarden.models.config import AgentConfig
from pathwarden.models.enums import Operation, PermissionStatus
from pathwarden.rules.base import Rule, RuleContext
from pathwarden.rules.common import (
    SENSITIVE_LEVELS,
    ToolResourceAccess,
    path_edge,
    resource_operations,
)
from pathwarden.severity import MUTATE, compute_severity

__all__ = ["PW007"]

#: Operations that make a tool a chain *endpoint*.
END_OPERATIONS = frozenset({Operation.WRITE, Operation.DELETE, Operation.EXECUTE})


class PW007(Rule):
    """Flag three-or-more-tool chains from a sensitive read to a risky endpoint."""

    id = "PW-007"
    title = "Privilege chain"
    rationale = (
        "Several individually permissible tools linked by flows_to edges can combine into a "
        "chain that starts at a confidential/restricted read and ends at an outbound or "
        "write/execute capability."
    )
    prerequisites = (
        "At least two flows_to edges among tools (three tools).",
        "A sensitive read at the start and an outbound or write/execute tool at the end.",
    )
    limitations = (
        "A chain is only a potential path. Two-tool read-to-outbound cases are reported by "
        "PW-005, not here. Structural connectivity is distinguished from permission validity: "
        "chains whose starting read is denied are reported as informational."
    )

    def evaluate(self, context: RuleContext) -> list[Finding]:
        config = context.config
        graph = context.graph
        flow_graph = self._flow_graph(graph)
        if flow_graph.number_of_edges() == 0:
            return []

        accesses = resource_operations(config, graph)
        starts: dict[str, ToolResourceAccess] = {}
        for access in accesses:
            if (
                access.operation is Operation.READ
                and access.resource.sensitivity in SENSITIVE_LEVELS
            ):
                starts.setdefault(access.tool.id, access)

        ends = {
            tool.id
            for tool in config.tools
            if tool.outbound or any(op in END_OPERATIONS for op in tool.operations)
        }

        findings: list[Finding] = []
        for start_id in sorted(starts):
            for end_id in sorted(ends):
                if start_id == end_id:
                    continue
                if start_id not in flow_graph or end_id not in flow_graph:
                    continue
                for path in nx.all_simple_paths(flow_graph, start_id, end_id):
                    if len(path) < 3:
                        continue
                    findings.append(
                        self._finding(context, starts[start_id], path, accesses)
                    )
        return findings

    def _flow_graph(self, graph: SecurityGraph) -> nx.DiGraph[str]:
        flow: nx.DiGraph[str] = nx.DiGraph()
        for source, target, edge_type, _ in graph.edges():
            if edge_type == "flows_to":
                flow.add_edge(source, target)
        return flow

    def _end_status(
        self,
        config: AgentConfig,
        graph: SecurityGraph,
        accesses: list[ToolResourceAccess],
        end_id: str,
    ) -> PermissionStatus:
        statuses: list[PermissionStatus] = []
        tool = config.tool_by_id(end_id)
        if tool is not None and tool.outbound:
            for source, target, edge_type, attrs in graph.edges():
                if source != tool.id or edge_type != "outbound_to":
                    continue
                if attrs.get("declared"):
                    result = check_destinations(
                        tool.allowed_destinations,
                        config.policy.allowed_outbound_destinations,
                        str(attrs.get("destination", target)),
                    )
                    statuses.append(result.status)
                else:
                    statuses.append(PermissionStatus.UNKNOWN)
        for access in accesses:
            if access.tool.id == end_id and access.operation in END_OPERATIONS:
                statuses.append(access.result.status)

        if not statuses:
            return PermissionStatus.UNKNOWN
        if PermissionStatus.ALLOWED in statuses:
            return PermissionStatus.ALLOWED
        if PermissionStatus.UNKNOWN in statuses:
            return PermissionStatus.UNKNOWN
        return PermissionStatus.DENIED

    def _finding(
        self,
        context: RuleContext,
        start: ToolResourceAccess,
        path: list[str],
        accesses: list[ToolResourceAccess],
    ) -> Finding:
        config = context.config
        graph = context.graph
        end_status = self._end_status(config, graph, accesses, path[-1])
        start_status = start.result.status

        if start_status is PermissionStatus.DENIED:
            status = FindingStatus.INFORMATIONAL
            status_unknown = True
            confidence = Confidence.LOW
        else:
            unresolved = (
                start_status is PermissionStatus.UNKNOWN
                or end_status is PermissionStatus.UNKNOWN
            )
            status = FindingStatus.INDETERMINATE if unresolved else FindingStatus.REACHABLE
            status_unknown = unresolved
            confidence = Confidence.LOW if unresolved else Confidence.HIGH

        severity = compute_severity(
            start.resource.sensitivity, MUTATE, status_unknown=status_unknown
        )

        edges = [path_edge(graph, start.tool.id, start.resource.id, "reads")]
        edges.extend(
            path_edge(graph, path[index], path[index + 1], "flows_to")
            for index in range(len(path) - 1)
        )
        path_model = FindingPath(nodes=(start.resource.id, *path), edges=tuple(edges))

        missing: list[str] = []
        if start_status is PermissionStatus.UNKNOWN:
            missing.append("starting read permission is unknown")
        if end_status is PermissionStatus.UNKNOWN:
            missing.append("ending tool permission or destination is unknown")
        if start_status is PermissionStatus.DENIED:
            missing.append("starting read is denied; chain is structurally connected only")

        return Finding(
            finding_id=make_finding_id(
                self.id, start.tool.id, start.resource.id, ">".join(path)
            ),
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=confidence,
            status=status,
            summary=(
                f"Chain of {len(path)} tools {' -> '.join(path)} starts at a "
                f"{start.resource.sensitivity.value} read ({start.resource.id!r}) and ends at "
                f"{path[-1]!r}."
            ),
            evidence=(
                f"starting read: {start.tool.id!r} -> {start.resource.id!r} "
                f"({start_status.value})",
                f"flows_to chain: {' -> '.join(path)}",
                f"ending tool status: {end_status.value}",
            ),
            path=path_model,
            affected_resources=(start.resource.id,),
            effective_identity=start.tool.identity,
            missing_or_uncertain_constraints=tuple(missing),
            remediation=(
                "Remove unnecessary flows_to links, narrow each tool's access, and require "
                "approval for the final outbound or mutating hop."
            ),
            limitations=self.limitations,
        )
