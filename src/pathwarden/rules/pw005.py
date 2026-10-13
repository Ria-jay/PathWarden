"""PW-005 — Exfiltration path."""

from __future__ import annotations

from typing import Any

from pathwarden.finding import (
    Confidence,
    Finding,
    FindingPath,
    FindingStatus,
    make_finding_id,
)
from pathwarden.graph.model import SecurityGraph
from pathwarden.graph.permissions import check_destinations
from pathwarden.models.entities import Tool
from pathwarden.models.enums import Operation, PermissionStatus
from pathwarden.rules.base import Rule, RuleContext
from pathwarden.rules.common import (
    SENSITIVE_LEVELS,
    ToolResourceAccess,
    path_edge,
    resource_operations,
)
from pathwarden.severity import MUTATE, compute_severity

__all__ = ["PW005"]


class PW005(Rule):
    """Flag paths from a sensitive read to an outbound tool of the same agent."""

    id = "PW-005"
    title = "Exfiltration path"
    rationale = (
        "An agent that can read a confidential-or-above resource and invoke an outbound tool "
        "whose destinations are absent or insufficient under policy has a potential "
        "exfiltration path."
    )
    prerequisites = (
        "A permission-valid or unknown read of a confidential/restricted resource.",
        "An outbound tool the same agent can invoke.",
    )
    limitations = (
        "This is a potential path, not proof that data leaves the system. Pathwarden cannot "
        "observe whether the agent forwards the resource contents or whether destinations are "
        "enforced at runtime."
    )

    def evaluate(self, context: RuleContext) -> list[Finding]:
        config = context.config
        graph = context.graph
        outbound_tools = [tool for tool in config.tools if tool.outbound]
        if not outbound_tools:
            return []

        sensitive_reads = [
            access
            for access in resource_operations(config, graph)
            if access.operation is Operation.READ
            and access.resource.sensitivity in SENSITIVE_LEVELS
            and access.result.status is not PermissionStatus.DENIED
        ]

        findings: list[Finding] = []
        for access in sensitive_reads:
            for tool in outbound_tools:
                findings.extend(self._for_outbound(context, access, tool))
        return findings

    def _outbound_edges(self, graph: SecurityGraph, tool: Tool) -> list[tuple[str, dict[str, Any]]]:
        return [
            (target, dict(attrs))
            for source, target, edge_type, attrs in graph.edges()
            if source == tool.id and edge_type == "outbound_to"
        ]

    def _for_outbound(
        self, context: RuleContext, access: ToolResourceAccess, outbound: Tool
    ) -> list[Finding]:
        config = context.config
        graph = context.graph
        policy = config.policy
        boundary = access.resource.sensitivity in policy.boundary_sensitivity
        findings: list[Finding] = []

        for destination_id, attrs in self._outbound_edges(graph, outbound):
            declared = bool(attrs.get("declared", False))
            if declared:
                label = str(attrs.get("destination", destination_id))
                dcheck = check_destinations(
                    outbound.allowed_destinations,
                    policy.allowed_outbound_destinations,
                    label,
                )
                if dcheck.status is PermissionStatus.DENIED:
                    continue
                destination_status = dcheck.status
            else:
                label = "unspecified"
                destination_status = PermissionStatus.UNKNOWN

            if destination_status is PermissionStatus.ALLOWED and not boundary:
                continue

            status_unknown = (
                access.result.status is PermissionStatus.UNKNOWN
                or destination_status is PermissionStatus.UNKNOWN
            )
            severity = compute_severity(
                access.resource.sensitivity, MUTATE, status_unknown=status_unknown
            )
            status = FindingStatus.INDETERMINATE if status_unknown else FindingStatus.REACHABLE
            confidence = Confidence.LOW if status_unknown else Confidence.HIGH

            missing: list[str] = []
            if destination_status is PermissionStatus.UNKNOWN:
                missing.append("allowed outbound destinations are absent or insufficient")
            if access.result.status is PermissionStatus.UNKNOWN:
                missing.append("read permission could not be fully verified")

            path = FindingPath(
                nodes=(
                    config.agent.id,
                    access.tool.id,
                    access.resource.id,
                    outbound.id,
                    destination_id,
                ),
                edges=(
                    path_edge(graph, config.agent.id, access.tool.id, "can_invoke"),
                    path_edge(graph, access.tool.id, access.resource.id, "reads"),
                    path_edge(graph, config.agent.id, outbound.id, "can_invoke"),
                    path_edge(graph, outbound.id, destination_id, "outbound_to"),
                ),
            )

            findings.append(
                Finding(
                    finding_id=make_finding_id(
                        self.id, access.tool.id, access.resource.id, outbound.id, destination_id
                    ),
                    rule_id=self.id,
                    title=self.title,
                    severity=severity,
                    confidence=confidence,
                    status=status,
                    summary=(
                        f"Agent {config.agent.id!r} can read {access.resource.sensitivity.value} "
                        f"resource {access.resource.id!r} via {access.tool.id!r} and invoke "
                        f"outbound tool {outbound.id!r} with destination {label!r}."
                    ),
                    evidence=(
                        f"read path: {access.tool.id!r} -> {access.resource.id!r} "
                        f"(permission: {access.result.status.value})",
                        f"outbound tool {outbound.id!r}: "
                        f"allowed_destinations={list(outbound.allowed_destinations or ()) or None}",
                        f"policy allowed_outbound_destinations: "
                        f"{list(policy.allowed_outbound_destinations or ()) or None}",
                        f"policy boundary_sensitivity: "
                        f"{[level.value for level in policy.boundary_sensitivity]}",
                        f"destination control status: {destination_status.value}",
                    ),
                    path=path,
                    affected_resources=(access.resource.id,),
                    effective_identity=access.tool.identity,
                    relevant_permissions=tuple(
                        f"{step.name}: {step.status.value}" for step in access.result.steps
                    ),
                    missing_or_uncertain_constraints=tuple(missing),
                    remediation=(
                        "Restrict outbound destinations to an explicit allowlist, add the "
                        "resource's sensitivity to the policy boundary, and require approval for "
                        "outbound operations."
                    ),
                    limitations=self.limitations,
                )
            )
        return findings
