"""PW-001 — Untrusted input to sensitive operation."""

from __future__ import annotations

from pathwarden.finding import (
    Confidence,
    Finding,
    FindingPath,
    FindingStatus,
    make_finding_id,
)
from pathwarden.models.entities import InputSource
from pathwarden.models.enums import PermissionStatus
from pathwarden.rules.base import Rule, RuleContext
from pathwarden.rules.common import (
    MUTATING_OPERATIONS,
    SENSITIVE_LEVELS,
    ToolResourceAccess,
    path_edge,
    resource_operations,
    status_label,
    unknown_constraints,
    untrusted_sources,
)
from pathwarden.severity import compute_severity, operation_class

__all__ = ["PW001"]


class PW001(Rule):
    """Flag potential influence paths from untrusted input to sensitive work."""

    id = "PW-001"
    title = "Untrusted input to sensitive operation"
    rationale = (
        "Untrusted or attacker-controlled content that can feed an agent which can "
        "invoke a tool touching a confidential/restricted resource (or performing a "
        "write, delete, execute, or send) creates a potential influence path."
    )
    prerequisites = (
        "At least one input source that is untrusted or flagged attacker-controlled.",
        "An agent that can invoke a tool with a declared sensitive operation.",
    )
    limitations = (
        "A path is a potential influence path, not proof that the input influenced the "
        "operation. Pathwarden does not model model behaviour and never claims the input "
        "caused the tool call."
    )

    def evaluate(self, context: RuleContext) -> list[Finding]:
        sources = untrusted_sources(context.config)
        if not sources:
            return []

        findings: list[Finding] = []
        for access in resource_operations(context.config, context.graph):
            if access.result.status is PermissionStatus.DENIED:
                continue
            sensitive = (
                access.resource.sensitivity in SENSITIVE_LEVELS
                or access.operation in MUTATING_OPERATIONS
            )
            if not sensitive:
                continue
            for source in sources:
                findings.append(self._finding(context, source, access))
        return findings

    def _finding(
        self, context: RuleContext, source: InputSource, access: ToolResourceAccess
    ) -> Finding:
        config = context.config
        graph = context.graph
        tool = access.tool
        resource = access.resource
        operation = access.operation
        result = access.result
        status_unknown = result.status is PermissionStatus.UNKNOWN

        severity = compute_severity(
            resource.sensitivity,
            operation_class(operation),
            untrusted=True,
            control_applies=False,
            status_unknown=status_unknown,
        )
        edge_type = "reads" if operation.value == "read" else "writes"
        path = FindingPath(
            nodes=(source.id, config.agent.id, tool.id, resource.id),
            edges=(
                path_edge(graph, source.id, config.agent.id, "feeds_context"),
                path_edge(graph, config.agent.id, tool.id, "can_invoke"),
                path_edge(graph, tool.id, resource.id, edge_type),
            ),
        )
        deciding = result.deciding_step
        status = FindingStatus.INDETERMINATE if status_unknown else FindingStatus.REACHABLE
        confidence = Confidence.LOW if status_unknown else Confidence.HIGH

        evidence = (
            f"input source {source.id!r}: trust={source.trust.value}, "
            f"may_contain_attacker_content={source.may_contain_attacker_content}",
            f"tool {tool.id!r} declares operation {operation.value!r}",
            f"resource {resource.id!r}: sensitivity={resource.sensitivity.value}",
            f"permission status: {status_label(result)}"
            + (f" (decided by {deciding.name}: {deciding.detail})" if deciding else ""),
        )

        return Finding(
            finding_id=make_finding_id(self.id, source.id, tool.id, operation.value, resource.id),
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=confidence,
            status=status,
            summary=(
                f"Untrusted source {source.id!r} can feed agent {config.agent.id!r}, which can "
                f"invoke tool {tool.id!r} to perform {operation.value!r} on "
                f"{resource.sensitivity.value} resource {resource.id!r}."
            ),
            evidence=evidence,
            path=path,
            affected_resources=(resource.id,),
            effective_identity=tool.identity,
            relevant_permissions=tuple(
                f"{step.name}: {step.status.value}" for step in result.steps
            ),
            missing_or_uncertain_constraints=unknown_constraints(result),
            remediation=(
                "Keep untrusted content out of sensitive operations, require an explicit "
                "approval and a requester-scoped authorization check, and narrow the tool's "
                "resource restrictions."
            ),
            limitations=self.limitations,
        )
