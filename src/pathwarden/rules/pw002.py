"""PW-002 — Confused deputy."""

from __future__ import annotations

from pathwarden.finding import (
    Confidence,
    Finding,
    FindingPath,
    FindingStatus,
    make_finding_id,
)
from pathwarden.models.entities import InputSource
from pathwarden.models.enums import AuthorizationCheckType, PermissionStatus, Trust
from pathwarden.rules.base import Rule, RuleContext
from pathwarden.rules.common import (
    ToolResourceAccess,
    path_edge,
    resource_operations,
    status_label,
)
from pathwarden.severity import compute_severity, operation_class

__all__ = ["PW002"]


class PW002(Rule):
    """Flag tools that may exercise their own authority for a requester."""

    id = "PW-002"
    title = "Confused deputy"
    rationale = (
        "A tool that runs under an identity which does not act as the requester, has no "
        "requester-scoped authorization check, and touches a resource the requester does "
        "not own may exercise its own authority on the requester's behalf."
    )
    prerequisites = (
        "An input source with a requesting_principal.",
        "A tool whose execution identity can reach a resource owned by a different principal.",
    )
    limitations = (
        "This is a potential confused-deputy configuration, not a demonstration that the "
        "deputy is abused. Runtime authorization behavior is not observable here."
    )

    def evaluate(self, context: RuleContext) -> list[Finding]:
        config = context.config
        graph = context.graph
        sources = [source for source in config.input_sources if source.requesting_principal]
        if not sources:
            return []

        findings: list[Finding] = []
        for access in resource_operations(config, graph):
            tool = access.tool
            identity = config.identity_by_id(tool.identity)
            if identity is None or identity.acts_as_requester is True:
                continue
            if access.result.status is PermissionStatus.DENIED:
                continue
            if (
                tool.authorization_check is not None
                and tool.authorization_check.type is AuthorizationCheckType.REQUESTER_SCOPED
            ):
                continue
            for source in sources:
                principal = source.requesting_principal
                if access.resource.owner == principal or access.resource.tenant == principal:
                    continue
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
        identity = config.identity_by_id(tool.identity)

        missing: list[str] = []
        if identity is not None and identity.acts_as_requester is None:
            missing.append("identity.acts_as_requester is undeclared")
        if tool.authorization_check is None:
            missing.append("tool.authorization_check is undeclared")

        result_unknown = result.status is PermissionStatus.UNKNOWN
        status_unknown = bool(missing) or result_unknown
        untrusted = source.trust is Trust.UNTRUSTED or source.may_contain_attacker_content

        severity = compute_severity(
            resource.sensitivity,
            operation_class(operation),
            untrusted=untrusted,
            control_applies=False,
            status_unknown=status_unknown,
        )
        status = FindingStatus.INDETERMINATE if status_unknown else FindingStatus.REACHABLE
        if missing:
            confidence = Confidence.LOW
        elif result_unknown:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.HIGH

        auth = (
            tool.authorization_check.type.value
            if tool.authorization_check is not None
            else "undeclared"
        )
        path = FindingPath(
            nodes=(source.id, config.agent.id, tool.id, resource.id),
            edges=(
                path_edge(graph, source.id, config.agent.id, "feeds_context"),
                path_edge(graph, config.agent.id, tool.id, "can_invoke"),
                path_edge(
                    graph,
                    tool.id,
                    resource.id,
                    "reads" if operation.value == "read" else "writes",
                ),
            ),
        )

        return Finding(
            finding_id=make_finding_id(self.id, source.id, tool.id, operation.value, resource.id),
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=confidence,
            status=status,
            summary=(
                f"Tool {tool.id!r} runs as identity {tool.identity!r} "
                f"(acts_as_requester={identity.acts_as_requester if identity else 'unknown'}), "
                f"has authorization_check={auth}, and can perform {operation.value!r} on "
                f"resource {resource.id!r} which is not owned by requester "
                f"{source.requesting_principal!r}."
            ),
            evidence=(
                f"requesting principal: {source.requesting_principal!r} (via {source.id!r})",
                f"execution identity: {tool.identity!r}",
                f"resource owner/tenant: {resource.owner!r}/{resource.tenant!r}",
                f"authorization_check: {auth}",
                f"permission status: {status_label(result)}",
            ),
            path=path,
            affected_resources=(resource.id,),
            effective_identity=tool.identity,
            relevant_permissions=tuple(
                f"{step.name}: {step.status.value}" for step in result.steps
            ),
            missing_or_uncertain_constraints=tuple(missing),
            remediation=(
                "Add a requester-scoped authorization check, or have the identity act as the "
                "requester, and restrict the tool to resources the requester is authorized for."
            ),
            limitations=self.limitations,
        )
