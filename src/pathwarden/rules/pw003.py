"""PW-003 — Over-broad scope."""

from __future__ import annotations

import re

from pathwarden.finding import (
    Confidence,
    Finding,
    FindingStatus,
    make_finding_id,
)
from pathwarden.graph.permissions import bare_pattern, is_deny_pattern, pattern_list_matches
from pathwarden.models.entities import Identity, Resource, Tool
from pathwarden.models.enums import Operation
from pathwarden.rules.base import Rule, RuleContext
from pathwarden.rules.common import most_sensitive, resource_operations
from pathwarden.severity import compute_severity

__all__ = ["PW003", "scope_operations"]

_OP_TOKENS: dict[str, frozenset[Operation]] = {
    "read": frozenset({Operation.READ}),
    "write": frozenset({Operation.WRITE}),
    "delete": frozenset({Operation.DELETE}),
    "execute": frozenset({Operation.EXECUTE}),
    "send": frozenset({Operation.SEND}),
    "admin": frozenset({Operation.WRITE, Operation.DELETE, Operation.EXECUTE}),
}


def scope_operations(scope: str) -> frozenset[Operation] | None:
    """Map a scope string to operations, or ``None`` if it cannot be determined.

    Operation tokens are read from the trailing ``read``/``write``/``delete``/
    ``execute``/``send``/``admin``/``*`` segment. Anything else is undetermined
    rather than guessed.
    """

    raw = bare_pattern(scope).strip()
    if raw == "*":
        return frozenset(Operation)
    token = re.split(r"[:/.]", raw)[-1].strip().lower()
    if token == "*":
        return frozenset(Operation)
    return _OP_TOKENS.get(token)


class PW003(Rule):
    """Flag permissions broader than a tool's declared operations or resources."""

    id = "PW-003"
    title = "Over-broad scope"
    rationale = (
        "When an identity or tool holds permissions beyond the tool's declared operations "
        "or resource restrictions, a compromise or misuse of that tool gains more access "
        "than its purpose requires."
    )
    prerequisites = (
        "A tool with declared operations.",
        "An identity whose granted scopes or resource restrictions can be compared to them.",
    )
    limitations = (
        "Intended scope is inferred from declared operations and restrictions. When a tool "
        "declares no purpose, or a scope string does not map to a known operation, or a "
        "resource restriction is undeclared, Pathwarden states the limitation instead of "
        "inventing the intended scope."
    )

    def evaluate(self, context: RuleContext) -> list[Finding]:
        config = context.config
        graph = context.graph
        accesses = resource_operations(config, graph)
        findings: list[Finding] = []

        for tool in config.tools:
            identity = config.identity_by_id(tool.identity)
            if identity is None:
                continue
            declared = set(tool.operations)

            excess_ops = self._excess_operations(identity, declared)
            if excess_ops:
                reachable = [access.resource for access in accesses if access.tool.id == tool.id]
                findings.append(
                    self._operation_finding(context, tool, identity, excess_ops, reachable)
                )

            if (
                identity.resource_restrictions is not None
                and tool.resource_restrictions is not None
            ):
                excess_resources = [
                    resource
                    for resource in config.resources
                    if pattern_list_matches(identity.resource_restrictions, resource.id)
                    and not pattern_list_matches(tool.resource_restrictions, resource.id)
                ]
                if excess_resources:
                    findings.append(
                        self._resource_finding(context, tool, identity, excess_resources)
                    )
        return findings

    def _excess_operations(self, identity: Identity, declared: set[Operation]) -> list[Operation]:
        excess: set[Operation] = set()
        if identity.granted_scopes is None:
            return []
        for scope in identity.granted_scopes:
            if is_deny_pattern(scope):
                continue
            operations = scope_operations(scope)
            if operations is None:
                continue
            excess |= set(operations) - declared
        return sorted(excess, key=lambda op: op.value)

    def _operation_finding(
        self,
        context: RuleContext,
        tool: Tool,
        identity: Identity,
        excess_ops: list[Operation],
        reachable: list[Resource],
    ) -> Finding:
        sensitivity = most_sensitive(reachable)
        op_class = "read" if all(op is Operation.READ for op in excess_ops) else "mutate"
        severity = compute_severity(sensitivity, op_class)
        missing: list[str] = []
        if tool.declared_purpose is None:
            missing.append(
                "tool.declared_purpose is undeclared; intended scope inferred from operations"
            )
        return Finding(
            finding_id=make_finding_id(
                self.id, tool.id, "operations", ",".join(op.value for op in excess_ops)
            ),
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=Confidence.MEDIUM if tool.declared_purpose is None else Confidence.HIGH,
            status=FindingStatus.REACHABLE,
            summary=(
                f"Identity {identity.id!r} grants operations "
                f"{[op.value for op in excess_ops]} to tool {tool.id!r}, which only declares "
                f"{[op.value for op in tool.operations]}."
            ),
            evidence=(
                f"identity granted_scopes: {list(identity.granted_scopes or ())}",
                f"tool declared operations: {[op.value for op in tool.operations]}",
                f"excess operations: {[op.value for op in excess_ops]}",
            ),
            affected_resources=tuple(resource.id for resource in reachable),
            effective_identity=identity.id,
            missing_or_uncertain_constraints=tuple(missing),
            remediation=(
                "Reduce the identity's granted scopes to the operations the tool declares, "
                "or document why the broader scope is required."
            ),
            limitations=self.limitations,
        )

    def _resource_finding(
        self,
        context: RuleContext,
        tool: Tool,
        identity: Identity,
        excess_resources: list[Resource],
    ) -> Finding:
        sensitivity = most_sensitive(excess_resources)
        op_class = "read" if all(op is Operation.READ for op in tool.operations) else "mutate"
        severity = compute_severity(sensitivity, op_class)
        return Finding(
            finding_id=make_finding_id(
                self.id, tool.id, "resources", ",".join(sorted(r.id for r in excess_resources))
            ),
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=Confidence.MEDIUM if tool.declared_purpose is None else Confidence.HIGH,
            status=FindingStatus.REACHABLE,
            summary=(
                f"Identity {identity.id!r} may reach resources that tool {tool.id!r} declares "
                f"out of scope: {sorted(r.id for r in excess_resources)}."
            ),
            evidence=(
                f"identity resource_restrictions: {list(identity.resource_restrictions or ())}",
                f"tool resource_restrictions: {list(tool.resource_restrictions or ())}",
                f"resources granted by identity but not the tool: "
                f"{sorted(r.id for r in excess_resources)}",
            ),
            affected_resources=tuple(sorted(r.id for r in excess_resources)),
            effective_identity=identity.id,
            missing_or_uncertain_constraints=(
                () if tool.declared_purpose else ("tool.declared_purpose is undeclared",)
            ),
            remediation=(
                "Narrow the identity's resource restrictions to the resources the tool is "
                "intended to use."
            ),
            limitations=self.limitations,
        )


# (end)
