"""PW-004 — Missing approval."""

from __future__ import annotations

from pathwarden.finding import (
    Confidence,
    Finding,
    FindingStatus,
    make_finding_id,
)
from pathwarden.graph.permissions import ApprovalAssessmentStatus, assess_approval
from pathwarden.models.entities import Resource, Tool
from pathwarden.models.enums import Operation, Sensitivity
from pathwarden.rules.base import Rule, RuleContext
from pathwarden.rules.common import resource_operations
from pathwarden.severity import compute_severity, operation_class

__all__ = ["PW004"]


class PW004(Rule):
    """Flag sensitive operations that lack a declared approval requirement."""

    id = "PW-004"
    title = "Missing approval"
    rationale = (
        "When policy requires approval for an operation or a resource's sensitivity, a tool "
        "that declares no approval can perform the operation without a declared control."
    )
    prerequisites = (
        "A policy that requires approval for an operation and/or sensitivity level.",
        "A tool whose approval declaration can be compared with the policy.",
    )
    limitations = (
        "A declared approval requirement is reported as declared, never as effective: "
        "runtime enforcement cannot be observed from configuration."
    )

    def evaluate(self, context: RuleContext) -> list[Finding]:
        config = context.config
        graph = context.graph
        accesses = resource_operations(config, graph)

        findings: list[Finding] = []
        for tool in config.tools:
            tool_accesses = [access for access in accesses if access.tool.id == tool.id]
            covered: set[Operation] = set()
            for access in tool_accesses:
                covered.add(access.operation)
                finding = self._finding(context, tool, access.operation, access.resource)
                if finding is not None:
                    findings.append(finding)
            for operation in tool.operations:
                if operation in covered:
                    continue
                finding = self._finding(context, tool, operation, None)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _finding(
        self,
        context: RuleContext,
        tool: Tool,
        operation: Operation,
        resource: Resource | None,
    ) -> Finding | None:
        policy = context.config.policy
        sensitive = resource is not None and resource.sensitivity in policy.approval_sensitivity
        assessment = assess_approval(policy, tool=tool, operation=operation, sensitive=sensitive)
        if assessment.status is ApprovalAssessmentStatus.NOT_REQUIRED:
            return None

        sensitivity = resource.sensitivity if resource is not None else Sensitivity.INTERNAL
        op_class = operation_class(operation)

        missing: tuple[str, ...] = ()
        if assessment.status is ApprovalAssessmentStatus.DECLARED:
            severity = compute_severity(sensitivity, op_class, control_applies=True)
            status = FindingStatus.INFORMATIONAL
            confidence = Confidence.HIGH
        elif assessment.status is ApprovalAssessmentStatus.INDETERMINATE:
            severity = compute_severity(sensitivity, op_class, status_unknown=True)
            status = FindingStatus.INDETERMINATE
            confidence = Confidence.LOW
            missing = ("tool approval is unspecified for this operation",)
        else:  # MISSING or PARTIAL
            severity = compute_severity(sensitivity, op_class)
            status = FindingStatus.REACHABLE
            confidence = Confidence.HIGH if resource is not None else Confidence.MEDIUM

        resource_label = resource.id if resource is not None else "(no specific resource)"
        return Finding(
            finding_id=make_finding_id(
                self.id, tool.id, operation.value, resource.id if resource else ""
            ),
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=confidence,
            status=status,
            summary=(
                f"Policy requires approval for {operation.value!r} on {resource_label}, but tool "
                f"{tool.id!r} declares approval={assessment.requirement.value!r} "
                f"({assessment.status.value})."
            ),
            evidence=(
                f"policy approval_operations: {[op.value for op in policy.approval_operations]}",
                f"policy approval_sensitivity: "
                f"{[level.value for level in policy.approval_sensitivity]}",
                f"tool approval for {operation.value!r}: {assessment.requirement.value}",
                f"assessment: {assessment.detail}",
            ),
            affected_resources=(resource.id,) if resource is not None else (),
            effective_identity=tool.identity,
            missing_or_uncertain_constraints=missing,
            remediation=(
                "Declare approval: required for this operation, and confirm that the execution "
                "environment enforces it."
            ),
            limitations=self.limitations,
        )
