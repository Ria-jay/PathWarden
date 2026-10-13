"""PW-006 — Cross-tenant exposure."""

from __future__ import annotations

from pathwarden.finding import (
    Confidence,
    Finding,
    FindingStatus,
    make_finding_id,
)
from pathwarden.models.entities import Identity, Resource
from pathwarden.models.enums import Operation
from pathwarden.rules.base import Rule, RuleContext
from pathwarden.rules.common import ToolResourceAccess, most_sensitive, resource_operations
from pathwarden.severity import compute_severity

__all__ = ["PW006"]


class PW006(Rule):
    """Flag identities that can reach resources across tenant boundaries."""

    id = "PW-006"
    title = "Cross-tenant exposure"
    rationale = (
        "An identity that can reach resources in more than one tenant, or resources outside "
        "its declared tenants, crosses a tenant boundary. A wildcard tenant identity is "
        "flagged when the resources it reaches span more than one tenant."
    )
    prerequisites = (
        "Resources with tenant declarations reachable through a tool.",
        "An identity with a tenant declaration (list or \"*\").",
    )
    limitations = (
        "Tenant semantics are taken from the configuration. When a resource tenant or an "
        "identity's tenants are undeclared, the result is reported as indeterminate rather "
        "than as a cross-tenant exposure."
    )

    def evaluate(self, context: RuleContext) -> list[Finding]:
        config = context.config
        graph = context.graph
        accesses = resource_operations(config, graph)

        findings: list[Finding] = []
        for identity in config.identities:
            identity_accesses = [
                access for access in accesses if access.tool.identity == identity.id
            ]
            resources = self._unique_resources(identity_accesses)
            if not resources:
                continue
            findings.extend(self._evaluate_identity(identity, resources, identity_accesses))
        return findings

    def _unique_resources(self, accesses: list[ToolResourceAccess]) -> list[Resource]:
        seen: dict[str, Resource] = {}
        for access in accesses:
            seen[access.resource.id] = access.resource
        return [seen[key] for key in sorted(seen)]

    def _evaluate_identity(
        self,
        identity: Identity,
        resources: list[Resource],
        accesses: list[ToolResourceAccess],
    ) -> list[Finding]:
        known = sorted({resource.tenant for resource in resources if resource.tenant is not None})
        unknown = [resource for resource in resources if resource.tenant is None]
        op_class = (
            "mutate"
            if any(access.operation is not Operation.READ for access in accesses)
            else "read"
        )
        findings: list[Finding] = []

        if identity.tenants is None:
            if known:
                findings.append(
                    self._indeterminate(
                        identity,
                        resources,
                        op_class,
                        "identity.tenants is undeclared; tenant boundary cannot be verified",
                    )
                )
            return findings

        if identity.tenants == "*":
            if len(known) > 1:
                findings.append(
                    self._reachable(
                        identity,
                        resources,
                        op_class,
                        "wildcard_tenants",
                        f"identity {identity.id!r} declares all tenants (\"*\") and can reach "
                        f"resources in {len(known)} tenants: {known}.",
                    )
                )
        else:
            outside = sorted(tenant for tenant in known if tenant not in identity.tenants)
            if outside:
                findings.append(
                    self._reachable(
                        identity,
                        resources,
                        op_class,
                        "outside_tenants",
                        f"identity {identity.id!r} is declared for tenants "
                        f"{list(identity.tenants)} but can reach resources in {outside}.",
                    )
                )
            elif len(known) > 1:
                findings.append(
                    self._reachable(
                        identity,
                        resources,
                        op_class,
                        "multi_tenant",
                        f"identity {identity.id!r} can reach resources in multiple tenants: "
                        f"{known}.",
                    )
                )

        if unknown:
            findings.append(
                self._indeterminate(
                    identity,
                    unknown,
                    op_class,
                    "reachable resources have no declared tenant; tenant boundary is uncertain",
                )
            )
        return findings

    def _reachable(
        self,
        identity: Identity,
        resources: list[Resource],
        op_class: str,
        reason: str,
        summary: str,
    ) -> Finding:
        severity = compute_severity(most_sensitive(resources), op_class)
        return Finding(
            finding_id=make_finding_id(
                self.id, identity.id, reason, ",".join(sorted(r.id for r in resources))
            ),
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=Confidence.HIGH,
            status=FindingStatus.REACHABLE,
            summary=summary,
            evidence=(
                f"identity tenants: {identity.tenants!r}",
                "reachable tenants: "
                + str(sorted({r.tenant for r in resources if r.tenant is not None})),
                "resources: " + ", ".join(sorted(r.id for r in resources)),
            ),
            affected_resources=tuple(sorted(r.id for r in resources)),
            effective_identity=identity.id,
            remediation=(
                "Scope the identity's tenants to exactly the tenants it must serve, and align "
                "resource tenants with that scope."
            ),
            limitations=self.limitations,
        )

    def _indeterminate(
        self,
        identity: Identity,
        resources: list[Resource],
        op_class: str,
        constraint: str,
    ) -> Finding:
        severity = compute_severity(most_sensitive(resources), op_class, status_unknown=True)
        return Finding(
            finding_id=make_finding_id(
                self.id, identity.id, "unknown", ",".join(sorted(r.id for r in resources))
            ),
            rule_id=self.id,
            title=self.title,
            severity=severity,
            confidence=Confidence.LOW,
            status=FindingStatus.INDETERMINATE,
            summary=(
                f"Tenant exposure for identity {identity.id!r} cannot be determined: {constraint}."
            ),
            evidence=(
                f"identity tenants: {identity.tenants!r}",
                "resources: " + ", ".join(sorted(r.id for r in resources)),
            ),
            affected_resources=tuple(sorted(r.id for r in resources)),
            effective_identity=identity.id,
            missing_or_uncertain_constraints=(constraint,),
            remediation=(
                "Declare the identity's tenants and every reachable resource's tenant so the "
                "tenant boundary can be verified."
            ),
            limitations=self.limitations,
        )
