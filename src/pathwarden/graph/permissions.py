"""The tri-state permission model.

Every check returns one of :class:`~pathwarden.models.enums.PermissionStatus`:

* ``allowed`` — the configuration positively grants the operation.
* ``denied`` — the configuration positively withholds or forbids it.
* ``unknown`` — the configuration does not say; the result is *not* collapsed
  into the other two.

Conventions used throughout (documented in ``docs/permission-model.md``):

* ``None`` for a declaration list means *undeclared* and yields ``unknown``.
* An *allow list* (granted scopes, resource restrictions, permitted operations,
  allowed destinations) that is explicitly empty declares that nothing is
  permitted and therefore denies.
* A *requirement list* (a tool's ``required_scopes``, a tool's ``operations``)
  that is empty is trivially satisfied and therefore allows.
* A pattern beginning with ``!`` is an explicit deny. An explicit deny beats an
  explicit allow.
* Scope and resource patterns are matched with :func:`fnmatch.fnmatchcase`
  (exact ID or shell-style glob), case-sensitively.
* A path's status is ``denied`` if any step is denied, else ``unknown`` if any
  step is unknown, else ``allowed``.
* Approval is a *control*, not an allow/deny of the operation itself. It is
  assessed separately by :func:`assess_approval` and never turns an operation
  into ``denied`` on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase

from pathwarden.models.config import AgentConfig
from pathwarden.models.entities import Policy, Resource, Tool
from pathwarden.models.enums import ApprovalRequirement, Operation, PermissionStatus

__all__ = [
    "DENY_PREFIX",
    "ApprovalAssessment",
    "ApprovalAssessmentStatus",
    "PermissionResult",
    "PermissionStep",
    "assess_approval",
    "check_destinations",
    "check_resource_operation",
    "check_resource_restrictions",
    "check_scopes",
    "check_tenants",
    "check_tool_operation",
    "evaluate_access",
    "fold_statuses",
]

#: Prefix marking an explicit deny pattern in a declaration list.
DENY_PREFIX = "!"


@dataclass(frozen=True)
class PermissionStep:
    """One evaluated constraint contributing to a combined result."""

    name: str
    status: PermissionStatus
    detail: str


@dataclass(frozen=True)
class PermissionResult:
    """A combined permission result with the steps that produced it."""

    status: PermissionStatus
    steps: tuple[PermissionStep, ...]

    @property
    def deciding_step(self) -> PermissionStep | None:
        """The first denied step, else the first unknown step, else ``None``."""

        for step in self.steps:
            if step.status is PermissionStatus.DENIED:
                return step
        for step in self.steps:
            if step.status is PermissionStatus.UNKNOWN:
                return step
        return None


class ApprovalAssessmentStatus(StrEnum):
    """Outcome of comparing policy approval requirements with a declaration."""

    NOT_REQUIRED = "not_required"
    DECLARED = "declared"
    MISSING = "missing"
    PARTIAL = "partial"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class ApprovalAssessment:
    """Assessment of whether an operation's approval satisfies policy.

    ``DECLARED`` means a requirement is declared in the configuration; it does
    **not** mean the requirement is enforced at runtime, which Pathwarden cannot
    observe from configuration alone.
    """

    status: ApprovalAssessmentStatus
    requirement: ApprovalRequirement
    policy_requires: bool
    detail: str


def fold_statuses(statuses: list[PermissionStatus]) -> PermissionStatus:
    """Combine step statuses: deny beats unknown beats allow."""

    if PermissionStatus.DENIED in statuses:
        return PermissionStatus.DENIED
    if PermissionStatus.UNKNOWN in statuses:
        return PermissionStatus.UNKNOWN
    return PermissionStatus.ALLOWED


def _is_deny(pattern: str) -> bool:
    return pattern.startswith(DENY_PREFIX) and len(pattern) > 1


def _bare(pattern: str) -> str:
    return pattern[len(DENY_PREFIX) :] if _is_deny(pattern) else pattern


def _matches(patterns: tuple[str, ...], value: str) -> bool:
    return any(fnmatchcase(value, _bare(pattern)) for pattern in patterns)


# --------------------------------------------------------------------------- #
# Individual constraint checks
# --------------------------------------------------------------------------- #


def check_tool_operation(operations: tuple[Operation, ...], operation: Operation) -> PermissionStep:
    """Whether the tool declares the operation at all."""

    if operation in operations:
        return PermissionStep(
            "tool_operation",
            PermissionStatus.ALLOWED,
            f"tool declares operation {operation.value!r}",
        )
    return PermissionStep(
        "tool_operation",
        PermissionStatus.DENIED,
        f"tool does not declare operation {operation.value!r}",
    )


def check_scopes(
    required: tuple[str, ...] | None, granted: tuple[str, ...] | None
) -> PermissionStep:
    """Whether the identity's granted scopes satisfy the tool's requirements."""

    if required is None:
        return PermissionStep(
            "scope",
            PermissionStatus.UNKNOWN,
            "tool does not declare required_scopes; scope compliance cannot be assessed",
        )
    if not required:
        return PermissionStep(
            "scope", PermissionStatus.ALLOWED, "tool declares no scope requirement"
        )
    if granted is None:
        return PermissionStep(
            "scope",
            PermissionStatus.UNKNOWN,
            "identity does not declare granted_scopes; scope compliance cannot be assessed",
        )

    denies = tuple(pattern for pattern in granted if _is_deny(pattern))
    for scope in required:
        if _matches(denies, scope):
            return PermissionStep(
                "scope", PermissionStatus.DENIED, f"required scope {scope!r} is explicitly denied"
            )

    allows = tuple(pattern for pattern in granted if not _is_deny(pattern))
    missing = sorted(scope for scope in required if not _matches(allows, scope))
    if missing:
        return PermissionStep(
            "scope",
            PermissionStatus.DENIED,
            "identity is not granted required scope(s): " + ", ".join(missing),
        )
    return PermissionStep("scope", PermissionStatus.ALLOWED, "identity grants all required scopes")


def check_resource_restrictions(
    identity_restrictions: tuple[str, ...] | None,
    tool_restrictions: tuple[str, ...] | None,
    resource_id: str,
) -> PermissionStep:
    """Whether the resource is within declared identity and tool restrictions."""

    lists = (identity_restrictions, tool_restrictions)
    if all(item is None for item in lists):
        return PermissionStep(
            "resource_restriction",
            PermissionStatus.UNKNOWN,
            "no resource restrictions declared for identity or tool",
        )

    for declared in lists:
        if declared:
            denies = tuple(pattern for pattern in declared if _is_deny(pattern))
            if _matches(denies, resource_id):
                return PermissionStep(
                    "resource_restriction",
                    PermissionStatus.DENIED,
                    f"resource {resource_id!r} is explicitly denied",
                )

    for declared in lists:
        if declared is not None and len(declared) == 0:
            return PermissionStep(
                "resource_restriction",
                PermissionStatus.DENIED,
                "identity or tool declares no allowed resources",
            )

    for declared in lists:
        if declared:
            allows = tuple(pattern for pattern in declared if not _is_deny(pattern))
            if allows and not _matches(allows, resource_id):
                return PermissionStep(
                    "resource_restriction",
                    PermissionStatus.DENIED,
                    f"resource {resource_id!r} is outside declared restrictions",
                )

    if any(item is None for item in lists):
        return PermissionStep(
            "resource_restriction",
            PermissionStatus.UNKNOWN,
            "resource restrictions are undeclared for the identity or tool",
        )
    return PermissionStep(
        "resource_restriction",
        PermissionStatus.ALLOWED,
        f"resource {resource_id!r} is within declared restrictions",
    )


def check_resource_operation(
    permitted: tuple[Operation, ...] | None, operation: Operation
) -> PermissionStep:
    """Whether the resource declares the operation as permitted."""

    if permitted is None:
        return PermissionStep(
            "resource_operation",
            PermissionStatus.UNKNOWN,
            "resource does not declare permitted_operations",
        )
    if not permitted:
        return PermissionStep(
            "resource_operation",
            PermissionStatus.DENIED,
            "resource declares no permitted operations",
        )
    if operation in permitted:
        return PermissionStep(
            "resource_operation",
            PermissionStatus.ALLOWED,
            f"resource permits {operation.value!r}",
        )
    return PermissionStep(
        "resource_operation",
        PermissionStatus.DENIED,
        f"resource does not permit {operation.value!r}",
    )


def check_tenants(
    identity_tenants: tuple[str, ...] | str | None, resource_tenant: str | None
) -> PermissionStep:
    """Whether the resource tenant is within the identity's declared tenants."""

    if identity_tenants is None:
        return PermissionStep(
            "tenant", PermissionStatus.UNKNOWN, "identity does not declare tenants"
        )
    if resource_tenant is None:
        return PermissionStep(
            "tenant", PermissionStatus.UNKNOWN, "resource does not declare a tenant"
        )
    if identity_tenants == "*":
        return PermissionStep(
            "tenant",
            PermissionStatus.ALLOWED,
            'identity declares access to all tenants ("*")',
        )
    if resource_tenant in identity_tenants:
        return PermissionStep(
            "tenant",
            PermissionStatus.ALLOWED,
            f"resource tenant {resource_tenant!r} is within declared tenants",
        )
    return PermissionStep(
        "tenant",
        PermissionStatus.DENIED,
        f"resource tenant {resource_tenant!r} is outside declared tenants "
        + ", ".join(sorted(identity_tenants)),
    )


def check_destinations(
    allowed_destinations: tuple[str, ...] | None,
    policy_destinations: tuple[str, ...] | None,
    destination: str,
) -> PermissionStep:
    """Whether an outbound destination is permitted by tool and policy lists."""

    lists = (allowed_destinations, policy_destinations)
    if all(item is None for item in lists):
        return PermissionStep(
            "destination",
            PermissionStatus.UNKNOWN,
            "no allowed destinations are declared by the tool or policy",
        )

    for declared in lists:
        if declared:
            denies = tuple(pattern for pattern in declared if _is_deny(pattern))
            if _matches(denies, destination):
                return PermissionStep(
                    "destination",
                    PermissionStatus.DENIED,
                    f"destination {destination!r} is explicitly denied",
                )

    for declared in lists:
        if declared is not None and len(declared) == 0:
            return PermissionStep(
                "destination",
                PermissionStatus.DENIED,
                "tool or policy declares no allowed destinations",
            )

    for declared in lists:
        if declared:
            allows = tuple(pattern for pattern in declared if not _is_deny(pattern))
            if allows and not _matches(allows, destination):
                return PermissionStep(
                    "destination",
                    PermissionStatus.DENIED,
                    f"destination {destination!r} is not in the allowed destinations",
                )

    if any(item is None for item in lists):
        return PermissionStep(
            "destination",
            PermissionStatus.UNKNOWN,
            "allowed destinations are undeclared for the tool or policy",
        )
    return PermissionStep(
        "destination",
        PermissionStatus.ALLOWED,
        f"destination {destination!r} is within the allowed destinations",
    )


# --------------------------------------------------------------------------- #
# Combined checks
# --------------------------------------------------------------------------- #


def evaluate_access(
    config: AgentConfig, *, tool: Tool, operation: Operation, resource: Resource
) -> PermissionResult:
    """Evaluate whether ``tool`` may perform ``operation`` on ``resource``.

    Combines the tool-operation, scope, resource-restriction, resource-operation,
    and tenant checks. The result is the fold of the individual steps and never
    treats graph connectivity as permission.
    """

    steps: list[PermissionStep] = [check_tool_operation(tool.operations, operation)]

    identity = config.identity_by_id(tool.identity)
    if identity is None:
        steps.append(
            PermissionStep(
                "identity",
                PermissionStatus.UNKNOWN,
                f"tool references identity {tool.identity!r}, which is not declared",
            )
        )
    else:
        steps.append(check_scopes(tool.required_scopes, identity.granted_scopes))
        steps.append(
            check_resource_restrictions(
                identity.resource_restrictions, tool.resource_restrictions, resource.id
            )
        )
        steps.append(check_tenants(identity.tenants, resource.tenant))

    steps.append(check_resource_operation(resource.permitted_operations, operation))

    return PermissionResult(
        status=fold_statuses([step.status for step in steps]), steps=tuple(steps)
    )


def assess_approval(
    policy: Policy,
    *,
    tool: Tool,
    operation: Operation,
    sensitive: bool,
) -> ApprovalAssessment:
    """Compare an operation's declared approval against the policy.

    ``sensitive`` indicates whether the target resource's sensitivity is one the
    policy requires approval for. A declared requirement is reported as
    ``DECLARED`` and is explicitly *not* a statement that runtime enforcement
    exists.
    """

    requirement = tool.approval.get(operation, ApprovalRequirement.UNSPECIFIED)
    policy_requires = operation in policy.approval_operations or sensitive

    if not policy_requires:
        return ApprovalAssessment(
            status=ApprovalAssessmentStatus.NOT_REQUIRED,
            requirement=requirement,
            policy_requires=False,
            detail="policy does not require approval for this operation",
        )

    if requirement is ApprovalRequirement.REQUIRED:
        return ApprovalAssessment(
            status=ApprovalAssessmentStatus.DECLARED,
            requirement=requirement,
            policy_requires=True,
            detail="approval is declared as required (declared, enforcement unknown)",
        )
    if requirement is ApprovalRequirement.OPTIONAL:
        return ApprovalAssessment(
            status=ApprovalAssessmentStatus.PARTIAL,
            requirement=requirement,
            policy_requires=True,
            detail="policy requires approval but the tool declares it optional",
        )
    if requirement is ApprovalRequirement.NONE:
        return ApprovalAssessment(
            status=ApprovalAssessmentStatus.MISSING,
            requirement=requirement,
            policy_requires=True,
            detail="policy requires approval but the tool declares none",
        )
    return ApprovalAssessment(
        status=ApprovalAssessmentStatus.INDETERMINATE,
        requirement=requirement,
        policy_requires=True,
        detail="policy requires approval but the tool's approval is unspecified",
    )
