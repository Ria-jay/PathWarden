"""Permission engine tests: tri-state logic and every branch."""

from __future__ import annotations

from typing import Any

from pathwarden.graph.permissions import (
    ApprovalAssessmentStatus,
    assess_approval,
    check_destinations,
    check_resource_operation,
    check_resource_restrictions,
    check_scopes,
    check_tenants,
    check_tool_operation,
    evaluate_access,
    fold_statuses,
)
from pathwarden.models.config import AgentConfig
from pathwarden.models.enums import ApprovalRequirement, Operation, PermissionStatus


def build_config(
    *,
    identity: dict[str, Any] | None = None,
    tool: dict[str, Any] | None = None,
    resource: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
) -> AgentConfig:
    identity_data: dict[str, Any] = {
        "id": "idn",
        "type": "service_account",
        "granted_scopes": ["db:read"],
        "resource_restrictions": ["r"],
        "tenants": ["acme"],
    }
    identity_data.update(identity or {})
    tool_data: dict[str, Any] = {
        "id": "t",
        "name": "T",
        "operations": ["read"],
        "identity": "idn",
        "required_scopes": ["db:read"],
        "resource_restrictions": ["r"],
    }
    tool_data.update(tool or {})
    resource_data: dict[str, Any] = {
        "id": "r",
        "type": "database",
        "sensitivity": "internal",
        "tenant": "acme",
        "permitted_operations": ["read"],
    }
    resource_data.update(resource or {})
    return AgentConfig.model_validate(
        {
            "schema_version": "1.0",
            "agent": {"id": "a", "name": "A", "execution_identity": "idn"},
            "identities": [identity_data],
            "tools": [tool_data],
            "resources": [resource_data],
            "policy": policy or {},
        }
    )


# -- fold ------------------------------------------------------------------- #


def test_fold_precedence() -> None:
    allowed = PermissionStatus.ALLOWED
    denied = PermissionStatus.DENIED
    unknown = PermissionStatus.UNKNOWN
    assert fold_statuses([allowed, allowed]) is allowed
    assert fold_statuses([allowed, unknown]) is unknown
    assert fold_statuses([unknown, denied]) is denied
    assert fold_statuses([allowed, unknown, denied]) is denied


# -- scopes ----------------------------------------------------------------- #


def test_scope_allowed_with_glob() -> None:
    step = check_scopes(("db:read",), ("db:*",))
    assert step.status is PermissionStatus.ALLOWED


def test_scope_denied_when_not_granted() -> None:
    step = check_scopes(("db:read",), ("db:write",))
    assert step.status is PermissionStatus.DENIED


def test_scope_explicit_deny_beats_allow() -> None:
    step = check_scopes(("db:read",), ("db:*", "!db:read"))
    assert step.status is PermissionStatus.DENIED
    assert "explicitly denied" in step.detail


def test_scope_unknown_when_requirement_undeclared() -> None:
    assert check_scopes(None, ("db:read",)).status is PermissionStatus.UNKNOWN


def test_scope_unknown_when_grant_undeclared() -> None:
    assert check_scopes(("db:read",), None).status is PermissionStatus.UNKNOWN


def test_scope_empty_requirement_is_allowed() -> None:
    assert check_scopes((), None).status is PermissionStatus.ALLOWED


def test_scope_empty_grant_denies() -> None:
    assert check_scopes(("db:read",), ()).status is PermissionStatus.DENIED


# -- tenants ---------------------------------------------------------------- #


def test_tenant_allowed() -> None:
    assert check_tenants(("acme",), "acme").status is PermissionStatus.ALLOWED


def test_tenant_denied_outside() -> None:
    assert check_tenants(("globex",), "acme").status is PermissionStatus.DENIED


def test_tenant_wildcard_allowed() -> None:
    assert check_tenants("*", "acme").status is PermissionStatus.ALLOWED


def test_tenant_unknown_when_identity_undeclared() -> None:
    assert check_tenants(None, "acme").status is PermissionStatus.UNKNOWN


def test_tenant_unknown_when_resource_undeclared() -> None:
    assert check_tenants(("acme",), None).status is PermissionStatus.UNKNOWN


# -- resource restrictions -------------------------------------------------- #


def test_resource_restriction_unknown_when_both_undeclared() -> None:
    assert check_resource_restrictions(None, None, "r").status is PermissionStatus.UNKNOWN


def test_resource_restriction_allowed_by_glob() -> None:
    step = check_resource_restrictions(("db/*",), None, "db/employees")
    assert step.status is PermissionStatus.UNKNOWN  # tool side undeclared

    step = check_resource_restrictions(("db/*",), ("db/*",), "db/employees")
    assert step.status is PermissionStatus.ALLOWED


def test_resource_restriction_denied_outside_declared() -> None:
    step = check_resource_restrictions(("db/*",), ("db/*",), "secrets")
    assert step.status is PermissionStatus.DENIED


def test_resource_restriction_explicit_deny() -> None:
    step = check_resource_restrictions(("db/*",), ("!db/employees",), "db/employees")
    assert step.status is PermissionStatus.DENIED


def test_resource_restriction_empty_list_denies() -> None:
    step = check_resource_restrictions((), None, "r")
    assert step.status is PermissionStatus.DENIED


def test_resource_restriction_unknown_when_one_side_undeclared() -> None:
    step = check_resource_restrictions(None, ("db/*",), "db/x")
    assert step.status is PermissionStatus.UNKNOWN


# -- resource operations ---------------------------------------------------- #


def test_resource_operation_allowed() -> None:
    assert (
        check_resource_operation((Operation.READ,), Operation.READ).status
        is PermissionStatus.ALLOWED
    )


def test_resource_operation_denied() -> None:
    assert (
        check_resource_operation((Operation.WRITE,), Operation.READ).status
        is PermissionStatus.DENIED
    )


def test_resource_operation_unknown_when_undeclared() -> None:
    assert check_resource_operation(None, Operation.READ).status is PermissionStatus.UNKNOWN


def test_resource_operation_empty_denies() -> None:
    assert check_resource_operation((), Operation.READ).status is PermissionStatus.DENIED


# -- tool operation --------------------------------------------------------- #


def test_tool_operation_checks_declaration() -> None:
    assert (
        check_tool_operation((Operation.READ,), Operation.READ).status is PermissionStatus.ALLOWED
    )
    assert (
        check_tool_operation((Operation.READ,), Operation.WRITE).status is PermissionStatus.DENIED
    )


# -- destinations ----------------------------------------------------------- #


def test_destination_unknown_when_undeclared() -> None:
    assert check_destinations(None, None, "mail.example.com").status is PermissionStatus.UNKNOWN


def test_destination_allowed_by_glob() -> None:
    step = check_destinations(("*.acme.com",), ("*.acme.com",), "mail.acme.com")
    assert step.status is PermissionStatus.ALLOWED


def test_destination_denied_outside_allowlist() -> None:
    step = check_destinations(("*.acme.com",), None, "evil.example.com")
    assert step.status is PermissionStatus.DENIED


def test_destination_empty_allowlist_denies() -> None:
    assert check_destinations((), None, "any.example.com").status is PermissionStatus.DENIED


def test_destination_explicit_deny() -> None:
    step = check_destinations(("*.acme.com", "!mail.acme.com"), None, "mail.acme.com")
    assert step.status is PermissionStatus.DENIED


# -- combined access -------------------------------------------------------- #


def test_access_allowed() -> None:
    config = build_config()
    result = evaluate_access(
        config, tool=config.tools[0], operation=Operation.READ, resource=config.resources[0]
    )
    assert result.status is PermissionStatus.ALLOWED
    assert result.deciding_step is None


def test_access_denied_by_scope() -> None:
    config = build_config(identity={"granted_scopes": ["db:write"]})
    result = evaluate_access(
        config, tool=config.tools[0], operation=Operation.READ, resource=config.resources[0]
    )
    assert result.status is PermissionStatus.DENIED
    assert result.deciding_step is not None
    assert result.deciding_step.name == "scope"


def test_access_denied_by_tenant() -> None:
    config = build_config(identity={"tenants": ["globex"]})
    result = evaluate_access(
        config, tool=config.tools[0], operation=Operation.READ, resource=config.resources[0]
    )
    assert result.status is PermissionStatus.DENIED
    assert result.deciding_step is not None
    assert result.deciding_step.name == "tenant"


def test_access_denied_by_resource_operation() -> None:
    config = build_config(resource={"permitted_operations": ["write"]})
    result = evaluate_access(
        config, tool=config.tools[0], operation=Operation.READ, resource=config.resources[0]
    )
    assert result.status is PermissionStatus.DENIED
    assert any(step.name == "resource_operation" for step in result.steps)


def test_access_unknown_when_scopes_undeclared() -> None:
    config = build_config(tool={"required_scopes": None})
    result = evaluate_access(
        config, tool=config.tools[0], operation=Operation.READ, resource=config.resources[0]
    )
    assert result.status is PermissionStatus.UNKNOWN
    assert result.deciding_step is not None
    assert result.deciding_step.name == "scope"


def test_access_unknown_when_tenant_undeclared() -> None:
    config = build_config(identity={"tenants": None})
    result = evaluate_access(
        config, tool=config.tools[0], operation=Operation.READ, resource=config.resources[0]
    )
    assert result.status is PermissionStatus.UNKNOWN


def test_access_unknown_when_restrictions_undeclared() -> None:
    # A declared allow check passes, but the missing identity restriction keeps
    # the result unknown rather than allowed.
    config = build_config(identity={"resource_restrictions": None})
    result = evaluate_access(
        config, tool=config.tools[0], operation=Operation.READ, resource=config.resources[0]
    )
    assert result.status is PermissionStatus.UNKNOWN
    assert result.deciding_step is not None
    assert result.deciding_step.name == "resource_restriction"


def test_access_denied_beats_unknown() -> None:
    # scope unknown, tenant denied -> denied wins
    config = build_config(tool={"required_scopes": None}, identity={"tenants": ["globex"]})
    result = evaluate_access(
        config, tool=config.tools[0], operation=Operation.READ, resource=config.resources[0]
    )
    assert result.status is PermissionStatus.DENIED


# -- approval --------------------------------------------------------------- #


def test_approval_not_required_by_policy() -> None:
    config = build_config()
    assessment = assess_approval(
        config.policy, tool=config.tools[0], operation=Operation.READ, sensitive=False
    )
    assert assessment.status is ApprovalAssessmentStatus.NOT_REQUIRED


def test_approval_declared() -> None:
    config = build_config(
        tool={"approval": {"read": "required"}},
        policy={"approval_operations": ["read"]},
    )
    assessment = assess_approval(
        config.policy, tool=config.tools[0], operation=Operation.READ, sensitive=False
    )
    assert assessment.status is ApprovalAssessmentStatus.DECLARED
    assert assessment.requirement is ApprovalRequirement.REQUIRED


def test_approval_missing() -> None:
    config = build_config(
        tool={"approval": {"read": "none"}},
        policy={"approval_operations": ["read"]},
    )
    assessment = assess_approval(
        config.policy, tool=config.tools[0], operation=Operation.READ, sensitive=False
    )
    assert assessment.status is ApprovalAssessmentStatus.MISSING


def test_approval_optional_is_partial() -> None:
    config = build_config(
        tool={"approval": {"read": "optional"}},
        policy={"approval_operations": ["read"]},
    )
    assessment = assess_approval(
        config.policy, tool=config.tools[0], operation=Operation.READ, sensitive=False
    )
    assert assessment.status is ApprovalAssessmentStatus.PARTIAL


def test_approval_unspecified_is_indeterminate() -> None:
    config = build_config(policy={"approval_operations": ["read"]})
    assessment = assess_approval(
        config.policy, tool=config.tools[0], operation=Operation.READ, sensitive=False
    )
    assert assessment.status is ApprovalAssessmentStatus.INDETERMINATE
    assert assessment.requirement is ApprovalRequirement.UNSPECIFIED


def test_approval_required_by_sensitivity() -> None:
    config = build_config(policy={"approval_sensitivity": ["internal"]})
    assessment = assess_approval(
        config.policy, tool=config.tools[0], operation=Operation.READ, sensitive=True
    )
    assert assessment.policy_requires is True
    assert assessment.status is ApprovalAssessmentStatus.INDETERMINATE
