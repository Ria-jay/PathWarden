"""Model-level tests: enums, unknown defaults, and field validators."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from pathwarden.models import Agent, Identity, InputSource, Policy, Resource, Tool
from pathwarden.models.enums import (
    ApprovalRequirement,
    IdentityType,
    InputSourceType,
    Operation,
    Sensitivity,
    Trust,
)


def _tool(**overrides: object) -> Tool:
    data: dict[str, object] = {
        "id": "reader",
        "name": "Reader",
        "operations": ["read"],
        "identity": "idn",
    }
    data.update(overrides)
    return Tool.model_validate(data)


def test_enum_values_are_stable() -> None:
    assert [op.value for op in Operation] == ["read", "write", "delete", "execute", "send"]
    assert [s.value for s in Sensitivity] == ["public", "internal", "confidential", "restricted"]
    assert [t.value for t in Trust] == ["trusted", "user", "untrusted"]
    assert InputSourceType.UPLOADED_FILE == "uploaded_file"


def test_missing_security_fields_are_unknown_not_permissive() -> None:
    identity = Identity(id="idn", type=IdentityType.SERVICE_ACCOUNT)
    assert identity.granted_scopes is None
    assert identity.resource_restrictions is None
    assert identity.tenants is None
    assert identity.acts_as_requester is None
    assert identity.credential_ref is None

    tool = _tool()
    assert tool.approval == {}
    assert tool.authorization_check is None
    assert tool.allowed_destinations is None
    assert tool.required_scopes is None
    assert tool.resource_restrictions is None
    assert tool.outbound is False


def test_absent_approval_is_unspecified_unknown() -> None:
    tool = _tool()
    approval = tool.approval.get(Operation.READ, ApprovalRequirement.UNSPECIFIED)
    assert approval is ApprovalRequirement.UNSPECIFIED


def test_input_source_trust_and_attacker_flag() -> None:
    source = InputSource.model_validate(
        {"id": "cv", "name": "CV", "type": "uploaded_file", "trust": "untrusted"}
    )
    assert source.trust is Trust.UNTRUSTED
    assert source.may_contain_attacker_content is False
    assert source.requesting_principal is None


def test_tenants_wildcard_alone_is_allowed() -> None:
    identity = Identity.model_validate({"id": "idn", "type": "service_account", "tenants": "*"})
    assert identity.tenants == "*"


def test_tenants_list_is_normalized_to_tuple() -> None:
    identity = Identity.model_validate(
        {"id": "idn", "type": "service_account", "tenants": ["acme", "globex"]}
    )
    assert identity.tenants == ("acme", "globex")


@pytest.mark.parametrize(
    "tenants",
    [
        ["acme", "*"],
        [],
        ["acme", "acme"],
        "acme",
    ],
)
def test_invalid_tenant_declarations_are_rejected(tenants: object) -> None:
    with pytest.raises(ValidationError):
        Identity.model_validate({"id": "idn", "type": "service_account", "tenants": tenants})


def test_resource_tenant_wildcard_rejected() -> None:
    with pytest.raises(ValidationError):
        Resource.model_validate(
            {
                "id": "r",
                "type": "database",
                "sensitivity": "internal",
                "tenant": "*",
            }
        )


def test_approval_for_undeclared_operation_rejected() -> None:
    with pytest.raises(ValidationError):
        _tool(approval={"write": "required"})


def test_duplicate_operations_rejected() -> None:
    with pytest.raises(ValidationError):
        _tool(operations=["read", "read"])


def test_empty_operations_rejected() -> None:
    with pytest.raises(ValidationError):
        _tool(operations=[])


def test_self_flow_rejected() -> None:
    with pytest.raises(ValidationError):
        _tool(id="loop", output_flows_to=["loop"])


def test_invalid_operation_rejected() -> None:
    with pytest.raises(ValidationError):
        _tool(operations=["read", "frobnicate"])


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError):
        Identity.model_validate({"id": "idn", "type": "service_account", "nope": 1})


def test_models_are_frozen() -> None:
    identity = Identity(id="idn", type=IdentityType.SERVICE_ACCOUNT)
    with pytest.raises(ValidationError):
        identity.id = "changed"  # type: ignore[misc]


def test_policy_defaults_do_not_constrain() -> None:
    policy = Policy()
    assert policy.approval_operations == ()
    assert policy.approval_sensitivity == ()
    assert policy.allowed_outbound_destinations is None
    assert policy.boundary_sensitivity == ()


def test_agent_requires_execution_identity() -> None:
    with pytest.raises(ValidationError):
        Agent.model_validate({"id": "a", "name": "A"})
