"""Pydantic domain models for the Pathwarden configuration schema (1.0).

Design rules that this module enforces:

* Structural identity fields (``id``, ``name``, ``type``) are required.
* Security-relevant fields are optional and default to *undeclared*
  (``None``), never to a permissive value. A missing declaration must remain
  unknown so later analysis cannot mistake it for "allowed".
* ``extra="forbid"`` so that typos and unsupported fields are rejected with a
  clear error instead of being silently ignored.

Cross-entity checks (duplicate identifiers, unknown references) live in
:mod:`pathwarden.config.loader`, because they require the whole document.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from pathwarden.models.enums import (
    ApprovalRequirement,
    AuthorizationCheckType,
    IdentityType,
    InputSourceType,
    Operation,
    Sensitivity,
    Trust,
)

__all__ = [
    "Agent",
    "ApprovalMap",
    "AuthorizationCheck",
    "Identifier",
    "Identity",
    "InputSource",
    "Policy",
    "Resource",
    "ScopePattern",
    "TenantName",
    "TenantsDecl",
    "Tool",
]

Identifier = Annotated[
    str, StringConstraints(min_length=1, max_length=256, strip_whitespace=True)
]
ScopePattern = Annotated[
    str, StringConstraints(min_length=1, max_length=512, strip_whitespace=True)
]
TenantName = Annotated[
    str, StringConstraints(min_length=1, max_length=128, strip_whitespace=True)
]

#: A tenant declaration is either a non-empty list of tenant names or the
#: single string ``"*"`` (all tenants). Mixing ``"*"`` into a list is rejected.
TenantsDecl = tuple[TenantName, ...] | Literal["*"]

ApprovalMap = dict[Operation, ApprovalRequirement]


class _Base(BaseModel):
    """Shared model configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorizationCheck(_Base):
    """A declared authorization check on a tool.

    An absent ``authorization_check`` on a tool is *unknown* (``None``), which
    is deliberately different from ``type: none`` (an explicit declaration that
    no requester-scoped check exists).
    """

    type: AuthorizationCheckType
    description: str | None = None


class InputSource(_Base):
    """A source of content that can enter the agent's context."""

    id: Identifier
    name: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    type: InputSourceType
    trust: Trust
    may_contain_attacker_content: bool = False
    requesting_principal: str | None = None


def _validate_tenant_decl(value: Any) -> Any:
    """Normalize and validate an identity ``tenants`` declaration.

    Accepts ``None`` (undeclared), the string ``"*"`` (all tenants), or a
    non-empty list of tenant names. Rejects an empty list, ``"*"`` mixed into a
    list, and duplicate entries.
    """

    if value is None:
        return None
    if isinstance(value, str):
        if value == "*":
            return "*"
        raise ValueError('tenants must be a list of tenant names or the string "*"')
    if isinstance(value, (list, tuple)):
        if len(value) == 0:
            raise ValueError('tenants must list at least one tenant, or be the string "*"')
        if any(item == "*" for item in value):
            raise ValueError(
                'use the string "*" alone to mean all tenants; do not mix "*" into a list'
            )
        if len(set(value)) != len(value):
            raise ValueError("tenants contains duplicate entries")
        return tuple(value)
    raise ValueError('tenants must be a list of tenant names or the string "*"')


class Identity(_Base):
    """A principal under which a tool or the agent runs."""

    id: Identifier
    type: IdentityType
    name: str | None = None
    #: scopes granted to this identity; ``None`` = undeclared (unknown).
    granted_scopes: tuple[ScopePattern, ...] | None = None
    #: resource id/glob restrictions; ``None`` = undeclared (unknown).
    resource_restrictions: tuple[ScopePattern, ...] | None = None
    #: tenant restriction; ``None`` = undeclared (unknown).
    tenants: tuple[TenantName, ...] | Literal["*"] | None = None
    #: whether this identity acts on behalf of the requesting principal.
    #: ``None`` = undeclared (unknown).
    acts_as_requester: bool | None = None
    #: symbolic credential reference (for example ``vault://kv/hr/token``).
    credential_ref: str | None = None

    _check_tenants = field_validator("tenants", mode="before")(_validate_tenant_decl)


class Resource(_Base):
    """A resource an operation can act upon."""

    id: Identifier
    type: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    sensitivity: Sensitivity
    name: str | None = None
    owner: str | None = None
    #: tenant the resource belongs to; ``None`` = undeclared (unknown).
    tenant: TenantName | None = None
    #: operations permitted on this resource; ``None`` = undeclared (unknown).
    permitted_operations: tuple[Operation, ...] | None = None
    #: access restrictions; ``None`` = undeclared (unknown).
    access_restrictions: tuple[ScopePattern, ...] | None = None

    @field_validator("tenant")
    @classmethod
    def _tenant_must_be_concrete(cls, value: str | None) -> str | None:
        if value == "*":
            raise ValueError('a resource tenant must be a concrete tenant, not "*"')
        return value


class Tool(_Base):
    """A tool the agent can invoke."""

    id: Identifier
    name: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    description: str | None = None
    operations: tuple[Operation, ...] = Field(min_length=1)
    identity: Identifier
    required_scopes: tuple[ScopePattern, ...] | None = None
    resource_restrictions: tuple[ScopePattern, ...] | None = None
    #: declared approval requirement per operation. A missing entry is treated
    #: as ``unspecified`` (unknown), never as ``none``.
    approval: ApprovalMap = Field(default_factory=dict)
    outbound: bool = False
    #: allowed outbound destinations; ``None`` = undeclared (unknown).
    allowed_destinations: tuple[str, ...] | None = None
    #: tool ids that receive this tool's output.
    output_flows_to: tuple[Identifier, ...] = ()
    #: declared authorization check; ``None`` = undeclared (unknown).
    authorization_check: AuthorizationCheck | None = None
    declared_purpose: str | None = None

    @field_validator("operations")
    @classmethod
    def _operations_unique(cls, value: tuple[Operation, ...]) -> tuple[Operation, ...]:
        if len(set(value)) != len(value):
            raise ValueError("operations contains duplicate entries")
        return value

    @field_validator("output_flows_to")
    @classmethod
    def _no_self_flow(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        tool_id = info.data.get("id")
        if tool_id is not None and tool_id in value:
            raise ValueError("a tool cannot declare output_flows_to itself")
        return value

    @model_validator(mode="after")
    def _approval_keys_are_declared_operations(self) -> Tool:
        undeclared = sorted(op.value for op in self.approval if op not in self.operations)
        if undeclared:
            raise ValueError(
                "approval declares operations the tool does not perform: "
                + ", ".join(undeclared)
            )
        return self


class Policy(_Base):
    """Document-level security policy."""

    #: operations for which approval is required.
    approval_operations: tuple[Operation, ...] = ()
    #: sensitivity levels for which approval is required.
    approval_sensitivity: tuple[Sensitivity, ...] = ()
    #: policy-level allowed outbound destinations; ``None`` = policy does not
    #: constrain destinations (undeclared), never "all allowed".
    allowed_outbound_destinations: tuple[str, ...] | None = None
    #: sensitivity levels that must not leave the system boundary.
    boundary_sensitivity: tuple[Sensitivity, ...] = ()
    description: str | None = None


class Agent(_Base):
    """The analyzed agent."""

    id: Identifier
    name: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    execution_identity: Identifier
    description: str | None = None
