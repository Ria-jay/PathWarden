"""Static rule tests: PW-001 … PW-007.

Each rule has positive, negative, boundary, insufficient-information, and
"structurally connected but not permission-reachable" coverage where applicable.
Tests assert finding semantics and paths, not just counts.
"""

from __future__ import annotations

from typing import Any

import yaml

from pathwarden.analyze import analyze
from pathwarden.config.loader import load_config_from_text
from pathwarden.finding import Confidence, FindingStatus, Severity

UNTRUSTED = {
    "id": "cv",
    "name": "CV",
    "type": "uploaded_file",
    "trust": "untrusted",
    "may_contain_attacker_content": True,
}


def cfg(
    *,
    identity: dict[str, Any] | None = None,
    tool: dict[str, Any] | None = None,
    resource: dict[str, Any] | None = None,
    inputs: list[dict[str, Any]] | None = None,
    tools: list[dict[str, Any]] | None = None,
    resources: list[dict[str, Any]] | None = None,
    policy: dict[str, Any] | None = None,
) -> str:
    ident: dict[str, Any] = {"id": "idn", "type": "service_account"}
    ident.update(identity or {})
    default_tool: dict[str, Any] = {
        "id": "t",
        "name": "T",
        "operations": ["read"],
        "identity": "idn",
    }
    if tool is not None:
        default_tool.update(tool)
    default_resource: dict[str, Any] = {
        "id": "r",
        "type": "database",
        "sensitivity": "internal",
        "tenant": "acme",
        "permitted_operations": ["read"],
    }
    if resource is not None:
        default_resource.update(resource)
    data = {
        "schema_version": "1.0",
        "agent": {"id": "a", "name": "A", "execution_identity": "idn"},
        "identities": [ident],
        "input_sources": list(inputs or []),
        "tools": list(tools) if tools is not None else [default_tool],
        "resources": list(resources) if resources is not None else [default_resource],
        "policy": dict(policy or {}),
    }
    return yaml.safe_dump(data)


def pw(rule_id: str, text: str) -> list[Any]:
    result = analyze(load_config_from_text(text).config)
    return [finding for finding in result.findings if finding.rule_id == rule_id]


# --------------------------------------------------------------------------- #
# PW-001
# --------------------------------------------------------------------------- #

_PW001_ALLOWED = {
    "identity": {
        "granted_scopes": ["db:read"],
        "resource_restrictions": ["*"],
        "tenants": ["acme"],
    },
    "tool": {"required_scopes": ["db:read"], "resource_restrictions": ["*"]},
    "resource": {"sensitivity": "confidential", "tenant": "acme", "permitted_operations": ["read"]},
    "inputs": [UNTRUSTED],
}


def test_pw001_positive_untrusted_to_confidential_read() -> None:
    findings = pw("PW-001", cfg(**_PW001_ALLOWED))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.REACHABLE
    assert finding.affected_resources == ("r",)
    assert finding.effective_identity == "idn"
    assert finding.path is not None
    assert finding.path.nodes == ("cv", "a", "t", "r")


def test_pw001_negative_trusted_source() -> None:
    text = cfg(
        identity=_PW001_ALLOWED["identity"],
        tool=_PW001_ALLOWED["tool"],
        resource=_PW001_ALLOWED["resource"],
        inputs=[{"id": "chat", "name": "Chat", "type": "user_message", "trust": "trusted"}],
    )
    assert pw("PW-001", text) == []


def test_pw001_boundary_public_read_not_sensitive() -> None:
    text = cfg(
        identity=_PW001_ALLOWED["identity"],
        tool=_PW001_ALLOWED["tool"],
        resource={"sensitivity": "public", "tenant": "acme", "permitted_operations": ["read"]},
        inputs=[UNTRUSTED],
    )
    assert pw("PW-001", text) == []


def test_pw001_write_operation_is_sensitive() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:write"],
            "resource_restrictions": ["*"],
            "tenants": ["acme"],
        },
        tool={
            "operations": ["write"],
            "required_scopes": ["db:write"],
            "resource_restrictions": ["*"],
        },
        resource={"sensitivity": "internal", "tenant": "acme", "permitted_operations": ["write"]},
        inputs=[UNTRUSTED],
    )
    findings = pw("PW-001", text)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH  # internal/mutate medium, raised by untrusted


def test_pw001_insufficient_information_is_indeterminate() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:read"],
            "resource_restrictions": ["*"],
            "tenants": ["acme"],
        },
        tool={"resource_restrictions": ["*"]},  # required_scopes undeclared -> unknown
        resource={
            "sensitivity": "confidential",
            "tenant": "acme",
            "permitted_operations": ["read"],
        },
        inputs=[UNTRUSTED],
    )
    findings = pw("PW-001", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.INDETERMINATE
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].confidence is Confidence.LOW
    assert findings[0].missing_or_uncertain_constraints


def test_pw001_structurally_connected_but_not_permission_reachable() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:read"],
            "resource_restrictions": ["*"],
            "tenants": ["globex"],
        },
        tool={"required_scopes": ["db:read"], "resource_restrictions": ["*"]},
        resource={
            "sensitivity": "confidential",
            "tenant": "acme",
            "permitted_operations": ["read"],
        },
        inputs=[UNTRUSTED],
    )
    result = analyze(load_config_from_text(text).config)
    edges = {(source, target, etype) for source, target, etype, _ in result.graph.edges()}
    assert ("t", "r", "reads") in edges  # structurally connected
    assert [f for f in result.findings if f.rule_id == "PW-001"] == []  # permission denied


# --------------------------------------------------------------------------- #
# PW-002
# --------------------------------------------------------------------------- #

_PW002_ACTOR = {
    "id": "cv",
    "name": "CV",
    "type": "uploaded_file",
    "trust": "untrusted",
    "requesting_principal": "candidate",
}


def test_pw002_positive_confused_deputy() -> None:
    text = cfg(
        identity={
            "acts_as_requester": False,
            "granted_scopes": ["db:read"],
            "resource_restrictions": ["*"],
            "tenants": ["acme"],
        },
        tool={
            "authorization_check": {"type": "none"},
            "required_scopes": ["db:read"],
            "resource_restrictions": ["*"],
        },
        resource={"sensitivity": "confidential", "owner": "hr-team", "tenant": "acme"},
        inputs=[_PW002_ACTOR],
    )
    findings = pw("PW-002", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.REACHABLE
    assert findings[0].confidence is Confidence.HIGH


def test_pw002_insufficient_information_is_indeterminate() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:read"],
            "resource_restrictions": ["*"],
            "tenants": ["acme"],
        },
        tool={"required_scopes": ["db:read"], "resource_restrictions": ["*"]},
        resource={"sensitivity": "confidential", "owner": "hr-team", "tenant": "acme"},
        inputs=[_PW002_ACTOR],
    )
    findings = pw("PW-002", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.INDETERMINATE
    assert any("acts_as_requester" in item for item in findings[0].missing_or_uncertain_constraints)
    assert any(
        "authorization_check" in item for item in findings[0].missing_or_uncertain_constraints
    )


def test_pw002_negative_when_identity_acts_as_requester() -> None:
    text = cfg(
        identity={"acts_as_requester": True, "granted_scopes": ["db:read"], "tenants": ["acme"]},
        tool={"authorization_check": {"type": "none"}, "required_scopes": ["db:read"]},
        resource={"sensitivity": "confidential", "owner": "hr-team", "tenant": "acme"},
        inputs=[_PW002_ACTOR],
    )
    assert pw("PW-002", text) == []


def test_pw002_negative_when_requester_scoped_check_declared() -> None:
    text = cfg(
        identity={"acts_as_requester": False, "granted_scopes": ["db:read"], "tenants": ["acme"]},
        tool={
            "authorization_check": {"type": "requester_scoped"},
            "required_scopes": ["db:read"],
        },
        resource={"sensitivity": "confidential", "owner": "hr-team", "tenant": "acme"},
        inputs=[_PW002_ACTOR],
    )
    assert pw("PW-002", text) == []


def test_pw002_negative_when_resource_owned_by_principal() -> None:
    text = cfg(
        identity={"acts_as_requester": False, "granted_scopes": ["db:read"], "tenants": ["acme"]},
        tool={"authorization_check": {"type": "none"}, "required_scopes": ["db:read"]},
        resource={"sensitivity": "confidential", "owner": "candidate", "tenant": "acme"},
        inputs=[_PW002_ACTOR],
    )
    assert pw("PW-002", text) == []


# --------------------------------------------------------------------------- #
# PW-003
# --------------------------------------------------------------------------- #


def test_pw003_positive_excess_operation() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:read", "db:write"],
            "resource_restrictions": ["db/*"],
            "tenants": ["acme"],
        },
        tool={
            "operations": ["read"],
            "required_scopes": ["db:read"],
            "resource_restrictions": ["db/*"],
        },
    )
    findings = pw("PW-003", text)
    assert len(findings) == 1
    assert "excess operations" in " ".join(findings[0].evidence)
    assert findings[0].effective_identity == "idn"


def test_pw003_positive_excess_resource() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:read"],
            "resource_restrictions": ["db/*"],
            "tenants": ["acme"],
        },
        tool={"required_scopes": ["db:read"], "resource_restrictions": ["db/employees"]},
        resources=[
            {
                "id": "db/employees",
                "type": "database",
                "sensitivity": "internal",
                "tenant": "acme",
                "permitted_operations": ["read"],
            },
            {
                "id": "db/salaries",
                "type": "database",
                "sensitivity": "confidential",
                "tenant": "acme",
                "permitted_operations": ["read"],
            },
        ],
    )
    findings = pw("PW-003", text)
    assert len(findings) == 1
    assert findings[0].affected_resources == ("db/salaries",)
    assert findings[0].severity is Severity.MEDIUM


def test_pw003_negative_when_scope_matches_operations() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:read"],
            "resource_restrictions": ["db/*"],
            "tenants": ["acme"],
        },
        tool={
            "operations": ["read"],
            "required_scopes": ["db:read"],
            "resource_restrictions": ["db/*"],
        },
    )
    assert pw("PW-003", text) == []


def test_pw003_limitation_noted_when_no_purpose() -> None:
    text = cfg(
        identity={"granted_scopes": ["db:read", "db:write"], "tenants": ["acme"]},
        tool={"operations": ["read"], "required_scopes": ["db:read"]},
    )
    findings = pw("PW-003", text)
    assert len(findings) == 1
    assert any("declared_purpose" in item for item in findings[0].missing_or_uncertain_constraints)
    assert findings[0].confidence is Confidence.MEDIUM


# --------------------------------------------------------------------------- #
# PW-004
# --------------------------------------------------------------------------- #


def test_pw004_positive_missing_approval() -> None:
    text = cfg(
        policy={"approval_operations": ["read"]},
        tool={"operations": ["read"], "approval": {"read": "none"}},
    )
    findings = pw("PW-004", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.REACHABLE


def test_pw004_indeterminate_when_unspecified() -> None:
    text = cfg(policy={"approval_operations": ["read"]}, tool={"operations": ["read"]})
    findings = pw("PW-004", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.INDETERMINATE
    assert findings[0].confidence is Confidence.LOW


def test_pw004_declared_is_informational() -> None:
    text = cfg(
        policy={"approval_operations": ["read"]},
        tool={"operations": ["read"], "approval": {"read": "required"}},
    )
    findings = pw("PW-004", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.INFORMATIONAL
    assert "declared" in findings[0].summary


def test_pw004_negative_when_policy_does_not_require() -> None:
    text = cfg(tool={"operations": ["read"], "approval": {"read": "none"}})
    assert pw("PW-004", text) == []


def test_pw004_sensitivity_trigger() -> None:
    text = cfg(
        policy={"approval_sensitivity": ["confidential"]},
        tool={"operations": ["read"], "approval": {"read": "none"}},
        resource={"sensitivity": "confidential"},
    )
    findings = pw("PW-004", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.REACHABLE


# --------------------------------------------------------------------------- #
# PW-005
# --------------------------------------------------------------------------- #

_PW005_IDENTITY = {
    "granted_scopes": ["db:read", "mail:send"],
    "resource_restrictions": ["*"],
    "tenants": ["acme"],
}


def _pw005_tools(*, outbound_extra: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    sender: dict[str, Any] = {
        "id": "email",
        "name": "Email",
        "operations": ["send"],
        "identity": "idn",
        "outbound": True,
    }
    if outbound_extra is not None:
        sender.update(outbound_extra)
    return [
        {
            "id": "reader",
            "name": "Reader",
            "operations": ["read"],
            "identity": "idn",
            "required_scopes": ["db:read"],
            "resource_restrictions": ["*"],
        },
        sender,
    ]


def test_pw005_positive_absent_destinations() -> None:
    text = cfg(
        identity=_PW005_IDENTITY,
        tools=_pw005_tools(),
        resource={
            "sensitivity": "confidential",
            "tenant": "acme",
            "permitted_operations": ["read"],
        },
    )
    findings = pw("PW-005", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.INDETERMINATE
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].affected_resources == ("r",)


def test_pw005_negative_when_destinations_allowlisted() -> None:
    text = cfg(
        identity=_PW005_IDENTITY,
        tools=_pw005_tools(outbound_extra={"allowed_destinations": ["*.acme.com"]}),
        resource={
            "sensitivity": "confidential",
            "tenant": "acme",
            "permitted_operations": ["read"],
        },
        policy={"allowed_outbound_destinations": ["*.acme.com"]},
    )
    assert pw("PW-005", text) == []


def test_pw005_boundary_violation_is_reported() -> None:
    text = cfg(
        identity=_PW005_IDENTITY,
        tools=_pw005_tools(outbound_extra={"allowed_destinations": ["*.acme.com"]}),
        resource={"sensitivity": "restricted", "tenant": "acme", "permitted_operations": ["read"]},
        policy={
            "allowed_outbound_destinations": ["*.acme.com"],
            "boundary_sensitivity": ["restricted"],
        },
    )
    findings = pw("PW-005", text)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].status is FindingStatus.REACHABLE


def test_pw005_negative_without_outbound_tool() -> None:
    text = cfg(
        identity=_PW005_IDENTITY,
        tool={"required_scopes": ["db:read"], "resource_restrictions": ["*"]},
        resource={
            "sensitivity": "confidential",
            "tenant": "acme",
            "permitted_operations": ["read"],
        },
    )
    assert pw("PW-005", text) == []


# --------------------------------------------------------------------------- #
# PW-006
# --------------------------------------------------------------------------- #


def test_pw006_positive_resource_outside_declared_tenants() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:read"],
            "resource_restrictions": ["*"],
            "tenants": ["acme"],
        },
        tool={"required_scopes": ["db:read"], "resource_restrictions": ["*"]},
        resources=[
            {
                "id": "db/a",
                "type": "database",
                "sensitivity": "internal",
                "tenant": "acme",
                "permitted_operations": ["read"],
            },
            {
                "id": "db/b",
                "type": "database",
                "sensitivity": "confidential",
                "tenant": "globex",
                "permitted_operations": ["read"],
            },
        ],
    )
    findings = pw("PW-006", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.REACHABLE
    assert "db/b" in findings[0].affected_resources


def test_pw006_positive_wildcard_identity_multi_tenant() -> None:
    text = cfg(
        identity={"granted_scopes": ["db:read"], "resource_restrictions": ["db/*"], "tenants": "*"},
        tool={"required_scopes": ["db:read"], "resource_restrictions": ["db/*"]},
        resources=[
            {
                "id": "db/a",
                "type": "database",
                "sensitivity": "internal",
                "tenant": "acme",
                "permitted_operations": ["read"],
            },
            {
                "id": "db/b",
                "type": "database",
                "sensitivity": "internal",
                "tenant": "globex",
                "permitted_operations": ["read"],
            },
        ],
    )
    findings = pw("PW-006", text)
    assert len(findings) == 1
    assert "all tenants" in findings[0].summary


def test_pw006_negative_single_tenant() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:read"],
            "resource_restrictions": ["*"],
            "tenants": ["acme"],
        },
        tool={"required_scopes": ["db:read"], "resource_restrictions": ["*"]},
        resource={"sensitivity": "internal", "tenant": "acme", "permitted_operations": ["read"]},
    )
    assert pw("PW-006", text) == []


def test_pw006_indeterminate_when_resource_tenant_unknown() -> None:
    text = cfg(
        identity={
            "granted_scopes": ["db:read"],
            "resource_restrictions": ["*"],
            "tenants": ["acme"],
        },
        tool={"required_scopes": ["db:read"], "resource_restrictions": ["*"]},
        resource={"sensitivity": "internal", "tenant": None, "permitted_operations": ["read"]},
    )
    findings = pw("PW-006", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.INDETERMINATE


# --------------------------------------------------------------------------- #
# PW-007
# --------------------------------------------------------------------------- #

_PW007_IDENTITY = {
    "granted_scopes": ["db:read", "mail:send"],
    "resource_restrictions": ["*"],
    "tenants": ["acme"],
}


def _pw007_tools(*, chain: bool = True) -> list[dict[str, Any]]:
    reader = {
        "id": "reader",
        "name": "Reader",
        "operations": ["read"],
        "identity": "idn",
        "required_scopes": ["db:read"],
        "resource_restrictions": ["*"],
        "output_flows_to": ["summarizer"] if chain else ["sender"],
    }
    tools = [reader]
    if chain:
        tools.append(
            {
                "id": "summarizer",
                "name": "Summarizer",
                "operations": ["read"],
                "identity": "idn",
                "output_flows_to": ["sender"],
            }
        )
    tools.append(
        {
            "id": "sender",
            "name": "Sender",
            "operations": ["send"],
            "identity": "idn",
            "outbound": True,
            "allowed_destinations": ["*.acme.com"],
        }
    )
    return tools


def test_pw007_positive_three_tool_chain() -> None:
    text = cfg(
        identity=_PW007_IDENTITY,
        tools=_pw007_tools(chain=True),
        resource={
            "sensitivity": "confidential",
            "tenant": "acme",
            "permitted_operations": ["read"],
        },
        policy={"allowed_outbound_destinations": ["*.acme.com"]},
    )
    findings = pw("PW-007", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.REACHABLE
    assert findings[0].severity is Severity.HIGH
    assert findings[0].path is not None
    assert set(findings[0].path.nodes) >= {"reader", "summarizer", "sender", "r"}


def test_pw007_negative_two_tool_chain_belongs_to_pw005() -> None:
    text = cfg(
        identity=_PW007_IDENTITY,
        tools=_pw007_tools(chain=False),
        resource={
            "sensitivity": "confidential",
            "tenant": "acme",
            "permitted_operations": ["read"],
        },
        policy={"allowed_outbound_destinations": ["*.acme.com"]},
    )
    assert pw("PW-007", text) == []


def test_pw007_structurally_connected_but_not_permission_valid() -> None:
    text = cfg(
        identity={**_PW007_IDENTITY, "tenants": ["globex"]},
        tools=_pw007_tools(chain=True),
        resource={
            "sensitivity": "confidential",
            "tenant": "acme",
            "permitted_operations": ["read"],
        },
        policy={"allowed_outbound_destinations": ["*.acme.com"]},
    )
    findings = pw("PW-007", text)
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.INFORMATIONAL
    assert any("denied" in item for item in findings[0].missing_or_uncertain_constraints)


# --------------------------------------------------------------------------- #
# Cross-cutting
# --------------------------------------------------------------------------- #


def test_analysis_is_deterministic() -> None:
    text = cfg(
        identity=_PW005_IDENTITY,
        tools=_pw007_tools(chain=True),
        resource={
            "sensitivity": "confidential",
            "tenant": "acme",
            "permitted_operations": ["read"],
        },
        inputs=[UNTRUSTED],
    )
    first = analyze(load_config_from_text(text).config)
    second = analyze(load_config_from_text(text).config)
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]
    assert first.findings == second.findings


def test_rule_coverage_lists_all_seven_rules() -> None:
    result = analyze(load_config_from_text(cfg()).config)
    assert [entry["id"] for entry in result.rule_coverage] == [
        "PW-001",
        "PW-002",
        "PW-003",
        "PW-004",
        "PW-005",
        "PW-006",
        "PW-007",
    ]
