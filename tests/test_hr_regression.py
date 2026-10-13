"""End-to-end HR example regression tests.

These tests assert finding *semantics* and the underlying permission and graph
differences, not hardcoded counts: the same rule set is run against a vulnerable
configuration and a remediated one, and the differences are traced to real
configuration changes.
"""

from __future__ import annotations

from pathlib import Path

from pathwarden.analyze import analyze
from pathwarden.config.loader import load_config, load_config_from_text
from pathwarden.finding import Confidence, FindingStatus, Severity
from pathwarden.graph.permissions import check_destinations, evaluate_access
from pathwarden.models.enums import Operation, PermissionStatus
from pathwarden.trace import ProvenanceClass, analyze_trace, load_trace

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
VULNERABLE = EXAMPLES / "vulnerable_agent.yaml"
FIXED = EXAMPLES / "fixed_agent.yaml"
TRACE = EXAMPLES / "trace.jsonl"


def _rules(findings: list[object]) -> set[str]:
    return {finding.rule_id for finding in findings}  # type: ignore[attr-defined]


def test_vulnerable_config_fires_the_risk_rules() -> None:
    result = analyze(load_config(VULNERABLE).config)
    rules = _rules(list(result.findings))
    for rule_id in ("PW-001", "PW-002", "PW-003", "PW-004", "PW-005", "PW-006", "PW-007"):
        assert rule_id in rules, f"{rule_id} expected on the vulnerable example"


def test_fixed_config_removes_the_risk_rules() -> None:
    result = analyze(load_config(FIXED).config)
    rules = _rules(list(result.findings))
    for rule_id in ("PW-002", "PW-003", "PW-005", "PW-006", "PW-007"):
        assert rule_id not in rules, f"{rule_id} should not fire on the fixed example"


def test_fixed_pw004_is_declared_not_reachable() -> None:
    result = analyze(load_config(FIXED).config)
    pw004 = [finding for finding in result.findings if finding.rule_id == "PW-004"]
    assert pw004
    assert all(finding.status is FindingStatus.INFORMATIONAL for finding in pw004)


def test_pw001_severity_drops_with_declared_control() -> None:
    vulnerable = analyze(load_config(VULNERABLE).config)
    fixed = analyze(load_config(FIXED).config)
    vuln_pw001 = [finding for finding in vulnerable.findings if finding.rule_id == "PW-001"]
    fixed_pw001 = [finding for finding in fixed.findings if finding.rule_id == "PW-001"]

    assert vuln_pw001 and all(finding.severity is Severity.HIGH for finding in vuln_pw001)
    # The declared approval lowers severity one level; the path remains reachable.
    assert fixed_pw001 and all(finding.severity is Severity.MEDIUM for finding in fixed_pw001)
    assert all(finding.status is FindingStatus.REACHABLE for finding in fixed_pw001)


def test_tenant_isolation_is_a_real_permission_difference() -> None:
    vulnerable = load_config(VULNERABLE).config
    fixed = load_config(FIXED).config

    def read_result(config: object, tool_id: str, resource_id: str):  # type: ignore[no-untyped-def]
        tool = config.tool_by_id(tool_id)  # type: ignore[attr-defined]
        resource = config.resource_by_id(resource_id)  # type: ignore[attr-defined]
        assert tool is not None and resource is not None
        return evaluate_access(
            config,
            tool=tool,
            operation=Operation.READ,
            resource=resource,  # type: ignore[arg-type]
        )

    # Vulnerable: the agent's identity lists both tenants, so the EU database is allowed.
    assert (
        read_result(vulnerable, "hr-database", "employee-db-eu").status is PermissionStatus.ALLOWED
    )
    # Fixed: the database identity is tenant-scoped to acme and restricted to employee-db.
    assert read_result(fixed, "hr-database", "employee-db-eu").status is PermissionStatus.DENIED


def test_fixed_config_has_no_cross_tenant_edge() -> None:
    vulnerable = analyze(load_config(VULNERABLE).config)
    fixed = analyze(load_config(FIXED).config)

    def edges(result: object) -> set[tuple[str, str, str]]:  # type: ignore[no-untyped-def]
        return {(s, t, e) for s, t, e, _ in result.graph.edges()}  # type: ignore[attr-defined]

    assert ("hr-database", "employee-db-eu", "reads") in edges(vulnerable)
    assert ("hr-database", "employee-db-eu", "reads") not in edges(fixed)


def test_outbound_destination_control_differs() -> None:
    vulnerable = load_config(VULNERABLE).config
    fixed = load_config(FIXED).config

    vuln_email = vulnerable.tool_by_id("email-sender")
    fixed_email = fixed.tool_by_id("email-sender")
    assert vuln_email is not None and fixed_email is not None

    # Vulnerable: no destinations declared -> unknown.
    vulnerable_check = check_destinations(
        vuln_email.allowed_destinations,
        vulnerable.policy.allowed_outbound_destinations,
        "mail.acme.com",
    )
    assert vulnerable_check.status is PermissionStatus.UNKNOWN

    # Fixed: an explicit allowlist makes an internal destination allowed ...
    fixed_allowed = check_destinations(
        fixed_email.allowed_destinations,
        fixed.policy.allowed_outbound_destinations,
        "mail.acme.com",
    )
    assert fixed_allowed.status is PermissionStatus.ALLOWED
    # ... and an external destination denied.
    fixed_denied = check_destinations(
        fixed_email.allowed_destinations,
        fixed.policy.allowed_outbound_destinations,
        "evil.example.com",
    )
    assert fixed_denied.status is PermissionStatus.DENIED


def test_findings_track_a_real_configuration_change() -> None:
    """Tightening tenants changes the PW-006 finding, not just a hardcoded number."""

    original = load_config(VULNERABLE).config
    multi = [f for f in analyze(original).findings if f.rule_id == "PW-006"]
    assert multi and "multiple tenants" in multi[0].summary

    tightened_text = VULNERABLE.read_text().replace(
        'tenants: ["acme", "globex"]', 'tenants: ["acme"]'
    )
    tightened = load_config_from_text(tightened_text).config
    outside = [f for f in analyze(tightened).findings if f.rule_id == "PW-006"]
    assert outside and "outside" in outside[0].summary
    # Different reason -> different stable finding id.
    assert outside[0].finding_id != multi[0].finding_id


def test_hr_trace_provenance() -> None:
    config = load_config(VULNERABLE).config
    static = analyze(config)
    trace = load_trace(TRACE)
    result = analyze_trace(config, trace, list(static.findings))

    by_call = {item.tool_call_event_id: item for item in result.provenance}
    assert by_call["e3"].overall is ProvenanceClass.DIRECT
    assert by_call["e5"].overall is ProvenanceClass.CONTEXTUAL
    assert by_call["e6"].overall is ProvenanceClass.UNKNOWN

    direct = next(f for f in result.findings if f.tool_call_event_id == "e3")
    assert direct.status.value == "observed"
    assert direct.confidence is Confidence.HIGH

    unknown = next(f for f in result.findings if f.tool_call_event_id == "e6")
    assert unknown.status.value == "indeterminate"
    assert any("temporal" in item for item in unknown.missing_information)
