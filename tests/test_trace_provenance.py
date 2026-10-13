"""Provenance classification and trace-finding tests."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pathwarden.analyze import analyze
from pathwarden.config.loader import load_config
from pathwarden.finding import Confidence, Severity
from pathwarden.trace import (
    ProvenanceClass,
    TraceStatus,
    analyze_provenance,
    analyze_trace,
    build_trace_findings,
    parse_trace,
    untrusted_inputs,
)

Fixture = Callable[[str], Path]


def _hr_config(fixture: Fixture):  # type: ignore[no-untyped-def]
    return load_config(fixture("valid_hr.yaml")).config


def test_classifications_on_fixture(fixture: Fixture) -> None:
    trace = parse_trace(fixture("trace_hr.jsonl").read_text())
    results = {item.tool_call_event_id: item for item in analyze_provenance(trace)}

    assert results["e3"].overall is ProvenanceClass.DIRECT
    assert results["e5"].overall is ProvenanceClass.CONTEXTUAL
    assert results["e6"].overall is ProvenanceClass.UNKNOWN

    assert results["e3"].candidates[0].input_event_id == "e1"
    assert results["e5"].candidates[0].classification is ProvenanceClass.CONTEXTUAL
    assert "temporal association only" in results["e6"].candidates[0].detail


def test_untrusted_inputs_selected(fixture: Fixture) -> None:
    trace = parse_trace(fixture("trace_hr.jsonl").read_text())
    assert [event.event_id for event in untrusted_inputs(trace)] == ["e1"]


def test_trace_findings_statuses_and_severity(fixture: Fixture) -> None:
    trace = parse_trace(fixture("trace_hr.jsonl").read_text())
    findings = {
        finding.tool_call_event_id: finding
        for finding in build_trace_findings(_hr_config(fixture), trace)
    }

    direct = findings["e3"]
    assert direct.classification is ProvenanceClass.DIRECT
    assert direct.status is TraceStatus.OBSERVED
    assert direct.confidence is Confidence.HIGH
    assert direct.severity is Severity.HIGH
    assert direct.resource_id == "employee-db"

    contextual = findings["e5"]
    assert contextual.classification is ProvenanceClass.CONTEXTUAL
    assert contextual.status is TraceStatus.OBSERVED
    assert contextual.confidence is Confidence.MEDIUM

    unknown = findings["e6"]
    assert unknown.classification is ProvenanceClass.UNKNOWN
    assert unknown.status is TraceStatus.INDETERMINATE
    assert unknown.confidence is Confidence.LOW
    assert unknown.severity is Severity.MEDIUM
    assert any("temporal ordering" in item for item in unknown.missing_information)


def test_no_untrusted_input_means_no_findings(fixture: Fixture) -> None:
    text = "\n".join(
        [
            '{"event_id": "i", "timestamp": "2026-01-01T00:00:00Z", "type": "input", '
            '"trust_level": "trusted"}',
            '{"event_id": "c", "timestamp": "2026-01-01T00:00:01Z", "type": "tool_call", '
            '"tool_id": "hr-database", "operation": "read", "parent_event_ids": ["i"]}',
        ]
    )
    trace = parse_trace(text)
    assert build_trace_findings(_hr_config(fixture), trace) == []


def test_input_after_tool_call_is_not_a_candidate(fixture: Fixture) -> None:
    text = "\n".join(
        [
            '{"event_id": "c", "timestamp": "2026-01-01T00:00:00Z", "type": "tool_call", '
            '"tool_id": "hr-database", "operation": "read", "resource_id": "employee-db"}',
            '{"event_id": "i", "timestamp": "2026-01-01T00:00:10Z", "type": "input", '
            '"trust_level": "untrusted"}',
        ]
    )
    trace = parse_trace(text)
    results = analyze_provenance(trace)
    assert results == []
    assert build_trace_findings(_hr_config(fixture), trace) == []


def test_multiple_candidates_are_all_listed(fixture: Fixture) -> None:
    text = "\n".join(
        [
            '{"event_id": "i1", "timestamp": "2026-01-01T00:00:00Z", "type": "input", '
            '"trust_level": "untrusted"}',
            '{"event_id": "i2", "timestamp": "2026-01-01T00:00:01Z", "type": "input", '
            '"trust_level": "untrusted"}',
            '{"event_id": "c", "timestamp": "2026-01-01T00:00:02Z", "type": "tool_call", '
            '"tool_id": "hr-database", "operation": "read", "resource_id": "employee-db", '
            '"parent_event_ids": ["i1"], "context_event_ids": ["i2"]}',
        ]
    )
    trace = parse_trace(text)
    result = analyze_provenance(trace)[0]
    classes = {
        candidate.input_event_id: candidate.classification for candidate in result.candidates
    }
    assert classes == {
        "i1": ProvenanceClass.DIRECT,
        "i2": ProvenanceClass.CONTEXTUAL,
    }


def test_missing_parent_is_not_evidence_of_no_influence(fixture: Fixture) -> None:
    text = "\n".join(
        [
            '{"event_id": "i", "timestamp": "2026-01-01T00:00:00Z", "type": "input", '
            '"trust_level": "untrusted"}',
            '{"event_id": "c", "timestamp": "2026-01-01T00:00:02Z", "type": "tool_call", '
            '"tool_id": "hr-database", "operation": "read", "resource_id": "employee-db", '
            '"parent_event_ids": ["ghost"]}',
        ]
    )
    trace = parse_trace(text)
    result = analyze_provenance(trace)[0]
    # The missing parent produces a warning but the input is still a candidate.
    assert result.overall is ProvenanceClass.UNKNOWN
    assert any("missing parent" in warning for warning in trace.warnings)


def test_analyze_trace_correlates_with_static_findings(fixture: Fixture) -> None:
    config = _hr_config(fixture)
    static = analyze(config)
    trace = parse_trace(fixture("trace_hr.jsonl").read_text())
    result = analyze_trace(config, trace, list(static.findings))

    kinds = {
        correlation.tool_call_event_id: correlation.kind for correlation in result.correlations
    }
    assert kinds["e3"].value == "correlated_by_identifiers"
    assert kinds["e5"].value == "correlated_by_identifiers"
    # Nothing static mentions a tool call for an undeclared tool.
    assert result.warnings == ()


def test_unconfirmed_for_undeclared_tool(fixture: Fixture) -> None:
    config = _hr_config(fixture)
    text = (
        '{"event_id": "c", "timestamp": "2026-01-01T00:00:02Z", "type": "tool_call", '
        '"tool_id": "not-declared", "operation": "send"}'
    )
    trace = parse_trace(text)
    result = analyze_trace(config, trace)
    assert result.correlations[0].kind.value == "unconfirmed"
