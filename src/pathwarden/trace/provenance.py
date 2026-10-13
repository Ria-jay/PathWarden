"""Provenance classification and trace findings.

For each sensitive tool call, each untrusted input event is classified:

* ``direct`` — reachable from the tool call through ``parent_event_ids``.
* ``contextual`` — present in ``context_event_ids`` (of the tool call or an
  ancestor) but with no parent link.
* ``unknown`` — neither link exists; only temporal ordering is available, which
  is reported as **temporal association only** and never as influence.

All candidates are listed; Pathwarden does not choose one. A missing parent or
context link is never treated as evidence that no influence existed.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from pathwarden.finding import (
    SEVERITY_ORDER,
    Confidence,
    Severity,
    make_finding_id,
)
from pathwarden.models.config import AgentConfig
from pathwarden.models.enums import Operation, Sensitivity
from pathwarden.rules.common import MUTATING_OPERATIONS, SENSITIVE_LEVELS
from pathwarden.severity import MUTATE, READ, compute_severity, operation_class
from pathwarden.trace.events import EventType, TraceEvent
from pathwarden.trace.parser import TraceData

__all__ = [
    "ProvenanceCandidate",
    "ProvenanceClass",
    "ToolCallProvenance",
    "TraceFinding",
    "TraceStatus",
    "analyze_provenance",
    "build_trace_findings",
    "classify_event",
    "is_sensitive_tool_call",
    "untrusted_inputs",
]


class ProvenanceClass(StrEnum):
    """How an untrusted input relates to a tool call."""

    DIRECT = "direct"
    CONTEXTUAL = "contextual"
    UNKNOWN = "unknown"


class TraceStatus(StrEnum):
    """Whether a trace finding is observed or indeterminate."""

    OBSERVED = "observed"
    INDETERMINATE = "indeterminate"


class ProvenanceCandidate(BaseModel):
    """A single untrusted-input candidate for a tool call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_event_id: str
    classification: ProvenanceClass
    detail: str
    via_event_ids: tuple[str, ...] = ()


class ToolCallProvenance(BaseModel):
    """All untrusted-input candidates for one tool call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_call_event_id: str
    candidates: tuple[ProvenanceCandidate, ...]

    @property
    def overall(self) -> ProvenanceClass | None:
        """Return the strongest classification present, or ``None``."""

        order = [
            ProvenanceClass.DIRECT,
            ProvenanceClass.CONTEXTUAL,
            ProvenanceClass.UNKNOWN,
        ]
        for candidate_class in order:
            if any(candidate.classification is candidate_class for candidate in self.candidates):
                return candidate_class
        return None


class TraceFinding(BaseModel):
    """An observed or indeterminate trace finding.

    Deliberately separate from static findings: a trace finding describes what
    was *observed* in an execution log, not what the configuration *permits*.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    title: str
    severity: Severity
    confidence: Confidence
    status: TraceStatus
    summary: str
    tool_call_event_id: str
    classification: ProvenanceClass
    candidates: tuple[ProvenanceCandidate, ...]
    sensitive_operation: str | None
    resource_id: str | None
    missing_information: tuple[str, ...] = ()
    recommended_investigation: str = ""
    limitations: str = ""


def untrusted_inputs(trace: TraceData) -> list[TraceEvent]:
    """Return input events whose trust level is ``untrusted``."""

    return [
        event
        for event in trace.events
        if event.type is EventType.INPUT
        and event.trust_level is not None
        and event.trust_level.value == "untrusted"
    ]


def _ancestors(trace: TraceData, event_id: str) -> list[str]:
    """Return ancestor event ids (via ``parent_event_ids``), cycle-safe."""

    seen: set[str] = set()
    ordered: list[str] = []
    start = trace.get(event_id)
    stack = list(start.parent_event_ids) if start is not None else []
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        ordered.append(current)
        parent = trace.get(current)
        if parent is not None:
            stack.extend(parent.parent_event_ids)
    return ordered


def _context_ids(trace: TraceData, event: TraceEvent, ancestors: list[str]) -> list[str]:
    """Context event ids of ``event`` and all of its ancestors."""

    collected: list[str] = list(event.context_event_ids)
    for ancestor_id in ancestors:
        ancestor = trace.get(ancestor_id)
        if ancestor is not None:
            collected.extend(ancestor.context_event_ids)
    # Deduplicate, preserve order.
    seen: set[str] = set()
    result: list[str] = []
    for item in collected:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def classify_event(
    trace: TraceData, event: TraceEvent, inputs: list[TraceEvent]
) -> list[ProvenanceCandidate]:
    """Classify every untrusted input candidate for ``event``."""

    ancestors = _ancestors(trace, event.event_id)
    ancestor_set = set(ancestors)
    context = _context_ids(trace, event, ancestors)
    context_set = set(context)
    candidates: list[ProvenanceCandidate] = []

    for source in inputs:
        if source.event_id in ancestor_set:
            candidates.append(
                ProvenanceCandidate(
                    input_event_id=source.event_id,
                    classification=ProvenanceClass.DIRECT,
                    detail="input is reachable through parent_event_ids",
                    via_event_ids=tuple(ancestors),
                )
            )
        elif source.event_id in context_set:
            candidates.append(
                ProvenanceCandidate(
                    input_event_id=source.event_id,
                    classification=ProvenanceClass.CONTEXTUAL,
                    detail="input appears in context_event_ids but has no parent link",
                    via_event_ids=tuple(context),
                )
            )
        elif source.timestamp <= event.timestamp:
            candidates.append(
                ProvenanceCandidate(
                    input_event_id=source.event_id,
                    classification=ProvenanceClass.UNKNOWN,
                    detail="temporal association only; no parent or context link",
                )
            )
    return candidates


def analyze_provenance(trace: TraceData) -> list[ToolCallProvenance]:
    """Return provenance candidates for every tool-call event."""

    inputs = untrusted_inputs(trace)
    results: list[ToolCallProvenance] = []
    for event in trace.events:
        if event.type is not EventType.TOOL_CALL:
            continue
        candidates = classify_event(trace, event, inputs)
        if candidates:
            results.append(
                ToolCallProvenance(
                    tool_call_event_id=event.event_id, candidates=tuple(candidates)
                )
            )
    return results


def is_sensitive_tool_call(config: AgentConfig, event: TraceEvent) -> bool:
    """Whether a tool-call event is sensitive under the configuration."""

    if event.operation is not None and event.operation in MUTATING_OPERATIONS:
        return True
    if event.resource_id is not None:
        resource = config.resource_by_id(event.resource_id)
        if resource is not None and resource.sensitivity in SENSITIVE_LEVELS:
            return True
        if resource is None:
            # Unknown resource: potential, but the operation still matters.
            return event.operation is None or event.operation is not Operation.READ
    return False


def build_trace_findings(config: AgentConfig, trace: TraceData) -> list[TraceFinding]:
    """Build trace findings for sensitive tool calls with untrusted candidates."""

    inputs = untrusted_inputs(trace)
    if not inputs:
        return []

    findings: list[TraceFinding] = []
    for event in trace.events:
        if event.type is not EventType.TOOL_CALL or not is_sensitive_tool_call(config, event):
            continue
        candidates = classify_event(trace, event, inputs)
        if not candidates:
            continue
        findings.append(_build_finding(config, trace, event, candidates))
    findings.sort(key=lambda finding: (-SEVERITY_ORDER[finding.severity], finding.finding_id))
    return findings


def _build_finding(
    config: AgentConfig,
    trace: TraceData,
    event: TraceEvent,
    candidates: list[ProvenanceCandidate],
) -> TraceFinding:
    direct = any(c.classification is ProvenanceClass.DIRECT for c in candidates)
    contextual = any(c.classification is ProvenanceClass.CONTEXTUAL for c in candidates)
    overall = (
        ProvenanceClass.DIRECT
        if direct
        else ProvenanceClass.CONTEXTUAL
        if contextual
        else ProvenanceClass.UNKNOWN
    )
    if direct:
        status = TraceStatus.OBSERVED
        confidence = Confidence.HIGH
    elif contextual:
        status = TraceStatus.OBSERVED
        confidence = Confidence.MEDIUM
    else:
        status = TraceStatus.INDETERMINATE
        confidence = Confidence.LOW

    resource = config.resource_by_id(event.resource_id) if event.resource_id else None
    sensitivity = resource.sensitivity if resource is not None else Sensitivity.INTERNAL
    if event.operation is not None:
        op_class = operation_class(event.operation)
    elif resource is not None:
        op_class = READ
    else:
        op_class = MUTATE

    severity = compute_severity(
        sensitivity,
        op_class,
        untrusted=True,
        status_unknown=(overall is ProvenanceClass.UNKNOWN),
    )

    missing: list[str] = []
    if overall is ProvenanceClass.UNKNOWN:
        missing.append(
            "no parent_event_ids or context_event_ids link; only temporal ordering is available"
        )
    if not event.context_event_ids:
        missing.append("the tool call records no context_event_ids")

    return TraceFinding(
        finding_id=make_finding_id("TRACE-001", event.event_id),
        title="Untrusted input associated with sensitive tool call",
        severity=severity,
        confidence=confidence,
        status=status,
        summary=(
            f"Tool call {event.event_id!r} performed a sensitive operation "
            f"({event.operation.value if event.operation else 'unspecified'}) with "
            f"{len(candidates)} untrusted-input candidate(s); strongest classification: "
            f"{overall.value}."
        ),
        tool_call_event_id=event.event_id,
        classification=overall,
        candidates=tuple(candidates),
        sensitive_operation=event.operation.value if event.operation else None,
        resource_id=event.resource_id,
        missing_information=tuple(missing),
        recommended_investigation=(
            "Confirm whether the untrusted input was in the model context for this tool call, "
            "inspect the tool call arguments, and verify the operation was authorized."
        ),
        limitations=(
            "An association in the log is not proof of causation. A missing parent or context "
            "link is never evidence that no influence existed."
        ),
    )
