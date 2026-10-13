"""Execution-log provenance analysis."""

from __future__ import annotations

from dataclasses import dataclass

from pathwarden.finding import Finding
from pathwarden.models.config import AgentConfig
from pathwarden.trace.correlate import Correlation, CorrelationKind, correlate
from pathwarden.trace.events import Decision, EventType, TraceEvent
from pathwarden.trace.parser import TraceData, load_trace, parse_trace
from pathwarden.trace.provenance import (
    ProvenanceCandidate,
    ProvenanceClass,
    ToolCallProvenance,
    TraceFinding,
    TraceStatus,
    analyze_provenance,
    build_trace_findings,
    classify_event,
    is_sensitive_tool_call,
    untrusted_inputs,
)

__all__ = [
    "Correlation",
    "CorrelationKind",
    "Decision",
    "EventType",
    "ProvenanceCandidate",
    "ProvenanceClass",
    "ToolCallProvenance",
    "TraceAnalysis",
    "TraceData",
    "TraceEvent",
    "TraceFinding",
    "TraceStatus",
    "analyze_provenance",
    "analyze_trace",
    "build_trace_findings",
    "classify_event",
    "is_sensitive_tool_call",
    "load_trace",
    "parse_trace",
    "untrusted_inputs",
]


@dataclass(frozen=True)
class TraceAnalysis:
    """The full result of analyzing a trace against a configuration."""

    trace: TraceData
    provenance: tuple[ToolCallProvenance, ...]
    findings: tuple[TraceFinding, ...]
    correlations: tuple[Correlation, ...]
    warnings: tuple[str, ...]


def analyze_trace(
    config: AgentConfig, trace: TraceData, static_findings: list[Finding] | None = None
) -> TraceAnalysis:
    """Analyze ``trace`` against ``config`` and optional static findings."""

    findings = tuple(build_trace_findings(config, trace))
    correlations = tuple(correlate(config, list(static_findings or []), trace))
    return TraceAnalysis(
        trace=trace,
        provenance=tuple(analyze_provenance(trace)),
        findings=findings,
        correlations=correlations,
        warnings=trace.warnings,
    )
