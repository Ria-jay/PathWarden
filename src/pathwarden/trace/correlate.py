"""Correlate observed trace events with the static security graph.

Correlation is always labelled. Static possibility and runtime observation are
different kinds of evidence and are never presented as equivalent:

* ``static_potential_path`` — a possible path inferred from configuration.
* ``observed_event`` — an execution event that occurred.
* ``correlated_by_identifiers`` — an observed event that matches a declared tool
  with a matching static finding.
* ``unconfirmed`` — an observed event that cannot be matched to the
  configuration.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from pathwarden.finding import Finding
from pathwarden.models.config import AgentConfig
from pathwarden.trace.events import EventType
from pathwarden.trace.parser import TraceData

__all__ = ["Correlation", "CorrelationKind", "correlate"]


class CorrelationKind(StrEnum):
    """The nature of a static/observed correlation."""

    STATIC_POTENTIAL_PATH = "static_potential_path"
    OBSERVED_EVENT = "observed_event"
    CORRELATED_BY_IDENTIFIERS = "correlated_by_identifiers"
    UNCONFIRMED = "unconfirmed"


class Correlation(BaseModel):
    """A labelled relationship between an observed event and static analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_call_event_id: str
    kind: CorrelationKind
    detail: str
    static_finding_ids: tuple[str, ...] = ()
    related_static_path: tuple[str, ...] = ()


def _finding_mentions(finding: Finding, tool_id: str) -> bool:
    if finding.path is not None and tool_id in finding.path.nodes:
        return True
    return any(f"tool {tool_id!r}" in item for item in finding.evidence)


def correlate(
    config: AgentConfig, static_findings: list[Finding], trace: TraceData
) -> list[Correlation]:
    """Return labelled correlations for each tool-call event."""

    correlations: list[Correlation] = []
    for event in trace.events:
        if event.type is not EventType.TOOL_CALL:
            continue
        tool_id = event.tool_id
        if not tool_id:
            correlations.append(
                Correlation(
                    tool_call_event_id=event.event_id,
                    kind=CorrelationKind.UNCONFIRMED,
                    detail="tool call records no tool_id; cannot match a declared tool",
                )
            )
            continue
        tool = config.tool_by_id(tool_id)
        if tool is None:
            correlations.append(
                Correlation(
                    tool_call_event_id=event.event_id,
                    kind=CorrelationKind.UNCONFIRMED,
                    detail=f"tool {tool_id!r} is not declared in the configuration",
                )
            )
            continue

        matches = [finding for finding in static_findings if _finding_mentions(finding, tool_id)]
        if matches:
            nodes: set[str] = set()
            for finding in matches:
                if finding.path is not None:
                    nodes.update(finding.path.nodes)
            correlations.append(
                Correlation(
                    tool_call_event_id=event.event_id,
                    kind=CorrelationKind.CORRELATED_BY_IDENTIFIERS,
                    detail=(
                        f"observed tool {tool_id!r} matches {len(matches)} static finding(s); "
                        "correlation is by matching identifiers, not proof of influence"
                    ),
                    static_finding_ids=tuple(sorted(finding.finding_id for finding in matches)),
                    related_static_path=tuple(sorted(nodes)),
                )
            )
        else:
            correlations.append(
                Correlation(
                    tool_call_event_id=event.event_id,
                    kind=CorrelationKind.OBSERVED_EVENT,
                    detail=(
                        f"tool {tool_id!r} is declared but no static rule produced a finding "
                        "for it; the event is observed without a matching static path"
                    ),
                )
            )
    return correlations
