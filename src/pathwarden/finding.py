"""Finding model shared by all static rules.

A finding is always *evidence-backed* and honest about uncertainty: it carries
the actual graph path, the resources involved, the effective identity, the
permission steps considered, and the constraints that remain missing. Static
findings describe **reachable** or **potential** paths; they never claim that an
operation will happen.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "SEVERITY_ORDER",
    "Confidence",
    "Finding",
    "FindingPath",
    "FindingStatus",
    "PathEdge",
    "Severity",
    "make_finding_id",
]


class Severity(StrEnum):
    """Finding severity. See ``docs/severity.md`` for the assignment matrix."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    """How well the evidence supports the finding, independent of severity."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(StrEnum):
    """Whether the finding is reachable, indeterminate, or informational."""

    REACHABLE = "reachable"
    INDETERMINATE = "indeterminate"
    INFORMATIONAL = "informational"


#: Ordering used for deterministic sorting (most severe first).
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class PathEdge(BaseModel):
    """One typed edge of a finding path, with the attributes that explain it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    target: str
    edge_type: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class FindingPath(BaseModel):
    """The actual graph nodes and edges that constitute a finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    nodes: tuple[str, ...]
    edges: tuple[PathEdge, ...]


class Finding(BaseModel):
    """An evidence-backed statement produced by a static rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    summary: str
    evidence: tuple[str, ...] = ()
    path: FindingPath | None = None
    affected_resources: tuple[str, ...] = ()
    effective_identity: str | None = None
    relevant_permissions: tuple[str, ...] = ()
    missing_or_uncertain_constraints: tuple[str, ...] = ()
    remediation: str = ""
    limitations: str = ""


def make_finding_id(rule_id: str, *parts: str) -> str:
    """Return a stable finding id derived from the rule and its key content.

    The id is deterministic for identical input and independent of finding
    ordering, so it is stable across runs and report formats.
    """

    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:10]
    return f"{rule_id}-{digest}"
