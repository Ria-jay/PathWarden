"""Common rule interface and deterministic ordering."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from pathwarden.finding import SEVERITY_ORDER, Finding
from pathwarden.graph.model import SecurityGraph
from pathwarden.models.config import AgentConfig

__all__ = ["Rule", "RuleContext", "sort_findings"]


@dataclass(frozen=True)
class RuleContext:
    """Inputs available to every static rule."""

    config: AgentConfig
    graph: SecurityGraph


class Rule(ABC):
    """A deterministic, evidence-backed static rule.

    Subclasses set the class attributes and implement :meth:`evaluate`. Rules
    must be pure with respect to the context: identical input produces identical
    findings.
    """

    #: Stable rule identifier, for example ``PW-001``.
    id: ClassVar[str] = ""
    #: Human-readable title.
    title: ClassVar[str] = ""
    #: Security rationale.
    rationale: ClassVar[str] = ""
    #: What the configuration must contain for the rule to apply.
    prerequisites: ClassVar[tuple[str, ...]] = ()
    #: What the rule cannot conclude.
    limitations: ClassVar[str] = ""

    @abstractmethod
    def evaluate(self, context: RuleContext) -> list[Finding]:
        """Return zero or more findings for ``context``."""

    def metadata(self) -> dict[str, object]:
        """Return rule metadata for reports and coverage sections."""

        return {
            "id": self.id,
            "title": self.title,
            "rationale": self.rationale,
            "prerequisites": list(self.prerequisites),
            "limitations": self.limitations,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings sorted by severity, then rule, then finding id."""

    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER[finding.severity],
            finding.rule_id,
            finding.finding_id,
        ),
    )
