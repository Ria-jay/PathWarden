"""Convenience facade for static analysis."""

from __future__ import annotations

from dataclasses import dataclass

from pathwarden.finding import Finding
from pathwarden.graph.build import build_graph
from pathwarden.graph.model import SecurityGraph
from pathwarden.models.config import AgentConfig
from pathwarden.rules import RuleContext, rule_metadata, run_rules

__all__ = ["StaticAnalysis", "analyze"]


@dataclass(frozen=True)
class StaticAnalysis:
    """The result of building a graph and running every static rule."""

    config: AgentConfig
    graph: SecurityGraph
    findings: tuple[Finding, ...]
    rule_coverage: tuple[dict[str, object], ...]


def analyze(config: AgentConfig) -> StaticAnalysis:
    """Build the graph and run all static rules deterministically."""

    graph = build_graph(config)
    findings = run_rules(RuleContext(config=config, graph=graph))
    return StaticAnalysis(
        config=config,
        graph=graph,
        findings=tuple(findings),
        rule_coverage=tuple(rule_metadata()),
    )
