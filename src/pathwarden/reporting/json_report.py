"""Structured report construction (shared by JSON and Markdown renderers).

The report is deterministic: identical input produces identical output apart
from ``generated_at``. Static findings and trace (observed) evidence are kept in
separate sections so they are never presented as equivalent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pathwarden import __version__
from pathwarden.analyze import StaticAnalysis
from pathwarden.finding import SEVERITY_ORDER, Finding, Severity
from pathwarden.trace import TraceAnalysis

__all__ = ["REPORT_VERSION", "build_report", "severity_counts", "summarize"]

REPORT_VERSION = "1.0"

_SEVERITY_NAMES = ("critical", "high", "medium", "low", "info")


def summarize(findings: list[Finding] | list[Any]) -> dict[str, Any]:
    """Return counts by severity and status for a list of findings."""

    by_severity = {name: 0 for name in _SEVERITY_NAMES}
    by_status: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.value] += 1
        key = finding.status.value
        by_status[key] = by_status.get(key, 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_status": by_status}


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Return counts by severity name for static findings."""

    counts = {name: 0 for name in _SEVERITY_NAMES}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def build_report(
    static: StaticAnalysis,
    *,
    config_path: str,
    trace: TraceAnalysis | None = None,
    trace_path: str | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build the report dictionary."""

    timestamp = (generated_at or datetime.now(UTC)).astimezone(UTC).isoformat()

    findings_by_rule: dict[str, int] = {}
    for finding in static.findings:
        findings_by_rule[finding.rule_id] = findings_by_rule.get(finding.rule_id, 0) + 1

    coverage = []
    for entry in static.rule_coverage:
        rule_id = str(entry["id"])
        coverage.append(
            {
                **entry,
                "findings": findings_by_rule.get(rule_id, 0),
                "check": "ran",
            }
        )

    report: dict[str, Any] = {
        "tool": {"name": "pathwarden", "version": __version__},
        "report_version": REPORT_VERSION,
        "schema_version": static.config.schema_version,
        "generated_at": timestamp,
        "scope": {
            "config": config_path,
            "agent": static.config.agent.id,
            "trace": trace_path,
        },
        "graph_summary": {
            "nodes": static.graph.node_count(),
            "edges": static.graph.edge_count(),
        },
        "summary": {"static": summarize(list(static.findings)), "trace": None},
        "rule_coverage": coverage,
        "static_findings": [finding.model_dump(mode="json") for finding in static.findings],
        "trace": None,
        "limitations": [
            "No findings means no issue was detected by the implemented rules; it does not "
            "mean the configuration is secure.",
            "Static findings describe potential or reachable paths, not confirmed exploitability.",
            "A declared control is reported as declared; runtime enforcement is unknown.",
        ],
    }

    if trace is not None:
        report["trace"] = {
            "path": trace_path,
            "warnings": list(trace.warnings),
            "summary": summarize(list(trace.findings)),
            "findings": [finding.model_dump(mode="json") for finding in trace.findings],
            "correlations": [
                correlation.model_dump(mode="json") for correlation in trace.correlations
            ],
        }
        report["summary"]["trace"] = summarize(list(trace.findings))

    return report


def highest_severity(findings: list[Any]) -> Severity | None:
    """Return the highest severity among findings, or ``None``."""

    highest: Severity | None = None
    for finding in findings:
        severity = finding.severity
        if highest is None or SEVERITY_ORDER[severity] > SEVERITY_ORDER[highest]:
            highest = severity
    return highest
