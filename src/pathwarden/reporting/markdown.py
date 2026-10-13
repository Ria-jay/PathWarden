"""Markdown rendering of a Pathwarden report."""

from __future__ import annotations

from typing import Any

__all__ = ["to_markdown"]


def _finding_section(finding: dict[str, Any], heading_level: int = 3) -> list[str]:
    prefix = "#" * heading_level
    lines = [
        f"{prefix} {finding['severity'].upper()} — {finding['rule_id']} {finding['title']}",
        "",
        f"- **Finding id:** `{finding['finding_id']}`",
        f"- **Status:** {finding['status']}",
        f"- **Confidence:** {finding['confidence']}",
        f"- **Severity:** {finding['severity']}",
    ]
    if finding.get("effective_identity"):
        lines.append(f"- **Effective identity:** `{finding['effective_identity']}`")
    if finding.get("affected_resources"):
        lines.append(
            "- **Affected resources:** "
            + ", ".join(f"`{r}`" for r in finding["affected_resources"])
        )
    lines += ["", finding["summary"], ""]

    if finding.get("evidence"):
        lines.append("**Evidence**")
        lines += [f"- {item}" for item in finding["evidence"]]
        lines.append("")

    path = finding.get("path")
    if path:
        lines.append("**Path**")
        for edge in path["edges"]:
            lines.append(f"- `{edge['source']}` --{edge['edge_type']}--> `{edge['target']}`")
        lines.append("")

    if finding.get("relevant_permissions"):
        lines.append("**Relevant permissions**")
        lines += [f"- {item}" for item in finding["relevant_permissions"]]
        lines.append("")

    if finding.get("missing_or_uncertain_constraints"):
        lines.append("**Missing or uncertain constraints**")
        lines += [f"- {item}" for item in finding["missing_or_uncertain_constraints"]]
        lines.append("")

    if finding.get("remediation"):
        lines += ["**Remediation**", "", finding["remediation"], ""]
    if finding.get("limitations"):
        lines += ["**Limitations**", "", finding["limitations"], ""]
    return lines


def to_markdown(report: dict[str, Any]) -> str:
    """Render a report dictionary as Markdown."""

    tool = report["tool"]
    scope = report["scope"]
    lines: list[str] = [
        "# Pathwarden report",
        "",
        "> Trace the paths. Expose the risks.",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Tool version | {tool['version']} |",
        f"| Report version | {report['report_version']} |",
        f"| Config schema version | {report['schema_version']} |",
        f"| Generated at | {report['generated_at']} |",
        f"| Config | `{scope['config']}` |",
        f"| Agent | `{scope['agent']}` |",
        f"| Trace | `{scope['trace']}` |" if scope.get("trace") else "| Trace | — |",
        (
            f"| Graph | {report['graph_summary']['nodes']} nodes, "
            f"{report['graph_summary']['edges']} edges |"
        ),
        "",
        "## Summary",
        "",
    ]

    static = report["summary"]["static"]
    lines += [
        f"Static findings: **{static['total']}**",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for name, count in static["by_severity"].items():
        lines.append(f"| {name} | {count} |")
    lines.append("")

    if static["total"] == 0:
        lines += ["_No issue detected by the implemented rules._", ""]

    lines.append("## Static findings")
    lines.append("")
    if not report["static_findings"]:
        lines += ["_No issue detected by the implemented rules._", ""]
    for finding in report["static_findings"]:
        lines += _finding_section(finding)

    trace = report.get("trace")
    if trace is not None:
        lines += ["## Trace findings (observed evidence)", ""]
        if not trace["findings"]:
            lines += ["_No trace finding produced by the implemented checks._", ""]
        for finding in trace["findings"]:
            lines += _finding_section(finding)
        if trace.get("correlations"):
            lines += ["### Static / observed correlation", ""]
            for correlation in trace["correlations"]:
                lines.append(
                    f"- `{correlation['tool_call_event_id']}`: {correlation['kind']} — "
                    f"{correlation['detail']}"
                )
            lines.append("")
        if trace.get("warnings"):
            lines += ["### Trace warnings", ""]
            lines += [f"- {warning}" for warning in trace["warnings"]]
            lines.append("")

    lines += [
        "## Rule coverage",
        "",
        "| Rule | Title | Check | Findings |",
        "| --- | --- | --- | --- |",
    ]
    for entry in report["rule_coverage"]:
        lines.append(
            f"| {entry['id']} | {entry['title']} | {entry['check']} | {entry['findings']} |"
        )
    lines.append("")

    lines += ["## Limitations", ""]
    lines += [f"- {item}" for item in report["limitations"]]
    lines.append("")
    return "\n".join(lines)
