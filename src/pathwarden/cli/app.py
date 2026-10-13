"""Pathwarden command-line interface.

Exit codes:

* ``0`` — the command ran and nothing met or exceeded the ``--fail-on`` threshold.
* ``1`` — findings met or exceeded ``--fail-on``.
* ``2`` — configuration or input error.
* ``3`` — internal error.

Diagnostics go to stderr; machine-readable output goes to stdout.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, NoReturn

import typer
import yaml

from pathwarden import __version__
from pathwarden.analyze import StaticAnalysis, analyze
from pathwarden.config.loader import load_config
from pathwarden.errors import PathwardenError
from pathwarden.finding import SEVERITY_ORDER, Finding, Severity
from pathwarden.graph.export import graph_to_dot, graph_to_json, graph_to_mermaid
from pathwarden.importers import import_tools
from pathwarden.redact import redact
from pathwarden.reporting import build_report, to_markdown
from pathwarden.trace import TraceAnalysis, analyze_trace, load_trace

__all__ = ["app", "main"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2
EXIT_INTERNAL = 3

SEVERITY_CHOICES = ("info", "low", "medium", "high", "critical")

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "Pathwarden — trace the paths, expose the risks.\n\n"
        "Static configuration and execution-log provenance analysis for AI agents. "
        "Analysis is deterministic, offline, and requires no LLM."
    ),
)


def _stderr(message: str) -> None:
    typer.echo(redact(message), err=True)


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )


def _handle(error: Exception, *, verbose: bool) -> NoReturn:
    if isinstance(error, PathwardenError):
        _stderr(f"error: {error.message}")
        raise typer.Exit(error.exit_code)
    if verbose:
        raise error
    _stderr(f"internal error: {error}")
    raise typer.Exit(EXIT_INTERNAL)


def _validate_fail_on(fail_on: str) -> str:
    if fail_on not in SEVERITY_CHOICES:
        raise typer.BadParameter(f"--fail-on must be one of {', '.join(SEVERITY_CHOICES)}")
    return fail_on


def _load(config: Path) -> Any:
    """Load a configuration and surface non-fatal warnings on stderr."""

    result = load_config(config)
    for warning in result.warnings:
        _stderr(f"warning: {warning}")
    return result.config


def _exit_for(findings: list[Any], fail_on: str) -> int:
    threshold = SEVERITY_ORDER[Severity(fail_on)]
    if any(SEVERITY_ORDER[finding.severity] >= threshold for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Text rendering
# --------------------------------------------------------------------------- #


def _finding_text(finding: Finding | Any) -> str:
    rule_id = getattr(finding, "rule_id", "TRACE-001")
    identity = getattr(finding, "effective_identity", None)
    resources = getattr(finding, "affected_resources", ())
    if not resources:
        resource_id = getattr(finding, "resource_id", None)
        if resource_id:
            resources = (resource_id,)
    missing = getattr(finding, "missing_or_uncertain_constraints", None)
    if missing is None:
        missing = getattr(finding, "missing_information", ())
    missing = tuple(missing) if missing else ()

    lines = [
        f"[{finding.severity.value.upper()}] {rule_id} {finding.title}",
        (
            f"  id={finding.finding_id} status={finding.status.value} "
            f"confidence={finding.confidence.value}"
        ),
        f"  {finding.summary}",
    ]
    if identity:
        lines.append(f"  identity: {identity}")
    if resources:
        lines.append("  resources: " + ", ".join(resources))
    path = getattr(finding, "path", None)
    for edge in path.edges if path else ():
        lines.append(f"  path: {edge.source} --{edge.edge_type}--> {edge.target}")
    for item in missing:
        lines.append(f"  missing: {item}")
    return "\n".join(lines)


def _render_static_text(static: StaticAnalysis, *, config_path: str) -> str:
    lines = [
        f"Pathwarden {__version__}",
        f"Config: {config_path}",
        f"Agent: {static.config.agent.id} (schema {static.config.schema_version})",
        f"Graph: {static.graph.node_count()} nodes, {static.graph.edge_count()} edges",
        f"Findings: {len(static.findings)}",
        "",
    ]
    if not static.findings:
        lines.append("No issue detected by the implemented rules.")
        lines.append("This does not mean the configuration is secure.")
    else:
        for finding in static.findings:
            lines.append(_finding_text(finding))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_trace_text(trace: TraceAnalysis, *, trace_path: str) -> str:
    lines = [f"Trace: {trace_path}", f"Trace findings: {len(trace.findings)}", ""]
    if not trace.findings:
        lines.append("No trace finding produced by the implemented checks.")
    else:
        for finding in trace.findings:
            lines.append(_finding_text(finding))
            lines.append("")
    if trace.correlations:
        lines.append("Static / observed correlation:")
        for correlation in trace.correlations:
            lines.append(
                f"  {correlation.tool_call_event_id}: {correlation.kind.value} "
                f"-> {list(correlation.static_finding_ids) or '-'}"
            )
        lines.append("")
    if trace.warnings:
        lines.append("Trace warnings:")
        lines += [f"  - {warning}" for warning in trace.warnings]
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


@app.command("analyze")
def analyze_command(
    config: Path = typer.Argument(..., help="Path to the configuration file (YAML or JSON)."),
    format: str = typer.Option("text", "--format", help="Output format: text or json."),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Minimum severity that causes exit code 1."
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug logging on stderr."),
) -> None:
    """Validate a configuration, build the graph, and run the static rules."""

    _setup_logging(verbose)
    _validate_fail_on(fail_on)
    if format not in ("text", "json"):
        raise typer.BadParameter("--format must be text or json")
    try:
        static = analyze(_load(config))
    except Exception as error:  # noqa: BLE001
        _handle(error, verbose=verbose)
        return

    if format == "json":
        report = build_report(static, config_path=str(config))
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(_render_static_text(static, config_path=str(config)))
    raise typer.Exit(_exit_for(list(static.findings), fail_on))


@app.command("trace")
def trace_command(
    config: Path = typer.Argument(..., help="Path to the configuration file."),
    trace: Path = typer.Argument(..., help="Path to the JSONL trace file."),
    format: str = typer.Option("text", "--format", help="Output format: text or json."),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Minimum severity that causes exit code 1."
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug logging on stderr."),
) -> None:
    """Analyze a trace against a configuration, separately from static findings."""

    _setup_logging(verbose)
    _validate_fail_on(fail_on)
    if format not in ("text", "json"):
        raise typer.BadParameter("--format must be text or json")
    try:
        static = analyze(_load(config))
        trace_analysis = analyze_trace(static.config, load_trace(trace), list(static.findings))
    except Exception as error:  # noqa: BLE001
        _handle(error, verbose=verbose)
        return

    if format == "json":
        report = build_report(
            static, config_path=str(config), trace=trace_analysis, trace_path=str(trace)
        )
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(_render_static_text(static, config_path=str(config)))
        typer.echo(_render_trace_text(trace_analysis, trace_path=str(trace)))
    combined = list(static.findings) + list(trace_analysis.findings)
    raise typer.Exit(_exit_for(combined, fail_on))


@app.command("graph")
def graph_command(
    config: Path = typer.Argument(..., help="Path to the configuration file."),
    format: str = typer.Option("mermaid", "--format", help="Output format: mermaid, dot, or json."),
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug logging on stderr."),
) -> None:
    """Export the normalized security graph."""

    _setup_logging(verbose)
    if format not in ("mermaid", "dot", "json"):
        raise typer.BadParameter("--format must be mermaid, dot, or json")
    try:
        static = analyze(_load(config))
    except Exception as error:  # noqa: BLE001
        _handle(error, verbose=verbose)
        return

    if format == "mermaid":
        typer.echo(graph_to_mermaid(static.graph), nl=False)
    elif format == "dot":
        typer.echo(graph_to_dot(static.graph), nl=False)
    else:
        typer.echo(graph_to_json(static.graph), nl=False)
    raise typer.Exit(EXIT_OK)


@app.command("report")
def report_command(
    config: Path = typer.Argument(..., help="Path to the configuration file."),
    format: str = typer.Option("md", "--format", help="Output format: md or json."),
    trace: Path | None = typer.Option(None, "--trace", help="Optional JSONL trace to include."),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Minimum severity that causes exit code 1."
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug logging on stderr."),
) -> None:
    """Generate a Markdown or JSON report."""

    _setup_logging(verbose)
    _validate_fail_on(fail_on)
    if format not in ("md", "json"):
        raise typer.BadParameter("--format must be md or json")
    try:
        static = analyze(_load(config))
        trace_analysis: TraceAnalysis | None = None
        if trace is not None:
            trace_analysis = analyze_trace(static.config, load_trace(trace), list(static.findings))
    except Exception as error:  # noqa: BLE001
        _handle(error, verbose=verbose)
        return

    report = build_report(
        static,
        config_path=str(config),
        trace=trace_analysis,
        trace_path=str(trace) if trace is not None else None,
    )
    if format == "json":
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(to_markdown(report), nl=False)

    combined = list(static.findings) + list(trace_analysis.findings if trace_analysis else [])
    raise typer.Exit(_exit_for(combined, fail_on))


@app.command("import-mcp")
def import_mcp_command(
    file: Path = typer.Argument(..., help="Path to an MCP tool-definition file (JSON or YAML)."),
    format: str = typer.Option("json", "--format", help="Output format: json or yaml."),
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug logging on stderr."),
) -> None:
    """Import MCP-style tool definitions as a partial config, with review notes."""

    _setup_logging(verbose)
    if format not in ("json", "yaml"):
        raise typer.BadParameter("--format must be json or yaml")
    try:
        partial = import_tools(file)
    except Exception as error:  # noqa: BLE001
        _handle(error, verbose=verbose)
        return

    _stderr(f"imported {len(partial.tools)} tool(s) from {partial.source}")
    _stderr(f"needs_review items: {len(partial.needs_review)}")
    if partial.unsupported_fields:
        _stderr("unsupported fields: " + ", ".join(partial.unsupported_fields))
    if partial.indicators:
        _stderr("review indicators (not proof of malicious behaviour):")
        for indicator in partial.indicators:
            _stderr(f"  [{indicator.kind.value}] {indicator.tool_id}: {indicator.detail}")
    _stderr("analysis of a partial config is indeterminate; see IMPORT-001 findings.")

    payload = partial.model_dump(mode="json")
    if format == "json":
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(yaml.safe_dump(payload, sort_keys=True), nl=False)
    raise typer.Exit(EXIT_OK)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"pathwarden {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the Pathwarden version and exit.",
    ),
) -> None:
    """Entry point callback."""


if __name__ == "__main__":  # pragma: no cover
    app()
