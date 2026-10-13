"""CLI tests: commands, exit codes, thresholds, output formats, redaction."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import yaml
from typer.testing import CliRunner

from pathwarden import __version__
from pathwarden.cli.app import app

Fixture = Callable[[str], Path]

runner = CliRunner()


def _invoke(*args: str):  # type: ignore[no-untyped-def]
    return runner.invoke(app, list(args), catch_exceptions=False)


def test_version() -> None:
    result = _invoke("--version")
    assert result.exit_code == 0
    assert result.stdout.strip() == f"pathwarden {__version__}"


def test_help() -> None:
    result = _invoke("--help")
    assert result.exit_code == 0
    assert "analyze" in result.stdout


def test_analyze_clean_config_exit_zero(fixture: Fixture) -> None:
    result = _invoke("analyze", str(fixture("valid_minimal.yaml")))
    assert result.exit_code == 0
    assert "No issue detected by the implemented rules." in result.stdout


def test_analyze_findings_exit_one(fixture: Fixture) -> None:
    result = _invoke("analyze", str(fixture("valid_hr.yaml")))
    assert result.exit_code == 1
    assert "PW-" in result.stdout


def test_fail_on_threshold(fixture: Fixture) -> None:
    # valid_hr has high findings but none critical.
    result = _invoke("analyze", str(fixture("valid_hr.yaml")), "--fail-on", "critical")
    assert result.exit_code == 0


def test_invalid_config_exit_two(fixture: Fixture) -> None:
    result = _invoke("analyze", str(fixture("invalid_schema_version.yaml")))
    assert result.exit_code == 2
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_missing_file_exit_two() -> None:
    result = _invoke("analyze", "/nonexistent/config.yaml")
    assert result.exit_code == 2
    assert "not found" in result.stderr


def test_invalid_format_exit_two(fixture: Fixture) -> None:
    result = _invoke("analyze", str(fixture("valid_minimal.yaml")), "--format", "xml")
    assert result.exit_code == 2


def test_invalid_fail_on_exit_two(fixture: Fixture) -> None:
    result = _invoke("analyze", str(fixture("valid_minimal.yaml")), "--fail-on", "urgent")
    assert result.exit_code == 2


def test_analyze_json_stdout_is_clean(fixture: Fixture) -> None:
    result = _invoke("analyze", str(fixture("valid_hr.yaml")), "--format", "json")
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["tool"]["name"] == "pathwarden"
    assert report["scope"]["agent"] == "hr-assistant"
    assert isinstance(report["static_findings"], list)
    assert report["summary"]["static"]["total"] == len(report["static_findings"])


def test_analyze_json_is_deterministic_except_timestamp(fixture: Fixture) -> None:
    first = json.loads(_invoke("analyze", str(fixture("valid_hr.yaml")), "--format", "json").stdout)
    second = json.loads(
        _invoke("analyze", str(fixture("valid_hr.yaml")), "--format", "json").stdout
    )
    first.pop("generated_at")
    second.pop("generated_at")
    assert first == second


def test_graph_formats(fixture: Fixture) -> None:
    mermaid = _invoke("graph", str(fixture("valid_hr.yaml")), "--format", "mermaid")
    assert mermaid.exit_code == 0
    assert "graph LR" in mermaid.stdout

    dot = _invoke("graph", str(fixture("valid_hr.yaml")), "--format", "dot")
    assert dot.exit_code == 0
    assert "digraph pathwarden" in dot.stdout

    as_json = _invoke("graph", str(fixture("valid_hr.yaml")), "--format", "json")
    assert as_json.exit_code == 0
    payload = json.loads(as_json.stdout)
    assert "nodes" in payload and "edges" in payload


def test_graph_invalid_format(fixture: Fixture) -> None:
    result = _invoke("graph", str(fixture("valid_minimal.yaml")), "--format", "svg")
    assert result.exit_code == 2


def test_report_markdown(fixture: Fixture) -> None:
    result = _invoke("report", str(fixture("valid_hr.yaml")), "--format", "md")
    assert result.exit_code == 1
    assert "# Pathwarden report" in result.stdout
    assert "## Static findings" in result.stdout
    assert "## Rule coverage" in result.stdout


def test_report_json_with_trace(fixture: Fixture) -> None:
    result = _invoke(
        "report",
        str(fixture("valid_hr.yaml")),
        "--format",
        "json",
        "--trace",
        str(fixture("trace_hr.jsonl")),
    )
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["trace"] is not None
    assert report["scope"]["trace"].endswith("trace_hr.jsonl")
    assert report["trace"]["findings"]


def test_trace_command_separates_evidence(fixture: Fixture) -> None:
    result = _invoke("trace", str(fixture("valid_hr.yaml")), str(fixture("trace_hr.jsonl")))
    assert result.exit_code == 1
    assert "Trace:" in result.stdout
    assert "Static / observed correlation:" in result.stdout


def test_import_mcp_json(fixture: Fixture) -> None:
    result = _invoke("import-mcp", str(fixture("mcp_tools.json")))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["format"] == "mcp-tools"
    assert len(payload["tools"]) == 4
    assert "needs_review" in result.stderr
    assert "review indicators" in result.stderr


def test_import_mcp_yaml(fixture: Fixture) -> None:
    result = _invoke("import-mcp", str(fixture("mcp_tools.json")), "--format", "yaml")
    assert result.exit_code == 0
    payload = yaml.safe_load(result.stdout)
    assert payload["format"] == "mcp-tools"


def test_import_mcp_missing_file_exit_two() -> None:
    result = _invoke("import-mcp", "/nonexistent/tools.json")
    assert result.exit_code == 2


def test_secret_is_redacted_in_diagnostics(fixture: Fixture) -> None:
    result = _invoke("analyze", str(fixture("secret_credential.yaml")))
    assert "[REDACTED]" in result.stderr
    assert "AKIAIOSFODNN7EXAMPLE" not in result.stderr
    assert "AKIAIOSFODNN7EXAMPLE" not in result.stdout
