"""MCP-style importer tests."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pathwarden.errors import InputError
from pathwarden.finding import FindingStatus
from pathwarden.importers import (
    ReviewIndicatorKind,
    import_data,
    import_tools,
    indeterminate_findings,
)

Fixture = Callable[[str], Path]


def _kinds(partial: Any, tool_id: str) -> set[str]:
    return {
        indicator.kind.value for indicator in partial.indicators if indicator.tool_id == tool_id
    }


def test_import_fixture_structure(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    assert partial.format == "mcp-tools"
    assert [tool.id for tool in partial.tools] == [
        "fetch",
        "helper",
        "read_employee",
        "send_email",
    ]
    assert partial.schema_version == "1.0"


def test_unknown_fields_are_listed_for_review(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    fields = {item.field for item in partial.needs_review}
    assert "operations" in fields
    assert "identity" in fields
    assert "tenants" in fields
    # One needs_review item per tool per unknown field.
    assert len(partial.needs_review) == len(partial.tools) * len(
        {item.field for item in partial.needs_review}
    )


def test_unsupported_fields_are_listed_not_dropped(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    assert "tool:read_employee:annotations" in partial.unsupported_fields
    tool = next(item for item in partial.tools if item.id == "read_employee")
    assert tool.unsupported_fields == ("annotations",)
    assert tool.annotations == {"readOnlyHint": True}


def test_instruction_like_text_indicator(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    assert ReviewIndicatorKind.INSTRUCTION_LIKE_TEXT.value in _kinds(partial, "helper")


def test_hidden_unicode_indicator(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    helper = next(item for item in partial.tools if item.id == "helper")
    assert "\u200b" in (helper.description or "")
    indicators = [indicator for indicator in partial.indicators if indicator.tool_id == "helper"]
    hidden = [item for item in indicators if item.kind is ReviewIndicatorKind.HIDDEN_UNICODE]
    assert hidden
    assert "U+200B" in hidden[0].evidence


def test_broad_schema_indicator(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    assert ReviewIndicatorKind.BROAD_PARAMETER_SCHEMA.value in _kinds(partial, "helper")


def test_arbitrary_destination_parameter_indicator(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    assert ReviewIndicatorKind.ARBITRARY_RESOURCE_OR_DESTINATION_PARAMETER.value in _kinds(
        partial, "fetch"
    )


def test_vague_description_indicator(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    assert ReviewIndicatorKind.MISSING_OR_VAGUE_DESCRIPTION.value in _kinds(partial, "fetch")
    assert ReviewIndicatorKind.MISSING_OR_VAGUE_DESCRIPTION.value in _kinds(partial, "send_email")


def test_clean_tool_has_no_indicators(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    assert _kinds(partial, "read_employee") == set()


def test_indeterminate_findings(fixture: Fixture) -> None:
    partial = import_tools(fixture("mcp_tools.json"))
    findings = indeterminate_findings(partial)
    assert len(findings) == 4
    assert all(finding.rule_id == "IMPORT-001" for finding in findings)
    assert all(finding.status is FindingStatus.INDETERMINATE for finding in findings)
    assert all(finding.missing_or_uncertain_constraints for finding in findings)


def test_import_single_tool_object() -> None:
    partial = import_data({"name": "solo", "description": "A single tool description here."})
    assert [tool.id for tool in partial.tools] == ["solo"]
    assert partial.tools[0].input_schema == {}


def test_import_list_of_tools() -> None:
    partial = import_data([{"name": "a"}, {"name": "b"}])
    assert [tool.id for tool in partial.tools] == ["a", "b"]


def test_duplicate_names_get_unique_ids() -> None:
    partial = import_data([{"name": "same"}, {"name": "same"}])
    assert [tool.id for tool in partial.tools] == ["same", "same_2"]


def test_missing_name_rejected() -> None:
    with pytest.raises(InputError) as excinfo:
        import_data({"tools": [{"description": "no name"}]})
    assert "name" in str(excinfo.value)


def test_bad_input_schema_rejected() -> None:
    with pytest.raises(InputError) as excinfo:
        import_data({"name": "x", "inputSchema": "not-an-object"})
    assert "inputSchema" in str(excinfo.value)


def test_unrecognized_shape_rejected() -> None:
    with pytest.raises(InputError) as excinfo:
        import_data({"unrelated": True})
    assert "recognized" in str(excinfo.value)


def test_import_is_deterministic(fixture: Fixture) -> None:
    first = import_tools(fixture("mcp_tools.json"))
    second = import_tools(fixture("mcp_tools.json"))
    assert first == second
