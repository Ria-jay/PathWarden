"""Trace parsing and validation tests."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC
from pathlib import Path

import pytest

from pathwarden.errors import InputError
from pathwarden.trace import parser
from pathwarden.trace.parser import load_trace, parse_trace

Fixture = Callable[[str], Path]


def test_parse_valid_trace(fixture: Fixture) -> None:
    trace = load_trace(fixture("trace_hr.jsonl"))
    assert len(trace) == 6
    assert trace.warnings == ()
    assert trace.get("e1") is not None
    assert trace.get("e1").trust_level.value == "untrusted"  # type: ignore[union-attr]


def test_malformed_json_reports_line() -> None:
    text = '{"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "type": "input"}\n{bad}'
    with pytest.raises(InputError) as excinfo:
        parse_trace(text, source="t")
    assert "t:2" in str(excinfo.value)
    assert "invalid JSON" in str(excinfo.value)


def test_duplicate_event_id_rejected() -> None:
    line = '{"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "type": "input"}'
    with pytest.raises(InputError) as excinfo:
        parse_trace(f"{line}\n{line}")
    assert "duplicate event_id" in str(excinfo.value)


def test_missing_required_field_rejected() -> None:
    text = '{"timestamp": "2026-01-01T00:00:00Z", "type": "input"}'
    with pytest.raises(InputError) as excinfo:
        parse_trace(text)
    assert "event_id" in str(excinfo.value)


def test_invalid_event_type_rejected() -> None:
    text = '{"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "type": "explosion"}'
    with pytest.raises(InputError) as excinfo:
        parse_trace(text)
    assert "type" in str(excinfo.value)


def test_missing_parent_is_a_warning_not_a_failure() -> None:
    text = (
        '{"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "type": "tool_call", '
        '"parent_event_ids": ["ghost"]}'
    )
    trace = parse_trace(text)
    assert any("missing parent" in warning for warning in trace.warnings)
    assert any("not evidence" in warning for warning in trace.warnings)


def test_self_parent_is_a_warning() -> None:
    text = (
        '{"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "type": "tool_call", '
        '"parent_event_ids": ["a"]}'
    )
    trace = parse_trace(text)
    assert any("lists itself" in warning for warning in trace.warnings)


def test_parent_cycle_detected() -> None:
    text = "\n".join(
        [
            '{"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "type": "tool_call", '
            '"parent_event_ids": ["b"]}',
            '{"event_id": "b", "timestamp": "2026-01-01T00:00:01Z", "type": "tool_call", '
            '"parent_event_ids": ["a"]}',
        ]
    )
    trace = parse_trace(text)
    assert any("parent cycle detected" in warning for warning in trace.warnings)


def test_out_of_order_is_accepted_and_ordered() -> None:
    text = "\n".join(
        [
            '{"event_id": "late", "timestamp": "2026-01-01T10:00:10Z", "type": "tool_call"}',
            '{"event_id": "early", "timestamp": "2026-01-01T10:00:00Z", "type": "input"}',
        ]
    )
    trace = parse_trace(text)
    assert [event.event_id for event in trace.events] == ["late", "early"]
    assert [event.event_id for event in trace.ordered()] == ["early", "late"]


def test_naive_timestamp_is_normalized_to_utc() -> None:
    text = '{"event_id": "a", "timestamp": "2026-01-01T00:00:00", "type": "input"}'
    trace = parse_trace(text)
    assert trace.get("a").timestamp.tzinfo == UTC  # type: ignore[union-attr]


def test_extra_metadata_is_preserved() -> None:
    text = (
        '{"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "type": "input", '
        '"vendor_trace": {"span": 7}}'
    )
    trace = parse_trace(text)
    assert trace.get("a").extra()["vendor_trace"] == {"span": 7}  # type: ignore[union-attr]


def test_line_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parser, "MAX_LINE_BYTES", 10)
    text = '{"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "type": "input"}'
    with pytest.raises(InputError) as excinfo:
        parse_trace(text)
    assert "line exceeds" in str(excinfo.value)


def test_event_count_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parser, "MAX_EVENTS", 1)
    text = "\n".join(
        [
            '{"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "type": "input"}',
            '{"event_id": "b", "timestamp": "2026-01-01T00:00:01Z", "type": "input"}',
        ]
    )
    with pytest.raises(InputError) as excinfo:
        parse_trace(text)
    assert "event limit" in str(excinfo.value)


def test_missing_file_is_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError) as excinfo:
        load_trace(tmp_path / "nope.jsonl")
    assert "not found" in str(excinfo.value)
