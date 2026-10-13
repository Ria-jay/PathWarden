"""JSONL trace parsing and validation.

Design notes:

* Out-of-order arrival is normal; events are kept in file order but can be
  viewed sorted by timestamp.
* Missing parent/context references are recorded as warnings, never as proof
  that no influence existed.
* Cycles in the parent graph are detected and reported; classification is
  cycle-safe.
* Size and per-line limits bound resource use on hostile input.
"""

from __future__ import annotations

import json
from pathlib import Path

import networkx as nx
from pydantic import ValidationError as PydanticValidationError

from pathwarden.errors import InputError
from pathwarden.trace.events import TraceEvent

__all__ = [
    "MAX_EVENTS",
    "MAX_LINE_BYTES",
    "MAX_TRACE_BYTES",
    "TraceData",
    "load_trace",
    "parse_trace",
]

#: Maximum accepted trace file size in bytes.
MAX_TRACE_BYTES = 32 * 1024 * 1024
#: Maximum accepted number of events (bounds peak memory: ~10 KB/event).
MAX_EVENTS = 100_000
#: Maximum accepted bytes per line.
MAX_LINE_BYTES = 1024 * 1024


class TraceData:
    """A parsed trace with lookup helpers and validation warnings."""

    def __init__(self, events: list[TraceEvent], warnings: list[str] | None = None) -> None:
        self.events: tuple[TraceEvent, ...] = tuple(events)
        self.warnings: tuple[str, ...] = tuple(warnings or ())
        self._by_id: dict[str, TraceEvent] = {event.event_id: event for event in self.events}

    def get(self, event_id: str) -> TraceEvent | None:
        """Return the event with ``event_id``, or ``None``."""

        return self._by_id.get(event_id)

    def __len__(self) -> int:
        return len(self.events)

    def ordered(self) -> list[TraceEvent]:
        """Return events sorted by timestamp then event id (deterministic)."""

        return sorted(self.events, key=lambda event: (event.timestamp, event.event_id))


def load_trace(path: str | Path) -> TraceData:
    """Load and validate a JSONL trace file."""

    file_path = Path(path)
    if not file_path.exists():
        raise InputError(f"trace file not found: {file_path}")
    if not file_path.is_file():
        raise InputError(f"trace path is not a regular file: {file_path}")
    try:
        size = file_path.stat().st_size
    except OSError as exc:  # pragma: no cover - defensive
        raise InputError(f"could not stat trace file: {file_path}") from exc
    if size > MAX_TRACE_BYTES:
        raise InputError(
            f"trace file {file_path} is {size} bytes, exceeding the {MAX_TRACE_BYTES}-byte limit"
        )
    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise InputError(f"could not read trace file {file_path}: {exc.strerror}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(
            f"{file_path}: not valid UTF-8 (invalid byte at offset {exc.start})"
        ) from exc
    return parse_trace(text, source=str(file_path))


def parse_trace(text: str, *, source: str = "<string>") -> TraceData:
    """Parse and validate JSONL trace ``text``."""

    if len(text.encode("utf-8", errors="replace")) > MAX_TRACE_BYTES:
        raise InputError(f"{source}: trace exceeds the {MAX_TRACE_BYTES}-byte limit")

    events: list[TraceEvent] = []
    seen: set[str] = set()

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        if len(raw.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
            raise InputError(f"{source}:{lineno}: line exceeds the {MAX_LINE_BYTES}-byte limit")
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"{source}:{lineno}: invalid JSON: {exc.msg}") from exc
        if not isinstance(obj, dict):
            raise InputError(f"{source}:{lineno}: each event must be a JSON object")
        try:
            event = TraceEvent.model_validate(obj)
        except PydanticValidationError as exc:
            raise InputError(_format_event_error(exc, source=source, lineno=lineno)) from exc
        if event.event_id in seen:
            raise InputError(f"{source}:{lineno}: duplicate event_id {event.event_id!r}")
        seen.add(event.event_id)
        events.append(event)
        if len(events) > MAX_EVENTS:
            raise InputError(f"{source}: trace exceeds the {MAX_EVENTS}-event limit")

    warnings = _validate_references(events, seen)
    return TraceData(events, warnings)


def _format_event_error(exc: PydanticValidationError, *, source: str, lineno: int) -> str:
    problems = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        problems.append(f"{location}: {error['msg']}")
    return f"{source}:{lineno}: invalid event: " + "; ".join(problems)


def _validate_references(events: list[TraceEvent], ids: set[str]) -> list[str]:
    warnings: list[str] = []
    for event in events:
        for ref in event.parent_event_ids:
            if ref == event.event_id:
                warnings.append(f"event {event.event_id!r} lists itself as a parent")
            elif ref not in ids:
                warnings.append(
                    f"event {event.event_id!r} references missing parent {ref!r}; "
                    "missing parents are not evidence that no influence existed"
                )
        for ref in event.context_event_ids:
            if ref not in ids:
                warnings.append(
                    f"event {event.event_id!r} references missing context event {ref!r}"
                )

    parent_graph: nx.DiGraph[str] = nx.DiGraph()
    for event in events:
        for ref in event.parent_event_ids:
            if ref in ids:
                parent_graph.add_edge(event.event_id, ref)
    for cycle in nx.simple_cycles(parent_graph):
        if len(cycle) >= 1:
            warnings.append("parent cycle detected: " + " -> ".join(cycle))
    return warnings
