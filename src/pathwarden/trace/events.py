"""Trace event model.

Pathwarden reads structured JSON Lines execution logs. Events carry provenance
links (``parent_event_ids``) and, optionally, the events known to be in the
model's context when the event was produced (``context_event_ids``).

Privacy: events reference content by ``content_ref`` and ``content_hash``; raw
prompts, secrets, and tool results need not be logged.

Validation is deliberately permissive about additional metadata
(``extra="allow"``) so provider-specific fields are preserved rather than
rejected, but unknown extra fields are never interpreted as instructions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from pathwarden.models.enums import Operation, Trust

__all__ = ["Decision", "EventType", "TraceEvent", "ensure_aware_utc"]


class EventType(StrEnum):
    """Supported execution-log event types."""

    INPUT = "input"
    MODEL_OUTPUT = "model_output"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"


class Decision(StrEnum):
    """A recorded policy or approval decision."""

    ALLOWED = "allowed"
    DENIED = "denied"
    UNKNOWN = "unknown"


def ensure_aware_utc(value: datetime) -> datetime:
    """Return ``value`` as a timezone-aware UTC datetime.

    Naive timestamps are interpreted as UTC so out-of-order and mixed-zone logs
    remain comparable.
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class TraceEvent(BaseModel):
    """One validated execution-log event."""

    model_config = ConfigDict(extra="allow", frozen=True)

    event_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    type: EventType
    source: str | None = None
    trust_level: Trust | None = None
    content_ref: str | None = None
    content_hash: str | None = None
    parent_event_ids: tuple[str, ...] = ()
    context_event_ids: tuple[str, ...] = ()
    identity: str | None = None
    resource_id: str | None = None
    tool_id: str | None = None
    operation: Operation | None = None
    policy_decision: Decision | None = None
    approval_decision: Decision | None = None

    @field_validator("timestamp")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        return ensure_aware_utc(value)

    def extra(self) -> dict[str, Any]:
        """Return any additional provider-specific fields, unmodified."""

        return dict(self.model_extra or {})
