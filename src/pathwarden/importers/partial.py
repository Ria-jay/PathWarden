"""Partial-configuration models produced by importers.

MCP tool definitions carry no scopes, resources, tenants, or sensitivity.
The importer therefore produces a **partial config**: it preserves what the
definition declares (names, descriptions, input schemas, metadata) and marks
everything it cannot know as unknown, listing it under ``needs_review``.

A partial config is deliberately *not* a
:class:`~pathwarden.models.config.AgentConfig`: it cannot be analyzed as if the
missing security-relevant fields had values. Instead,
:func:`indeterminate_findings` reports indeterminate results.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from pathwarden.config.versions import CURRENT_SCHEMA_VERSION
from pathwarden.finding import Confidence, Finding, FindingStatus, Severity, make_finding_id

__all__ = [
    "ImportedTool",
    "NeedsReviewItem",
    "PartialConfig",
    "ReviewIndicator",
    "ReviewIndicatorKind",
    "indeterminate_findings",
]


class ReviewIndicatorKind(StrEnum):
    """Deterministic, non-conclusive review indicators."""

    INSTRUCTION_LIKE_TEXT = "instruction_like_text"
    HIDDEN_UNICODE = "hidden_unicode"
    BROAD_PARAMETER_SCHEMA = "broad_parameter_schema"
    ARBITRARY_RESOURCE_OR_DESTINATION_PARAMETER = "arbitrary_resource_or_destination_parameter"
    MISSING_OR_VAGUE_DESCRIPTION = "missing_or_vague_description"


class ReviewIndicator(BaseModel):
    """A review indicator. An indicator is a prompt to look, never proof."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ReviewIndicatorKind
    tool_id: str
    detail: str
    evidence: str


class NeedsReviewItem(BaseModel):
    """A field the importer could not know and that a human must supply."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    field: str
    reason: str


class ImportedTool(BaseModel):
    """A normalized tool definition, with unknown security fields made explicit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = None
    #: MCP definitions do not declare operations; this is always unknown.
    declared_operations: None = None
    unknown_fields: tuple[str, ...] = ()
    unsupported_fields: tuple[str, ...] = ()
    raw: dict[str, Any] = Field(default_factory=dict)


class PartialConfig(BaseModel):
    """The result of importing tool definitions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = CURRENT_SCHEMA_VERSION
    format: str = "mcp-tools"
    source: str = "<memory>"
    tools: tuple[ImportedTool, ...] = ()
    needs_review: tuple[NeedsReviewItem, ...] = ()
    unsupported_fields: tuple[str, ...] = ()
    indicators: tuple[ReviewIndicator, ...] = ()
    limitations: tuple[str, ...] = ()


#: Fields the importer cannot know from an MCP definition.
_UNKNOWN_FIELDS = (
    "operations",
    "identity",
    "required_scopes",
    "resource_restrictions",
    "resources",
    "tenants",
    "approval",
    "outbound",
    "allowed_destinations",
    "authorization_check",
)


def indeterminate_findings(partial: PartialConfig) -> list[Finding]:
    """Return one indeterminate finding per imported tool.

    A partial config cannot be analyzed as a normal configuration, so Pathwarden
    reports indeterminate results rather than guessing operations, identities,
    or resources.
    """

    findings: list[Finding] = []
    for tool in sorted(partial.tools, key=lambda item: item.id):
        findings.append(
            Finding(
                finding_id=make_finding_id("IMPORT-001", tool.id),
                rule_id="IMPORT-001",
                title="Imported tool requires review",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                status=FindingStatus.INDETERMINATE,
                summary=(
                    f"Tool {tool.id!r} was imported from {partial.format} and cannot be "
                    "statically analyzed: security-relevant fields are unknown."
                ),
                evidence=(
                    f"declared name: {tool.name!r}",
                    f"declared description: {tool.description!r}",
                    "unknown fields: " + ", ".join(tool.unknown_fields or _UNKNOWN_FIELDS),
                ),
                affected_resources=(),
                effective_identity=None,
                missing_or_uncertain_constraints=tuple(
                    f"{field} is unknown" for field in (tool.unknown_fields or _UNKNOWN_FIELDS)
                ),
                remediation=(
                    "Supply operations, identity, scopes, resource restrictions, tenants, and "
                    "approval, then re-run analysis."
                ),
                limitations=(
                    "MCP definitions do not carry scopes, resources, tenants, or sensitivity, so "
                    "no rule can be evaluated."
                ),
            )
        )
    return findings
