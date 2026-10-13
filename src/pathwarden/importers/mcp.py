"""MCP-style tool definition importer.

Supports a documented subset of MCP tool definitions and produces a partial
config. It never executes imported tools and never makes network requests.

Recognized shapes::

    {"tools": [ {"name": ..., "description": ..., "inputSchema": {...}}, ... ]}
    [ {"name": ..., ...}, ... ]
    {"name": ..., "description": ..., "inputSchema": {...}}

Everything the importer cannot know (operations, identity, scopes, resources,
tenants, sensitivity, approval, outbound) is marked unknown and listed under
``needs_review``. Unsupported fields are listed, not dropped. Deterministic
review indicators are produced as prompts for review, never as proof of malice.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from pathwarden.errors import InputError
from pathwarden.importers.base import ToolImporter
from pathwarden.importers.partial import (
    ImportedTool,
    NeedsReviewItem,
    PartialConfig,
    ReviewIndicator,
    ReviewIndicatorKind,
)

__all__ = ["McpToolsImporter"]

_SUPPORTED_TOOL_KEYS = frozenset({"name", "description", "inputSchema", "input_schema"})
_TOP_LEVEL_KEYS = frozenset({"tools"})

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

_INSTRUCTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore (all )?previous", re.IGNORECASE),
    re.compile(r"\bsystem\s*:", re.IGNORECASE),
    re.compile(r"\byou (must|should|will)\b", re.IGNORECASE),
    re.compile(r"\bdo not (tell|reveal|mention|disclose)", re.IGNORECASE),
    re.compile(r"\binstructions?\s*:", re.IGNORECASE),
    re.compile(r"\balways (call|use|invoke)\b", re.IGNORECASE),
    re.compile(r"\boverride\b", re.IGNORECASE),
    re.compile(r"<\s*(system|instruction|important)\b", re.IGNORECASE),
)

#: Property names that can select an arbitrary resource, path, or destination.
_ARBITRARY_NAMES = frozenset(
    {
        "resource",
        "resource_id",
        "resourceid",
        "path",
        "file",
        "filename",
        "url",
        "uri",
        "endpoint",
        "host",
        "destination",
        "recipient",
        "recipient_email",
        "to",
        "email",
        "target",
        "bucket",
        "database",
        "table",
        "tenant",
        "command",
    }
)

#: Property names suggesting free-form content.
_FREE_TEXT_NAMES = frozenset({"content", "body", "data", "query", "text", "prompt", "script"})

_GENERIC_DESCRIPTIONS = frozenset(
    {"does stuff", "does things", "a tool", "tool", "helper", "utility", "misc", "n/a"}
)

_ZW_FORMAT = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF})


class McpToolsImporter(ToolImporter):
    """Importer for a documented subset of MCP tool definitions."""

    name = "mcp-tools"

    def can_import(self, data: Any) -> bool:
        if isinstance(data, dict):
            if "tools" in data and isinstance(data["tools"], list):
                return True
            return "name" in data
        if isinstance(data, list):
            return all(isinstance(item, dict) and "name" in item for item in data) and bool(data)
        return False

    def import_data(self, data: Any, *, source: str) -> PartialConfig:
        tools_raw, top_extra = self._extract(data, source=source)
        tools: list[ImportedTool] = []
        needs_review: list[NeedsReviewItem] = []
        indicators: list[ReviewIndicator] = []
        unsupported: list[str] = [f"<top>:{key}" for key in top_extra]

        used_ids: set[str] = set()
        for index, definition in enumerate(tools_raw):
            name = definition.get("name")
            if not isinstance(name, str) or not name.strip():
                raise InputError(f"{source}: tool #{index + 1} is missing a non-empty 'name'")
            tool_id = _unique_slug(name, used_ids)
            schema = self._input_schema(definition, source=source, name=name)
            annotations = definition.get("annotations")
            extra_keys = sorted(set(definition) - _SUPPORTED_TOOL_KEYS)
            unsupported.extend(f"tool:{tool_id}:{key}" for key in extra_keys)

            tool = ImportedTool(
                id=tool_id,
                name=name,
                description=definition.get("description"),
                input_schema=schema,
                annotations=annotations if isinstance(annotations, dict) else None,
                declared_operations=None,
                unknown_fields=_UNKNOWN_FIELDS,
                unsupported_fields=tuple(extra_keys),
                raw=dict(definition),
            )
            tools.append(tool)

            for field in _UNKNOWN_FIELDS:
                needs_review.append(
                    NeedsReviewItem(
                        tool_id=tool_id,
                        field=field,
                        reason="not present in MCP tool definitions",
                    )
                )
            indicators.extend(self._review_indicators(tool))

        indicators.sort(key=lambda item: (item.kind.value, item.tool_id, item.evidence))
        tools.sort(key=lambda item: item.id)
        return PartialConfig(
            source=source,
            tools=tuple(tools),
            needs_review=tuple(needs_review),
            unsupported_fields=tuple(unsupported),
            indicators=tuple(indicators),
            limitations=(
                "The importer preserves declared names, descriptions, input schemas, and "
                "metadata only. It cannot determine operations, identities, scopes, resources, "
                "tenants, sensitivity, approval, or destinations.",
                "Review indicators are deterministic signals for human review, not proof of "
                "malicious behaviour.",
                "Imported content is never executed and no network requests are made.",
            ),
        )

    # -- helpers ----------------------------------------------------------- #

    def _extract(self, data: Any, *, source: str) -> tuple[list[dict[str, Any]], list[str]]:
        if isinstance(data, list):
            raw = data
            top_extra: list[str] = []
        elif isinstance(data, dict) and "tools" in data:
            raw = data["tools"]
            if not isinstance(raw, list):
                raise InputError(f"{source}: 'tools' must be a list")
            top_extra = sorted(set(data) - _TOP_LEVEL_KEYS)
        elif isinstance(data, dict) and "name" in data:
            raw = [data]
            top_extra = []
        else:
            raise InputError(
                f"{source}: unrecognized MCP tool definition shape (expected a tool object, a "
                "list of tool objects, or an object with a 'tools' list)"
            )
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise InputError(f"{source}: tool #{index + 1} must be a JSON object")
        return raw, top_extra

    def _input_schema(
        self, definition: dict[str, Any], *, source: str, name: str
    ) -> dict[str, Any]:
        schema = definition.get("inputSchema", definition.get("input_schema", {}))
        if schema is None:
            return {}
        if not isinstance(schema, dict):
            raise InputError(f"{source}: tool {name!r} inputSchema must be an object")
        return schema

    def _review_indicators(self, tool: ImportedTool) -> list[ReviewIndicator]:
        indicators: list[ReviewIndicator] = []
        description = tool.description

        if description is not None:
            for pattern in _INSTRUCTION_PATTERNS:
                match = pattern.search(description)
                if match:
                    indicators.append(
                        ReviewIndicator(
                            kind=ReviewIndicatorKind.INSTRUCTION_LIKE_TEXT,
                            tool_id=tool.id,
                            detail="description contains instruction-like text",
                            evidence=match.group(0),
                        )
                    )
                    break

            hidden = _hidden_characters(description)
            if hidden:
                indicators.append(
                    ReviewIndicator(
                        kind=ReviewIndicatorKind.HIDDEN_UNICODE,
                        tool_id=tool.id,
                        detail="description contains hidden or format characters",
                        evidence=" ".join(f"U+{code:04X}" for code in hidden),
                    )
                )

        if description is None or not description.strip():
            indicators.append(
                ReviewIndicator(
                    kind=ReviewIndicatorKind.MISSING_OR_VAGUE_DESCRIPTION,
                    tool_id=tool.id,
                    detail="tool has no description",
                    evidence="",
                )
            )
        elif len(description.strip()) < 15 or description.strip().lower() in _GENERIC_DESCRIPTIONS:
            indicators.append(
                ReviewIndicator(
                    kind=ReviewIndicatorKind.MISSING_OR_VAGUE_DESCRIPTION,
                    tool_id=tool.id,
                    detail="tool description is vague or very short",
                    evidence=description.strip(),
                )
            )

        indicators.extend(_schema_indicators(tool))
        return indicators


def _unique_slug(name: str, used: set[str]) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_") or "tool"
    candidate = base
    counter = 2
    while candidate in used:
        candidate = f"{base}_{counter}"
        counter += 1
    used.add(candidate)
    return candidate


def _hidden_characters(text: str) -> list[int]:
    found: list[int] = []
    for char in text:
        code = ord(char)
        if (code in _ZW_FORMAT or unicodedata.category(char) == "Cf") and code not in found:
            found.append(code)
    return found


def _schema_indicators(tool: ImportedTool) -> list[ReviewIndicator]:
    indicators: list[ReviewIndicator] = []
    schema = tool.input_schema
    if not schema:
        return indicators

    properties = schema.get("properties")
    if schema.get("type") == "object" and (not isinstance(properties, dict) or not properties):
        if schema.get("additionalProperties", True) is not False:
            indicators.append(
                ReviewIndicator(
                    kind=ReviewIndicatorKind.BROAD_PARAMETER_SCHEMA,
                    tool_id=tool.id,
                    detail="object schema declares no properties and allows additional properties",
                    evidence="additionalProperties",
                )
            )
        return indicators

    if not isinstance(properties, dict):
        return indicators

    for prop_name, prop_schema in sorted(properties.items()):
        if not isinstance(prop_schema, dict):
            continue
        prop_type = prop_schema.get("type")
        constrained = any(key in prop_schema for key in ("enum", "pattern", "format", "const"))
        if prop_type is None:
            indicators.append(
                ReviewIndicator(
                    kind=ReviewIndicatorKind.BROAD_PARAMETER_SCHEMA,
                    tool_id=tool.id,
                    detail=f"parameter {prop_name!r} has no declared type",
                    evidence=prop_name,
                )
            )
        if prop_schema.get("additionalProperties") is True:
            indicators.append(
                ReviewIndicator(
                    kind=ReviewIndicatorKind.BROAD_PARAMETER_SCHEMA,
                    tool_id=tool.id,
                    detail=f"parameter {prop_name!r} allows additional properties",
                    evidence=prop_name,
                )
            )
        if prop_type == "string" and not constrained:
            if prop_name.lower() in _ARBITRARY_NAMES:
                indicators.append(
                    ReviewIndicator(
                        kind=ReviewIndicatorKind.ARBITRARY_RESOURCE_OR_DESTINATION_PARAMETER,
                        tool_id=tool.id,
                        detail=(
                            f"parameter {prop_name!r} can select an arbitrary resource or "
                            "destination without constraints"
                        ),
                        evidence=prop_name,
                    )
                )
            elif prop_name.lower() in _FREE_TEXT_NAMES:
                indicators.append(
                    ReviewIndicator(
                        kind=ReviewIndicatorKind.BROAD_PARAMETER_SCHEMA,
                        tool_id=tool.id,
                        detail=f"parameter {prop_name!r} accepts free-form text",
                        evidence=prop_name,
                    )
                )
    return indicators
