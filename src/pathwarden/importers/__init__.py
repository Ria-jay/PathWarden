"""Tool-definition importers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from pathwarden.errors import InputError
from pathwarden.importers.base import ToolImporter
from pathwarden.importers.mcp import McpToolsImporter
from pathwarden.importers.partial import (
    ImportedTool,
    NeedsReviewItem,
    PartialConfig,
    ReviewIndicator,
    ReviewIndicatorKind,
    indeterminate_findings,
)

__all__ = [
    "IMPORTERS",
    "ImportedTool",
    "McpToolsImporter",
    "NeedsReviewItem",
    "PartialConfig",
    "ReviewIndicator",
    "ReviewIndicatorKind",
    "ToolImporter",
    "import_data",
    "import_tools",
    "indeterminate_findings",
]

#: Maximum accepted input file size in bytes.
MAX_IMPORT_BYTES = 5 * 1024 * 1024

#: Registered importers, tried in order.
IMPORTERS: tuple[ToolImporter, ...] = (McpToolsImporter(),)


def import_data(data: Any, *, source: str = "<memory>") -> PartialConfig:
    """Import already-parsed tool-definition data."""

    for importer in IMPORTERS:
        if importer.can_import(data):
            return importer.import_data(data, source=source)
    raise InputError(f"{source}: no registered importer recognized this input shape")


def import_tools(path: str | Path) -> PartialConfig:
    """Read, parse, and import a tool-definition file (JSON or YAML)."""

    file_path = Path(path)
    if not file_path.exists():
        raise InputError(f"import file not found: {file_path}")
    if not file_path.is_file():
        raise InputError(f"import path is not a regular file: {file_path}")
    try:
        size = file_path.stat().st_size
    except OSError as exc:  # pragma: no cover - defensive
        raise InputError(f"could not stat import file: {file_path}") from exc
    if size > MAX_IMPORT_BYTES:
        raise InputError(
            f"import file {file_path} is {size} bytes, exceeding the {MAX_IMPORT_BYTES}-byte limit"
        )
    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise InputError(f"could not read import file {file_path}: {exc.strerror}") from exc
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(
            f"{file_path}: not valid UTF-8 (invalid byte at offset {exc.start})"
        ) from exc

    if file_path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputError(
                f"{file_path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc
    else:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise InputError(f"{file_path}: invalid YAML: {exc}") from exc

    return import_data(data, source=str(file_path))
