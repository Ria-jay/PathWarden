"""Supported configuration schema versions.

The configuration schema is versioned so that the analyzer never silently
misinterprets a document written for a different schema. Unsupported versions
are rejected; they are not guessed at or partially parsed.
"""

from __future__ import annotations

import re

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "VERSION_FORMAT",
    "is_supported_version",
    "supported_versions",
]

#: The schema version emitted by current examples and documentation.
CURRENT_SCHEMA_VERSION = "1.0"

#: Every schema version this build of Pathwarden can parse.
SUPPORTED_SCHEMA_VERSIONS: frozenset[str] = frozenset({"1.0"})

#: ``major.minor`` only.
VERSION_FORMAT = re.compile(r"^\d+\.\d+$")


def is_supported_version(version: str) -> bool:
    """Return ``True`` if ``version`` is a schema version this build supports."""

    return version in SUPPORTED_SCHEMA_VERSIONS


def supported_versions() -> tuple[str, ...]:
    """Return supported versions in a deterministic (sorted) order."""

    return tuple(sorted(SUPPORTED_SCHEMA_VERSIONS))
