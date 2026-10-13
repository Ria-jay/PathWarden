"""Safe configuration loading and validation.

The loader is the single entry point for turning a YAML or JSON file into a
validated :class:`~pathwarden.models.config.AgentConfig`.

Safety properties:

* Input size, nesting depth, and node count are bounded so pathological or
  hostile documents fail with a clear error instead of exhausting resources.
* YAML is parsed with ``safe_load`` only; no arbitrary object construction.
* All user-facing messages are redacted before they are raised.
* Semantic checks (duplicate identifiers, unknown references, unsupported
  schema versions) never repair the document; they reject it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError as PydanticValidationError

from pathwarden.config.versions import (
    VERSION_FORMAT,
    is_supported_version,
    supported_versions,
)
from pathwarden.errors import ConfigError, ConfigValidationError, SchemaVersionError
from pathwarden.models.config import AgentConfig
from pathwarden.redact import looks_secret_like, redact

__all__ = [
    "MAX_CONFIG_BYTES",
    "MAX_NESTING_DEPTH",
    "MAX_NODES",
    "LoadResult",
    "load_config",
    "load_config_from_text",
]

#: Maximum accepted configuration file size in bytes.
MAX_CONFIG_BYTES = 5 * 1024 * 1024
#: Maximum accepted nesting depth of the parsed structure.
MAX_NESTING_DEPTH = 64
#: Maximum accepted number of values in the parsed structure.
MAX_NODES = 200_000
#: Maximum number of validation problems reported at once.
MAX_REPORTED_PROBLEMS = 50


@dataclass(frozen=True)
class LoadResult:
    """Outcome of loading a configuration.

    Attributes:
        config: The validated configuration.
        warnings: Non-fatal, advisory messages (for example, a ``credential_ref``
            that looks like a real secret). Warnings never change validation.
        source: Where the configuration came from, for messages and reports.
    """

    config: AgentConfig
    warnings: tuple[str, ...] = ()
    source: str = "<memory>"


def load_config(path: str | Path) -> LoadResult:
    """Load, parse, and validate a configuration file.

    Args:
        path: Path to a ``.yaml``, ``.yml``, or ``.json`` file.

    Raises:
        ConfigError: The file is missing, unreadable, oversized, wrongly
            encoded, or syntactically invalid.
        ConfigValidationError: The document parsed but failed schema or
            semantic validation.
        SchemaVersionError: The declared schema version is unsupported.
    """

    file_path = Path(path)
    if not file_path.exists():
        raise ConfigError(f"configuration file not found: {file_path}")
    if not file_path.is_file():
        raise ConfigError(f"configuration path is not a regular file: {file_path}")

    try:
        size = file_path.stat().st_size
    except OSError as exc:  # pragma: no cover - defensive
        raise ConfigError(f"could not stat configuration file: {file_path}") from exc

    if size > MAX_CONFIG_BYTES:
        raise ConfigError(
            f"configuration file {file_path} is {size} bytes, which exceeds the "
            f"{MAX_CONFIG_BYTES}-byte limit"
        )

    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"could not read configuration file {file_path}: {exc.strerror}") from exc

    text = _decode(raw, source=str(file_path))
    fmt = _format_for_suffix(file_path.suffix)
    data = _parse(text, fmt=fmt, source=str(file_path))
    return _build(data, source=str(file_path))


def load_config_from_text(
    text: str, *, source: str = "<string>", fmt: str | None = None
) -> LoadResult:
    """Load and validate a configuration from an in-memory string.

    Args:
        text: The YAML or JSON document.
        source: Label used in messages.
        fmt: ``"yaml"``, ``"json"``, or ``None`` to detect (defaults to YAML,
            which is a superset of JSON).
    """

    if len(text.encode("utf-8", errors="replace")) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{source}: input exceeds the {MAX_CONFIG_BYTES}-byte limit")
    data = _parse(text, fmt=fmt or "yaml", source=source)
    return _build(data, source=source)


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #


def _decode(raw: bytes, *, source: str) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(
            f"{source}: not valid UTF-8 (invalid byte at offset {exc.start})"
        ) from exc


def _format_for_suffix(suffix: str) -> str:
    lowered = suffix.lower()
    if lowered == ".json":
        return "json"
    if lowered in (".yaml", ".yml"):
        return "yaml"
    return "yaml"


def _parse(text: str, *, fmt: str, source: str) -> Any:
    if fmt == "json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(
                f"{source}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        location = ""
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            location = f" at line {mark.line + 1}, column {mark.column + 1}"
        problem = getattr(exc, "problem", None) or str(exc)
        raise ConfigError(f"{source}: invalid YAML{location}: {redact(str(problem))}") from exc
    except RecursionError as exc:
        raise ConfigError(f"{source}: YAML structure is too deeply nested to parse") from exc


def _guard_structure(data: Any, *, source: str) -> None:
    """Reject structures that are too deep or too large to analyze safely."""

    stack: list[tuple[Any, int]] = [(data, 1)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_NODES:
            raise ConfigError(f"{source}: document exceeds the {MAX_NODES}-value limit")
        if depth > MAX_NESTING_DEPTH:
            raise ConfigError(
                f"{source}: document nesting exceeds the {MAX_NESTING_DEPTH}-level limit"
            )
        if isinstance(node, Mapping):
            for value in node.values():
                stack.append((value, depth + 1))
        elif isinstance(node, (list, tuple)):
            for value in node:
                stack.append((value, depth + 1))


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #


def _build(data: Any, *, source: str) -> LoadResult:
    if data is None:
        raise ConfigError(f"{source}: document is empty")
    if not isinstance(data, Mapping):
        raise ConfigValidationError(
            f"{source}: top level must be a mapping, got {type(data).__name__}"
        )

    _guard_structure(data, source=source)
    _check_schema_version(data, source=source)

    try:
        config = AgentConfig.model_validate(data)
    except PydanticValidationError as exc:
        raise _format_pydantic_error(exc, source=source) from exc

    _check_semantics(config, source=source)
    warnings = _collect_warnings(config)
    return LoadResult(config=config, warnings=tuple(warnings), source=source)


def _check_schema_version(data: Mapping[str, Any], *, source: str) -> None:
    if "schema_version" not in data:
        raise ConfigValidationError(f"{source}: missing required field 'schema_version'")
    version = data["schema_version"]
    if not isinstance(version, str):
        raise ConfigValidationError(
            f"{source}: 'schema_version' must be a string, got {type(version).__name__}"
        )
    if not VERSION_FORMAT.match(version):
        raise ConfigValidationError(
            f"{source}: 'schema_version' {version!r} is not of the form 'major.minor'"
        )
    if not is_supported_version(version):
        supported = ", ".join(supported_versions())
        raise SchemaVersionError(
            f"{source}: unsupported schema_version {version!r}; supported versions: {supported}"
        )


def _format_pydantic_error(exc: PydanticValidationError, *, source: str) -> ConfigValidationError:
    problems: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        problems.append(f"{location}: {redact(str(error['msg']))}")
    return ConfigValidationError(_format_problems(problems, source=source))


def _format_problems(problems: list[str], *, source: str) -> str:
    shown = problems[:MAX_REPORTED_PROBLEMS]
    lines = [f"{source}: configuration validation failed:"]
    lines.extend(f"  - {problem}" for problem in shown)
    if len(problems) > MAX_REPORTED_PROBLEMS:
        lines.append(f"  - ... and {len(problems) - MAX_REPORTED_PROBLEMS} more")
    return "\n".join(lines)


def _check_semantics(config: AgentConfig, *, source: str) -> None:
    """Cross-entity checks that require the whole document."""

    problems: list[str] = []
    seen: dict[str, str] = {}

    def note(identifier: str, kind: str) -> None:
        prior = seen.get(identifier)
        if prior is not None:
            problems.append(f"duplicate identifier {identifier!r} used by both {prior} and {kind}")
        else:
            seen[identifier] = kind

    note(config.agent.id, "the agent")
    for identity in config.identities:
        note(identity.id, f"identity {identity.id!r}")
    for input_source in config.input_sources:
        note(input_source.id, f"input source {input_source.id!r}")
    for tool in config.tools:
        note(tool.id, f"tool {tool.id!r}")
    for resource in config.resources:
        note(resource.id, f"resource {resource.id!r}")

    identity_ids = {identity.id for identity in config.identities}
    tool_ids = {tool.id for tool in config.tools}

    if config.agent.execution_identity not in identity_ids:
        problems.append(
            f"agent {config.agent.id!r} execution_identity "
            f"{config.agent.execution_identity!r} does not match any declared identity"
        )

    for tool in config.tools:
        if tool.identity not in identity_ids:
            problems.append(
                f"tool {tool.id!r} references unknown identity {tool.identity!r}"
            )
        for target in tool.output_flows_to:
            if target not in tool_ids:
                problems.append(
                    f"tool {tool.id!r} output_flows_to unknown tool {target!r}"
                )

    if problems:
        raise ConfigValidationError(_format_problems(problems, source=source))


def _collect_warnings(config: AgentConfig) -> list[str]:
    warnings: list[str] = []
    for identity in config.identities:
        if identity.credential_ref and looks_secret_like(identity.credential_ref):
            warnings.append(
                f"identity {identity.id!r} credential_ref looks like a real secret; "
                "use a symbolic reference instead "
                f"(value: {redact(identity.credential_ref)})"
            )
    return warnings
