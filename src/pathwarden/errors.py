"""Exception hierarchy for Pathwarden.

Every error raised deliberately by Pathwarden for user-facing conditions
derives from :class:`PathwardenError`, which carries an ``exit_code`` used by the
CLI. User-facing messages are expected to be actionable and already redacted by
the raising code.
"""

from __future__ import annotations

__all__ = [
    "ConfigError",
    "ConfigValidationError",
    "InputError",
    "InternalError",
    "PathwardenError",
    "SchemaVersionError",
]


class PathwardenError(Exception):
    """Base class for deliberate, user-facing Pathwarden errors.

    Args:
        message: A human-readable, actionable message. Callers are responsible
            for redacting anything secret-like before raising.
    """

    #: Process exit code the CLI should use for this error class.
    exit_code: int = 3

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConfigError(PathwardenError):
    """A configuration could not be read or parsed."""

    exit_code = 2


class ConfigValidationError(ConfigError):
    """A configuration parsed but failed schema or semantic validation."""

    exit_code = 2


class SchemaVersionError(ConfigValidationError):
    """The declared configuration schema version is unsupported."""

    exit_code = 2


class InputError(PathwardenError):
    """A non-configuration input (trace, imported definition) was invalid."""

    exit_code = 2


class InternalError(PathwardenError):
    """An unexpected internal failure. Indicates a bug, not user error."""

    exit_code = 3
