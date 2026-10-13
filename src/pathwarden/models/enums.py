"""Enumerations for the Pathwarden configuration schema (version 1.0).

Enumerations make invalid declarations fail fast. Where the configuration may
legitimately be silent about a security-relevant decision, an explicit
``UNSPECIFIED``-style value or ``None`` is used instead of inventing a default;
see :mod:`pathwarden.models.entities` for how unknowns are represented.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "ApprovalRequirement",
    "AuthorizationCheckType",
    "IdentityType",
    "InputSourceType",
    "Operation",
    "PermissionStatus",
    "Sensitivity",
    "Trust",
]


class Operation(StrEnum):
    """An operation a tool can perform on a resource."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    SEND = "send"


class Sensitivity(StrEnum):
    """Sensitivity classification of a resource, from least to most severe."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Trust(StrEnum):
    """Declared trust level of an input source.

    A declared trust level is a configuration statement, not proof that the
    content is safe. ``UNTRUSTED`` and the ``may_contain_attacker_content`` flag
    both raise severity; ``USER`` is treated as untrusted-by-default in the
    severity model only via the attacker-content flag.
    """

    TRUSTED = "trusted"
    USER = "user"
    UNTRUSTED = "untrusted"


class InputSourceType(StrEnum):
    """The kind of content an input source delivers to the agent."""

    USER_MESSAGE = "user_message"
    UPLOADED_FILE = "uploaded_file"
    RETRIEVED_DOCUMENT = "retrieved_document"
    EXTERNAL_CONTENT = "external_content"
    TOOL_OUTPUT = "tool_output"


class ApprovalRequirement(StrEnum):
    """Declared approval requirement for a tool operation.

    ``UNSPECIFIED`` means the configuration did not say, and is treated as
    *unknown* by analysis. It is never interpreted as ``NONE``.
    """

    REQUIRED = "required"
    OPTIONAL = "optional"
    NONE = "none"
    UNSPECIFIED = "unspecified"


class AuthorizationCheckType(StrEnum):
    """The kind of authorization check a tool declares.

    ``NONE`` means the tool explicitly declares no requester-scoped
    authorization check. An absent ``authorization_check`` block is *unknown*
    (``None``), which is different from ``NONE``.
    """

    NONE = "none"
    REQUESTER_SCOPED = "requester_scoped"
    OTHER = "other"


class IdentityType(StrEnum):
    """The kind of principal an identity represents."""

    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    AGENT = "agent"
    WORKLOAD = "workload"
    SYSTEM = "system"
    OTHER = "other"


class PermissionStatus(StrEnum):
    """Result of a permission check.

    ``ALLOWED`` and ``DENIED`` are explicit. ``UNKNOWN`` means the available
    configuration cannot decide; it is never collapsed into the other two.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    UNKNOWN = "unknown"
