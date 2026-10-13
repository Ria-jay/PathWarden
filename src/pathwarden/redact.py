"""Secret detection and redaction helpers.

Pathwarden never requires real secret values. Configurations should reference
credentials symbolically (for example ``vault://kv/hr/email-token``). To keep
secrets out of errors and reports, all user-facing text passes through
:func:`redact`, and :func:`looks_secret_like` identifies values that resemble
real secrets so they can be flagged for review.

The detectors are intentionally conservative: they target well-known token
formats and secret-looking key/value assignments. They do not attempt to redact
arbitrary high-entropy strings, because legitimate values such as content
hashes (``sha256:...``) must remain readable in reports.
"""

from __future__ import annotations

import re

__all__ = ["REDACTED", "looks_secret_like", "redact"]

REDACTED = "[REDACTED]"

# Well-known credential formats. Applied anywhere in a string.
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    # AWS access key id
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # JSON Web Token (three base64url segments beginning with a JOSE header)
    re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
    # PEM private key blocks
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # Authorization: Bearer <token>
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"),
)

# key: value / key=value pairs whose key name implies a secret.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)"
    r"(\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret|credential|authorization)\b"
    r"\s*[:=]\s*)"
    r"(\"[^\"\n]{1,512}\"|'[^'\n]{1,512}'|[^\s\"',;]{4,})"
)

# Symbolic credential references are explicitly not secrets.
_SYMBOLIC_PREFIXES = ("vault://", "config://", "secret-ref:", "ref:", "env://")


def redact(text: str) -> str:
    """Return ``text`` with secret-like substrings replaced by ``[REDACTED]``.

    The function is idempotent and safe to call on already-redacted text.
    Non-secret content, including content hashes, is preserved.
    """

    if not text:
        return text
    result = text
    for pattern in _TOKEN_PATTERNS:
        result = pattern.sub(REDACTED, result)
    result = _SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + REDACTED, result)
    return result


def looks_secret_like(value: object) -> bool:
    """Return ``True`` if ``value`` resembles a real secret.

    This is a heuristic used to flag configurations whose ``credential_ref``
    appears to embed a real secret instead of a symbolic reference. It is
    deliberately conservative and may produce false positives; callers treat a
    positive result as a warning for human review, not as proof.
    """

    if not isinstance(value, str) or not value:
        return False
    if value.startswith(_SYMBOLIC_PREFIXES):
        return False
    for pattern in _TOKEN_PATTERNS:
        if pattern.search(value):
            return True
    # Long, whitespace-free strings mixing upper, lower, and digits resemble
    # generated secrets (tokens, keys) rather than identifiers or paths.
    return (
        len(value) >= 24
        and " " not in value
        and re.search(r"[a-z]", value) is not None
        and re.search(r"[A-Z]", value) is not None
        and re.search(r"[0-9]", value) is not None
    )
