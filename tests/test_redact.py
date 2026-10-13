"""Redaction and secret-detection tests."""

from __future__ import annotations

import pytest

from pathwarden.redact import REDACTED, looks_secret_like, redact


@pytest.mark.parametrize(
    "text",
    [
        "key AKIAIOSFODNN7EXAMPLE is exposed",
        "Authorization: Bearer abcdef1234567890ABCDEF",
        "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij",
        "password: hunter2secret",
        "api_key = sk_live_0123456789abcdef",
    ],
)
def test_secret_like_content_is_redacted(text: str) -> None:
    result = redact(text)
    assert REDACTED in result
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "abcdef1234567890ABCDEF" not in result


def test_private_key_block_is_redacted() -> None:
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
    result = redact(block)
    assert result == REDACTED
    assert "MIIEow" not in result


def test_content_hashes_are_preserved() -> None:
    digest = "sha256:" + "a" * 64
    assert redact(digest) == digest


def test_redaction_is_idempotent() -> None:
    once = redact("token=supersecretvalue123")
    assert redact(once) == once


def test_redact_empty_string() -> None:
    assert redact("") == ""


def test_looks_secret_like_detects_tokens() -> None:
    assert looks_secret_like("AKIAIOSFODNN7EXAMPLE")
    assert looks_secret_like("AbCdEf0123456789AbCdEf01")


def test_looks_secret_like_ignores_symbolic_references() -> None:
    assert not looks_secret_like("vault://kv/hr/agent-token")
    assert not looks_secret_like("env://HR_AGENT_TOKEN")
    assert not looks_secret_like("hr-agent-identity")


def test_looks_secret_like_rejects_non_strings() -> None:
    assert not looks_secret_like(None)
    assert not looks_secret_like(12345)
