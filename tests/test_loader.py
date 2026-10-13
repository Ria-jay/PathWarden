"""Loader tests: parsing, validation, limits, and redaction."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from pathwarden.config import loader
from pathwarden.config.loader import load_config, load_config_from_text
from pathwarden.errors import ConfigError, ConfigValidationError, SchemaVersionError
from pathwarden.models.enums import ApprovalRequirement, Operation, Sensitivity

Fixture = Callable[[str], Path]


def test_load_valid_minimal(fixture: Fixture) -> None:
    result = load_config(fixture("valid_minimal.yaml"))
    assert result.config.schema_version == "1.0"
    assert result.config.agent.id == "assistant"
    assert result.config.agent.execution_identity == "assistant-identity"
    assert result.warnings == ()
    assert result.config.identity_by_id("assistant-identity") is not None


def test_load_valid_hr(fixture: Fixture) -> None:
    result = load_config(fixture("valid_hr.yaml"))
    config = result.config
    assert config.agent.id == "hr-assistant"
    assert config.identity_by_id("hr-agent-identity") is not None

    identity = config.identity_by_id("hr-agent-identity")
    assert identity is not None
    assert identity.tenants == ("acme", "globex")

    email = config.tool_by_id("email-sender")
    assert email is not None
    assert email.outbound is True
    assert email.approval[Operation.SEND] is ApprovalRequirement.NONE

    database = config.resource_by_id("employee-db")
    assert database is not None
    assert database.sensitivity is Sensitivity.CONFIDENTIAL


def test_load_valid_json(fixture: Fixture) -> None:
    result = load_config(fixture("valid.json"))
    assert result.config.agent.id == "assistant"


def test_load_config_from_text_inline() -> None:
    text = """
schema_version: "1.0"
agent:
  id: a
  name: A
  execution_identity: i
identities:
  - id: i
    type: service_account
"""
    result = load_config_from_text(text)
    assert result.config.agent.id == "a"


def test_duplicate_identifiers_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_duplicate_id.yaml"))
    assert "duplicate identifier" in str(excinfo.value)
    assert "shared-id" in str(excinfo.value)


def test_unknown_identity_reference_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_unknown_identity.yaml"))
    assert "unknown identity" in str(excinfo.value)


def test_unknown_flow_target_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_unknown_flow_target.yaml"))
    assert "output_flows_to unknown tool" in str(excinfo.value)


def test_unsupported_schema_version_rejected(fixture: Fixture) -> None:
    with pytest.raises(SchemaVersionError) as excinfo:
        load_config(fixture("invalid_schema_version.yaml"))
    message = str(excinfo.value)
    assert "unsupported schema_version '2.0'" in message
    assert "1.0" in message


def test_missing_schema_version_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_missing_schema_version.yaml"))
    assert "missing required field 'schema_version'" in str(excinfo.value)


def test_missing_required_field_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_missing_operations.yaml"))
    assert "tools.0.operations" in str(excinfo.value)


def test_invalid_operation_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_operation.yaml"))
    assert "operations" in str(excinfo.value)


def test_invalid_sensitivity_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_sensitivity.yaml"))
    assert "sensitivity" in str(excinfo.value)


def test_tenant_mix_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_tenant_mix.yaml"))
    assert "tenants" in str(excinfo.value)


def test_approval_for_undeclared_operation_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_approval_unknown_op.yaml"))
    assert "approval declares operations" in str(excinfo.value)


def test_top_level_not_mapping_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_not_mapping.yaml"))
    assert "top level must be a mapping" in str(excinfo.value)


def test_yaml_syntax_error_is_a_config_error(fixture: Fixture) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(fixture("invalid_yaml_syntax.yaml"))
    assert "invalid YAML" in str(excinfo.value)


def test_unknown_field_rejected(fixture: Fixture) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        load_config(fixture("invalid_unknown_field.yaml"))
    assert "unexpected_field" in str(excinfo.value)


def test_secret_credential_warns_and_is_redacted(fixture: Fixture) -> None:
    result = load_config(fixture("secret_credential.yaml"))
    assert len(result.warnings) == 1
    warning = result.warnings[0]
    assert "credential_ref" in warning
    assert "[REDACTED]" in warning
    assert "AKIAIOSFODNN7EXAMPLE" not in warning


def test_missing_file_is_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path / "does-not-exist.yaml")
    assert "not found" in str(excinfo.value)


def test_directory_is_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path)
    assert "not a regular file" in str(excinfo.value)


def test_invalid_utf8_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_bytes(b'schema_version: "1.0"\xff\xfe')
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "UTF-8" in str(excinfo.value)


def test_oversized_file_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "MAX_CONFIG_BYTES", 16)
    path = tmp_path / "big.yaml"
    path.write_text('schema_version: "1.0"\n' * 10, encoding="utf-8")
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "exceeds" in str(excinfo.value)


def test_deep_nesting_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    nested: dict[str, object] = {}
    cursor = nested
    for _ in range(loader.MAX_NESTING_DEPTH + 5):
        child: dict[str, object] = {}
        cursor["n"] = child
        cursor = child
    text = yaml.safe_dump({"schema_version": "1.0", "deep": nested})
    with pytest.raises(ConfigError) as excinfo:
        load_config_from_text(text)
    assert "nesting" in str(excinfo.value)


def test_node_limit_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "MAX_NODES", 3)
    text = """
schema_version: "1.0"
agent:
  id: a
  name: A
  execution_identity: i
"""
    with pytest.raises(ConfigError) as excinfo:
        load_config_from_text(text)
    assert "limit" in str(excinfo.value)


def test_repeated_loads_are_deterministic(fixture: Fixture) -> None:
    first = load_config(fixture("valid_hr.yaml"))
    second = load_config(fixture("valid_hr.yaml"))
    assert first.config == second.config
    assert first.config.model_dump(mode="json") == second.config.model_dump(mode="json")
