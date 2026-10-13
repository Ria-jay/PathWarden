"""Severity matrix and modifier tests."""

from __future__ import annotations

import pytest

from pathwarden.finding import Severity
from pathwarden.models.enums import Operation, Sensitivity
from pathwarden.severity import MUTATE, READ, base_severity, compute_severity, operation_class


@pytest.mark.parametrize(
    ("sensitivity", "op_class", "expected"),
    [
        (Sensitivity.RESTRICTED, READ, Severity.HIGH),
        (Sensitivity.RESTRICTED, MUTATE, Severity.CRITICAL),
        (Sensitivity.CONFIDENTIAL, READ, Severity.MEDIUM),
        (Sensitivity.CONFIDENTIAL, MUTATE, Severity.HIGH),
        (Sensitivity.INTERNAL, READ, Severity.LOW),
        (Sensitivity.INTERNAL, MUTATE, Severity.MEDIUM),
        (Sensitivity.PUBLIC, READ, Severity.INFO),
        (Sensitivity.PUBLIC, MUTATE, Severity.LOW),
    ],
)
def test_base_matrix(sensitivity: Sensitivity, op_class: str, expected: Severity) -> None:
    assert base_severity(sensitivity, op_class) is expected


def test_operation_class() -> None:
    assert operation_class(Operation.READ) is READ
    for operation in (Operation.WRITE, Operation.DELETE, Operation.EXECUTE, Operation.SEND):
        assert operation_class(operation) is MUTATE


def test_untrusted_raises_one_level() -> None:
    severity = compute_severity(Sensitivity.INTERNAL, READ, untrusted=True)
    assert severity is Severity.MEDIUM


def test_untrusted_is_capped_at_critical() -> None:
    severity = compute_severity(Sensitivity.RESTRICTED, MUTATE, untrusted=True)
    assert severity is Severity.CRITICAL


def test_control_lowers_one_level_with_floor_low() -> None:
    assert (
        compute_severity(Sensitivity.CONFIDENTIAL, MUTATE, control_applies=True) is Severity.MEDIUM
    )
    # info would fall below low, so it floors at low
    assert compute_severity(Sensitivity.PUBLIC, READ, control_applies=True) is Severity.LOW


def test_unknown_caps_at_medium() -> None:
    assert compute_severity(Sensitivity.RESTRICTED, MUTATE, status_unknown=True) is Severity.MEDIUM
    assert compute_severity(Sensitivity.INTERNAL, READ, status_unknown=True) is Severity.LOW


def test_modifier_order_trust_then_control_then_unknown() -> None:
    # restricted/mutate critical -> untrusted stays critical -> control high -> unknown medium
    severity = compute_severity(
        Sensitivity.RESTRICTED,
        MUTATE,
        untrusted=True,
        control_applies=True,
        status_unknown=True,
    )
    assert severity is Severity.MEDIUM
