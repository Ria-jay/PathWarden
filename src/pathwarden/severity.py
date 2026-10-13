"""Severity assignment.

Severity comes from the **most sensitive affected resource** and the
**operation class**, then applies modifiers in a fixed order. Confidence is
tracked separately and never folded into severity. The full matrix and rationale
live in ``docs/severity.md``.

Base matrix::

    sensitivity \\ class     read     mutate (write/delete/execute/send/outbound)
    restricted              high     critical
    confidential            medium   high
    internal                low      medium
    public                  info     low

Modifiers, applied in order:

1. Source trust is ``untrusted`` or the attacker-content flag is set: raise one
   level (cap at ``critical``).
2. A declared control applies (approval required, or restricted outbound
   destinations): lower one level (floor at ``low``).
3. The path status is ``unknown``: cap at ``medium`` and mark the finding
   ``indeterminate``.
"""

from __future__ import annotations

from pathwarden.finding import Severity
from pathwarden.models.enums import Operation, Sensitivity

__all__ = [
    "MUTATE",
    "READ",
    "OperationClass",
    "base_severity",
    "compute_severity",
    "operation_class",
]

#: Operation-class labels used by the severity matrix.
READ = "read"
MUTATE = "mutate"

OperationClass = str

_BASE_MATRIX: dict[tuple[Sensitivity, OperationClass], Severity] = {
    (Sensitivity.RESTRICTED, READ): Severity.HIGH,
    (Sensitivity.RESTRICTED, MUTATE): Severity.CRITICAL,
    (Sensitivity.CONFIDENTIAL, READ): Severity.MEDIUM,
    (Sensitivity.CONFIDENTIAL, MUTATE): Severity.HIGH,
    (Sensitivity.INTERNAL, READ): Severity.LOW,
    (Sensitivity.INTERNAL, MUTATE): Severity.MEDIUM,
    (Sensitivity.PUBLIC, READ): Severity.INFO,
    (Sensitivity.PUBLIC, MUTATE): Severity.LOW,
}

_LEVELS: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def operation_class(operation: Operation) -> OperationClass:
    """Return ``read`` for reads and ``mutate`` for every other operation."""

    return READ if operation is Operation.READ else MUTATE


def base_severity(sensitivity: Sensitivity, op_class: OperationClass) -> Severity:
    """Return the unmodified matrix severity."""

    return _BASE_MATRIX[(sensitivity, op_class)]


def _shift(severity: Severity, delta: int, *, floor: Severity, cap: Severity) -> Severity:
    index = _LEVELS.index(severity) + delta
    index = max(index, _LEVELS.index(floor))
    index = min(index, _LEVELS.index(cap))
    return _LEVELS[index]


def compute_severity(
    sensitivity: Sensitivity,
    op_class: OperationClass,
    *,
    untrusted: bool = False,
    control_applies: bool = False,
    status_unknown: bool = False,
) -> Severity:
    """Compute the final severity for a finding."""

    severity = base_severity(sensitivity, op_class)
    if untrusted:
        severity = _shift(severity, +1, floor=Severity.INFO, cap=Severity.CRITICAL)
    if control_applies:
        severity = _shift(severity, -1, floor=Severity.LOW, cap=Severity.CRITICAL)
    if status_unknown:
        severity = _shift(severity, 0, floor=Severity.INFO, cap=Severity.MEDIUM)
    return severity
