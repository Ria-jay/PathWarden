"""Static analysis rules PW-001 … PW-007."""

from __future__ import annotations

from pathwarden.finding import Finding
from pathwarden.rules.base import Rule, RuleContext, sort_findings
from pathwarden.rules.pw001 import PW001
from pathwarden.rules.pw002 import PW002
from pathwarden.rules.pw003 import PW003
from pathwarden.rules.pw004 import PW004
from pathwarden.rules.pw005 import PW005
from pathwarden.rules.pw006 import PW006
from pathwarden.rules.pw007 import PW007

__all__ = ["ALL_RULES", "Rule", "RuleContext", "rule_metadata", "run_rules", "sort_findings"]

#: Every implemented rule, in stable order.
ALL_RULES: tuple[Rule, ...] = (PW001(), PW002(), PW003(), PW004(), PW005(), PW006(), PW007())


def run_rules(context: RuleContext) -> list[Finding]:
    """Run every rule and return findings in deterministic order."""

    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule.evaluate(context))
    return sort_findings(findings)


def rule_metadata() -> list[dict[str, object]]:
    """Return metadata for every rule, for reports and coverage sections."""

    return [rule.metadata() for rule in ALL_RULES]
