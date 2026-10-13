"""Reporting: structured JSON and human-readable Markdown."""

from __future__ import annotations

from pathwarden.reporting.json_report import (
    REPORT_VERSION,
    build_report,
    highest_severity,
    severity_counts,
    summarize,
)
from pathwarden.reporting.markdown import to_markdown

__all__ = [
    "REPORT_VERSION",
    "build_report",
    "highest_severity",
    "severity_counts",
    "summarize",
    "to_markdown",
]
