"""Pathwarden command-line interface.

Only ``--version`` and ``--help`` are implemented at Stage 1. The analysis
commands (``analyze``, ``trace``, ``graph``, ``report``, ``import-mcp``) are
added in Stage 6, together with their exit-code handling. They are intentionally
absent here rather than present as non-functional stubs.
"""

from __future__ import annotations

import typer

from pathwarden import __version__

__all__ = ["app", "main"]

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "Pathwarden — trace the paths, expose the risks.\n\n"
        "Static configuration and execution-log provenance analysis for AI agents. "
        "Analysis is deterministic, offline, and requires no LLM."
    ),
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"pathwarden {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the Pathwarden version and exit.",
    ),
) -> None:
    """Entry point callback. Subcommands are added in later stages."""


if __name__ == "__main__":  # pragma: no cover
    app()
