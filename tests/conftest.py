"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_dir() -> Path:
    """Directory containing configuration fixtures."""

    return FIXTURES_DIR


@pytest.fixture
def fixture(fixture_dir: Path) -> Callable[[str], Path]:
    """Return a callable that resolves a fixture name to a checked path."""

    def _resolve(name: str) -> Path:
        path = fixture_dir / name
        assert path.exists(), f"missing fixture: {path}"
        return path

    return _resolve
