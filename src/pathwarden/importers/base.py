"""Importer adapter interface.

Adapters normalize an external tool-definition format into a
:class:`~pathwarden.importers.partial.PartialConfig`. The interface is small so
additional formats can be added later without touching the analyzer; no
speculative adapters are implemented.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pathwarden.importers.partial import PartialConfig

__all__ = ["ToolImporter"]


class ToolImporter(ABC):
    """Base class for tool-definition importers."""

    #: Short format name, for example ``mcp-tools``.
    name: ClassVar[str] = ""

    @abstractmethod
    def can_import(self, data: Any) -> bool:
        """Return ``True`` if this adapter recognizes ``data``."""

    @abstractmethod
    def import_data(self, data: Any, *, source: str) -> PartialConfig:
        """Normalize ``data`` into a partial configuration.

        Implementations must never execute imported content or make network
        requests.
        """
