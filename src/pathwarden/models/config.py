"""The top-level configuration document model."""

from __future__ import annotations

from pydantic import Field

from pathwarden.models.entities import Agent, Identity, InputSource, Policy, Resource, Tool, _Base

__all__ = ["AgentConfig"]


class AgentConfig(_Base):
    """A complete, validated agent configuration document.

    This is the normalized in-memory representation produced by the loader.
    Referential integrity (identifiers resolve, no duplicates) is validated by
    the loader, which has access to the whole document.
    """

    schema_version: str
    agent: Agent
    identities: tuple[Identity, ...] = ()
    input_sources: tuple[InputSource, ...] = ()
    tools: tuple[Tool, ...] = ()
    resources: tuple[Resource, ...] = ()
    policy: Policy = Field(default_factory=Policy)

    # Convenience lookups ---------------------------------------------------

    def identity_by_id(self, identity_id: str) -> Identity | None:
        """Return the identity with ``identity_id``, or ``None``."""

        return next((identity for identity in self.identities if identity.id == identity_id), None)

    def tool_by_id(self, tool_id: str) -> Tool | None:
        """Return the tool with ``tool_id``, or ``None``."""

        return next((tool for tool in self.tools if tool.id == tool_id), None)

    def resource_by_id(self, resource_id: str) -> Resource | None:
        """Return the resource with ``resource_id``, or ``None``."""

        return next((resource for resource in self.resources if resource.id == resource_id), None)

    def input_source_by_id(self, source_id: str) -> InputSource | None:
        """Return the input source with ``source_id``, or ``None``."""

        return next(
            (source for source in self.input_sources if source.id == source_id), None
        )
