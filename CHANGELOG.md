# Changelog

All notable changes to Pathwarden are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Stage 1 — foundation and configuration schema:
  - Project packaging (`pyproject.toml`), MIT license, and development tooling.
  - Pydantic domain models for agents, input sources, tools, resources,
    identities, approval, authorization checks, and policy.
  - Versioned configuration schema with explicit handling of unknown values.
  - Safe YAML/JSON loading with size, nesting, and node-count limits.
  - Cross-entity validation: duplicate identifiers, unknown references,
    invalid operations, unsupported schema versions, tenant inconsistencies.
  - Secret redaction utilities for errors and reports.
  - Schema, loader, and redaction tests.

- Stage 2 — graph and permission-aware reachability:
  - Tri-state permission engine (`allowed` / `denied` / `unknown`) with explicit
    deny, glob matching, and recorded deciding steps.
  - Tenant, scope, resource-restriction, resource-operation, and destination
    checks; approval assessed separately as a declared control.
  - Typed `networkx` graph with the documented node and edge types, built from
    declared capabilities.
  - Deterministic JSON, Mermaid, and Graphviz DOT exports.
  - `docs/permission-model.md` and permission/graph tests.
