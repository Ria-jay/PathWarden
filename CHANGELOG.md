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

- Stage 3 — static rules PW-001…PW-007:
  - Finding model with evidence, paths, effective identity, permission steps,
    missing constraints, remediation, and limitations.
  - Documented severity matrix and ordered modifiers; confidence tracked
    separately.
  - Seven deterministic rules: untrusted input to sensitive operation, confused
    deputy, over-broad scope, missing approval, exfiltration path, cross-tenant
    exposure, and privilege chain.
  - `docs/severity.md` and `docs/rules.md`.

- Stage 4 — execution-log provenance analysis:
  - JSONL event model and safe parser with validation, reference warnings,
    cycle detection, out-of-order tolerance, and input limits.
  - `direct` / `contextual` / `unknown` provenance classification with all
    candidates listed; temporal association never treated as influence.
  - Trace findings (observed / indeterminate) separate from static findings.
  - Labelled correlation with static findings.
  - `docs/trace-format.md` and `docs/provenance.md`.

- Stage 5 — MCP-style importer:
  - Adapter interface and a documented MCP-tools importer.
  - Partial-config output with `needs_review`, preserved unsupported fields, and
    indeterminate `IMPORT-001` findings.
  - Deterministic review indicators (instruction-like text, hidden Unicode,
    broad schemas, arbitrary destination parameters, vague descriptions).
  - `docs/importer.md`.

- Stage 6 — CLI and reporting:
  - Typer commands `analyze`, `trace`, `graph`, `report`, `import-mcp` with
    `--fail-on`, `--format`, and `--verbose`.
  - Stable Markdown and JSON reports (deterministic apart from the timestamp).
  - Documented exit codes (0/1/2/3), clean JSON on stdout, diagnostics on stderr,
    and secret redaction in all diagnostics.
  - `docs/exit-codes.md` and `docs/report-format.md`.
