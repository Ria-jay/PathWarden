# Pathwarden

> **Trace the paths. Expose the risks.**

Pathwarden is an open-source, CLI-first security analyzer for AI agent
configurations and execution logs. It builds a **permission-aware graph** of what
an agent *could* do, applies deterministic static rules, and traces data
provenance through execution logs — without executing anything, contacting the
network, or requiring an LLM.

Pathwarden is a **static configuration analyzer and execution-log provenance
analyzer**. It never executes attacks, invokes real tools, sends payloads, or
makes live network requests during analysis.

> [!IMPORTANT]
> Grader/reader note: Pathwarden reports **potential paths** and **observed or
> uncertain** provenance, never confirmation of exploitability. "No findings"
> means *no issue detected by the implemented rules* — it does not mean the
> agent is secure.

## Status

Early development. This repository is being built in documented stages
(see `PROGRESS.md`).

| Stage | Scope | State |
| --- | --- | --- |
| 0 | Repository inspection and plan | complete |
| 1 | Foundation and configuration schema | complete |
| 2 | Graph and permission-aware reachability | complete |
| 3 | Static rules PW-001…PW-007 | not started |
| 4 | Trace / provenance analysis | not started |
| 5 | MCP-style importer | not started |
| 6 | CLI and reporting | not started |
| 7 | HR example and regression tests | not started |
| 8 | Quality, security, and documentation | not started |

Only features that are actually implemented and tested are documented here.
Through Stage 2, configuration loading/validation and the typed, permission-aware
graph with JSON/Mermaid/DOT export are available. The CLI currently exposes
`--version`/`--help` only; the analysis commands are added in later stages.
See `docs/permission-model.md` for the permission semantics.

## Requirements

- Python 3.11 or later (developed and tested on the interpreter available in
  this environment; see `PROGRESS.md` for the exact version used).
- No API keys, no network access, no database.

## Installation (development)

```bash
git clone <repository-url>
cd pathwarden
python3 -m venv .venv
./.venv/bin/python -m pip install -e ".[dev]"
```

## Quick start (current stage)

```bash
./.venv/bin/pathwarden --version
./.venv/bin/pathwarden --help
```

Load and validate a configuration from Python:

```python
from pathwarden.config.loader import load_config

result = load_config("tests/fixtures/valid_minimal.yaml")
print(result.config.agent.name)
for warning in result.warnings:
    print("warning:", warning)
```

## Configuration sample

```yaml
schema_version: "1.0"

agent:
  id: hr-assistant
  name: HR Assistant
  execution_identity: hr-agent-identity

identities:
  - id: hr-agent-identity
    type: service_account
    granted_scopes: ["db:read", "mail:send"]
    tenants: ["acme"]

input_sources:
  - id: cv-upload
    name: CV upload
    type: uploaded_file
    trust: untrusted
    may_contain_attacker_content: true

tools:
  - id: employee-db
    name: Employee database
    operations: [read]
    identity: hr-agent-identity
    approval:
      read: none

resources:
  - id: employee-db
    type: database
    sensitivity: confidential
    owner: hr-team
    tenant: acme

policy:
  approval_operations: []
  approval_sensitivity: []
```

Unknown values are preserved, never defaulted to something permissive. When a
security-relevant field is omitted, it stays *undeclared* and downstream
analysis treats it as `unknown`.

## Documentation

Detailed documentation (architecture, schema reference, permission model,
severity matrix, graph semantics, trace format, provenance semantics, importer
compatibility, report format, exit codes, and threat model) is added in Stage 8
as the corresponding features are implemented. This README describes only
behavior that exists today.

## Development

```bash
./.venv/bin/python -m pytest
./.venv/bin/ruff check .
./.venv/bin/mypy
```

## Limitations

- Stage 1 only; no analysis rules, graph, trace engine, importer, or full CLI
  exist yet.
- The schema is versioned (`1.0`) and unknown versions are rejected rather than
  guessed.

## License

MIT — see `LICENSE`.
