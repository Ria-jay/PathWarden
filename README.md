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
| 3 | Static rules PW-001…PW-007 | complete |
| 4 | Trace / provenance analysis | complete |
| 5 | MCP-style importer | complete |
| 6 | CLI and reporting | complete |
| 7 | HR example and regression tests | complete |
| 8 | Quality, security, and documentation | not started |

Only features that are actually implemented and tested are documented here.
Through Stage 7, Pathwarden provides configuration loading/validation, the typed
permission-aware graph with JSON/Mermaid/DOT export, the seven static rules
(PW-001…PW-007), execution-log provenance analysis, the MCP-tools importer, the
CLI commands `analyze`, `trace`, `graph`, `report`, and `import-mcp` with
Markdown and JSON reports, and a reproducible HR before/after example. See
`docs/`.

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

## Quick start

```bash
# Validate, build the graph, and run the static rules.
./.venv/bin/pathwarden analyze tests/fixtures/valid_hr.yaml

# Emit a structured JSON report.
./.venv/bin/pathwarden analyze tests/fixtures/valid_hr.yaml --format json

# Analyze an execution trace (observed evidence, kept separate from static).
./.venv/bin/pathwarden trace tests/fixtures/valid_hr.yaml tests/fixtures/trace_hr.jsonl

# Export the graph.
./.venv/bin/pathwarden graph tests/fixtures/valid_hr.yaml --format mermaid

# Markdown report with trace evidence.
./.venv/bin/pathwarden report tests/fixtures/valid_hr.yaml --format md \
    --trace tests/fixtures/trace_hr.jsonl

# Import MCP-style tool definitions as a partial config.
./.venv/bin/pathwarden import-mcp tests/fixtures/mcp_tools.json

# CI: fail when a finding is high or above.
./.venv/bin/pathwarden analyze tests/fixtures/valid_hr.yaml --fail-on high
```

See `docs/exit-codes.md` for the exit codes and a CI snippet.

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

## Example: HR assistant

`examples/` contains a reproducible before/after scenario:

* `examples/vulnerable_agent.yaml` — CV uploads (untrusted), a confidential
  employee database spanning two tenants, an email tool with no destination
  restriction, a `flows_to` chain, and no declared approval.
* `examples/trace.jsonl` — a matching execution trace with a direct link, a
  contextual link, and a deliberately link-less call.
* `examples/fixed_agent.yaml` — the same agent with per-tool scoped identities,
  tenant isolation, declared approval, a destination allowlist, and
  requester-scoped authorization checks.

```bash
./.venv/bin/pathwarden analyze examples/vulnerable_agent.yaml
./.venv/bin/pathwarden analyze examples/fixed_agent.yaml
./.venv/bin/pathwarden trace examples/vulnerable_agent.yaml examples/trace.jsonl
```

Running the same rule set against both, the remediated configuration removes
PW-002, PW-003, PW-005, PW-006, and PW-007, turns PW-004 into a declared
(informational) control, and lowers PW-001 from high to medium. PW-001 remains
because untrusted input can still reach a confidential read — the fixed example
adds a declared (not verified) control rather than pretending the risk is gone.
`tests/test_hr_regression.py` verifies these differences are caused by real
permission and graph changes.

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
