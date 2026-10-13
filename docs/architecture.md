# Architecture

Pathwarden is a static configuration analyzer and execution-log provenance
analyzer. The core is deterministic, offline, and LLM-free.

## Package layout

```
src/pathwarden/
├── models/        Pydantic domain models and enums
├── config/        versioned schema + safe YAML/JSON loading and validation
├── graph/         typed graph, tri-state permission engine, exports
├── rules/         seven static rules + registry
├── trace/         JSONL parsing, provenance classification, correlation
├── importers/     adapter interface + MCP-tools importer
├── reporting/     structured JSON and Markdown report construction
├── cli/           Typer command-line interface
├── finding.py     finding model and stable finding ids
├── severity.py    severity matrix and modifiers
├── analyze.py     static-analysis facade
├── errors.py      user-facing exception hierarchy
└── redact.py      secret detection and redaction
```

## Data flow

```
config file ──load_config──▶ AgentConfig
                                 │
                                 ▼
                          build_graph ──▶ SecurityGraph ──▶ exports (JSON/Mermaid/DOT)
                                 │
                                 ▼
                           run_rules ──▶ findings ──┐
                                                    ├──▶ reporting ──▶ JSON / Markdown
trace.jsonl ──load_trace──▶ TraceData               │
                    │                               │
                    ▼                               │
            analyze_trace ──▶ trace findings ───────┘
                          └─▶ correlations (labelled)
```

## Design principles

* **Determinism.** Nodes, edges, findings, and report content are sorted on
  stable keys. The only variable field in a report is `generated_at`.
* **Honest unknowns.** Missing declarations resolve to `unknown` and are
  surfaced; they are never replaced by permissive defaults.
* **Separation of evidence.** Static findings (potential/reachable) and trace
  findings (observed/indeterminate) live in distinct models and report sections.
* **Safety.** Parsing uses `yaml.safe_load`/`json`; imported content is data,
  never instructions; the core performs no network requests and executes
  nothing.
* **Small modules.** Each rule, checker, and exporter has a single
  responsibility and its own tests.

## Error handling

Deliberate, user-facing conditions raise `PathwardenError` subclasses carrying
an exit code (`errors.py`). The CLI converts them to a redacted message on
stderr and the documented exit code; unexpected exceptions become exit code 3
(or re-raise with `--verbose`).
