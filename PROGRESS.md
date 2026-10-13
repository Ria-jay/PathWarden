# Pathwarden — Progress

Living record of completed stages, files changed, commands run, results,
decisions, and limitations. Updated at the end of every stage.

## Environment

- Repository: `/home/kali/pathwarden`
- Python: 3.14.6 (system interpreter; project declares `requires-python = ">=3.11"`)
- Virtualenv: `./.venv`
- Key dependency versions installed for development:
  pydantic 2.14.1, networkx 3.7.0, PyYAML 6.0.3, typer 0.27.3,
  pytest 9.1.1, ruff 0.17.0, mypy 2.4.0

## Stage status

| Stage | Scope | Status |
| --- | --- | --- |
| 0 | Repository inspection and plan | complete (approved) |
| 1 | Foundation and configuration schema | complete |
| 2 | Graph and permission-aware reachability | not started |
| 3 | Static rules PW-001…PW-007 | not started |
| 4 | Trace / provenance analysis | not started |
| 5 | MCP-style importer | not started |
| 6 | CLI and reporting | not started |
| 7 | HR example and regression tests | not started |
| 8 | Quality, security, and documentation | not started |

## Stage 1 — Foundation and configuration schema

### Implemented

- Installable package (`hatchling`), `pathwarden` console entry point, MIT
  license, Ruff and mypy configuration, pytest configuration.
- Pydantic domain models for agent, identities, input sources, tools,
  resources, policy, and authorization checks, with `extra="forbid"`.
- Explicit **unknown** semantics: security-relevant fields are optional and
  default to `None` (undeclared), never to a permissive value. Approval uses the
  explicit `unspecified` enum member.
- Tenant declarations: `"*"` (all tenants) as the string form, or a non-empty
  list; mixing `"*"` into a list, empty lists, duplicates, and resource tenant
  `"*"` are rejected.
- Versioned schema (`1.0`) with rejection of missing, malformed, and
  unsupported `schema_version` values.
- Safe loader: UTF-8 only, size limit (5 MiB), nesting-depth limit (64),
  node-count limit (200 000), `yaml.safe_load` only, JSON by suffix.
- Cross-entity validation: duplicate identifiers, unknown `execution_identity`
  / tool `identity` / `output_flows_to` references.
- Secret redaction utility applied to loader error messages and warnings;
  `credential_ref` values that resemble real secrets raise a non-fatal warning
  with the value redacted.

### Files created

- `pyproject.toml`, `LICENSE`, `.gitignore`, `README.md`, `CHANGELOG.md`,
  `CONTRIBUTING.md`, `PROGRESS.md`
- `src/pathwarden/__init__.py`, `__main__.py`, `errors.py`, `redact.py`
- `src/pathwarden/models/__init__.py`, `enums.py`, `entities.py`, `config.py`
- `src/pathwarden/config/__init__.py`, `versions.py`, `loader.py`
- `src/pathwarden/cli/__init__.py`, `app.py`
- `tests/conftest.py`, `test_models.py`, `test_loader.py`, `test_redact.py`
- `tests/fixtures/` — 2 valid configs + 13 invalid/edge fixtures

### Commands run (working directory `/home/kali/pathwarden`)

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -e ".[dev]"
./.venv/bin/python -m pytest
./.venv/bin/ruff check .
./.venv/bin/mypy
./.venv/bin/pathwarden --version
```

### Actual results

- `pytest`: **57 passed**.
- `ruff check .`: **All checks passed!**
- `mypy` (strict): **Success: no issues found in 13 source files**.
- `pathwarden --version` → `pathwarden 0.1.0`; `--help` renders and exits 0.
- Loading `valid_hr.yaml` succeeds with 2 tools and no warnings; loading
  `secret_credential.yaml` yields one warning with the secret redacted.

### Decisions

1. CLI command name is **`pathwarden`** (the first brief mandated it and
   required the entry point to match); the Master Build Prompt's `agentpath`
   was treated as an inconsistent draft. Product name remains Pathwarden.
2. Package layout follows the Master Build Prompt's logical modules
   (`models/`, `config/`, later `graph/`, `rules/`, `trace/`, `importers/`,
   `reporting/`, `cli/`).
3. Security-relevant fields that are absent remain `None` (unknown); approval
   absence maps to the explicit `unspecified` value.
4. Identifier uniqueness is enforced globally across agents, identities, input
   sources, tools, and resources, for unambiguous references.
5. `allowed_destinations`/`allowed_outbound_destinations = None` means
   *undeclared*, not "all destinations allowed".
6. CLI ships only `--version`/`--help` in Stage 1 so the package is installable
   and the entry point is real; analysis subcommands arrive in Stage 6 rather
   than as non-functional stubs.

### Known limitations

- No analysis rules, graph, permission engine, trace analysis, importer, or
  reporting yet — those are later stages.
- Documentation under `docs/` and the GitHub Actions workflow are deferred to
  Stage 8.
- The `>=3.11` claim is exercised on Python 3.14 only; 3.11–3.13 are not yet
  verified (nothing version-specific is used, but this is unproven).

### Next step

Stage 2 — typed graph construction and permission-aware reachability
(tri-state `allowed`/`denied`/`unknown`), tenant and approval constraints, and
graph export (JSON/Mermaid/DOT).
