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
| 2 | Graph and permission-aware reachability | complete |
| 3 | Static rules PW-001…PW-007 | complete |
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

### Next step (superseded)

## Stage 2 — Graph and permission-aware reachability

### Implemented

- Tri-state permission model (`graph/permissions.py`): `allowed` / `denied` /
  `unknown`; explicit deny (`!` prefix) beats allow; `None` = undeclared =
  unknown; empty allow list = deny; empty requirement list = satisfied; glob
  matching via `fnmatch`; fold rule deny > unknown > allowed; recorded steps and
  a deciding step.
- Tenant, scope, resource-restriction, resource-operation, tool-operation, and
  destination checks, each fully branched and tested.
- Approval assessed as a *control* (`not_required` / `declared` / `partial` /
  `missing` / `indeterminate`), never as allow/deny; declared is *not* effective.
- Typed graph (`graph/model.py`, `graph/build.py`) over a `networkx.MultiDiGraph`
  with node types (`input_source`, `agent`, `tool`, `resource`, `identity`,
  `external_destination`) and edge types (`feeds_context`, `can_invoke`,
  `reads`, `writes`, `uses_identity`, `outbound_to`, `flows_to`). Edges carry
  operations, restriction basis, tenant, trust, and destination attributes.
- Deterministic exports (`graph/export.py`): JSON, Mermaid, Graphviz DOT, all
  sorted so identical input yields identical output.
- `docs/permission-model.md` documenting every semantic and both branches of
  the unknown cases.

### Files created

- `src/pathwarden/graph/__init__.py`, `model.py`, `permissions.py`, `build.py`,
  `export.py`
- `tests/test_permissions.py`, `tests/test_graph.py`
- `docs/permission-model.md`

### Commands run (working directory `/home/kali/pathwarden`)

```bash
./.venv/bin/python -m pytest
./.venv/bin/ruff check .
./.venv/bin/mypy
```

### Actual results

- `pytest`: **109 passed**.
- `ruff check .`: **All checks passed!**
- `mypy` (strict): **Success: no issues found in 18 source files**.
- Demonstration of the three reachability states (same `reads` edge present in
  all three): `allowed` (deciding step none), `denied` (deciding step `tenant`),
  `unknown` (deciding step `resource_restriction`). This confirms that graph
  connectivity does not imply permission.

### Decisions

1. `None` (undeclared) yields `unknown`; an explicitly empty *allow* list
   (`[]`) yields `denied`; an empty *requirement* list is satisfied. See
   `docs/permission-model.md`.
2. `!`-prefixed patterns are explicit denies (a Pathwarden convention).
3. Resource restrictions are the intersection of the identity's and the tool's
   declared restrictions. `allowed` therefore requires both sides declared.
4. Approval is modelled separately from permissions.
5. Undeclared tool resource restrictions connect the tool to all resources in
   the graph, with `restriction_basis: undeclared`; permission status stays
   `unknown` at query time.

### Known limitations

- No path enumeration for rules yet; Stage 2 provides the permission primitive
  and graph that Stage 3 rules consume.
- `allowed` is intentionally hard to reach; most partial configs yield
  `unknown`.

### Next step

Stage 3 — static rules PW-001…PW-007.

## Stage 3 — Static rules PW-001…PW-007

### Implemented

- `finding.py`: the finding model with `finding_id`, `rule_id`, `title`,
  `severity`, `confidence`, `status`, `summary`, `evidence`, `path`,
  `affected_resources`, `effective_identity`, `relevant_permissions`,
  `missing_or_uncertain_constraints`, `remediation`, `limitations`. Stable,
  content-derived `finding_id`.
- `severity.py`: the documented matrix and modifiers (untrusted raise, declared
  control lower, unknown cap at medium), applied in order.
- `rules/`: `base.py` (Rule interface, deterministic sorting), `common.py`
  (shared access enumeration), and `pw001.py` … `pw007.py`, plus `rules/__init__`
  registry and the `analyze()` facade in `analyze.py`.
- `docs/severity.md` and `docs/rules.md`.

### Commands run (working directory `/home/kali/pathwarden`)

```bash
./.venv/bin/python -m pytest
./.venv/bin/ruff check .
./.venv/bin/mypy
```

### Actual results

- `pytest`: **156 passed**.
- `ruff check .`: **All checks passed!**
- `mypy` (strict): **Success: no issues found in 31 source files**.
- Demonstration on `tests/fixtures/valid_hr.yaml`: 9 findings across PW-001,
  PW-002, PW-003, PW-004, PW-005, with correct severities, statuses
  (reachable/indeterminate), evidence, paths, and missing-constraint lists. No
  PW-006 (only one tenant represented) and no PW-007 (no `flows_to` chain).

### Decisions

1. Each rule is a class with stable metadata; `run_rules` sorts findings by
   severity, rule, then finding id for determinism.
2. `finding_id` is a short hash of the rule plus its key content, so it is stable
   across runs and independent of ordering.
3. PW-003 evaluates identity-vs-tool scope per tool, so a shared identity holding
   an operation one tool does not use is reported for that tool. Documented as a
   limitation.
4. PW-005 applies no untrusted-source modifier (its risk is the outbound path,
   not injection); PW-007 reports chains whose starting read is denied as
   *informational* to distinguish structural connectivity from permission
   validity.

### Known limitations

- PW-003 scope-to-operation mapping is token-based; unmapped scope strings are
  reported as undetermined rather than guessed.
- PW-006 reasons at the identity level; tool tenant behaviour is derived from its
  execution identity.
- Findings are computed in memory; reporting/CLI rendering land in Stage 6.

### Next step

Stage 4 — execution-log provenance analysis (JSONL parsing, validation,
`direct`/`contextual`/`unknown` classification, correlation, tests).
