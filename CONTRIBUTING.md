# Contributing to Pathwarden

Thank you for considering a contribution. Pathwarden is a security-sensitive
tool: correctness and honesty about coverage matter more than feature volume.

## Ground rules

1. **Never claim more than the evidence supports.** Static findings describe
   *potential* or *reachable* paths; trace findings describe *observed* or
   *influence-candidate* relationships. Do not use "vulnerable", "exploitable",
   or "confirmed" unless a direct parent link genuinely establishes it.
2. **Unknown stays unknown.** Missing configuration is represented as `unknown`,
   never silently treated as allowed or denied.
3. **Determinism.** Identical input must produce identical output, apart from
   explicitly variable metadata such as the report timestamp.
4. **No network, no execution, no LLM** in the analysis core. Pathwarden must
   work offline with no API keys.
5. **Do not weaken or delete a failing test to get green.** If an expectation is
   wrong, explain why and fix it transparently.

## Development setup

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -e ".[dev]"
```

## Before opening a pull request

```bash
./.venv/bin/python -m pytest
./.venv/bin/ruff check .
./.venv/bin/mypy
```

All three must pass. New behavior needs tests, including a
"structurally connected but not permission-reachable" case where relevant.

## Style

- Type hints throughout; the project is checked with `mypy --strict`.
- Keep modules focused and functions small.
- Match the existing naming and structure.
