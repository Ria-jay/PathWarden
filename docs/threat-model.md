# Threat model

Pathwarden analyzes AI agent configurations and execution logs. It is itself
security-sensitive, so this document states its assumptions and boundaries.

## What Pathwarden is

* A **static** analyzer of declared configuration.
* An **offline** provenance analyzer of structured logs.
* **Deterministic** and reproducible.

## What Pathwarden is not

* It does not execute attacks, invoke real tools, send payloads, or make network
  requests during analysis.
* It does not require an LLM, API key, database, or cloud service.
* It does not confirm exploitability or causation.

## Trust assumptions

* Configuration files and logs are **untrusted input**.
* A declared trust level, approval, or control is a **declaration**, not proof of
  runtime behaviour.
* Imported tool descriptions are **data**. They are never interpreted as
  instructions and never executed.

## Input handling

| Threat | Mitigation |
| --- | --- |
| Oversized files | Config 5 MiB, trace 32 MiB, import 5 MiB, 1 MiB per trace line, 100,000 events per trace. |
| Deeply nested / pathological YAML | Depth limit (64), value limit (200,000), `RecursionError` caught. |
| Arbitrary object construction | `yaml.safe_load` only; JSON via `json`. |
| Malformed JSON/JSONL | Actionable errors with line numbers; no stack traces for user input. |
| Duplicate / missing ids | Rejected (duplicates) or warned (missing references). |
| Cyclic provenance | Detected and reported; classification is cycle-safe. |
| Unicode errors | UTF-8 enforced; invalid bytes reported with an offset. |
| Secret exposure | Secret-like values redacted from errors, warnings, and reports. |
| Unbounded memory | Input size and count limits. |

## Secret handling

* Configurations reference credentials symbolically (`credential_ref`).
* Real secrets must never be required. A `credential_ref` resembling a real
  secret produces a redacted warning.
* `redact()` masks well-known token formats and secret-looking key/value pairs;
  content hashes (for example `sha256:...`) are preserved.

## Determinism

Identical input produces identical output apart from the report `generated_at`.
No randomness, no wall-clock dependence in analysis, no network.

## Residual risks and limitations

* Pathwarden reflects the **declared** configuration; it cannot observe runtime
  policy engines, approvals, or model behaviour.
* Rules encode specific, documented checks; they do not cover every agent
  weakness. No findings means no issue was detected by the implemented rules —
  not that the agent is secure.
* A trace association is not proof of causation; pathwarden reports `direct`,
  `contextual`, and `unknown` separately and never equates temporal ordering
  with influence.
* MCP import preserves only the documented subset; unknown security fields are
  reported, not inferred.
* The `>=3.11` floor is verified locally on Python 3.14; CI is configured to test
  additional versions.
