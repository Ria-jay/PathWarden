# Provenance semantics

For each **sensitive tool call**, Pathwarden classifies every **untrusted input
event** by how it relates to the tool call.

| Classification | Meaning |
| --- | --- |
| `direct` | The input is reachable from the tool call through `parent_event_ids`. |
| `contextual` | The input appears in `context_event_ids` (of the tool call or an ancestor) but has no parent link. |
| `unknown` | Neither link exists; only temporal ordering is available. Reported as **temporal association only**. |

## Rules

* **All candidates are listed.** Pathwarden never picks a single "the" input.
* **Temporal association is not influence.** An `unknown` classification records
  that an untrusted input happened earlier; it does not claim the tool call
  depended on it.
* **A missing parent is never evidence of no influence.** Missing links yield a
  warning and an `unknown` classification, not an absence of association.
* **Directly linked is described precisely.** Even with a parent link, the
  relation is "directly linked by provenance", never "caused".

## Which tool calls are sensitive

A tool call is sensitive when its operation is a write, delete, execute, or
send; or when its `resource_id` maps to a confidential/restricted resource; or
when a resource is referenced that the configuration does not declare and the
operation is not a read.

## Findings

Each trace finding contains:

* the tool-call event id and the sensitive operation,
* every candidate input event id with its classification,
* the resource id when present,
* the missing information that limits the conclusion,
* a recommended investigation.

Trace findings are **separate** from static findings. An observed event is not a
static path, and a static path is not an observation.

## Severity and confidence

Severity uses the same matrix as static analysis (`docs/severity.md`) with the
`mutate` class for outbound/write operations and the resource sensitivity when
known. `direct` evidence gives `high` confidence, `contextual` gives `medium`,
and `unknown` gives `low`. An `unknown` classification caps severity at `medium`
and sets the finding status to `indeterminate`.

## Correlation with the static graph

Correlation is always labelled (`docs/graph-semantics.md` will describe the
graph; correlation kinds are defined here):

| Kind | Meaning |
| --- | --- |
| `static_potential_path` | A possible path inferred from configuration. |
| `observed_event` | An execution event that occurred. |
| `correlated_by_identifiers` | An observed event whose tool matches a declared tool with a matching static finding. |
| `unconfirmed` | An observed event that cannot be matched to the configuration. |

Static possibility and runtime observation are never presented as equal
evidence. Correlation by matching identifiers is explicitly not proof of
influence.
