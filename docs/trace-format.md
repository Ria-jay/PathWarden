# Trace event format

Pathwarden reads execution logs as **JSON Lines** (`.jsonl`): one JSON object per
line, UTF-8 encoded.

## Fields

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `event_id` | yes | string | Unique identifier for the event. |
| `timestamp` | yes | string | ISO 8601 timestamp. Naive timestamps are interpreted as UTC. |
| `type` | yes | string | One of `input`, `model_output`, `tool_call`, `tool_result`. |
| `source` | no | string | The producing source. |
| `trust_level` | no | string | `trusted`, `user`, or `untrusted`. |
| `content_ref` | no | string | Reference to the content (not the content itself). |
| `content_hash` | no | string | Hash of the content (for example `sha256:...`). |
| `parent_event_ids` | no | list of strings | Events this event derives from. |
| `context_event_ids` | no | list of strings | Events known to be in the model's context when this event was produced. |
| `identity` | no | string | Identity under which the event occurred. |
| `resource_id` | no | string | Resource referenced by the event. |
| `tool_id` | no | string | Tool invoked (`tool_call`). |
| `operation` | no | string | `read`, `write`, `delete`, `execute`, or `send`. |
| `policy_decision` | no | string | `allowed`, `denied`, or `unknown`. |
| `approval_decision` | no | string | `allowed`, `denied`, or `unknown`. |

Additional provider-specific fields are **preserved**, not rejected, and are
never interpreted as instructions.

## Privacy

Raw prompts, secrets, and tool results need not be logged. Use `content_ref`
and `content_hash` to reference content out of band.

## Validation

* Required fields must be present and well typed.
* Event ids must be unique across the trace.
* Timestamps must be parseable.
* Parent and context references to missing ids produce **warnings**, not
  failures. A missing parent is never treated as evidence that no influence
  existed.
* Cycles in the parent graph are detected and reported; classification is
  cycle-safe.

## Limits

| Limit | Value |
| --- | --- |
| Trace file size | 50 MiB |
| Events per trace | 500,000 |
| Line length | 1 MiB |

Exceeding a limit is an input error (exit code 2).

## Example

```json
{"event_id": "e1", "timestamp": "2026-01-01T10:00:00Z", "type": "input", "source": "cv-upload", "trust_level": "untrusted", "content_ref": "cv.pdf", "content_hash": "sha256:aaaa..."}
{"event_id": "e2", "timestamp": "2026-01-01T10:00:05Z", "type": "model_output", "parent_event_ids": ["e1"]}
{"event_id": "e3", "timestamp": "2026-01-01T10:00:06Z", "type": "tool_call", "tool_id": "hr-database", "operation": "read", "resource_id": "employee-db", "parent_event_ids": ["e2"]}
```

## Out-of-order arrival

Events may arrive in any order. Analysis does not depend on file order; a
deterministic timestamp ordering is available (`TraceData.ordered`).
