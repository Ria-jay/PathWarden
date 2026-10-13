# Configuration schema

Current schema version: **1.0**. The schema is versioned; unsupported versions
are rejected rather than guessed.

## Top-level document

```yaml
schema_version: "1.0"
agent: {...}
identities: [...]
input_sources: [...]
tools: [...]
resources: [...]
policy: {...}
```

`agent`, `identities`, `tools`, `resources`, and `policy` are validated as a
whole; duplicate identifiers and unresolved references are rejected.

## Agent

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Stable identifier. |
| `name` | yes | Human-readable name. |
| `execution_identity` | yes | Must match a declared identity. |
| `description` | no | Free text. |

## Input source

| Field | Required | Notes |
| --- | --- | --- |
| `id`, `name`, `type` | yes | `type` ∈ `user_message`, `uploaded_file`, `retrieved_document`, `external_content`, `tool_output`. |
| `trust` | yes | `trusted`, `user`, `untrusted`. A declaration, not proof. |
| `may_contain_attacker_content` | no | Default `false`. |
| `requesting_principal` | no | Who the content is attributed to. |

## Identity

| Field | Required | Notes |
| --- | --- | --- |
| `id`, `type` | yes | `type` ∈ `user`, `service_account`, `agent`, `workload`, `system`, `other`. |
| `granted_scopes` | no | List; `!` prefix = explicit deny. `null` = unknown. |
| `resource_restrictions` | no | Glob list; `null` = unknown. |
| `tenants` | no | Non-empty list or `"*"`. `null` = unknown. Mixing `"*"` into a list is rejected. |
| `acts_as_requester` | no | `true`/`false`; `null` = unknown. |
| `credential_ref` | no | Symbolic reference (for example `vault://...`). Never a real secret. |

## Tool

| Field | Required | Notes |
| --- | --- | --- |
| `id`, `name`, `operations` | yes | `operations` ⊆ `read`, `write`, `delete`, `execute`, `send`. |
| `identity` | yes | Must match a declared identity. |
| `description`, `declared_purpose` | no | Used by PW-003 to judge intent; absence is noted, not guessed. |
| `required_scopes` | no | `null` = unknown; `[]` = no requirement. |
| `resource_restrictions` | no | Glob list; `null` = unknown. |
| `approval` | no | Map of operation → `required`/`optional`/`none`/`unspecified`. Missing = `unspecified`. |
| `outbound` | no | Default `false`. |
| `allowed_destinations` | no | Allowlist; `null` = unknown; `[]` = denies all. |
| `output_flows_to` | no | Tool ids that receive this tool's output. |
| `authorization_check` | no | `{type: none|requester_scoped|other, description}`. Absent = unknown. |

## Resource

| Field | Required | Notes |
| --- | --- | --- |
| `id`, `type`, `sensitivity` | yes | `sensitivity` ∈ `public`, `internal`, `confidential`, `restricted`. |
| `owner`, `tenant` | no | `tenant` must be concrete (not `"*"`). |
| `permitted_operations` | no | `null` = unknown; `[]` = deny all. |
| `access_restrictions` | no | Glob list. |

## Policy

| Field | Notes |
| --- | --- |
| `approval_operations` | Operations requiring approval. |
| `approval_sensitivity` | Sensitivity levels requiring approval. |
| `allowed_outbound_destinations` | Policy destination allowlist; `null` = unconstrained. |
| `boundary_sensitivity` | Levels that must not leave the system boundary. |

## Unknown handling

`null` (or an absent optional field) means **undeclared** and resolves to
`unknown` in analysis. An explicitly empty *allow* list denies; an empty
*requirement* list is satisfied. See `docs/permission-model.md`.

## Validation errors

Validation rejects duplicate identifiers, unknown references, invalid
operations, unsupported schema versions, missing required fields, tenant
inconsistencies, and unknown fields (`extra="forbid"`), with actionable
messages. It never repairs a document.

## Size limits

| Limit | Value |
| --- | --- |
| Config file size | 5 MiB |
| Nesting depth | 64 |
| Values | 200,000 |
