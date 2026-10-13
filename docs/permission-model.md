# Permission model

Pathwarden's analysis is built on a **tri-state permission model**. Every
security-relevant decision resolves to exactly one of three states:

| Status | Meaning |
| --- | --- |
| `allowed` | The configuration positively grants the operation. |
| `denied` | The configuration positively withholds or forbids it. |
| `unknown` | The configuration does not say. |

`unknown` is never collapsed into `allowed` or `denied`. A missing declaration
is not treated as permission, and it is not treated as a prohibition.

> Language note: a result of `allowed` means the *declared* configuration
> permits the operation. It is not a statement about runtime enforcement,
> model behaviour, or exploitability. Static analysis reports **reachable** or
> **potential** paths, never confirmation.

## Conventions

These conventions are implemented in `pathwarden/graph/permissions.py` and
covered by `tests/test_permissions.py`.

### `None` versus an empty list

* **`None`** — the declaration is absent. This yields `unknown`.
* **Empty allow list** (`[]`) — the configuration explicitly permits nothing on
  that dimension. This yields `denied`.
* **Empty requirement list** — a tool that declares no `required_scopes`, or an
  empty `operations` list that is impossible to satisfy, is treated as a
  requirement, and an empty requirement is trivially satisfied.

| Field | Kind | `None` | `[]` |
| --- | --- | --- | --- |
| `identity.granted_scopes` | allow list | `unknown` | denies every required scope |
| `identity.resource_restrictions` | allow list | `unknown` (that side) | `denied` |
| `tool.resource_restrictions` | allow list | `unknown` (that side) | `denied` |
| `tool.required_scopes` | requirement list | `unknown` | `allowed` (nothing required) |
| `resource.permitted_operations` | allow list | `unknown` | `denied` |
| `tool.allowed_destinations` | allow list | `unknown` | `denied` |
| `policy.allowed_outbound_destinations` | allow list | `unknown` | `denied` |
| `identity.tenants` | see tenants | `unknown` | rejected by validation |

### Explicit deny

A pattern beginning with `!` is an explicit **deny**. An explicit deny always
beats an explicit allow, regardless of order.

```yaml
granted_scopes: ["db:*", "!db:read"]   # read is denied even though db:* matches
```

### Pattern matching

Scopes and resource identifiers are matched with `fnmatch`-style globs,
case-sensitively. An exact string matches exactly; `*`, `?`, and `[]` are glob
metacharacters.

```yaml
resource_restrictions: ["db/*"]   # matches "db/employees", not "secrets/vault"
```

## Individual checks

`evaluate_access` combines the following steps for a `(tool, operation,
resource)` triple.

| Step | Rule |
| --- | --- |
| `tool_operation` | `denied` unless the operation is in `tool.operations`. |
| `scope` | `denied` if a required scope is explicitly denied or not granted; `allowed` if all are granted; `unknown` if the tool's requirement or the identity's grant is undeclared. |
| `resource_restriction` | `denied` if an explicit deny matches, if a declared side excludes the resource, or if a side declares an empty allow list; `allowed` only if both identity and tool restrictions are declared and admit the resource; otherwise `unknown`. |
| `resource_operation` | `denied` unless the operation is in the resource's `permitted_operations`; `unknown` if undeclared. |
| `tenant` | see below. |

### Tenant check

| Identity tenants | Resource tenant | Result |
| --- | --- | --- |
| undeclared (`None`) | any | `unknown` |
| any | undeclared (`None`) | `unknown` |
| `"*"` | declared | `allowed` |
| list containing resource tenant | declared | `allowed` |
| list not containing resource tenant | declared | `denied` |

A wildcard identity (`"*"`) is `allowed` for any single resource, but Rule 6
(PW-006) flags it when resources span more than one tenant.

### Combining steps

A path's status is:

1. `denied` if **any** step is denied,
2. else `unknown` if **any** step is unknown,
3. else `allowed`.

The result records every step, plus a **deciding step**: the first denied step,
else the first unknown step. Findings use the deciding step to explain why a
path has the status it does.

## Approval is a control, not a permission

Approval does not make an operation `allowed` or `denied`. It is assessed
separately by `assess_approval`, which compares the tool's declared
`approval` for the operation with the policy:

| Policy requires approval? | Tool declares | Assessment |
| --- | --- | --- |
| no | anything | `not_required` |
| yes | `required` | `declared` — *enforcement unknown* |
| yes | `optional` | `partial` |
| yes | `none` | `missing` |
| yes | `unspecified` (or absent) | `indeterminate` |

A policy "requires approval" for an operation when the operation is listed in
`policy.approval_operations`, or the resource's sensitivity is listed in
`policy.approval_sensitivity`.

A declared approval requirement is reported as **declared**, never as
**effective**: Pathwarden cannot observe whether a real execution environment
enforces it.

## Outbound destinations

`check_destinations` evaluates whether a destination is permitted, combining the
tool's `allowed_destinations` with `policy.allowed_outbound_destinations`:

* both undeclared → `unknown`;
* an explicit deny matches → `denied`;
* a declared empty allow list → `denied`;
* a declared, non-empty allow list that does not match → `denied`;
* one side undeclared → `unknown`;
* both declared and matching → `allowed`.

## Worked examples

**Allowed.** Identity grants `db:read`, is restricted to `db/*`, and is
tenant-scoped to `acme`; the tool requires `db:read`, is restricted to `db/*`,
and the resource `db/employees` is confidential in tenant `acme` and permits
`read`. All steps are declared and pass → `allowed`.

**Denied.** The same configuration but the resource lives in tenant `globex`.
The tenant step is `denied` → the path is `denied`, even though the graph has a
`reads` edge. **Graph connectivity does not imply permission.**

**Unknown.** The tool declares no `resource_restrictions`. The resource
restriction step is `unknown` → the path is `unknown`, reported as a potential
path with an explicit note about the missing declaration.

## Limitations

* The model reflects the configuration only. It cannot observe runtime
  behaviour, policy engines, or approvals.
* `allowed` is deliberately hard to reach: it requires every relevant dimension
  to be declared and to agree. This is intentional — Pathwarden prefers an
  honest `unknown` over a false `allowed`.
* Deny patterns (`!`) are a Pathwarden convention, not part of an external
  standard.
