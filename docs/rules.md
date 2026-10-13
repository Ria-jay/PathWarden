# Rule catalog

Pathwarden ships seven deterministic static rules. Every rule reports
**potential** or **reachable** paths, never confirmed exploitation. Findings are
evidence-backed and list the constraints that remain unknown.

Severity is assigned per `docs/severity.md`. All rules run against the
permission-aware graph (`docs/permission-model.md`); structural connectivity
alone never produces a finding.

---

## PW-001 — Untrusted input to sensitive operation

**Detects.** An input source that is `untrusted` or flagged
`may_contain_attacker_content` feeds an agent that can invoke a tool performing a
sensitive operation: touching a `confidential`/`restricted` resource, or any
write, delete, execute, or send.

**Prerequisites.** At least one untrusted/attacker-flagged source; an agent that
can invoke a tool with a declared sensitive operation.

**Procedure.** For each untrusted source and each declared (tool, operation,
resource) triple whose permission status is not `denied`, emit a potential
influence path `source → agent → tool → resource`.

**Severity.** Matrix over the resource sensitivity and operation class, raised by
the untrusted modifier; capped at `medium` when the path status is unknown.

**Remediation.** Keep untrusted content out of sensitive operations; add
approval and a requester-scoped authorization check; narrow resource
restrictions.

**Limitations.** A path is a potential influence path, not proof of influence.
Pathwarden does not model model behaviour.

---

## PW-002 — Confused deputy

**Detects.** A tool whose execution identity does **not** act as the requester
(`acts_as_requester` false, or undeclared), has no `requester_scoped`
authorization check, and can touch a resource whose owner/tenant is not the
requesting principal.

**Prerequisites.** An input source with a `requesting_principal`; a tool whose
identity can reach a resource not owned by that principal.

**Procedure.** For each such source and tool/resource access that is not denied:
if the resource owner or tenant equals the principal, skip; otherwise emit a
finding. When `acts_as_requester` or `authorization_check` is undeclared, emit an
**indeterminate** finding naming the missing fields.

**Severity.** Matrix over the resource sensitivity and operation class; unknown
status caps at `medium`.

**Remediation.** Add a requester-scoped authorization check, or have the identity
act as the requester, and restrict the tool to resources the requester is
authorized for.

**Limitations.** A potential confused-deputy configuration, not a demonstration
of abuse. Does not flag every privileged agent — the specific missing
relationship must exist.

---

## PW-003 — Over-broad scope

**Detects.** Identity or tool permissions that exceed the tool's declared
operations or resource restrictions: a granted scope denoting an operation the
tool does not declare (for example write scope on a read-only tool), or an
identity resource restriction that admits resources the tool's own restriction
excludes.

**Prerequisites.** A tool with declared operations; an identity whose grants or
resource restrictions can be compared.

**Procedure.** Map granted-scope operation tokens (`read`/`write`/`delete`/
`execute`/`send`/`admin`/`*`) to operations and compare with `tool.operations`.
Compare identity and tool resource restrictions against the declared resources.
Report each excess.

**Severity.** Matrix over the most sensitive affected resource and the excess
operation class.

**Remediation.** Reduce the identity's grants to the tool's declared operations
and resources, or document why the broader scope is required.

**Limitations.** Intended scope is inferred from declarations. When a tool
declares no purpose, or a scope string does not map to a known operation, or a
resource restriction is undeclared, the finding states the limitation instead of
inventing intent.

---

## PW-004 — Missing approval

**Detects.** An operation for which policy requires approval (`approval_operations`
or `approval_sensitivity`) but the tool declares `approval: none`.

**Prerequisites.** A policy requiring approval; a tool whose approval can be
compared with it.

**Procedure.** For each declared operation (with a resource where reachable) call
`assess_approval`. Emit `reachable` for `missing`/`partial`, `indeterminate` for
`unspecified`, and `informational` for a declared requirement.

**Severity.** Matrix over the resource sensitivity and operation class; a
declared control lowers one level (it is still only *declared*).

**Remediation.** Declare approval required for the operation and confirm the
execution environment enforces it.

**Limitations.** A declared requirement is reported as declared, never
effective.

---

## PW-005 — Exfiltration path

**Detects.** An agent that can read a `confidential`/`restricted` resource and
invoke an outbound tool of the same agent, where the destination is absent or
insufficient under policy.

**Prerequisites.** A permission-valid or unknown sensitive read; an outbound
tool the same agent can invoke.

**Procedure.** For each sensitive read (status not denied) and each destination
of each outbound tool: skip when the destination control is `denied`, or is
`allowed` and the resource sensitivity is not in `policy.boundary_sensitivity`.
Otherwise emit the path.

**Severity.** Matrix with the `mutate` class (outbound), capped at `medium` when
the read or destination is unknown.

**Remediation.** Restrict outbound destinations to an allowlist, add the
resource sensitivity to the policy boundary, and require approval for outbound
operations.

**Limitations.** A potential path, not proof data leaves the system.

---

## PW-006 — Cross-tenant exposure

**Detects.** An identity that can reach resources in more than one tenant, or a
resource outside its declared tenants; a wildcard (`"*"`) identity reaching more
than one tenant.

**Prerequisites.** Resources with tenant declarations reachable through a tool;
an identity with a tenant declaration.

**Procedure.** Group reachable resources by identity. Report `reachable` for
tenants outside a declared list, for multiple reachable tenants, and for a
wildcard identity spanning tenants. Report `indeterminate` when tenant data is
undeclared.

**Severity.** Matrix over the most sensitive affected resource and the strongest
operation class used.

**Remediation.** Scope the identity's tenants to exactly the tenants it must
serve, and align resource tenants.

**Limitations.** Tenant semantics come from the configuration. Unknown tenant
data yields `indeterminate`, never a cross-tenant claim.

---

## PW-007 — Privilege chain

**Detects.** A path of three or more tools linked by `flows_to` edges that starts
at a confidential/restricted read and ends at an outbound or write/execute tool.

**Prerequisites.** At least two `flows_to` edges (three tools); a sensitive read
at the start and a risky endpoint.

**Procedure.** Build the `flows_to` subgraph and enumerate simple paths of length
≥ 3 from a sensitive-read tool to an outbound/write/execute tool. `reachable`
when the start and end are allowed; `indeterminate` when either is unknown;
`informational` when the start is denied (structurally connected only).

**Severity.** Matrix over the starting resource sensitivity and the `mutate`
class.

**Remediation.** Remove unnecessary `flows_to` links, narrow each tool's access,
and require approval for the final outbound or mutating hop.

**Limitations.** Two-tool read-to-outbound cases belong to PW-005, not here.
Structural connectivity is distinguished from permission validity.

---

## Coverage and honesty

A rule that does not apply produces no finding; that is not a statement that the
configuration is safe. Reports distinguish "the check ran and found nothing",
"the check could not run", and "the result is indeterminate". See
`docs/severity.md`. Findings contain the actual graph nodes and edges, the
effective identity, the permission steps, and the missing constraints, so they
can be verified rather than taken on trust.
