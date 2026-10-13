# Graph semantics

The security graph is a typed, deterministic `networkx.MultiDiGraph`.

## Node types

| Type | Source |
| --- | --- |
| `input_source` | Each `input_sources` entry. |
| `agent` | The agent. |
| `tool` | Each `tools` entry. |
| `resource` | Each `resources` entry. |
| `identity` | Each `identities` entry. |
| `external_destination` | Declared outbound destinations, or `external:unspecified` when a tool is outbound with no usable destinations. |

Node ids are the real configuration identifiers. Node attributes preserve the
fields needed to explain them (trust, sensitivity, scopes, tenants, operations,
approval, destinations, …).

## Edge types

| Type | Direction | Meaning |
| --- | --- | --- |
| `feeds_context` | input source → agent | The source can enter the agent's context. |
| `can_invoke` | agent → tool | The agent can invoke the tool. |
| `uses_identity` | tool → identity (and agent → identity) | The identity the tool/agent runs as. |
| `reads` | tool → resource | The tool declares a read operation on the resource. |
| `writes` | tool → resource | write/delete/execute/send operations. |
| `outbound_to` | tool → external destination | The tool can send data out. |
| `flows_to` | tool → tool | This tool's output feeds another tool. |

Edges carry the attributes needed to explain them: `operations`, the
`restriction_basis` (`declared`/`undeclared`/`empty`), trust and
attacker-content flags, and destination/`declared` flags.

## How connectivity is built

* A tool's resource edges depend on its `resource_restrictions`:
  * declared non-empty list → only matching resources;
  * explicit empty list → no resource edges;
  * undeclared (`null`) → all resources, marked `restriction_basis: undeclared`.
* Resource edges use the intersection of the tool's operations and the
  resource's `permitted_operations` (when declared).

**Connectivity does not imply permission.** A tool with undeclared restrictions
is connected to every resource so the potential is visible, but the permission
engine returns `unknown` for those edges. A tool with declared restrictions is
connected only to the resources those restrictions admit, yet a tenant or scope
mismatch still yields `denied`.

## Reachability

Reachability is computed by `pathwarden.graph.permissions.evaluate_access`,
which combines tool-operation, scope, resource-restriction, resource-operation,
and tenant checks with the fold rule `denied > unknown > allowed`. See
`docs/permission-model.md`.

## Determinism and export

Nodes are sorted by `(type, id)` and edges by `(source, target, type)`. The same
configuration always produces the same graph and the same exported bytes.

* `graph --format json` — nodes and edges with attributes.
* `graph --format mermaid` — `graph LR` with labelled edges.
* `graph --format dot` — a Graphviz digraph with typed edges.
