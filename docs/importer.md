# MCP-style importer

Pathwarden imports a documented subset of MCP (Model Context Protocol) tool
definitions and produces a **partial config**. It never executes imported tools
and never makes network requests.

## Supported shapes

```json
{"tools": [{"name": "...", "description": "...", "inputSchema": {...}}]}
```

```json
[{"name": "...", "description": "...", "inputSchema": {...}}]
```

```json
{"name": "...", "description": "...", "inputSchema": {...}}
```

Both `inputSchema` (MCP) and `input_schema` are accepted.

## Supported fields

| Field | Handling |
| --- | --- |
| `name` | Required; becomes the normalized tool id (slugified, de-duplicated). |
| `description` | Preserved and analyzed for review indicators. |
| `inputSchema` / `input_schema` | Preserved; analyzed for review indicators. |
| `annotations` | Preserved verbatim (not normalized). |
| anything else | Listed under `unsupported_fields`; the raw definition is preserved. |

## What is unknown

MCP definitions carry no operations, scopes, resources, tenants, or
sensitivity. The importer marks these unknown and lists them under
`needs_review`:

`operations`, `identity`, `required_scopes`, `resource_restrictions`,
`resources`, `tenants`, `approval`, `outbound`, `allowed_destinations`,
`authorization_check`.

**Analyzing a partial config produces indeterminate results**, not guesses. Each
imported tool yields an `IMPORT-001` finding with status `indeterminate` listing
the unknown fields, because no static rule can be evaluated without them.

## Review indicators

Deterministic, non-conclusive signals for human review:

| Kind | Trigger |
| --- | --- |
| `instruction_like_text` | Description matches instruction-like patterns (`ignore previous`, `system:`, `you must`, `do not tell`, …). |
| `hidden_unicode` | Description contains zero-width, bidirectional, or other format characters. |
| `broad_parameter_schema` | An object parameter declares no properties while allowing additional ones, a property has no type, or a free-text parameter is unconstrained. |
| `arbitrary_resource_or_destination_parameter` | An unconstrained string parameter whose name can select an arbitrary resource, path, or destination (`path`, `url`, `destination`, `recipient`, `to`, `command`, …). |
| `missing_or_vague_description` | Description absent, empty, very short, or generic. |

> These are indicators for review, **not proof of malicious behaviour**.
> Instruction-like wording is not automatically malicious; unusual Unicode is
> not automatically an attack; a broad parameter is not automatically
> exploitable.

## Safety

* Imported content is parsed with `json`/`yaml.safe_load` only.
* Imported descriptions are never interpreted as instructions.
* Imported tools are never executed; no network requests are made.
* Input size is bounded (5 MiB).

## Extending

Adapters implement `pathwarden.importers.base.ToolImporter` (`can_import` /
`import_data`) and are registered in `pathwarden.importers.IMPORTERS`. The
interface is intentionally small so additional formats can be supported later
without changing the analyzer. No speculative adapters are included, and none
should be claimed as supported until they are implemented and tested.
