# Report format

Pathwarden produces Markdown (`--format md`) and JSON (`--format json`) reports
with a stable schema. Identical input produces identical output apart from
`generated_at`.

## JSON schema

```jsonc
{
  "tool": {"name": "pathwarden", "version": "0.1.0"},
  "report_version": "1.0",
  "schema_version": "1.0",          // configuration schema version
  "generated_at": "2026-01-01T00:00:00+00:00",  // the only variable field
  "scope": {"config": "...", "agent": "...", "trace": null},
  "graph_summary": {"nodes": 0, "edges": 0},
  "summary": {
    "static": {"total": 0, "by_severity": {...}, "by_status": {...}},
    "trace": null                    // or the same shape when --trace is given
  },
  "rule_coverage": [
    {"id": "PW-001", "title": "...", "rationale": "...",
     "prerequisites": [...], "limitations": "...", "findings": 0, "check": "ran"}
  ],
  "static_findings": [ /* finding objects */ ],
  "trace": {                         // null unless --trace is given
    "path": "...",
    "warnings": [...],
    "summary": {...},
    "findings": [ /* trace finding objects */ ],
    "correlations": [ /* labelled correlations */ ]
  },
  "limitations": ["..."]
}
```

### Finding object

`finding_id`, `rule_id`, `title`, `severity`, `confidence`, `status`, `summary`,
`evidence`, `path` (`nodes` + `edges` with attributes), `affected_resources`,
`effective_identity`, `relevant_permissions`,
`missing_or_uncertain_constraints`, `remediation`, `limitations`.

### Trace finding object

`finding_id`, `rule_id` (`TRACE-001`), `title`, `severity`, `confidence`,
`status` (`observed` / `indeterminate`), `summary`, `tool_call_event_id`,
`classification` (`direct` / `contextual` / `unknown`), `candidates`,
`sensitive_operation`, `resource_id`, `missing_information`,
`recommended_investigation`, `limitations`.

### Correlation object

`tool_call_event_id`, `kind` (`static_potential_path` / `observed_event` /
`correlated_by_identifiers` / `unconfirmed`), `detail`, `static_finding_ids`,
`related_static_path`.

## Markdown structure

1. Header table (tool/report/schema versions, timestamp, scope, graph size).
2. Summary with severity counts.
3. Static findings (evidence, path, permissions, missing constraints,
   remediation, limitations).
4. Trace findings and correlation (only with `--trace`).
5. Rule coverage table.
6. Limitations.

## Distinguishing outcomes

* **No issue detected by the implemented rules** — every rule ran and produced no
  finding.
* **Finding** — a rule produced a reachable or informational finding.
* **Indeterminate** — a required declaration is missing; shown as a finding with
  status `indeterminate`.
* **Could not run** — surfaced as an error (exit code 2) rather than a silent
  pass.

No findings never means "secure". Reports state this explicitly.
