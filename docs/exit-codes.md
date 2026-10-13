# Exit codes and CI usage

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The command ran and nothing met or exceeded the `--fail-on` threshold. |
| `1` | Findings met or exceeded `--fail-on`. |
| `2` | Configuration or input error (bad file, invalid schema, invalid arguments). |
| `3` | Internal error (a bug). |

`--fail-on` accepts `info`, `low`, `medium`, `high`, or `critical`, and defaults
to `high`.

## Commands

```bash
pathwarden analyze <config> [--format text|json] [--fail-on LEVEL] [--verbose]
pathwarden trace <config> <trace.jsonl> [--format text|json] [--fail-on LEVEL] [--verbose]
pathwarden graph <config> --format mermaid|dot|json [--verbose]
pathwarden report <config> [--format md|json] [--trace <trace.jsonl>] [--fail-on LEVEL] [--verbose]
pathwarden import-mcp <file> [--format json|yaml] [--verbose]
```

Diagnostics (warnings, review indicators, progress) go to **stderr**;
machine-readable output goes to **stdout**.

## CI snippet

```yaml
- name: Pathwarden analysis
  run: |
    pip install -e .
    pathwarden analyze agent.yaml --fail-on high
    pathwarden report agent.yaml --format md --trace run.jsonl > pathwarden-report.md
```

The job fails when a finding meets or exceeds `high`. Use `--fail-on medium` for
stricter gates or `--fail-on critical` for report-only pipelines. `--fail-on` is
evaluated over **both** static findings and observed trace findings for `trace`
and `report`.

## Notes

* A `0` exit does **not** mean the configuration is secure — only that the
  implemented rules found nothing at or above the threshold.
* `import-mcp` exits `0` on success and `2` on a bad input; it does not apply a
  `--fail-on` threshold because a partial config is inherently indeterminate.
