# Severity and confidence

Severity and confidence are **separate**. Severity expresses potential impact;
confidence expresses how well the available evidence supports the finding.

## Severity matrix

Severity is assigned from the **most sensitive affected resource** and the
**operation class**. `read` is the read operation; `mutate` covers
write, delete, execute, send, and outbound (exfiltration).

| Sensitivity \ class | read | mutate |
| --- | --- | --- |
| restricted | high | critical |
| confidential | medium | high |
| internal | low | medium |
| public | info | low |

## Modifiers

Applied in this fixed order, one level each:

1. **Untrusted source.** If the source trust is `untrusted`, or the source's
   `may_contain_attacker_content` flag is set, raise one level. Capped at
   `critical`.
2. **Declared control applies.** If a control is declared (approval required, or
   restricted outbound destinations), lower one level. Floored at `low`.
3. **Unknown path status.** If the path status is `unknown`, cap at `medium` and
   set the finding status to `indeterminate`.

The order matters. For example, restricted/mutate is `critical`; untrusted keeps
it `critical`; an applicable control lowers it to `high`; an unknown status then
caps it at `medium`.

> A control is only ever counted as **declared**. Pathwarden cannot observe
> runtime enforcement, so "declared control" means a declaration exists, not
> that it works.

## Confidence

| Confidence | Meaning |
| --- | --- |
| `high` | Every relevant step is declared and permission-valid. |
| `medium` | Some non-blocking detail is inferred (for example, intent inferred from declared operations because no purpose is declared). |
| `low` | A key constraint is unknown, so the conclusion is provisional. |

## Finding status

| Status | Meaning |
| --- | --- |
| `reachable` | A permission-valid or undeclared path exists per the declared configuration. |
| `indeterminate` | A required declaration is missing; the result is uncertain, not confirmed. |
| `informational` | Reported for completeness (for example, a declared-but-unenforced approval, or a structurally connected chain whose start is denied). |

## Why this shape

* Tying severity to the most sensitive resource prevents a broad, low-value
  grant from outranking a narrow, high-value one.
* Keeping confidence separate prevents "we are sure this is a risk" and "this
  risk is severe" from being conflated.
* Capping unknown results at `medium` prevents uncertain evidence from
  producing `critical` findings.
* The matrix is fixed and documented so results are reproducible. Changing it
  requires a stated reason and a changelog entry.
