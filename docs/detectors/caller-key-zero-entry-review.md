# caller-key-zero-entry-review

Availability: **opt-in**; no policy required. Severity: **info**. Confidence:
**high** for the supported static source relationship.

Select with `--detectors caller-key-zero-entry-review`. The observer fixes an
actual numeric entry parameter to zero and preserves other inputs and helper
arguments. APIs inserting literal zero use complete ordinary histories and need
no fabricated amount parameter. It reports a numeric `Map<Bytes<32>, ...>.insert` whose amount retains an unchanged entry-input identity or is literal zero,
and whose key retains an unchanged entry-input identity, when the write survives a modeled full
successful invocation without required initial membership at that exact key or
an enforced finite literal key domain. One qualifying successful history suffices;
other zero histories may perform no insertion.

Required same-key initial membership excludes existing-only updates. Unrelated
may-alias keys do not establish equal entries. Literal key domains, fixed-key
writes, transformed amounts, positive guards, and writes later removed, reset or
overwritten are quiet. A later overlapping write withholds survival evidence
unless its exact ordered insert/remove operation addresses the same Map with an
immutable key required distinct on that same successful history. Possible Boolean
alternatives, wildcard addresses, ancestor resets and unproven aliases supply no
disequality proof. Withheld survival evidence does not claim the write was
necessarily removed.

Exact collection/query revisions and ordered write positions are shared with
`zero-amount-initial-membership`. Ordinary scans are unchanged. Missing exact
facts, unqualified no-zero-success cases, reached checkpoints and exhausted
budgets produce rule diagnostics. Direct nonzero entry guards are a narrow
qualified rejection boundary; other zero-path failures remain unavailable.

An API that intentionally creates a zero-valued entry can match. Review whether
the application requires an existing key or a positive amount before treating
the finding as a defect; the rule does not infer that policy.
