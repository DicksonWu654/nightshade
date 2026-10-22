# circuit-work-budget

Availability: **policy-required**; selected by default, but needs
`policies.workBudgets`. Severity **low**, confidence **high** for the source estimate.

Reports an expanded source-operation upper bound above a configured circuit
budget. The estimate expands static loops and callee work and conservatively
counts both branch alternatives.

## Example and review scenario

The compiler-qualified owned [fixture](#example-1)
repeats a Counter update four times. Its explicit review threshold is:

```json
{ "workBudgets": [{ "circuit": "update", "maxUnits": 5 }] }
```

Place this object under `policies` in the [configuration](../configuration.md).
The [correction](#example-2) contains one update.
Use the rule to notice source-work growth beyond an agreed project limit.

Recommendation: inspect repeated loop and callee work, then measure actual
compiler/prover cost before optimizing or adjusting the budget. For an opt-in
fixed threshold without policy, see [circuit-cost](circuit-cost.md).

## False positives and limitations

Intentional large circuits or conservative branch expansion can exceed a useful
application budget. Units are not proof rows, optimized compiler cost, runtime,
memory usage or prover time. A finding is not evidence of an attacker-controlled
unbounded loop or denial of service. An unavailable finite estimate emits an
incomplete diagnostic instead of passing the configured check. A configured
threshold is a project review limit, not a performance guarantee.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/work-budget.compact`).

```compact
pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger count: Counter;
export circuit update(): [] {
  for (const index of 0..4) { count += 1; }
}
```

### Example 2

Correction (source: `tests/corpus/safe/work-budget.compact`).

```compact
pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger count: Counter;
export circuit update(): [] {
  count += 1;
}
```
