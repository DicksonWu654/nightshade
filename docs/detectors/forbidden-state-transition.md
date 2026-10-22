# forbidden-state-transition

Availability: **policy-required**; selected by default, but needs
`policies.transitions`. Severity **medium**, confidence **medium**.

Reports a scalar ledger write whose modeled prior-state constants/exclusions and
next value do not exclude a forbidden transition. Policies support enum, Boolean
and numeric state; `"to": "*"` forbids any mutation from the selected prior state.

## Example and review scenario

The compiler-qualified owned [fixture](#example-1)
sets `phase` to `OPEN` without excluding `CLOSED`. Its policy is:

```json
{ "transitions": [{ "state": "phase", "from": "CLOSED", "to": "OPEN" }] }
```

Place this object under `policies` in the [configuration](../configuration.md).
The [correction](#example-2) enforces:

```compact
assert(phase != Phase.CLOSED, "terminal state");
phase = Phase.OPEN;
```

Recommendation: compare the reported write with the application's transition
table and constrain the old state before mutation. Review terminal states and
all writers, including helper-mediated writes.

## False positives and limitations

Unknown prior or next values leave transitions possible; a report does not prove
that the old state is reachable across transactions. Application invariants
outside the modeled invocation can make a match intentional or infeasible.
Aggregate/collection member transitions and general transaction sequences are
outside this scalar rule. Policies provide the intended prohibition; findings
do not infer it. Missing models and exhausted budgets remain incomplete.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/forbidden-transition.compact`).

```compact
pragma language_version >= 0.26.0;
export enum Phase { OPEN, CLOSED }
export ledger phase: Phase;
export circuit reopen(): [] {
  phase = Phase.OPEN;
}
```

### Example 2

Correction (source: `tests/corpus/safe/forbidden-transition.compact`).

```compact
pragma language_version >= 0.26.0;
export enum Phase { OPEN, CLOSED }
export ledger phase: Phase;
export circuit reopen(): [] {
  assert(phase != Phase.CLOSED, "terminal state");
  phase = Phase.OPEN;
}
```
