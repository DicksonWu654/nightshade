# exact-balance-threshold

Availability: **opt-in**. Severity **informational**, confidence **high** for the
resolved source relationship. Select with `--detectors exact-balance-threshold`.

Compact's `unshieldedBalance(color)` fixes the queried balance to its value at
transaction construction. Application requires that exact value to remain the
same, even when a threshold would still hold. The comparison helpers record the
comparison instead. This distinction is documented in the pinned standard library
and verified in owned compiler output on five supported compiler profiles.

## Example and review scenario

```compact
assert(unshieldedBalance(disclose(color)) >= disclose(amount), "balance");
```

If only the lower bound matters, consider:

```compact
assert(unshieldedBalanceGte(disclose(color), disclose(amount)), "balance");
```

A changing contract balance can make the first transaction depend on more than
its stated threshold. This finding does not demonstrate a failed transaction,
funds loss, missing funding, or deployed impact. Exact balance coupling can be
intentional; review it before changing the API.

## Matching and recommendation

The rule recognizes the canonical getter directly or through immutable local
identity aliases, disclosure and identity casts. Exactly one direct threshold
assertion must be its only terminal source use, and the bound must fit the
comparison helper's Uint<128> parameter. Reversed operands select the corresponding
helper. Canonical import aliases work; application namesakes do not.

Other numeric uses, equality/reconciliation, multiple bounds, closure captures,
computed values and retained snapshots withhold the finding. Even a dead-source
use conservatively retains the getter. Arbitrary helper forwarding, parameters
passed between circuits, compound conditions and runtime reachability are outside
this source matching contract. Entry-reference reachability includes syntactic
branches and zero-iteration bodies; it is not proof of execution.

Use the suggested comparison helper only when exact construction/application
balance equality is unnecessary. Preserve the same color and amount, and check
other validation and transaction effects. The getter and comparison APIs all
refer to the invocation's initial balance, not a running total after sends,
receives or mints.

## Evidence and limits

Owned realistic Counter positive/corrected/lookalike mutations retain the original
increment and notices. Getter-threshold / comparison-helper / exact-equality
controls compile on 0.30.0, 0.31.1, 0.33.0-rc.2, 0.34.0 and 0.35.0. Emitted getters
return the numeric ledger-query result; the corrected helper performs the less-than
operation inside the ledger query and returns a Boolean.

Reference: Compact 0.34.0 source `1f671fc27818df2b2676b3a97f85b2b821756243`,
`doc/api/CompactStandardLibrary/exports.md:961–969` and
`compiler/standard-library.compact:324–340`. The pinned 0.31.1 source
`0da5b0452eb0c1053d42418bf34b12cc29c7d63e` documents the same distinction.
These are reference/compiler facts, not independently labeled application bugs.

Missing front-end evidence and baseline resource exhaustion remain explicit.
The bounded source query discards its partial result on exhaustion and marks this
rule incomplete independently of baseline analysis. No new engine, budget increase,
symbolic execution, runtime evaluation or exploit confirmation is introduced.
