# ADR 0022: checked Counter boundaries

Date: 2026-09-26. Status: implemented.

## Evidence

The Compact 0.34.0 release source is
`1f671fc27818df2b2676b3a97f85b2b821756243`. Its ledger catalogue initializes
Counter as an eight-byte unsigned cell, reads Uint64, accepts Uint16 updates,
and lowers increment/decrement to `addi`/`subi`. At the corresponding ledger pin
`4823b5351b17cc49e30f19760dbd30a73cf95e22`, `onchain-vm/src/vm.rs` decodes those
operands as `u64` and uses checked addition/subtraction. Overflow and underflow
return `ArithmeticOverflow`. The exact source hash and restoration pins are in
[the runtime fixture record](../runtime-qualification.md).

Owned fixture qualification uses runtime 0.19.0 and fixed synthetic Counter
representations. Before evaluation, the adapter checks the compiled constructor
layout, eight-byte alignment, public descriptor roundtrip, contract-state
serialization and generated ledger accessor. Ten fixed cases exercise exact
maximum success, zero updates, overflowing increments, Uint16 maximum updates
and underflow. Each starts from a separate snapshot; inspect/update/inspect/reset
observations and retention of input snapshots are checked.

These inputs establish the selected representation/evaluation behavior, not
deployment reachability, proof validity, transaction acceptance or transaction
atomicity. The adapter accepts neither arbitrary state nor source from requests.
The earlier research-source evidence in ADR 0019 remains a separate checkpoint.

## Decision

If a known Counter update computes a result outside Uint64, terminate that
successful analysis path. Previously, the failed Uint64 conversion discarded the
constant and incorrectly retained a possible successful update. Handle this in
the shared `counterMutation` transfer so methods, compound assignments and eligible
mutation-summary replay agree. Do not change general Uint arithmetic.

Unknown operands remain conservative. An unknown result is neither a wrapped
integer nor evidence that a transaction will apply. Definite ledger arithmetic
rejection does not fabricate a source assertion failure. Cached updates recheck
the current storage value, including overflow after a previous successful call.

## Validation

Compiler-valid regressions use explicit equality guards on entry storage; those
guards state a precondition and do not prove that the constructor reaches it.
All tests compare complete paths and detector observations across both engines
and cache settings. Method-helper replay tests require real stateful cache hits;
compound assignments remain outside summary eligibility and execute normally.
Success controls include exact-boundary updates, zero operands and retained
pre-update snapshots. Unknown-operand controls retain a possible successful path.

These checks do not qualify other ledger ADTs or establish complete release
qualification.
