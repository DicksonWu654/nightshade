# ADR 0019: Bounded collection facts and definite ledger failures

Status: implemented; qualification depends on the selected compiler profile.

Subsequent work: ADRs 0021–0022 add bounded List facts and checked Counter overflow
using matching-release/runtime evidence. The source and qualification scope below
remain the historical Map/Set and definite-underflow checkpoint.

## Evidence and scope

Target: compiler 0.34.0 / language 0.26.0, default ZKIR2. Source evidence is pinned
to `LFDT-Minokawa/compact` revision
`b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`:

- `compiler/midnight-ledger.ss` declares empty Map/Set defaults, replacement/idempotent
  insertion, membership, size, removal and reset operations. `doc/ledger-adt.mdx`
  documents their source signatures. Removing an absent key does not introduce an
  entry or decrement cardinality.
- Map lookup uses a ledger index operation, not an option/default result. The
  generated accessor in `compiler/typescript-passes/print-typescript.ss` rejects
  undefined entries. `compiler/test.ss` explicitly expects failed missing-key
  lookups, including nested ADTs. `examples/adt/negative/map_failing.compact`
  exercises failed lookup during a circuit call.
- Counter decrement documents a runtime error below zero in `midnight-ledger.ss`
  and `ledger-adt.mdx`; `examples/adt/negative/counter_failing.compact` supplies
  the corresponding negative example.
- `runtime/src/circuit-context.ts` executes ledger queries during circuit
  invocation. These operations are not merely unconstrained annotations.

Compiler acceptance is checked separately from these runtime-semantic sources.
We do not run upstream negative cases, reproduce compiler vulnerabilities, or
claim that a compiler-accepted transaction necessarily applies. The Rust
onchain-runtime checkout is not present; its implementation is not independently
qualified here. Overflow/transaction atomicity and empty List pop behavior remain
outside this change.

## Domain contract

`src/dataflow/collections.ts` owns finite Map/Set facts separately from stored
values: per-region default membership, concrete-key presence/absence, and exact
cardinality when known. Unknown external state is not empty. Constructors,
explicit resets and default-valued writes establish emptiness; constraints only
refine possible states and do not fabricate ledger mutations.

Known-key insertion/replacement and removal update membership and cardinality.
Unknown keys and wildcard receivers weaken affected facts. Replacing an ancestor
invalidates possible descendant containers without deleting the ancestor's own
membership. Exact scalar keys are tracked; aggregate/nonconstant keys remain
conservative. No identity-based alias proof is invented for unknown keys.

Both tracked containers and total key facts are bounded at 256. Exhaustion is
sticky and emits `collection-budget`; a dropped fact cannot turn an unfinished
entrypoint into a complete scan. Clones isolate branches, and stable snapshots
participate in equivalent-state and guard-cover continuation identities.

## Shared transfers

The common ledger transfer serves the instruction engine, expression reference
engine and cached mutation replay. `member`, `isEmpty` and `size` expose constants
when justified. Boolean membership/emptiness conditions and assertions refine
facts, including direct negation and Boolean equality forms. Successful lookup
establishes presence; known absence terminates that successful path instead of
returning an unknown/default value. Known Counter underflow likewise terminates
method and compound-assignment paths, including replayed summaries.

Query values remain snapshots. Their predicates carry a ledger-root revision, so
branching on a saved pre-write Boolean cannot constrain post-write membership.
Mutation invalidation is deliberately root-wide for predicate freshness, even
where finer region invalidation might retain more precision. Private source/key
dependencies, operation-argument sinks, caller control, guards and write histories
continue through the existing value/effect engine.

Wildcard regions are may-alias sets, not value identities. Different dynamic
receiver keys must not make their lookup/member/emptiness/size results equal.
Review exposed four compiler-valid cases where the old wildcard-derived identity
falsely made a possible inequality fail. Scalar wildcard reads and collection
queries now withhold that identity; concrete same-revision queries retain it.
Regressions require both a successful path and no spurious detector finding.
Correlating repeated unknown-key reads or saved wildcard values more precisely
requires a separate stable snapshot/address identity model; it is not inferred
from a shared wildcard storage region.

Summary entries retain operands and order, not old storage. Every replay rechecks
current collection/Counter facts and may now abort even when the recording call
succeeded. Eligibility remains restricted to existing linear state-independent
operands: moving a literal cast outside a helper in a cache regression is not
permission to cache arbitrary checked expressions.

## Validation and remaining work

- A standalone domain suite compares short deterministic operation sequences
  against concrete finite sets, and tests assumptions, wildcard invalidation,
  cloning, snapshots and resource bounds.
- Collection integrations compare complete paths, assertions, entry completion
  and detector observations with caching disabled and the expression reference.
  Compiler-valid programs exercise nested defaults, replacement, removal, private
  keys/control, operation ordering, policy preservation and cached underflow.
- Snapshot regressions check pre-write predicates, successful lookup refinement,
  constructors versus unknown entry state, nested failure and budget diagnostics.
- A composed compiler-feature fixture and packed CLI/API consumers exercise the
  new transfers. The existing security corpus and detector labels are unchanged.

One old region regression expected reset followed by missing lookup to return an
unknown value. It now expects no successful path, and a separate reinsertion case
checks that old private provenance does not return. This corrects the test's
semantic assumption rather than weakening a detector expectation.

The domain does not implement List ordering, exact unknown-key relationships,
size intervals, full collection algebra or general correlated state joins.
State-dependent call summaries and the default engine's stateful branch explosion
remain separate work. This is reusable analysis infrastructure, not a new
detector, independent security review or Slither-parity claim.
