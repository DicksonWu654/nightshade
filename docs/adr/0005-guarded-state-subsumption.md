# ADR 0005: Guarded-state subsumption without invented histories

Status: implemented as an opt-in core API experiment, 2026-09-25. The CLI and
`scanFile` retain equivalent-state deduplication. General may/must joins remain open.

## Problem and scope

Unioning path histories can pair a hash binding in one arm with a publication in
the other. Intersecting guard sets alone can also invent a path that contains neither
of two mutually exclusive guard calls. Later assertions must still be able to discard
incompatible predecessors. A successful-path fact must not silently become a bag of
uncorrelated effects.

The first step is a **guard antichain over otherwise equivalent continuation states**.
This reduces redundant guard variants without joining different private values,
storage, bindings, publications or transition observations. It is not a general
value lattice, effect-history DAG or solution to exponential stateful branches.

## Compatibility and partial order

At a CFG join, match the node and, for an expression merge, its predecessor. The
continuation identity includes live values, ledger regions/revisions, constraints,
ambient control, ordered bindings/sinks/writes, source identities, transforms and
call paths. Only descriptive provenance traces and guard sets are excluded.

Each compatible state has a guard vector: the current completed guards followed by
the guard set **at each historical write**. State A covers B only when every set
in A is a subset of its corresponding set in B. Keep A as an actual predecessor;
do not construct a third state. Incomparable vectors remain separate. For comparable
sets, the retained predecessor supplies their intersection without inventing evidence.
May dependencies already agree by the compatibility precondition; no dependency is
discarded or unioned across inconsistent histories.

This relation is preserved by the modeled guard transfers: adding a successfully
completed circuit, invalidating guards that read mutated state, and recording the
current guard set at a new write. Neither guard membership nor historical guard
observations control execution or assertion evaluation. Equivalent continuation
values/constraints therefore permit the same future transitions. Every missing-guard
observation on a removed predecessor is also present on its retained covering path.

The DFS worklist may already have evaluated a stronger predecessor before a weaker
one arrives. Its completed observations are not retrospectively removed. This affects
optimization, not coverage; the result need not be a minimal set of paths.

## Constraint liveness and provenance

In the opt-in mode, predicates referenced only by ambient control do not keep
constraint-map entries alive. Control is used for provenance, not reevaluated as a
condition. Retain the control values and their implicit flows unchanged. Constraints
whose identities remain in live locals, captured values, ledger values, comparisons
or negations remain live; ledger identities also retain the existing conservative
exception. Later uses of a branch flag must therefore prevent premature subsumption.

Do not drop provenance merely because a flag is no longer used as an expression.
Conditional aborts can keep it relevant to a later public effect. Tests check captured
predicates, later rejection, implicit sinks and guard invalidation after mutation.

## API and bounds

```ts
const facts = new Dataflow(
  program, 20000, 256, 50000, "instructions", true, true, "guard-cover"
).analyze();
```

`facts.pathSemantics` distinguishes `guard-cover` from the default
`equivalent-states`; `metrics.guardSubsumptions` counts additional covered states.
The seven current detectors are compatible: they either ignore guard membership or
report a missing individual required guard. **A future detector querying existence
of a present guard, combinations of guard histories or exact path counts must use
the default mode or establish a separate abstraction contract.** A guard-cover
completion is not a claim that every guard-bearing path was enumerated.

Each invocation stores at most 256 guard profiles and 4,096 profile-set/membership
units. Profiles are immutable snapshots. If the optimization table cannot accept a
profile, interpret normally; never prune an unrecorded state. Existing step/path/value
budgets still yield incomplete diagnostics. Tables do not survive an invocation or
analysis call. Summary eligibility and replay remain unchanged.

## Qualification and related correctness fix

`tests/guard-cover.test.ts` compares detector identities/locations/messages against
the exact-path mode on all 25 labeled cases and compiler-checked inline programs.
Cached/uncached guard-cover paths and failure traces must match completely. Cases
exercise current and historical guard vectors, incomparable guards, private source
identity, mutually exclusive binding/publication, captured predicates, later aborts,
summary invalidation, repeated analyses and budget exhaustion.

This work also exposed a default-engine defect: state hashing removed every JSON
property named `trace`, including a **user struct field**. Two different field values
could consequently deduplicate. Trace removal now recognizes analysis flow/binding
metadata; user fields named `trace` or `guards` remain data. A compiler-valid helper
returning either field value now preserves both alternatives. This fix applies to
the default engine as well as guard-cover mode.

`benchmark:guards` alternates five fresh processes per mode. Six optional checks
compare completed detector observations; twelve checks compare coverage under the
same budgets, without presenting partial exact output as an equivalence oracle.
Compiler acceptance is recorded separately. Ten independent Counter-update branches
still exhaust the path budget, including in guard-cover mode.

Promotion to scanner default requires further independent abstraction review. The
remaining P05 work includes general may-value joins, correlated effect histories,
state-dependent/branching summaries and independent compiler/IR conformance.
