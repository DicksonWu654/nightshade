# ADR 0023: Revision-checked List nonempty refinement

Date: 2026-09-26. Status: implemented.

## Grounding and scope

At the pinned Compact 0.34.0 release, List `isEmpty()` tests whether the tail
has the VM Null tag. `popFront()` replaces the List with that tail without
decoding its head. A well-formed, nonempty typed List therefore permits a pop
even when the analyzer cannot recover its head payload. The separate fixed
guarded runtime fixture checks one-cell and
multi-cell tails, empty-guard rejection, and retained accepted snapshots.

This contract assumes well-formed typed List storage. A nonempty predicate is
not a validator for arbitrary malformed injected representations. Evidence is
compiled circuit evaluation, not proof verification or transaction application.
The earlier unguarded empty-pop observation and its explicit incomplete analysis
remain unchanged.

## Domain and assumptions

Extend the existing ordered prefix with a tail state of `empty`, `unknown`, or
`nonempty`. Tail facts and structural provenance remain separate from known
prefix payloads. A revision-matched, canonical exact-region `isEmpty()` predicate
can establish an empty or nonempty tail only when the prefix is empty and the
current domain permits it. Contradictions prune successful paths.

A guard on an already nonempty prefix says nothing about its suffix. Conversely,
a nonempty suffix established before a push survives removal of that known
prefix. Popping a proven nonempty unknown tail consumes its proof and produces
an unknown tail. The transfer invents neither a payload nor an exact length.
Subsequent emptiness is unknown and another pop needs fresh evidence. A known
nonempty List can have a present Maybe head with unknown payload.

Predicate metadata retains canonical region, root revision and structural
dependencies. Shared assumption handling supports stored predicates, negation,
and Boolean equality/inequality. A saved predicate cannot refine a newer root
revision. Ancestor and wildcard writes invalidate overlapping facts; wildcard
queries never establish must-equality or a universal nonempty fact. Established
facts may survive disjoint writes, while saved predicates conservatively require
an unchanged root revision.

## Provenance, replay and limits

Assumption-created structure retains ledger and region-selection dependencies.
Pop combines prior/current structure with current control and selection evidence;
it does not contaminate the remaining tail with an unconditional popped payload.
Saved Maybe/predicate/payload values stay snapshots. Writes record completed
caller guards before invalidating guards that read the mutated root.

Both engines and mutation replay use the existing shared ledger transfer.
Summaries cache operations, never a prior pop's eligibility or stored proof.
Read footprints, state identity, cloning and retained-value liveness include the
new facts. Same-revision refinements distinguish read-cache contexts. Arguments
carrying predicate storage evidence bypass context-free summary reuse.

Assumption-created regions consume the existing 256-region capacity. Existing
cell, value, step, path and summary limits remain unchanged. Exhaustion is sticky
and produces explicit incomplete diagnostics. Empty or possibly empty pop keeps
`list-pop-outcome-unqualified`; it is neither a fabricated assertion failure nor
an assumed no-op.

## Validation boundary

Domain tests cover contradictions, prefix/suffix separation, cloning, invalidation
and capacity. Compiler-backed integrations compare instruction/reference engines
with caches enabled/disabled, including complete observations and actual cache
hits where reuse is claimed. They check stale snapshots, selection/control
provenance, nested replay, caller guards and resource exhaustion. The fixed
runtime tests provide separate semantic grounding beyond engine agreement.

This is a narrow structural refinement. General List algebra, cardinality
relationships, correlated joins, branching summaries, coin/tree/Kernel effects
and independent abstraction review remain open.
