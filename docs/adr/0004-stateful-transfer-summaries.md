# ADR 0004: Stateful transfer summaries, not cached ledger snapshots

Status: implemented for the bounded linear subset, 2026-09-25.

## Problem

The pure-call cache cannot reuse helpers that publish derived values, update a
Counter, or insert into a collection. Reusing their previous post-state would be
incorrect: storage, caller guards, region revisions and write history may have
changed. Copying earlier write facts also corrupts transition checks and can retain
authorization that a preceding mutation invalidated.

General branch joins need a separate design: dependency union and must-guard
intersection alone do not preserve correlations between bindings and publications.
Do not silently combine mutually exclusive effects into a purported successful path.
This change advances interprocedural reuse without pretending that path explosion
or general effect-history joins are solved.

## Transfer model

`MutationCircuitEligibility` recognizes resolved, capture-free, branch-free circuits
whose body does not read ledger values into computation, call witnesses, assert,
perform checked casts/projections, or invoke an unmodeled/uncertain intrinsic. Calls
must recursively satisfy the same contract. Supported mutations are direct ledger
root assignments and modeled root-ADT mutation methods returning `[]`. Parameters
may be projected normally, but ledger-backed abstract arguments are not cache keys.
Dynamic/nested addresses and compound assignments remain interpreted.

For a successful eligible invocation, record an ordered transfer sequence:

1. **Assignment:** target region, independently computed assigned value, source span.
2. **Ledger operation:** resolved operation, target region, independently computed
   arguments. Never cache its previous receiver or resulting stored value.
3. **Circuit completion:** actual nested completion order and caller-relative call path.

On reuse, invoke the existing state transfer functions against current storage.
Recompute before-values, exclusions, ADT receiver dependencies, wildcard joins,
strong updates, revisions, publication sinks and guard invalidation. Append these
new facts to the current history instead of replacing it. Replay successful
completions in their original positions between mutations. Rebase call paths to the
current caller; definition/source spans remain unchanged.

The returned abstract value and mutation operands depend only on the exact typed
arguments, their source identities/traces, caller constraints and ambient private
control. All of these are in the cache key. History, guards and storage are not
cached inputs: eligible computation cannot inspect them, and transfer effects are
re-evaluated. Existing hash bindings and failure/success histories remain caller data.
Assertions and witness evaluation are deliberately ineligible, not cached as opaque
effects. A caller abort still discards every successful-write observation from that
invocation.

Nested recordings include effects of both interpreted and already summarized
callees. Every recording is unwound on exceptional/early exits. Eligibility examines
reachable bodies; unreachable calls do not become guard completions. Cached pure
and stateful calls also check their transitive call depth against the current stack,
fixing a prior pure-cache shortcut that could bypass the 32-circuit depth limit.

## Bounds and fallback

- At most 256 pure/stateful entries combined, 256 events per recording and 4,096
  cached mutation events per analysis. Overflow abandons that recording and retains
  ordinary interpretation, not a truncated effect sequence.
- Each replayed event consumes a step. Dynamic region/value expansion retains its
  existing budgets. Incomplete interpretation is never admitted to either cache.
- Caches are reset for every `analyze()` call. No disk or cross-project cache exists.
- `statefulSummaryHits` and `summaryEffects` expose reuse and cached transfer size;
  `summaryHits` and `summaryEntries` include both kinds.
- For regression comparison, the seventh constructor argument can disable only
  stateful summaries: `new Dataflow(program, 20000, 256, 50000, "instructions", true, false)`.
  The existing sixth argument `false` disables all summaries.

## Qualification and remaining work

Complete cached/uncached path facts, source traces, failed assertions and completion
coverage are compared in `stateful-summaries.test.ts`. Positive inline cases compile
when `COMPACTC_TEST` is supplied. The feature fixture covers whole-aggregate writes,
Map insertion, Counter mutation and nested helper replay. Dedicated cases exercise
changed prior storage, guard invalidation, rebased callers, distinct witnesses,
implicit flow, caller aborts, key sinks, reset semantics and recording/budget limits.

Compiler qualification rejected direct assignment to a plain struct projection
(`pair.first = value`): that expression has a value type, not an ADT lvalue. The
qualified aggregate examples replace the whole ledger value. Summary eligibility
therefore requires a direct ledger root rather than inventing mutable struct-field
addresses. Existing abstract-region unit tests are not whole-language type validation.

`benchmark:summaries` alternates five fresh processes per mode on identical derived
scalar, Counter and aggregate/Map workloads. Both modes retain pure summaries; all
path/trace observations must match. Optional explicit `--compiler` records source
acceptance separately. Timing is measured, not assumed to improve for every workload.

State-dependent computation, guards/constraints, branching callees, general joins,
collection membership/absence semantics remain unfinished.
Ten independent stateful branches still exceed the default exact-path budget. Do not
promote this transfer cache to a claim of full stateful summary coverage or Slither
parity. This ADR extends, but does not complete, the release plan's P05/P09 gates.
