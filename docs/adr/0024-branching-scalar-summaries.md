# ADR 0024: Bounded branching scalar transfer summaries

Status: implemented. The implementation reuses the existing analyzer budgets;
validation must compare cached and uncached analysis results.

## Contract

Reuse the scalar helper only
under the existing exact argument, control and constraint key. Retain each
successful alternative as its own immutable journal. Do not join mutually
exclusive writes, cache caller storage or restore guard/constraint snapshots.

Admission remains limited to non-entry void helpers with ordinary Boolean/Field
parameters, one disclosed direct Boolean-parameter branch, root scalar assignments
from parameters/defaults/literals, optional prefix/suffix writes and an optional
final empty return. No calls, witnesses, assertions, loops, nested branches,
arithmetic, casts, destructuring, captured locals, ADT effects or storage-derived
operands qualify. Runtime arguments carrying storage, predicate, comparison,
negation, equality, commitment or aggregate metadata also decline the cache.
Guard-cover mode continues ordinary interpretation.

Instruction address temporaries can read current storage even in this restricted
subset. Replay may omit their snapshots only if no nonparameter callee-owned
value remains live at a join. Both actual CFG routes must satisfy the structural
contract, which excludes merge instructions. Refusal is an optimization miss;
ordinary interpretation still reports unsupported effects or exhausted budgets.

## Recording and replay

Cloned states share immutable journal tails. Appending a node-cleanup marker,
branch choice, scalar assignment or completion creates a new link for that path.
Candidates remember the owning circuit and branch site. Unexpected evaluations,
ledger operations, non-write sinks or foreign choices/completions invalidate the
whole candidate. Active legacy linear recorders are invalidated before recording
or replaying branching alternatives, preventing concatenation into a linear effect
history. A candidate with two observed choices and only one deduplicated completion
is conservatively refused.

Replay executes the physically shared prefix once and then forks the current
state in ordinary completion order. Reexecuting prefix assignments independently
would allocate different write identities; restoring a cached prefix state would
instead reuse stale storage and guards. Shared node identity identifies the prefix,
not equality of serialized events. Each arm executes its own suffix even where
source CFG nodes converge.

Parameter binding and node scope cleanup use the same helpers as interpretation.
Cleanup scans current caller references when forgetting dead constraint identities.
Replay applies each selected assumption and preserves the CFG's actual control
lifetime, including `-1` when assignment abort edges extend private control beyond
syntactic convergence. Assignments use the ordinary mutation transfer, recomputing
before-values, ledger revisions, publication, current guards and invalidation.
Completion rebases the call path and adds the helper guard. Join deduplication uses
current state, never saved state identities.

The helper's only result is an empty tuple. It carries no private data; public
write sinks retain selected control and operand provenance. Caller scalar returns
read current storage after replay. Successful facts, full traces, failed assertions
and completion coverage must agree with ordinary interpretation in each engine.

## Bounds and measurement

A candidate has at most 256 physical journal events, shared by at most two
alternatives. Branch caches share the existing 256-entry and 4,096-retained-event
limits with other summaries. Journal expansion is bounded and rejects cycles or
oversized chains. Cache saturation falls back without truncating effects.

Calls still check recursion/depth before lookup. Replayed events charge steps,
shared writes charge ordinary value budgets, and caller expansion checks account
for every returned alternative, including calls in final returns. Cold partial or
incomplete executions cannot seed a summary. No analysis limit is raised.

`summaryHits`, `summaryEntries`, `statefulSummaryHits` and `summaryEffects` include
these journals; node markers count as retained events. This does not introduce a
new public coverage mode or schema. Lower interpreted step counts are not evidence
of a wall-time improvement. Separate fresh-process measurements must retain
compiler acceptance, full observation agreement, actual hits, all attempts and
unchanged host-local regression thresholds.

## Boundary

This is a restricted interprocedural optimization. An unknown ordering result
currently lacks a reusable Boolean identity; repeated calls can retain four
conservative histories for two concrete outcomes. Preserving those histories is
reference equivalence, not improved relational precision. General correlated joins,
read-dependent or constraining branch summaries, the default call-free ten-branch
workload and independent review remain open. It does not establish Slither parity
or public-release readiness.
