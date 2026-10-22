# ADR 0020: Exact-context read-only circuit summaries

Status: implemented.

## Eligibility and context

The read cache extends the pure and linear mutation caches with straight-line
circuits whose transitive effects only read storage. Scalar/field reads and
modeled read-only queries may be reused. Witnesses, assertions, branches, checked
operations/casts, dynamic projections, captures, higher-order operations,
unsupported derived natives, recursion and writes remain excluded.

Map lookup is excluded, including lookup through a nested receiver. Successful
lookup refines membership and a missing entry can abort (ADR 0019); it is not an
effect-free query. Eligibility is an optimization boundary, not a claim of wider
language support.

A key includes circuit identity, exact arguments, ambient control and current
constraints, plus every transitive read root's stored regions, revision and
collection facts. A root revision alone is insufficient: successful lookup can
refine membership without a write or a change to the generic constraint maps.
Unrelated writes need not invalidate reuse. Arguments carrying storage regions
or ledger evidence bypass caching. Private source identities and traces remain
part of the context; separate entry inputs cannot share their provenance.

## Replay

A summary retains its returned abstract value and ordered public-sink/completion
events. It never stores caller storage, guards, bindings or control snapshots.
Replay clones current caller state, rebases call suffixes, appends every sink and
re-enters the shared completion transfer. Replayed events participate in enclosing
recordings, including nested cache hits. Later writes still invalidate guards
using their transitive read roots. Returned Boolean predicates retain their
original revisions, and returned comparison/hash evidence remains available to
the caller's assertion transfer.

Read-only operations record public sinks; writes and refining operations record
transfer events. An unexpected transfer invalidates an active read recording
instead of silently dropping the event. Interpretation still performs the effect.
This is defensive protection against future eligibility/transfer drift, not
evidence of a previously reachable missing-effect defect.

## Resource limits and failure

The read cache admits at most 64 read roots and 256 stored regions per footprint.
All cache modes share 256 entries and 4,096 retained effects; each effect recording
is limited to 256 events. Exceeding cache capacity falls back to interpretation.
It does not by itself make analysis incomplete because no semantic work is lost.

Replay checks maximum transitive call depth and charges each ordered event to the
step budget. Analysis depth, step, value and collection exhaustion remain explicit
incomplete diagnostics. Failed/incomplete calls cannot seed a successful summary.
Cache capacity and analysis budgets have different meanings and are tested
separately. `readSummaryHits` counts read reuse; aggregate summary metrics include
read entries/effects while `statefulSummaryHits` remains mutation-only.

## Evidence and limits

Compiler-backed integration and resource tests compare cached/uncached execution
within both engines, including full traces and call paths. Cross-engine checks
compare semantic paths, assertions and entry completion. They require actual cache
hits and assert concrete constants, private sinks, policy observations, guard
invalidation, snapshot freshness and nested completion order. Recorder unit tests
exercise defensive rejection and independent nested recording limits. Packed
consumer checks cover reuse, invalidation, public sinks and isolated API metrics.

The paired benchmark alternates five fresh processes per mode, requires compiler
acceptance and identical full observation hashes, and preserves failed results.
Performance on the new server is a separate baseline; historical artifacts are
unchanged. Cache overhead can exceed interpretation cost on small helpers.

These are implementation regressions and compiler acceptance checks, not independent
security labels. General correlated joins, branching/constraining summaries,
unknown-key algebra, List ordering and the ten-stateful-branch completeness gap
remain separate work. Symbolic execution is out of scope.
