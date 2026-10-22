# ADR 0002: expression effects, bounded summaries and scan isolation

Status: implemented for the experimental supported subset, 2026-09-25.

## Problem

Statement-only CFGs hide conditional-expression, short-circuit and nested assertion
effects inside recursive transfer functions. Analyses of guards, dominance and
privacy need those boundaries. Replacing the evaluator, adding general joins and
broadening language support simultaneously would obscure regressions. Cooperative
analysis counters also cannot contain a native parser crash or hang.

## Decisions

Keep the owned AST and statement CFG. Lazily lower a second instruction CFG via
`Program.instructionCFG(functionId)`. The default data-flow engine executes it;
the recursive expression evaluator remains an explicitly selected regression oracle.

- Evaluation instructions name ordered operand temporaries and one result. Their
  original expression supplies operator/type/source metadata, not recursive execution.
- Conditional expressions and short-circuit operators become branches. A merge
  selects a value by incoming predecessor. Expression temporaries have one definition;
  dominance/merge-edge verification checks every reachable use before analysis.
- This is **expression-temporary SSA**, not whole-program SSA. Mutable ledger regions,
  lexical bindings and path histories are not converted into memory SSA or phi lattices.
- Source-mapped effects distinguish state addresses from reads, writes, witness calls,
  ordinary calls, constraints and disclosure permission. Potential assertion/cast/
  ledger/callee aborts have edges; exact dynamic rejection stays in transfer functions.
  Modeled total helper/hash calls do not acquire fictitious abort edges.
- Map/fold remain bounded higher-order instructions with a resolved target; their
  invocations use the same instruction engine. They are not flattened into one large
  interprocedural CFG. Unknown effect models still fail visibly.
- Statement-level source-work budgets retain their existing versioned definition;
  extra lowering temporaries do not inflate that measure.

The verifier computes dominance through an acyclic predecessor worklist and tree
intervals rather than retaining a quadratic set of every definition at every node.
Liveness drops dead operands/bindings during execution, not just at branch joins.

Cache at most 256 exact-context outcomes for eligible, capture-free, branch-free
circuits without ledger access, witnesses, assertions, checked projections/casts or
uncertain derived intrinsics. Keys include typed arguments, identities, traces,
constraints and ambient control. Reuse preserves caller state and replays only
actually reachable successful circuit completions in execution order. Source-backed
ledger arguments are excluded. Caches belong to one analysis run; there is no
cross-project/on-disk cache. Misses use ordinary interpretation. Summary hits still
consume a step and cannot turn exhausted analysis into complete analysis.

ADR 0004 extends this cache with bounded linear stateful transfer sequences, not
post-state snapshots, and adds transitive call-depth checks on cache hits.
These summaries are not general recursive/context-sensitive effect summaries.
Distinct stateful histories still require bounded paths. Future finite may/must joins
must union dependencies and intersect guards, with separate feasibility metadata.

CLI scans run each root sequentially in a supervised Node process. Defaults are a
60-second wall timeout, 512 MiB V8 old-space limit, 16 MiB combined stdout/stderr limit
and 1 MiB request limit. Timeouts, worker failures and output exhaustion produce an
incomplete report and CI exit 2. The supervisor cleans the worker's scratch directory
even after termination. POSIX workers use their own process group so explicit
compiler subprocesses are terminated with them. SIGINT/SIGTERM stops the current
scan instead of advancing to more roots.

This is **fault containment, not a security sandbox**. V8 old-space is not RSS/native
memory. Services processing hostile inputs still need OS/container CPU, RSS, disk
and filesystem controls. `scanFile` remains a synchronous in-process API;
`scanFileIsolated` is its asynchronous bounded alternative. Structural printers are
in-process and are not qualified as an untrusted-input service endpoint.

## Evidence and limitations

All 25 existing corpus cases compare findings and selected path facts between the
instruction and reference engines. Dedicated tests verify source spans, short-circuit
effect order, temporary dominance, merge predecessors, abort edges and invalid IR.
Summary tests compare complete path facts with caching disabled, including guard
order, unreachable calls, changing inputs/constraints and private control. Worker
tests exercise bounded timeout/output, error reporting, scratch cleanup and packed
distribution. These are implementation regressions, not independent security review.

Public APIs treat a Program as an immutable analysis snapshot. Construct a new Program
after source/options change; mutating its internal symbols/graphs does not invalidate
caches automatically. IR format `expression-effects-v1` is experimental. Do not yet
promise an external plugin ABI or a stable symbolic-execution serialization contract.
