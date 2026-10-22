# ADR 0007: Resolved higher-order calls reuse ordinary call transfers

Status: implemented for the bounded source model, 2026-09-25.

## Semantics and evidence

Compact `map` and `fold` invoke circuits or witnesses, including named overloaded
and explicitly specialized generic targets, anonymous circuits, and standard-library
circuits. Sequence arguments are evaluated once, left to right, before callbacks.
Fold evaluates its initializer before the sequences; each returned accumulator is
passed to the next invocation. Zero-length inputs invoke no callbacks.

`infer-types.ss` at compiler revision `b3a90d…` provides the relevant `do-call`,
`max-type`, `vector-element-type`, `map` and `fold` rules. The reference's circuit
call and sequence sections describe the same contract. Source HEAD is not the release
version, so the tests independently check acceptance/rejection with Compact 0.34.0,
language 0.26.0. No witness implementation or compiled contract is executed.

Important boundaries confirmed against the release:

- Tuple element inference compares each type against the current maximum under
  subtyping; choosing only the first element is incorrect. It does not synthesize arbitrary
  componentwise least upper bounds for incomparable tuple elements.
- Uint widening is subtyping; Uint-to-Field is **not**. Arithmetic accepting mixed
  operands does not imply function arguments may omit explicit conversions. An
  earlier analyzer assignability shortcut was removed after compiler rejection.
- Fold's return type must equal its first parameter type. Overload filtering uses
  this condition before testing uniqueness; it does not choose the narrowest overload.
  A declared anonymous return type contextualizes an undeclared accumulator parameter
  only when the initial argument is assignable to that type.
- An empty tuple's element is a bottom type during argument inference, not an unknown
  private value. In contrast, `Vector<0, Field>` and `Vector<0, Boolean>` retain their
  different declared element types. This also applies inside nominal generic aliases.
- `keccak256<T>` takes an input **type** parameter, not a byte-count parameter.
  Release-compiler tests cover nominal and higher-order calls to it.

## Reusable resolution

`Program.commonType` and a shared sequence-shape query compute bounded iteration
types. Map, fold, `for-of` and slice use the same element-type semantics. Incomparable
elements, mismatched sizes, unknown types and sequences beyond 256 elements fail
with explicit diagnostics. Empty types cannot stand in for unresolved information.

Ordinary and higher-order named calls share overload candidate filtering. Candidates
must match generic kinds/counts, argument types and, for fold, accumulator/result
identity. Selected imports/prefixes retain their overload groups. Generic witnesses
and circuits specialize before invocation. Anonymous calls check argument arity and
types; annotated anonymous return expressions check their declared types.

The intrinsic catalogue now records parameter types and generic parameters in
addition to result/provenance classification. Higher-order intrinsic calls validate
these contracts instead of assuming arity alone establishes compatibility. Nominal
calls use the same signatures. This is not a complete compiler legality checker,
nor does it model curve equations or all primitive abort conditions.

## Shared transfer semantics

The data-flow iterator supplies already evaluated arguments to the ordinary call
transfer. It does not maintain a second witness/hash/commitment implementation:

- Witness invocations receive fresh source identities, retain argument dependencies,
  and preserve the exact callback-reference span. Repeated iterations do not reuse
  an earlier witness result. Direct witness map/fold instructions expose that effect.
- Hash/commitment transformations and constructor field sensitivity match ordinary
  calls. Existing detectors consume these facts without new traversal logic.
- Circuit calls retain captures, constraints, caller guards, source traces and
  effect order. Repeated eligible mutations may reuse transfers, not ledger snapshots.
- An abort discards the successful path, including prior iteration writes. Empty
  iteration cannot fabricate guard completion. Callbacks consume analysis budgets;
  incomplete execution remains diagnosed.
- Source-work estimates unwrap nominal sequence types before multiplying callback
  costs. This remains a source-operation estimate, not proof-row or runtime prediction.

## Qualification and limits

`higher-order.test.ts` includes compiler-positive and compiler-rejected applications,
cached/uncached full-fact and instruction/reference comparisons, source spans, policy
observations, zero/oversized sequences, overloads, captures, effects and budgets.
`higher-order-library.compact` composes a generic witness, overloaded circuit, hash
and constructor. Two older transfer-unit snippets now spell compiler-required Field
casts; their original assertions are unchanged.

These are implementation regressions, not independently labeled security findings.
Lexical overload fallback is now covered by ADR 0008 and module-state composition
by ADR 0009. Full type validity, generic circuit cache equivalence and general
correlated stateful joins remain separate release work.
Higher-order transfers do not remove path/sequence budgets, enable symbolic
execution or establish independent detector precision.
