# ADR 0015: Validate ordinary values before interpreting effects

Status: implemented for compiler 0.34.0 / language 0.26.0, 2026-09-25.

## Compiler evidence

Source revision `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad` defines
subtyping, result checking, conditional joins, local bindings, assertions, struct
initialization and ledger assignment in `analysis-passes/infer-types.ss`.
`frontend-passes/report-unreachable.ss`, `reject-for-return.ss` and
`eliminate-statements.ss` establish syntactic continuation/return rules before
ordinary type inference. `compiler/midnight-ledger.ss` supplies ADT signatures.
The pinned release executable independently accepts/rejects our small inputs;
compiler acceptance alone does not establish successful transaction execution.

- Uint widening is allowed, but implicit Uint-to-Field conversion is not.
- Circuit/lambda bodies must also type-check their implicit empty result on
  syntactic fallthrough. `assert(false)` and a constant-true branch do not remove
  that requirement. Statements after unconditional returns are errors, and a
  return inside a loop is illegal even when the loop has zero iterations.
- The compiler lowers statement continuations into conditional expressions.
  Branch result types must be comparable before widening to the declared result;
  an annotation cannot rescue incomparable tuples in an inner conditional.
- Conditions, assertions and logical operands admit nominal Boolean
  representations. Equality requires comparable ordinary types. Ordering accepts
  unsigned types, not Field or Boolean. It recursively requires identical nominal
  declarations but permits different underlying unsigned widths; arithmetic has
  a different, stricter nominal requirement.
- Struct initialization checks fields, spreads and compatible value types.
  Bare circuit/witness/type names are not ordinary values.
- Cells support read/write/reset, not increment/decrement. Counters support
  increment/decrement with Uint16 arguments and `lessThan` with a Uint64 threshold,
  not ordinary assignment. A scalar/struct projection or ordinary Map result is
  not a live storage target; a Map lookup returning a ledger ADT can be one.

## Implementation

Shared value checks reuse semantic subtyping and preserve existing nominal
diagnostics. They cover declared local types, explicit/implicit named and anonymous
returns, struct fields, assignments, ledger method arguments and Boolean/comparison
operands. Unknown types do not silently pass compatibility checks. Return-shape
validation is separate from path feasibility, and continuation-based result joins
preserve the compiler's tree rather than flattening all returns into one list.

The ledger catalogue carries parameter types as well as arity/results/effects.
Storage-target resolution distinguishes a live root or nested ADT from an ordinary
snapshot. Assignment read/write accounting follows the selected operation, not
the outermost Map's type. Detectors continue to consume facts without rechecking
types or inspecting parser nodes.

## Transfer defects exposed by composition

The new differential cases exposed two pre-existing precision discrepancies.
Known in-range Counter updates now retain exact constants, including nested
`insertDefault` receivers, both method/sugar forms, side-effecting operands and
stateful-summary replay. The mutation transfer combines provenance before computing
the value and refreshes the receiver after operand effects. Only representable
Uint64 results are retained as constants. Unknown inputs and out-of-range results
remain unknown; this change does not prove Counter underflow/overflow or transaction
application success. It does not invent an explicit ledger read for an update.

The statement/reference CFG previously omitted indirect aborts. A conditional
guard call could therefore lose the enclosing decision's implicit provenance at a
lexical join, although the instruction engine correctly retained it. Both models
now share the interprocedural may-abort query. The statement graph gains abort
edges after binding; branch control ends at the common postdominator of its
successful successors. An abort while evaluating the condition happens *before*
the decision, so it affects enclosing branches but does not extend that condition's
own control scope. Conditional and short-circuit reference evaluation also retain
control when a selected arm can abort. Total arms still rejoin normally.

These are conservative structural abort edges, not proofs of failure. Existing
instruction/reference and cached/uncached comparisons remain required; aligning
engines does not turn them into independent semantic or security oracles.

## Qualification and limits

`tests/type-compatibility.test.ts` contains 102 regressions: 48 compiler-valid
applications with complete analysis and 54 compiler rejections. Positive cases
compare semantic path facts, failed assertions, completion, cached/uncached results
and detector observations. Dedicated checks preserve constants, private flows,
path-specific authorization and original imported UTF-8 spans. Two empty-branch
tests also check equivalent-state coalescing rather than requiring every syntactic
branch to survive. A supported feature root and packed-consumer checks exercise
the combined implementation. Several older transfer snippets needed explicit
Field casts or compiler-valid unreachable paths; their transfer assertions remain.

This is not a full type checker. Cast qualification follows in ADR 0016. Indexing/slicing and
destructuring constraints, primitive restrictions, wider ADT operations and version
qualification remain work. Collection membership/absence and Counter failure
conditions are not precisely tracked. All labels here are self-authored conformance
regressions, not independently reviewed security findings.
