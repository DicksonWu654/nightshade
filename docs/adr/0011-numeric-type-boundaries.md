# ADR 0011: Compiler-qualified numeric types and exact arithmetic inference

Status: implemented for compiler 0.34.0 / language 0.26.0, 2026-09-25.

## Findings

The qualified compiler limits Uint widths to **248 bits**, not the 254 full bits
that fit in the native Field. `langs.ss` defines unsigned width using whole Field
bytes so ledger alignments remain byte-based. Release-compiler probes accept
`Uint<248>` and reject `Uint<249>` and `Uint<254>`. Width zero is legal and denotes
the sole value zero. Explicit Uint ranges start at zero, have an exclusive positive
endpoint, and cannot exceed `2^248`. Bytes/vector lengths range from zero through
`2^24`; these source-language limits are not the analyzer's smaller resource budgets.

The old source model allowed oversized numeric types. It also confused exclusive
type bounds with maximum values during arithmetic inference. For operand bounds
`A` and `B`, the correct result bounds are:

- Addition: `A + B - 1`.
- Multiplication: `(A - 1) * (B - 1) + 1`.
- Subtraction: `A`, with a runtime underflow constraint.

Thus two `Uint<8>` operands add to `Uint<0..511>`, not `Uint<0..512>`. This is not
merely presentation: the wrong bound can make a compatible inner overload appear
inapplicable, selecting an outer constant-returning function and losing the actual
private-derived return flow. Compiler-valid call-boundary and lexical-overload
regressions now expose that difference.

## Compiler evidence

At pinned revision `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`:

- `langs.ss`: `field-bytes`, `unsigned-bits`, `max-unsigned` and
  `max-bytes/vector-length` establish numeric and sequence limits.
- `expand-modules-and-types.ss`: the Type pass validates Uint widths/ranges and
  sequence lengths, including arguments whose instantiated function never uses them.
- `infer-types.ss`: `arithmetic-binop` computes maximum result values and rejects
  results exceeding `max-unsigned`. An outer cast does not legalize that arithmetic;
  an operand must already be Field to select Field semantics. Nominal Uint operations
  also require a legal intermediate result before their checked narrowing.
- The quote rule rejects unannotated literals above the largest Uint. A dedicated
  direct-cast rule accepts larger Field literals, including Field aliases and nominal
  aliases. Lexer Field-range legality still applies.

The source checkout is ahead of the release. `tests/numeric-types.test.ts` checks
the release executable independently: 23 complete positive applications, 21 compiler
rejections and one utility regression. Maximum sequence sizes are tested as unused
generic type arguments, not by allocating huge values or generating large circuits.
No generated contract or witness code is executed.

## Implementation

The shared semantic type layer owns the qualified numeric constants, primitive
size validation and exact exclusive-bound arithmetic. Canonicalization checks
numeric type shapes after generic substitution, before data-flow analysis or cache
selection can depend on an invalid bound. Range/size errors remain incomplete
reports, distinct from value/loop/analysis-budget exhaustion.

Semantic binding validates numeric operands and unsigned intermediate bounds. Only
a direct literal-to-Field-representation cast bypasses the unsigned literal limit;
it must still be a valid Field value. This shortcut has no skipped effects: its
operand must be a literal. An ordinary valid Field-to-Uint narrowing remains a
potential runtime abort, not a static invalid-program diagnostic.

Type/generic metadata is serialized from parser tokens rather than raw source
slices. Grammar comment nodes and inter-token whitespace do not become part of a
type identifier, dimension or padded-literal size. Quoted token contents are kept
unchanged, including comment-like text. Original source and UTF-8/UTF-16 spans are
not rewritten. Only the parser accesses concrete grammar nodes; semantic and
detector layers continue to consume the owned model.

Accepted programs compare cached/uncached complete facts and instruction/reference
semantic paths and detector observations. Tests cover zero/maximum types, Field
wraparound, narrowing aborts, generic sizes, exact overload selection, private
provenance and commented type/padding syntax. `numeric-types.compact` adds a
supported compiler-valid feature root.

## Remaining work

This does not complete source type checking. ADR 0012 subsequently qualifies lexical
type lookup, standard-library imports, generic struct/enum arity and important
ordinary/ledger positions. Exported generic schemas, broader declaration/expression
legality and assignment/return compatibility remain mandatory frontend work.

The compiler limits here are qualified only for 0.34.0. Larger compiler-valid
aggregates can still exhaust analyzer budgets. These regressions are implementation
evidence, not independent detector labels or a claim that all type errors or runtime
failures are detected.
