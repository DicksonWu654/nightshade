# ADR 0017: Model sequence shapes and projection bindings

Status: implemented for compiler 0.34.0 / language 0.26.0, default ZKIR2.

## Compiler evidence

At source revision `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`,
`analysis-passes/infer-types.ss` distinguishes literal indices through safe casts
from other index expressions. Indices require an unsigned representation. A
literal selects a tuple element's own type; a non-literal tuple index first requires
a comparable common element type, even if later analysis can compute its value.
Indexing element zero is not a valid substitute for this join.

Literal tuple slices retain the selected heterogeneous tuple shape. Vector slices
remain vectors, and Bytes slices remain Bytes. Non-literal tuple slices require a
common element type and return vectors. Zero-length slices can start at the end,
but the independent literal-index limit still applies. Compiler size legality and
the analyzer's smaller layout budgets are separate questions.

Type inference accepts non-literal unsigned indices, but
`circuit-passes/resolve-indices-simplify.ss` subsequently requires indices to reduce
to constants after circuit inlining and loop unrolling. Release-executable checks
reject unresolved input-dependent indexing/slicing, including pure circuits. A
helper called with a constant index can be legal. We do not invent a general dynamic
indexing runtime or enumerate private index alternatives on that premise. The source
analyzer diagnoses an unresolved projection; explicit compiler validation is still
needed to establish the compiler's complete constant-reduction legality.

`Tuple-Argument` in type inference makes construction with a Vector or Bytes spread
a vector with a common element type. Tuple-only spreads can remain heterogeneous.
Even zero-length vector spreads retain their element type. Literal range loops are
expanded to tuples in `analysis-passes/expand-modules-and-types.ss`; the unsigned
exclusive bound of a nonempty range's common element type is its end, not Uint64.

`frontend-passes/expand-patterns.ss` lowers patterns to selected field/index reads.
Patterns need not exhaust the source; omitted slots produce no read. Empty/all-omitted
patterns impose no container requirement. An actual selected field must still exist,
even if its nested pattern is empty. Parameter destructuring introduces a separate
local prologue after all ordinary parameters: its names shadow ordinary parameters
regardless of argument order. Duplicate bindings within that prologue are rejected.

## Implementation

`semantic/sequences.ts` centralizes construction and projection type rules over
owned types and expressions. Vector spreads use compressed type shapes rather than
materializing their declared length. Parameter binding is two-phase; selected
pattern projections validate types before data flow. Anonymous circuits use the
same binding logic. Range-loop symbols and generated index literals retain qualified
unsigned bounds.

The pinned v5 grammar overlay adds omitted tuple pattern slots and empty struct
patterns, retaining sequence/import/string/generic-cast fixes. It does not rewrite
user source. Generated C, ABI/build identity and license notices follow the existing
reproducible production packaging path; ABI remains 15.

Sequence projections and destructuring share the same value projection helper.
Slices retain Bytes constants and field-sensitive values. A full-width Bytes slice
preserves raw source identity; a partial slice remains derived. Copying an entire
credential through a slice cannot hide it from the preimage publication rule, and
copying a digest does not turn it into a raw credential. Index selection dependencies
reuse the existing ledger-selection provenance combinator. Evaluation order, guard
facts and ledger snapshots remain shared with ordinary expression interpretation.
Unresolved/out-of-range computed indices and missing layouts fail visibly; sequence
construction/slice layouts over 256 elements report an analysis budget diagnostic.

## Qualification and limits

`tests/sequences.test.ts` has 83 regressions: 45 compiler-valid complete applications,
35 compiler-rejected applications, two compiler-valid layout-budget gaps and one
analyzer-only shape-size check. The last uses a declared large vector without
expanding its elements or invoking the compiler on a large generated application.
Positive cases compare full cached/uncached facts, instruction/reference semantic
paths, failed assertions, completion and detector observations. Unicode/import spans,
omitted slots, parameter/lambda scopes, generic loops, guards and snapshots compose
with the type checks. Compiler validity is separate from proof execution.

`preimage-corpus-3` adds a full-slice publication/corrected-digest pair; its previous
27 cases are unchanged. A supported feature root and packed-consumer checks exercise
sequence construction, Bytes slices and parameter shadowing. These remain synthetic
implementation regressions, not independent security labels or a full type checker.
Broader primitive/ADT legality, compiler constant-reduction conformance and larger
layout/loop analysis remain qualification work.

Both Linux Node 24.15.0 and 22.23.3 runs pass all 1,130 tests with the pinned compiler,
source checkout and official SARIF schema supplied; no tests are skipped. Packed
production installs pass CLI, ESM/isolated API and strict TypeScript consumer checks
on both versions, including sequence constants `62,97,98`.

Clean pinned-input regeneration through `npm run build:parser` reproduces the v5
manifest and all 11 artifact/notice hashes. Its ABI-15 build identity is
`bfeea118a1b867b75793c034d6f2bbd396eef25d4cc9cc6bc1ab11db86edc3ee`.
An earlier scratch attempt invoked the script directly outside npm's tool PATH:
system node-gyp 9.3.0 selected system Node headers, and loading that addon under
Node 24 aborted. A fresh scratch build through the documented npm command uses
node-gyp 12.3.0 and the active Node headers and succeeds without source changes.
This environmental failure is not hidden as a successful reproduction; direct
script invocation with a mismatched system toolchain is not qualified. Packed
installs use the npm lifecycle and are tested separately. Remote macOS remains unrun.
