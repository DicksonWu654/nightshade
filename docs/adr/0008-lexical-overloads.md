# ADR 0008: Keep lexical callable groups separate from symbol identity

Status: implemented for the bounded source model, 2026-09-25.

## Problem and evidence

Flattening nested scopes by replacing an outer binding with an inner binding is
incorrect for Compact functions. A compiler-accepted example has an outer
`select(Field)` returning its argument, an inner `select(Boolean)` returning zero,
and an inner call `select(privateField)`. The previous analyzer chose the Boolean
function, reported complete analysis and lost the private argument's provenance.
This is a resolution defect, not a missing detector pattern.

At compiler revision `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`,
`expand-modules-and-types.ss`'s `lookup-fun` / `find-functions` collect function
bindings in lexical groups. A non-function binding stops outward lookup. Repeated
appearances of the same imported function are deduplicated. `infer-types.ss`'s
`do-call` visits groups from nearest to farthest, filters by generic arguments,
parameter subtyping and fold result/accumulator equality, and selects the first
group containing compatible functions. Multiple matches in that group are an
error; lookup does not continue to an outer group to resolve that ambiguity.

The checkout is ahead of the qualified release. Acceptance and rejection tests
against compiler 0.34.0 / language 0.26.0 confirm these boundaries. They also confirm
that imported standard-library functions may overload user functions, and repeated
imports of the same callable are not duplicate function declarations.

## Representation and resolution

- Canonical `SymbolInfo` objects remain declaration identities. Same-scope groups
  are binding wrappers; no wrapper replaces a canonical symbol in `Program.symbols`.
- Lexical lookup builds internal `ScopedSymbol` wrappers with ordered function
  groups. A parameter, local, type or other non-callable binding replaces the
  inherited binding and stops fallback. Group metadata never enters program facts.
- Named ordinary calls and named map/fold callbacks share candidate filtering.
  Generic arguments resolve in the caller's scope; parameter/result types resolve
  in the candidate's declaration scope. Intrinsic signatures use their catalogue,
  not potentially shadowed user definitions.
- Each function identity is considered once per lookup. Same-identity imports can
  repeat, but distinct functions with duplicate signatures still fail. Ambiguity
  never means “pick the narrower overload.”
- Singleton ordinary circuit, witness and intrinsic calls now enforce argument
  subtyping too. Intrinsic generic count/kind validation is unconditional, rather
  than accidentally depending on whether the program declares nominal types.
- Selected calls retain the original declaration identity and call-site span.
  Data-flow, privacy and guard models consume the resolved call; detectors need no
  scope traversal or name-based exceptions.

Three existing transfer-unit sources gained compiler-required Field casts. Their
original assertions remain unchanged. Broad assignment/return/type legality is
still separate work; this change does not claim the source analyzer is a compiler.

## Qualification

`tests/lexical-overloads.test.ts` covers scope priority, wider/narrower parameter
types, generic kinds/counts and caller-local types, map/fold, witness/native targets,
selected aliases/prefixes, reimports, external definition scopes, shadow barriers,
ambiguity, state/call effects, privacy and authorization evidence. Positive programs
compare cached/uncached facts and instruction/reference semantic paths. Rejected
programs must produce an incomplete report, not a clean scan.

`tests/fixtures/features/lexical-overloads.compact` composes ordinary, mapped,
native and folded lexical resolution in one compiler-valid application root.

These are compiler-grounded implementation regressions, not independently labeled
security cases. Module composition is now covered by ADR 0009. Exported overloaded
application entrypoints, full type legality and compiler-version expansion remain separate
coverage/release gates. Lexical resolution does not change analysis budgets or
close the correlated stateful-join limitation.
