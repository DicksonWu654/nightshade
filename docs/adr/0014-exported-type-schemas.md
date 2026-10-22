# ADR 0014: Export schemas are not runtime type instantiations

Status: implemented for compiler 0.34.0 / language 0.26.0, 2026-09-25.

## Evidence

At compiler source revision `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`,
`analysis-passes/expand-modules-and-types.ss` creates `Info-free-tvar` bindings
for every parameter of a top-level exported struct or type alias. It expands
the declaration in its defining environment and emits an `export-typedef`.
Natural parameters are omitted from the generated TypeScript type parameter list.
`Type-Size->nat` explicitly erases free dimensions using context-specific defaults:
zero for a Uint range start and one for widths, range ends, vectors and bytes.
The defaults validate an external schema; they are not concrete application sizes.

Consequently, a free parameter may appear directly in a type or size position
during export validation regardless of its declared kind. This is **not** a
relaxation of ordinary generic application rules. `Type-Argument->info` wraps
a referenced free variable as an ordinary type argument when applying another
generic declaration. A nested natural parameter still requires an actual natural
argument; an ordinary type binding cannot be used as a size. The release compiler
independently accepts/rejects these distinctions in our conformance cases.

`analysis-passes/infer-types.ss` checks expanded struct/tuple/vector elements as
ordinary types and rejects exported aliases whose result is a ledger ADT.
Direct exports of native opaque/curve types and ledger ADT declarations are
rejected during expansion. Imported standard-library structs such as Maybe and
MerkleTreePath can be re-exported; user aliases to ordinary native types can too.
Unused unexported bodies, including unused imported exports, remain lazy until
instantiation or application re-export. The source exporter, not declaration
spelling alone, determines when validation is required.

## Decision

`TypeExportValidator` performs a separate bounded validation traversal. Its
environment distinguishes free export variables, concrete naturals and resolved
type arguments. Its result is only the ordinary/ledger classification needed for
export legality; it is not a new concrete type identity or public type-IR format.
Shared numeric limits and the standard type catalogue remain authoritative.
User fields/aliases resolve in their defining lexical scope; library field
prototypes retain canonical native identities. Duplicate parameters, generic
arity/kinds, unresolved names, ordinary-only positions and concrete dimension
limits produce source diagnostics. Depth and total work remain bounded.

Schema traversal never populates concrete field, nominal-alias, call or module
specialization caches. In particular, it does not substitute Field/zero as sample
generic arguments or claim that validating one instantiation validates all others.
Erased numeric defaults are local to the compiler-qualified schema check only.
Actual program uses continue through concrete lexical type resolution and retain
their precise dimensions, fields, nominal identities and provenance. Concrete
exports now also reject illegal ADT aliases and direct native/ADT re-exports.

## Adjacent parser correction

The composed nominal-schema tests exposed an upstream grammar ambiguity:
`value as Tag<Field>` was reduced as a cast to bare Tag followed by relational
operators. Merely reversing associativity fixes that input but breaks the legal
comparison `value as Word < 3`. The owned v4 overlay instead retains both parses
at a type-reference conflict and gives a complete generic reference dynamic
precedence. Compiler-backed tests cover nested and chained generic casts, natural
arguments, ordinary comparisons after nongeneric casts, and original Unicode
source spans. Fields and owned AST shapes are unchanged; no source rewriting is
performed. Existing sequence/import/string fixes remain in the overlay.

## Qualification and remaining work

`tests/type-exports.test.ts` contains 71 regressions: 41 complete compiler-valid
applications (including one generated-declaration check), 29 compiler rejections
and one schema-budget unit. It compares compiler acceptance/rejection and generated
TypeScript schema shape without executing generated contracts. Analysis cases
compare cached/uncached facts, instruction/reference semantic paths and detector
observations. Composition cases retain private fields, witness hash bindings,
ledger writes, nominal types, imported aliases, module sizes and defining-file
source locations. A separate unit checks the schema work budget.
The earlier exported-generic-schema coverage gap is promoted to a complete test,
and a supported language-feature root exercises the composed implementation.

This does not implement general expression/assignment/return compatibility or all
primitive constraints. Export-only compiler acceptance is not proof that every
concrete generic instantiation or generated TypeScript consumer will type-check.
Unsupported native declarations and operations still need their own models.
These are self-authored implementation regressions, not independent security labels.
