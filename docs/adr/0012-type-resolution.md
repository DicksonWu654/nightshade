# ADR 0012: Lexical type resolution and canonical library identities

Status: implemented for compiler 0.34.0 / language 0.26.0, 2026-09-25.

## Findings and evidence

Type references obey lexical binding, not a global list of familiar spellings.
Counter, Map, Set, List, tree ADTs, Kernel, Maybe and native curve types require
imports. Selection, renaming and prefixes affect the available source names.
Cell is an implicit compiler wrapper, not a CompactStandardLibrary export.
A local value can shadow a type name. Parameter annotations are resolved before
the corresponding parameter value bindings enter scope; forward type references
are legal. Generic count and natural/type kinds apply to structs, aliases, enums,
native types and ledger ADTs, not only circuits and modules.

At source revision `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`:

- `expand-modules-and-types.ss`: `handle-type-ref`, `add-tvar-rib`, `apply-struct`
  and `apply-ledger-ADT` distinguish binding kinds, generic kinds/counts and the
  defining lexical environment for struct fields.
- `infer-types.ss`: Argument/Return-Type and Non-ADT-Type reject ledger ADTs in
  circuit/witness signatures, tuple/vector elements and struct fields.
- `midnight-ledger.ss`: Map takes an ordinary key and an ADT-or-ordinary value;
  Set/List/tree values are ordinary. Kernel is top-level only and has no default.
- `langs.ss`: MerkleTree/HistoricMerkleTree depth is 2 through 32 inclusive.
- `standard-library.compact`: Maybe/Either and Merkle path field declarations
  establish generic positions and dependencies on other library types.

Release-executable checks independently qualify these assumptions. In particular,
**ordinary-value restrictions do not extend to every local/default/cast**:
`const empty: Map<Field,Field> = default<Map<Field,Field>>` can initialize nested
ledger storage. Blanket rejection would break a compiler-valid existing feature.
Likewise, an unused unexported struct may contain an unresolved name, while an
instantiated or concrete exported struct must resolve its fields. Importing an
unused exported library struct is not itself instantiation or application re-export.

## Decision

The semantic layer owns a version-qualified standard type catalogue: generic
signatures, ledger classification and ordinary-only argument positions. Source
resolution requires lexical bindings and diagnoses unknown or non-type names.
Generic numeric arguments have a separate entry point; numbers are not ordinary
types. Numeric size/range limits remain in the shared type layer (ADR 0011).

Resolved library types retain identities such as `standard-type::Maybe<Field>`.
They must not become bare `Maybe` again and be recaptured by a caller's struct or
local value. Internal intrinsic signatures/results and library field prototypes
create these identities without requiring the caller to import an implicit result
type. Importing only `some`, for example, permits projection from its result but
does not make `Maybe` available in a source annotation. Higher-order calls use the
same representation as direct calls.

`representationOf` unwraps nominal aliases and maps only the outer native identity
to an operational ADT name for existing effect models. Generic arguments retain
their canonical identities. `fieldsOf` uses canonical identity, not a fallback
search for matching bare names across unrelated scopes. Instantiated user fields
are resolved in the declaration's lexical environment and cached by instantiated
type; recursive/deep types and excessive instances remain bounded diagnostics.

Signature and aggregate positions require ordinary types, including through nominal
aliases. Ledger roots and Map values can be ADTs; locals/defaults retain the qualified
ADT forms. Nested Kernel and invalid Merkle depths are diagnosed, without claiming
to model tree/Kernel operation effects. Opaque accepts the literal `string` and
`Uint8Array` kinds with either quote style. ADR 0013 subsequently adds escaped spellings.

Anonymous parameters now distinguish source annotations from inferred parameter
types. Unannotated result types stay absent until inference. The source identifier
`unknown` is no longer accidentally accepted as the analyzer's inference sentinel.
An explicitly declared type with that spelling still resolves normally.
The internal tuple tag likewise uses an impossible source spelling: `Tuple` is a
valid user type name, not a keyword denoting `[]`. Compiler-valid struct/alias and
private-field regressions prevent that collision from silently dropping provenance.

## Validation and limitations

`tests/type-resolution.test.ts` checks compiler acceptance/rejection, completed
entries, cached/uncached full facts, instruction/reference semantic paths and
detector observations: originally 34 complete applications, 53 compiler rejections and
two compiler-valid coverage gaps (89 regressions). ADR 0013 promotes the escaped-Opaque
gap to a complete application: 35 complete, 53 rejected, one remaining gap. ADR 0014
closes the export-schema gap: 36 complete, 53 rejected. Cases
cover native-name capture, implicit native results,
field-sensitive private provenance, imports, aliases, generics, ADT positions,
lexical shadowing, Unicode spans and recursive-type diagnostics. The corresponding
feature root composes selected imports, generic structs and List effects.

Older transfer-unit snippets now explicitly import their ADTs; no test helper
silently injects imports. Assertions remain unchanged. The stateful-branch benchmark
also required that import. Its source hashes changed, making the previous effect
artifact unsuitable for a whole-workload regression comparison. New measurements
must not be described as passing that old comparable-baseline gate.

This is not a full type checker. General assignment/return compatibility and full
expression/primitive legality remain open. String decoding is qualified in ADR 0013.
Concrete exported types are checked. This checkpoint originally reported
`unsupported-generic-type-export` for uninstantiated generic schemas; ADR 0014
subsequently adds separate free-parameter validation and closes that gap. Generic
types used in actual specialized application positions remain supported.

These are self-authored implementation regressions, not independent detector labels.
No generated contract or witness implementation is executed.
