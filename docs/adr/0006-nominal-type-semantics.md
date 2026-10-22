# ADR 0006: Nominal identity without erasing representation or provenance

Status: implemented for the documented subset, 2026-09-25.

## Compiler-grounded contract

Compact `new type Name = T` is not a structural alias. A nominal type is distinct
from its underlying type and from other nominal declarations, even when their
run-time representations coincide. The pinned compiler's `sametype?` compares
the declaration identity and underlying instantiated type. It does not compare
every written generic argument independently: `new type Marker<#N> = Field`
produces the same type for `Marker<1>` and `Marker<2>`. By contrast,
`new type Sized<#N> = Bytes<N>` distinguishes its differently sized instances.
This also affects module specialization and shared ledger identities.

Evidence comes from `infer-types.ss`, `expand-modules-and-types.ss` and the
reference's type-alias, arithmetic and cast sections at compiler source revision
`b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`. That checkout is ahead of release;
the acceptance/rejection and generated-JavaScript tests separately qualify the
0.34.0 executable, language 0.26.0. No claim covers all later language versions.

## Owned semantic representation

`Program.nominalTypes` maps canonical identities to their declaration and
underlying type. `sameType` retains nominal identity; `assignable` supports a
bounded sequence/range subset without implicit nominal-to-representation coercion.
`representationOf` unwraps only the outer nominal chain. Nested field and element
types remain nominal, so projection and storage operations do not lose identity.
Equivalent instances of the same declaration reuse their canonical specialization.
Alias depth is bounded at 32 and nominal specializations at 4,096.

Bindings, returns, named/witness/anonymous arguments, supported intrinsic/ledger
arguments, assignments and struct fields check nominal compatibility. Fold checks
its result against its accumulator's declared type. Ordinary overload selection
uses the same compatibility relation. These checks are not a substitute for the
official compiler's complete legality, higher-order inference or subtype rules.
Unknown nominal intrinsic constraints and unsupported casts fail visibly.

Representation-aware type queries are shared by IR effects, ADT transfer functions,
summary eligibility and policies. Nominal Map/Set/List/Counter aliases reuse existing
effect contracts rather than adding detector-specific rules. Scalar `.read()`
preserves the declared nominal type; Counter reads retain their numeric result.
Nominal enum member lookup preserves enum ordinals and policy state values.

## Values, effects and privacy

- Arithmetic requires the same nominal numeric type on both operands. Nominal
  Uint operations retain their original bounds, rather than silently widening;
  constant overflow/underflow discards the aborting path. IR exposes possible aborts
  and the linear summary caches exclude these checked computations. Nominal Field
  subtraction wraps modulo the native field and does not acquire Uint underflow.
- Representation-only casts preserve source identity, raw provenance, constraints
  and hash bindings. A nominal wrapper is not a privacy transformation. Other casts
  retain dependency while modeling their conversion/checks, not claiming raw equality.
- Boolean conversion maps any nonzero numeric value to true. Boolean-to-Uint
  narrowing still checks the range: `true as Uint<0..1>` aborts. These correct two
  pre-existing scalar transfer errors and apply without nominal types too.
- Numeric/Bytes constants use little-endian conversion with bounds checks. Bounded
  Bytes/vector/tuple conversion preserves individual element dependencies. Enum
  conversions use declaration ordinals and reject out-of-range constants.
- Ledger snapshots, nested regions and summary replay retain their existing
  address-versus-value invariants. Nominal aliases do not create heap references.

The pinned grammar attaches the anonymous-circuit `return` field to a hidden
sequence containing both `:` and a type. The parser adapter now selects the typed
child rather than the punctuation. This is an adapter correction, not a new native
grammar overlay or a generated-table edit.

## Qualification and limits

`nominal-types.test.ts` checks positive, compiler-rejected and bounded-recursion
cases. Positive transfer cases compare full cached/uncached facts and normalized
instruction/reference paths; they also compare detector observations. Separate
generated-JavaScript assertions check nonzero Boolean conversion, narrowing,
nominal addition checks and representation-only identity. Generated contracts are
read as evidence, not executed. A phantom-generic module test compares the compiler's
generated ledger indices as well as analyzer state identity.

Two additional feature roots exercise nominal value/privacy and ledger/ADT behavior.
The unchanged upstream `types/examples` root now passes nominal declarations but
stops at unsupported `Set<QualifiedShieldedCoinInfo>.insertCoin`. It remains a
coverage-gap regression, not a newly complete application. Coin/tree/Kernel effects,
large sequences, comprehensive type validity and wider higher-order/intrinsic
semantics remain release work. No new vulnerability rule or independent security
label is claimed by these language-conformance tests.
