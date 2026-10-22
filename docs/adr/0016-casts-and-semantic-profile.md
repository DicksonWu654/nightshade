# ADR 0016: Classify casts before interpreting provenance

Status: implemented for compiler 0.34.0 / language 0.26.0, default ZKIR2;
explicit ZKIR3 and historical-profile extensions described below.

## Historical compiler profiles (W1)

Pinned 0.30.0/language 0.22.0/runtime 0.15.0 and
0.31.1/language 0.23.0/runtime 0.16.0 use their tagged standard library and native
signatures. Source commits and release/source SHA-256 identities are in
`scripts/compiler-sources.json`. Both historical standard-library files are identical;
ledger operation definitions are also identical to tagged 0.34.0. This comparison
uses release tags, not the research checkout's moving HEAD.

Root `language_version` and `compiler_version` predicates retain 0.34.0 whenever
compatible; otherwise they select the newest matching stable profile. Stable 0.35.0
and explicitly selected 0.35.0-rc.1 share a pinned ZKIR2 subset with PublicAddress
and the Schnorr identity-key guard. Caller, dynamic calls and 0.35 ZKIR3 remain
incomplete. Explicit API/config/CLI compiler pins, or an explicitly invoked
compiler executable, take precedence and must satisfy the pragmas. Imported
pragmas constrain that same selection. Predicates follow `compiler/version.ss`,
including wildcard omitted components and unary negation. Unknown pragmas and
unsupported versions diagnose incomplete analysis. No implicit compiler execution
or download occurs.

The historical profiles permit Uint-to-Field subtyping through arguments, returns,
bindings and comparable aggregate joins. Jubjub scalar inputs are Field, and
JubjubPoint is nominal over an opaque point representation. Newer scalar/Schnorr
types, ecNeg, keccak256, events and ZKIR3 are unavailable. Uint bit widths start at
one; the explicit `Uint<0..1>` range remains legal. Compiler 0.30 checks literal
loop bounds before generic specialization, with at most 1000 iterations;
0.31.1 accepts natural-parameter bounds. Concrete and exported generic schemas
share profile-specific numeric legality.

Compiler 0.30 emits reference equality for JubjubPoint; 0.31.1 emits a component
comparator. Owned compiler output confirms the difference. The analyzer reports
`unsupported-profile-point-equality` for affected 0.30 comparisons, including
aggregate and nominal wrappers. It does not apply modern component equality to
those inputs. Native group-order reasoning remains available for arithmetic and
coordinate queries. Legacy proof-backend conditional-operation defects documented
in the 0.31 release notes are outside source-path analysis; compilation with
`--skip-zk` does not qualify proof generation or transaction execution.

`tests/compiler-profiles.test.ts` checks these differences against the three pinned
compilers, including public provenance, both engines/cache modes, imported pragmas,
isolated/CLI reports and early-failure identities. These are engineering regressions,
not independent review or whole-language qualification.

## NativePoint profiles 0.29.0 and 0.28.0 (pinned subsets)

0.29.0/language 0.21.0/runtime 0.14.0 (tag `v0.29.0`, `f17a98c1`) and
0.28.0/language 0.20.0/runtime 0.14.0 (tag `v0.28.0`, `dce2f11d`) are pragma
fallbacks after every stable 0.30+ profile. Their ledger ADT source equals 0.30
apart from doc strings; both reuse the legacy machinery (Uint-to-Field subtyping,
Field curve scalars, no events/keccak/ecNeg/JubjubScalar, Uint width >= 1, literal
`for` bounds <= 1000). Library differences from 0.30 are modeled from the exact
tagged source: `new type NativePoint = SimplePoint` with Compact accessors and
struct literal/field/component-equality semantics (`nativePointX`/`Y` and
`constructNativePoint` in 0.29; `NativePointX`/`Y` in 0.28). The 0.28 file's 13
body-less native declarations are blanked byte-for-byte before parsing and the
qualified hash/conversion/wallet natives are injected and curve natives diagnose;
0.28 helpers do not auto-receive self-addressed
outputs, so `redundant-self-shielded-receive` reports itself unavailable there.
Unmodeled differences diagnose: struct-backed curve natives
(`unsupported-profile-native`), Opaque hashing (`unsupported-opaque-intrinsic`,
accepted by these compilers), and any file include/import
(`unsupported-profile-search-order`: these compilers try the invocation directory
first). `Opaque<'JubjubPoint'>`, JubjubPoint names and 0.30 natives are absent.
Proof-only defects (0.30 issue #187: `>`/`<=` operand order in the proof circuit;
generated JavaScript is left-to-right), ledger-7 transaction failures and the
0.28 witness-disclosure checker are outside source-path analysis. Issue 155
(free `Uint<n>` type declarations rejected by these compilers) is not checked.
`tests/compiler-profiles-native-point.test.ts` validates fixtures with
`COMPACTC_029_TEST`/`COMPACTC_028_TEST` when set.

Current report schemas 1.6.0 (default) and 1.7.0 (Counter predicates) admit these
profile names and record successfully resolved roots without application entries
in `coverage.noEntrypointRoots`. This is declaration-check coverage, not executed
entry coverage; semantic/worker failures do not receive the label. Earlier schema
files remain archived. The byte pins and corpus repins do not themselves establish
a new compiler-backed suite, packed-install or benchmark qualification result.

## Exact 0.33.0-rc.2 profile

RC2/language 0.25/runtime 0.18.0-rc.1 is pinned to
`566ef0eb66c3442e189b5e2d7ae9e1b99426db26`, with unmodified stdlib bytes and
archive/native/ledger hashes in `scripts/compiler-sources.json`. It uses nominal
opaque Jubjub points but modern scalar operands, Schnorr, hashes and events;
`legacy:true` would incorrectly allow Field curve operands and implicit widening.
Uint width zero is illegal; singleton ranges remain legal. Its three reserved
primitive keywords are checked in owned identifier positions before generic
bodies are discarded; import prefix/alias tokens are checked before concatenation.
JubjubScalar is available without imports, including free exported schemas.

The published Linux-musl binary prints unstamped `0.33.0`. Compiler validation
maps it to RC2 only after exact binary authentication; there is no selectable
stable 0.33 profile. Language-0.25/compiler-0.33 predicates can select RC2 after
stable profiles fail. Other binary platforms and RC2 ZKIR3 remain unqualified.
Generated source confirms component point equality, identity defaults and empty
event operand erasure; potentially effectful empty operands remain incomplete.
Compiler/engine/cache, schema, consumer and real-root evidence is external in
`nightshade-profile-033-20261001/`; this does not establish deployment behavior.

## Compiler evidence

Source revision `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad` defines cast
legality and byte constructors in `compiler/analysis-passes/infer-types.ss`.
`compiler/typescript-passes/print-typescript.ss` selects the actual conversion
helpers; `runtime/src/casts.ts` defines their checked conversion behavior.
The original qualification inspected generated JavaScript without executing it. Runtime helper names alone
are not sufficient evidence of the semantics selected by the compiler.

- Ordinary subtype casts preserve values. Casting between tuple/vector types
  permits widening, not arbitrary per-element conversion or numeric narrowing.
  Nominal wrappers retain the established representation rules; nested nominal
  element identities are not generally erased by a container cast.
- Numeric casts preserve the integer on successful paths. Narrowing checks can
  abort rather than truncate. Boolean conversion tests nonzero; enum conversion
  checks the target ordinal range. These conversions need not preserve raw identity.
- Numeric/byte conversion is little-endian and range checked. Native Bytes-to-Field
  emits `convertBytesToUint(MAX_FIELD, ...)`, **not** the modular foreign-field
  helper `convertBytesToField`. Values at or above the native modulus do not wrap.
- Bytes/tuple/vector conversions require equal length and suitable element
  representations. Empty vectors still have element-type requirements, unlike
  empty tuples. Byte constructor elements must have unsigned byte-compatible
  representations; spread operands must be suitable sequences.
- Default compiler 0.34.0 uses ZKIR2. Under this profile Field-to-JubjubScalar is
  emitted as identity. `--feature-zkir-v3` instead emits
  `convertNumericToJubjubScalar`; see the subsequent profile extension below.
  Bytes-to-JubjubScalar is a normal compiler-rejected cast. The unsupported
  reverse direction is diagnosed by the analyzer and is not counted as an ordinary
  compiler-rejection conformance case.

## Implementation

`semantic/casts.ts` classifies a resolved cast as identity, numeric, scalar,
bytes-to-sequence or sequence-to-bytes. Invalid casts fail before data flow;
unknown conversion metadata produces an explicit diagnostic. Byte-constructor
validation examines type shapes without materializing arbitrarily large vectors.

Transfer functions consume this owned classification, not parser nodes or guessed
type spellings. Identity casts preserve aggregate fields and provenance. Successful
numeric casts preserve raw source identity and ledger dependencies; converting a
credential from Uint to Field cannot make it disappear from the existing preimage
publication rule. Other scalar conversions retain derived dependencies rather than
claiming raw equivalence. Shared bounded byte assembly retains known constructor
and sequence-conversion constants. Checked impossible conversions remove their
successful path, not all findings on unrelated paths.

`Program.semanticProfile` and the exported `SEMANTIC_PROFILE` identify
`compact-0.34.0-zkir2`. Report schema 1.1.0 requires this field; JSON, human output,
SARIF and isolated-worker validation preserve it. This identifies the analyzer's
assumption, **not** evidence that an input project was compiled using that profile.
Ordinary scans are offline; explicit compiler validation remains separate.

## Qualification and limits

`tests/casts.test.ts` has 89 regressions: 55 compiler-valid analysis applications
(including eight modeled runtime rejections), 30 ordinary compiler rejections,
one compiler-valid layout-budget gap, one constant unit, one analyzer-only
unsupported conversion and one generated-output check of both compiler profiles.
Positive analysis cases compare cached/uncached and instruction/reference facts,
failed assertions, completion and detector observations. Composition checks cover
field-sensitive aggregates, guard/secrecy policies, digest-only negative lookalikes
and imported Unicode source spans.

`preimage-corpus-2` adds a numeric-cast publication/corrected-digest pair without
changing the previous 25 cases. A supported feature fixture and packed CLI/API
checks exercise the same integration. These remain self-authored regression labels,
not an independent security assessment or proof execution. Larger sequence layouts,
projection/slice/destructuring legality, further primitive constraints and other
compiler profiles remain separate coverage gates.

## Explicit ZKIR3 extension

`zkirVersion: 3` selects the distinct profile in API/config; the CLI uses
`--zkir-version 3`. Compiler evidence is the exact 0.34.0 release source
`1f671fc27818df2b2676b3a97f85b2b821756243` and runtime 0.19.0 owned probes.
Secp Base/Scalar arithmetic and Bytes<32> casts are modular in different fields.
ZKIR3 Field-to-JubjubScalar conversion reduces and loses input identity. Uint's
248-bit bound already fits, so those conversions preserve raw identity. Scalar
casts discard old byte layouts: comparing those bytes after reduction previously
pruned feasible equality. `tests/zkir3.test.ts` retains the runtime-backed regression.
Reports, workers and compiler validation preserve profile choice; mixed-profile
merges are explicitly incomplete. Coverage limits and checkpoint evidence remain
in the public coverage reference; this does not qualify proof generation.
