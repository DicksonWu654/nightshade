# Compact semantics research

Research snapshot: 2026-09-24. These are source-grounded notes, not a complete formal
specification or a claim that the initial analyzer implements every construct.

## Collection and ledger-failure qualification

ADR 0019 records the bounded Map/Set model against compiler 0.34.0 and the pinned
compiler/runtime sources. Resets/defaults are empty; Map insertion replaces a key,
Set insertion is idempotent, and absent removal does not reduce cardinality.
Missing Map lookup fails rather than returning a type default. Counter decrement
below zero is documented to fail at runtime. These failures now terminate known
impossible successful paths, including cached transfer replay.

Unknown entry-state collections are not default-initialized. Successful lookup
can establish presence, while predicates saved before a write cannot refine the
new state. Compiler acceptance, circuit evaluation and ledger transaction success
are distinct evidence. Counter overflow, List ordering/empty-pop outcomes, general
collection relationships and full runtime/transaction behavior are not qualified
by this tranche; do not infer them from the new constant facts.

## Ordinary value compatibility qualification

The compiler 0.34.0 checks recorded in ADR 0015 distinguish ordinary subtyping from
arithmetic coercion at locals, returns, struct fields and ledger operations. Uint
widening is legal; assigning an unsigned value to Field requires an explicit cast.
Fallthrough has the empty-tuple result even after an impossible assertion or
constant-true branch. Return branches must be comparable before result annotation
widening, and returns inside loops are rejected syntactically.

Boolean contexts admit nominal Boolean representations. Ordinary equality needs
comparable types; ordering requires unsigned operands with the same nominal
declaration chains, allowing distinct underlying widths. Cells have no compound
increment and Counters have no ordinary write. Counter update arguments are
Uint16, while `lessThan` accepts Uint64. A lookup returning a Counter/other ledger
ADT is a live receiver; an ordinary lookup result or struct field is a value,
not storage. These distinctions are verified by acceptance/rejection tests against
the pinned executable and the source passes named in the ADR.

Indirect assertion/operation aborts affect control dependence. A branch whose
callee might abort need not rejoin the following statement; its private decision
can therefore influence later observable effects. An abort during evaluation of
the condition occurs before the branch decision and must not spuriously extend
that decision's own scope. This is conservative structural reasoning, not proof
that the operation fails or that a transaction is feasible.

Compiler source provenance is maintained in
[`scripts/compiler-sources.json`](../scripts/compiler-sources.json).

The current pinned stable compiler release is **0.35.0**, reporting **language
0.27.0** and runtime **0.20.0**, from source `debb05f9414b9d1e176741c2be289bb32233f0fc`.
Its ZKIR2 subset shares the RC's exact stdlib/native/ledger sources; caller,
dynamic cross-contract calls and 0.35 ZKIR3 remain explicitly incomplete.
The existing **0.34.0 / language 0.26.0** profile remains the default whenever
compatible with source pragmas. The notes below retain their stated compiler
evidence; the research HEAD pin in the table is historical.
Compiler release, language pragma, grammar branch label, and library version are
different version axes. Do not infer semantic compatibility from equal-looking numbers.

## Execution and trust boundaries

Compact source describes computations that produce client-side JS plus proof
circuits and ledger interactions. Proof generation/witness execution happens off-chain;
proof verification and authorized ledger effects underpin the on-chain contract.
It is incorrect to model every circuit as an EVM-style on-chain function execution.
The docs distinguish exported circuits touching the ledger from pure computations.

`ledger` denotes **public** state even without `export`. Export affects names/API
visibility, not confidentiality. Ledger ADTs include scalar cells, Counter, Map,
Set, List, MerkleTree, and HistoricMerkleTree. Operations have different read,
write, and publication effects. Nested ledger ADTs are allowed within Map values;
they are not ordinary first-class heap references. `sealed` means only constructor
initialization may write the field, including through helpers; it does not mean private.

`witness name(args): T;` declares a callback supplied by the application. Its returned
value and off-chain private-state handling are not verified merely because the
TypeScript callback is honest. Circuit constraints determine which values can produce
valid proofs. Private application state lives outside the public ledger. Compact
source alone cannot establish witness implementation honesty or entropy.

Exported circuit and constructor arguments are potential private sources too.
Internal parameters inherit callers' provenance; they are not automatically public
or independently attacker-controlled. `pure` means no ledger, witness, emit, or impure
callee effects. It does not mean non-private inputs or outputs.

## Syntax, names, and composition

The authoritative syntax is the compiler's `doc/compact-grammar.mdx` and parser;
tree-sitter acceptance alone is not compiler acceptance. Important forms include:

```compact
pragma language_version >= 0.26.0;
import CompactStandardLibrary;
module Example<T> { export circuit identity(value: T): T { return value; } }
import { identity } from Example<Field> prefix Example_;
export ledger result: Field;
witness privateValue(): Field;
export circuit publish(): [] { result = disclose(privateValue()); }
```

Modules provide **static namespaces**, not Solidity inheritance. Generic modules
specialize at import; circuits specialize at calls. Type and natural-number (`#N`)
parameters both exist. Locally declared modules see lexically enclosing contract
bindings; modules imported from separate files do not capture the importing
contract's bindings (reference: “Identifiers, bindings, and scope”).
Export modifiers and `export { name }` expose bindings; import selections and prefixes
change names at the importing scope. Modern language versions also support overloads,
structural and nominal aliases, destructuring, anonymous circuits, and external
contract interfaces. These require semantic resolution, not string matching.
A call through a declared `contract X { circuit f(...): T; }` interface is typed from
that declaration (as in compactc, a ledger ADT operation of the same name on a ledger
receiver takes precedence). Its callee effects are not modeled: every entry whose
analysis reaches such a call reports `unsupported-contract-call` and is incomplete,
and no history continues past it. Entries that never reach one are analyzed as usual.

Filesystem imports resolve a named module from `<name>.compact`, relative to the active
compilation-unit directory first, then `--compact-path`, else `COMPACT_PATH`.
`CompactStandardLibrary` is built into the compiler but can be shadowed by a visible
local module; a quoted name instead requests a physical file. External files must
provide only the named module definition; they are not JS-style
bags of exported top-level functions. `include` is source inclusion with different
scope semantics. Compiler 0.34.0 appends `.compact` to include names as well:
`include "helper";` reads `helper.compact`, whereas `include "helper.compact";`
attempts `helper.compact.compact`. This was checked directly against the compiler
and its `examples/std_lib/import/test_include_std.compact` fixture.

**Module identity correction, compiler 0.34.0:** repeated direct imports of the
same module with the same generic arguments **share** circuit and state identities,
even with different prefixes. Distinct generic specializations have distinct state.
This was checked in generated JS without executing it: repeated imports call the
same `_put_0` and exported getters address ledger index `0`; specializations `<1>`
and `<2>` call `_put_0`/`_put_1` and their getters address `0`/`1`. Compiler-conformance
regressions now assert those indices. Prefixes rename bindings; they do not by
themselves create fresh storage. Additional release-compiler tests now establish
direct/diamond sharing, nested exported-module identity and semantic generic equality
(including `Uint<8>` versus `Uint<0..256>`). The former blanket transitive-state
diagnostic has been replaced with a reusable instance model; see ADR 0009.

Physical source identity is **not** compiler module identity: resolved pathname
spellings, including `Store` versus `./Store` and symlink aliases, can create different
state instances in 0.34.0. The analyzer caches physical syntax separately from module
definitions. Imports in included text use the enclosing compilation-unit directory,
not the include file's source-location directory. An exported local module resolves
its imports in the first importing context; physical external modules establish
their own resolved directory. Compiler getter-index regressions cover these cases.
Do not extrapolate this version-qualified behavior to other compiler releases.

## Control flow, constraints, and numbers

`if`, conditional expressions, and short-circuit `&&` / `||` have evaluation order
and branch-dependent effects. `const` creates a lexical binding; nested blocks may
shadow outer names. Ordinary local reassignment is not ledger mutation. Returns
terminate the invocation. Named-circuit recursion is rejected by the compiler.

`for (const index of start .. end)` uses an inclusive start and exclusive end with
literal or generic-natural bounds. Sequence iteration has a statically fixed size.
Returns out of loops are forbidden. `map` and `fold` introduce anonymous or named
callee edges. Attacker-controlled unbounded loops are therefore not a sensible default
detector; statically large circuit cost is a different, measurable hypothesis.

Modern assertions are expressions `assert(condition, "message")` of type `[]`.
They abort computation on failure and are constrained in-circuit. A constraint that
a witness Boolean is true is real, but does not establish that Boolean means
"authorized". Conversely, the absence of a nearby assert does not establish a bug:
callee assertions, ledger operations, and cryptographic relations can constrain values.

`Field` arithmetic is modulo the target field. Uint addition/multiplication widen
their static ranges; subtraction below zero is a dynamic error. Narrowing casts
perform range checks. Indexing requires compile-time-reducible indices within the
sequence size. Do not import Solidity overflow/unchecked-index claims unchanged.

## Disclosure and cryptographic provenance

`disclose(expression)` **does not itself publish a value**. It authorizes disclosure
for the compiler's witness protection program. The compiler tracks private-derived
data through arithmetic, casts, calls, and conditionals. Relevant sinks include
public ledger operations, exported returns, and cross-contract arguments; current
language versions also introduce public events. A disclosure whose value is discarded
is not a public leak. Application-visible data and on-chain observability should
remain distinct sink classes even when both require disclosure.

The compiler uses an abstract interpreter (`analysis-passes/track-witness-data.ss`),
then `remove-disclose.ss` erases annotations. In `midnight-natives.ss`, persistent
and transient hashes retain "a hash of" witness information, while persistent and
transient commitment arguments use `(discloses nothing)`. This is the compiler's
disclosure contract, not a universal cryptographic secrecy guarantee: predictable
hash inputs and weak/reused commitment randomness still matter.

Our domain must retain source identity after `disclose`, distinguish raw/derived/hash/
commitment transformations, and attach disclosure permission separately. A hash is
not a universal sanitizer. OZ Ownable deliberately uses a stable hash of a secret
as a pseudonymous identity; its documented cross-contract linkability is intentional.
Do not flag every stable hash or every disclosure as a vulnerability.

## Compiler foundation

The compiler is written primarily in Chez Scheme using Nanopass. It defines typed
intermediate languages, expands modules/types, infers types, rejects recursion,
checks sealed-field writes, computes purity and ledger paths, tracks witness data,
and generates JS and ZKIR through separate backends. The toolchain also contains Rust
tooling and a TypeScript runtime.

Documented outputs include JS, `.d.ts`, JS source maps, `contract-info.json`, ZKIR,
and proving/verifying artifacts; `--skip-zk` avoids expensive key generation.
In the tested 0.34.0 binary, metadata is emitted beneath `compiler/` (including
`contract-info.json` and `contract-manifest.json`); older documentation examples put
contract info under `contract/`. Adapters must follow the actual compiler version.
`contract-info.json` describes exported signatures, versions and contract metadata,
not a complete source AST/CFG. `--trace-passes` emits debugging representations, not
a stable JSON IR API. Source-first analysis with compiler validation is the practical
initial foundation; a pinned typed-IR adapter would eventually improve completeness.

## Public research leads and open questions

Shared transitive dependencies can require explicit state isolation when library
modules are composed. This behavior is compiler-version dependent and should be
verified against the pinned compiler; it does not imply that every version or
program exhibits the same issue. Compiler validity should be recorded separately
from analyzer expectations when deriving fixtures.
The compiler has extensive public bug and witness-protection regression tests.
Record compiler validity separately from analyzer expectations when deriving fixtures.

[Midnight Forge](https://github.com/mzf11125/Midnight-Forge), inspected at
`0f39f4f2aebe2716fd05dceaa6e9a2228e1fcc03`, includes line/regex-based rules in
`src/analyzer/rules`. Its public-function and require/owner heuristics are not a
substitute for Compact semantic analysis. Search is non-exhaustive; absence of other
results is not evidence that no other tools exist.

Still requiring version-specific work: exact per-ADT transcript disclosure rules,
cross-contract implementation rollout versus language support, events, overloads,
module-instance identity, compiler metadata schema stability, and numeric/domain
proof obligations. Library comments can lag current compiler capabilities.

## Additional frontend and value-model checks

- Compiler 0.34.0 accepts nested structural aliases for Map values containing
  structs (`adt-aliases.compact`). Projection must preserve both stored field
  provenance and private key-selection dependencies; a wildcard ancestor mutation
  invalidates descendant constants rather than only equal-depth slots.
- Ordinary aggregate locals/parameters are value snapshots, not live ledger
  addresses. `ledger-snapshot.compact` is compiler accepted. The source model now
  uses statically resolved ledger roots to distinguish direct field access from a
  local/parameter projection after another circuit changes storage.
- Operation arguments can call a circuit that mutates the receiver's ledger region.
  `argument-effects.compact` covers Counter method and compound-assignment forms.
  Mutation transfers refresh the region after argument evaluation when its revision
  changed; otherwise an outer update could erase an inner call's dependencies.
  This abstract-state refresh does not invent an explicit Compact ledger read.
- The compiler's `parser.ss` reserves identifiers such as `public`, `private` and
  `await`. The pinned tree-sitter grammar accepts some as identifiers; the adapter
  rejects them explicitly rather than silently treating the file as supported.
- Grammar revision `22de6ee9dbf4b92fe4e2fe3602e53f1e352b79fd` defines expression
  sequences as one or at least three expressions, accidentally excluding two.
  The owned grammar overlay (now `sequences-imports-strings-v3`) corrects this production
  without source rewriting or parse recovery. Compiler-accepted fixtures cover pairs,
  longer sequences, effect order and early abort; malformed separators still fail.
  Both upstream revision and native build identity appear in reports. See ADR 0003
  for pinned generator/ABI, packaging, provenance and qualification requirements.
- Compiler 0.34.0 rejects direct assignment to a plain stored-struct projection
  (`pair.first = value`) because the projected `Field` is not an ADT lvalue. Read
  projections do not grant live write-address semantics. The stateful-summary
  conformance fixture replaces the whole ledger aggregate; mutation summaries
  require direct ledger roots. This does not turn the analyzer into a type checker.

## Nominal types and conversion conformance

Compiler 0.34.0 confirms the nominal-identity rules in `infer-types.ss` and the
reference's type-alias, arithmetic and cast sections. `new type Name = T` creates
a distinct type with `T`'s representation. Compatibility depends on the declaration
and instantiated underlying type, not every syntactic generic argument: unused
parameters in `new type Marker<#N> = Field` do not distinguish `Marker<1>` from
`Marker<2>`. Sizes used in `new type Sized<#N> = Bytes<N>` do distinguish instances.
The module-specialization regression also checks generated ledger indices for
equivalent nominal arguments. Do not invent separate storage for phantom arguments.

Nominal numeric operands must have the same nominal type. Nominal Uint arithmetic
checks the original range rather than only its widened intermediate type; Field
subtraction wraps modulo the native field. Representation-only casts neither hide
private data nor remove constraints. Raw nominal witness values still remain raw
when cast to their representation, while hash results retain their transformation.

Scalar conversions exposed two earlier transfer errors: `2 as Boolean` is true,
not an abort; `true as Uint<0..1>` aborts rather than producing an out-of-range 1.
Generated JavaScript assertions now check both and the nominal Uint addition check.
Numeric/Bytes casts are little-endian with fit checks; enum casts use ordinal values.
Anonymous-circuit parameter/result types and fold accumulator equality are checked
at their semantic boundary. These rules were validated with release-compiler
acceptance/rejection tests, not inferred solely from the ahead-of-release checkout.

See ADR 0006 for the owned representation, supported boundaries and conformance
suite. The unchanged upstream `types/examples` root now reaches an unmodeled coin
operation (`Set<QualifiedShieldedCoinInfo>.insertCoin`); it remains incomplete.

## Higher-order and sequence typing

Release-compiler qualification confirms `map`/`fold` may target witnesses, ordinary
and generic circuits, overload groups and modeled standard-library circuits. Inputs
are evaluated once in source order; callback applications then proceed left to right.
An empty sequence has no witness invocation, guard completion or callback effects.
Fold still evaluates its initializer even when it has no iterations.

The compiler's sequence `max-type` selects a comparable common element type, not
the first element's type and not a synthesized join of arbitrary incompatible
components. The same rule applies to `for-of` and slices. Fold filters overloads by
equal first-parameter/result types before choosing a unique target. Anonymous fold
result annotations can contextualize the accumulator when the initial type is a
subtype. The release rejected treating Uint as a subtype of Field: mixed arithmetic
support must not be generalized to implicit argument conversion. The analyzer's
earlier shortcut was corrected; explicit numeric casts remain available.

An empty tuple contributes a bottom element type to inference. A declared zero-length
vector still carries its element type: `Vector<0, Field>` is not interchangeable
with `Vector<0, Boolean>`. Nominal aliases of these types must also remain distinct.
The release additionally accepts `keccak256<Input>` where `Input` is a nominal Bytes
type; its generic parameter is a type, not a byte length. Sources are `midnight-natives.ss`,
`standard-library.compact` and `infer-types.ss` at the pinned compiler revision;
the corresponding accepted/rejected synthetic programs are in `higher-order.test.ts`.
See ADR 0007 for shared call transfers, effect guarantees and outstanding limits.

## Lexical overload priority

Functions do not obey simple name-replacement shadowing. The compiler collects
lexical groups and selects the nearest group containing compatible candidates.
Argument arity/types, generic count/kinds and fold accumulator/result equality can
make an entire inner group inapplicable, allowing an outer function to be selected.
An ambiguous inner group is an error, not permission to fall through. Non-callable
bindings stop outward function lookup, including parameters, block locals and types.
Repeated appearances of one imported function do not create competing identities.
User circuits and imported native functions can coexist in one overload group.

These rules are visible in `lookup-fun` / `find-functions` in
`expand-modules-and-types.ss` and `do-call` in `infer-types.ss` at the pinned source
revision. `tests/lexical-overloads.test.ts` independently checks the release compiler.
The owned resolver previously flattened inner/outer bindings and could silently
select an incompatible inner singleton, losing private flows or state effects.
It now preserves group priority and validates singleton arguments, including
intrinsic generics. ADR 0008 documents identity, shadow barriers and qualification.

## Generic call identity and natural values

Generic circuit/witness instances use declaration identity plus semantic generic
argument equality, just like modules. `Uint<8>` and `Uint<0..256>` share one instance;
so do equivalent tuple/vector shapes and phantom generic types. Different nominal
declarations, used generic fields or natural values remain distinct. Imported aliases
share their original declaration, while different enclosing module instances can
create separate callable declarations. Ordinary and higher-order references use the
same instance. `make/register-frob` in `expand-modules-and-types.ss` establishes this
rule; generated release-compiler method counts independently qualify it in
`tests/generic-specializations.test.ts`. Shared witness declaration identity does
not make two witness invocations the same private source.

The lexer accepts binary, octal and hexadecimal natural numbers with lowercase or
uppercase prefixes. These are values, not distinct generic identities or opaque
constant strings. Padded-string sizes and type dimensions accept the same radices.
Leading-zero decimals and malformed digits are rejected in source; Field-range
legality is an additional compiler check, not fully implemented by this analyzer.
Natural normalization uses BigInt. The current CFG uses exact JavaScript numbers
for loop bounds and explicitly rejects bounds outside their safe range, even for
compiler-valid short loops, instead of silently rounding iteration counts. ADR 0010
records the evidence and remaining limits.

## Numeric type boundaries and arithmetic inference

The release compiler caps Uint widths at **248 bits** (whole bytes fitting in Field),
not the Field's 254 full bits. `Uint<0>` is legal. A range must start at zero and have
an exclusive endpoint from 1 through `2^248`. Bytes/vector lengths may be zero and
are capped at `2^24`; analysis budgets are smaller and remain separate diagnostics.
These rules come from `langs.ss` and `expand-modules-and-types.ss` and are qualified
against the release executable, including unused generic type arguments.

`infer-types.ss` computes arithmetic maximum values before checking the unsigned
limit. With exclusive operand bounds A and B, addition has bound A+B−1,
multiplication (A−1)(B−1)+1 and subtraction A. The former source-model bounds were
too large and could change overload selection and lose actual private dependencies.
Unsigned arithmetic whose inferred maximum exceeds `2^248−1` is rejected, even if
an enclosing cast requests Field or a nominal type would later narrow it. Explicitly
casting an operand selects Field arithmetic instead. Nominal arithmetic still checks
its intermediate result before narrowing back to the nominal bound.

An unannotated integer literal above the largest Uint is rejected. A direct cast to
Field, including a Field alias, permits larger literals below the Field modulus.
The analyzer now distinguishes invalid source forms from valid casts that may abort
at runtime. Parser-owned token serialization also keeps comments out of type/generic
metadata without deleting comment-like text inside strings or rewriting source maps.
See ADR 0011 and `tests/numeric-types.test.ts` for boundaries and remaining type gaps.

## Type binding and ledger-only positions

Compiler `handle-type-ref` and `apply-struct` resolve names in lexical environments,
validate generic arity/kinds and expand fields in the defining environment. A type
name is not a globally reserved classification: Counter, Map and native library
structs require imports, and selections/renames/prefixes determine source visibility.
Cell is not a library export. A source name bound to a local, parameter, circuit,
ledger or module cannot be used as a type. Parameter annotations are resolved before
their value bindings are introduced; later type declarations can be referenced.

An intrinsic result keeps the library's type identity even when only the function
was imported or a user type has the same name. For example, `some<Field>(secret)`
has a library Maybe result; a caller's own `struct Maybe` cannot change its fields.
The analyzer now retains canonical native IDs and never performs bare-name fallback
when projecting resolved fields. This matters for private provenance and overload
compatibility, not just compiler error reporting.

Circuit/witness parameters and results, struct fields and tuple/vector elements
must be ordinary types. Map keys and Set/List/tree elements are ordinary, but Map
values may themselves be ADTs. Generic user type parameters can receive ADTs if the
instantiation does not use them in an ordinary-only position. Local/default/cast
positions are not uniformly ordinary-only: a typed local default Map can initialize
nested ledger storage. Kernel is top-level only and has no default; Merkle tree
depth is 2–32. Type-shape acceptance is not an implementation of tree/Kernel effects.

Unused unexported type bodies need not resolve. Concrete exported types do, including
application re-exports of imported types. Exported generic schemas now have separate
free-parameter validation (ADR 0014), without concrete sample instantiation. Literal Opaque kinds `string` and `Uint8Array`
support either quote style and escaped spellings. ADRs 0012–0013 and release-compiler
regressions distinguish supported applications, rejected types and remaining gaps.

## Strings and input line endings

Compiler `lexer.ss` accepts single/double quotes, escaped quote/backslash, the
`n r 0 b f t v` escapes, exactly two hexadecimal digits after `x`, exactly four
after `u`, unescaped newlines and escaped line continuations. Escapes denote Unicode
scalars, not UTF-16 code units; JSON surrogate-pair escape semantics do not transfer.
Literal astral characters remain valid. Arbitrary identity escapes and escaped
slash are rejected. `\01` means NUL followed by the character 1, not an octal byte.

Before lexing, `compact-input-transcoder` in `utils.ss` normalizes CRLF, CR, NEL,
CRNEL and Unicode line separator to LF; paragraph separator is unchanged. Thus
raw line endings in strings and comments follow the same conversion, while escaped
`\r` and `\u2028` decode afterward and remain data. `lparser-to-lsrc.ss` encodes the
decoded string as UTF-8 and zero-pads to the requested byte length. It rejects a
padding length shorter than the UTF-8 representation. `\xE9` therefore occupies
two bytes, whereas a literal rocket occupies four.

The analyzer decodes once at its parser boundary and retains typed literal metadata;
JSON quoting is used only to serialize canonical metadata after decoding. Its LF
parser view maps back to original UTF-8 byte spans without modifying files. Includes,
external imports, Opaque types and assertion messages share this decoding. The owned
v3 grammar fixes missing line-continuation token support. Compiler-emitted byte arrays
are read (never executed) to qualify literal values, and engine differentials check
private branches and actual sinks. Reached string/padding constants over one MiB now
produce `literal-budget`, separately from compiler size legality. See ADR 0013.

## Exported generic schemas

Top-level exported structs and aliases are expanded with free variables, not
sample Field/zero instantiations. Compiler `Info-free-tvar` bindings support
direct type and size positions during schema generation; natural parameters and
dimensions are erased from generated TypeScript declarations. Context-specific
numeric defaults validate only the export schema and must never populate concrete
application type caches. Passing a free variable to another generic declaration
creates an ordinary type argument, so natural-argument requirements still apply.
Actual concrete uses retain normal type/kind and size checking.

Exported aliases cannot resolve to ledger ADTs. Native curve types and ledger ADT
declarations cannot be directly re-exported from an application; modeled library
structs can. Imported schemas resolve in their defining scope, and unused imported
exports remain lazy until application use/re-export. ADR 0014 records source and
release-executable evidence. Its composed tests also qualify generic cast targets;
the v4 grammar preserves nongeneric casts followed by relational comparisons.

## Casts, byte constructors and compiler profile

`infer-types.ss` permits ordinary subtype casts and explicit scalar conversions,
not unrestricted structural reinterpretation. Tuple/vector casts can widen element
types but cannot apply arbitrary scalar conversions to elements. Bytes/sequence
casts require equal length and compatible element representations. An empty vector
still has an element type that participates in legality checks. Byte constructors
accept byte-compatible unsigned representations, including nominal wrappers, and
suitable sequence spreads; a scalar spread is not a sequence.

Numeric casts preserve the integer if they succeed; narrowing checks do not silently
truncate. Numeric/byte encoding is little-endian. Crucially, emitted native
Bytes-to-Field code uses `convertBytesToUint(MAX_FIELD, ...)`, which rejects overflow.
The runtime also contains a modular `convertBytesToField` helper for other compiler
uses; its name does not establish native cast behavior. Generated-output checks
and `runtime/src/casts.ts` ground constants independently of analyzer engines.

Compiler 0.34.0 defaults to ZKIR2, where Field-to-JubjubScalar is emitted as identity.
The experimental ZKIR3 feature emits `convertNumericToJubjubScalar` instead. The
analyzer selects this distinct model only with explicit `zkirVersion: 3` / CLI
`--zkir-version 3`; reports name the assumption without inferring the project's build.
The initial generated-code inspection is supplemented by pinned 0.19.0 runtime
probes of owned fixtures. Checked conversion failures are modeled successful-path
exclusions, not compiler rejection or proof execution. See ADR 0016 for the
accepted/rejected conformance matrix and explicit remaining coverage boundaries.

## Sequence shapes, indices and patterns

Compiler type inference distinguishes a literal index (including safe casts) from
an arbitrary expression whose value may later become constant. Literal tuple access
selects the exact element type; non-literal tuple access requires a comparable common
element type. Slice shapes differ too: literal tuple slices preserve their selected
tuple fields, vector slices remain vectors and Bytes slices remain Bytes. Tuple
slices with non-literal starts first join element types and produce vectors.

After inlining and loop unrolling, `circuit-passes/resolve-indices-simplify.ss` requires
indices to reduce to constants. Release compiler 0.34.0 rejects unresolved input-
dependent indices even in pure exported circuits. A helper's index parameter can
be legal when all actual calls reduce it to constants. Do not infer general runtime
index support solely from the earlier type rules or emitted JavaScript indexing.

Vector/Bytes spreads force construction to a vector whose element types are comparable;
tuple-only spreads can remain heterogeneous. Empty vector spreads still contribute
their element type. Literal range loops lower to tuples of unsigned literals, so
their nonempty common type has exclusive bound equal to the range end, not Uint64.

Patterns lower to selected projections rather than exhaustive shape matching. Omitted
slots cause no projection, and empty/all-omitted patterns can discard a scalar. A
selected field/index must exist even when its nested pattern binds nothing. Parameter
pattern locals are introduced after all ordinary parameters and can shadow them,
independently of parameter order. Duplicate names in the pattern-local prologue are
errors. ADR 0017 records source references, the v5 parser correction and regressions.

## Native input restrictions

`midnight-natives.ss` gives generic persistent hash/commitment and keccak signatures,
but signatures are not their complete source-level contract. `infer-types.ss`
additionally checks the selected native's first argument for JavaScript Opaque
values. The recursive test follows represented fields, tuple/vector elements and
nominal underlying types, including zero-length vector types and inactive native
constructor fields. Phantom generic arguments alone do not count as represented
Opaque values. The check follows overload selection rather than participating in
candidate filtering; a selected native's restriction does not permit outer fallback.

Transient hashing/commitments and user functions with native-like names do not
receive this exclusion. Release-compiler checks also accept an aliased native form
that the analyzer deliberately leaves outside its qualified model. This is recorded
as a compiler-valid coverage gap, not a compiler rejection or a runtime guarantee.
The analyzer's `unsupported-opaque-intrinsic` diagnostic uses canonical targets and
applies to ordinary and higher-order calls even for zero iterations. ADR 0018 gives
the bounded support contract; no new vulnerability detector follows from it.

## Roots without application entrypoints

A successfully resolved root with no application entrypoints reports complete declaration checks and records its path in `coverage.noEntrypointRoots`. Human output labels it `no entrypoints analyzed` and includes the exact informational diagnostic `no-entrypoints-analyzed`: "No entrypoints analyzed; declaration checks completed."; this is not execution coverage. Constructors are entrypoints. Failed semantic resolution and failed workers do not receive this label. Merged scans retain the label per root; module-only libraries remain omitted by project discovery.
