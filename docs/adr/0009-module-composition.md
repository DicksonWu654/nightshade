# ADR 0009: Separate physical sources, module declarations and module instances

Status: implemented for compiler 0.34.0 / language 0.26.0, 2026-09-25.

## Why this is analysis semantics

Incorrectly splitting one module instance loses dependencies between its writers
and readers. Incorrectly merging distinct instances invents dependencies and can
invalidate guard or state-machine conclusions. Prefixes and physical file identity
alone cannot establish storage identity.

Two previous source-model assumptions were incorrect:

1. Generic argument text was used as an instance-cache key. `Uint<8>` and
   `Uint<0..256>` consequently created distinct analyzer state, although the
   qualified compiler's exported getters addressed the same ledger slot.
2. Filesystem imports were canonicalized before establishing module identity.
   The release compiler instead distinguishes resolved pathname spellings such
   as `Store.compact` and `./Store.compact`, even when they read the same file.
   Symlinked paths can similarly define separate module/state identities.

These corrections come from accepted synthetic programs and generated-JavaScript
ledger getter indices, not executing a contract or witness implementation. The
compiler-grounded tests deliberately corrected an initial expectation of shared
storage for two path spellings after the compiler showed distinct indices.

## Compiler evidence

At pinned compiler revision `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`:

- `expand-modules-and-types.ss` stores an instance table on each `Info-module`.
  Generic type arguments compare using `sametype?`; natural arguments compare
  numerically. The table is reused across direct and transitive imports.
- Instantiating a module creates its nested module declarations. Equivalent
  imports reuse those declarations; different enclosing instances produce
  different nested declarations, even when a child's body ignores outer generics.
- `process-pelts` processes imports/declarations in source order. A local module
  can be exported, selected, renamed, prefixed, reexported and subsequently imported.
  Reimporting the same binding is legal; distinct same-name bindings can conflict.
- `do-import` looks up visible identifiers before considering the built-in standard
  library or filesystem. A non-module binding is an error. Quoted filenames do not
  resolve to built-ins or same-named local modules. An external file contains a
  single module definition and that module has no enclosing source-file namespace.
- `pass-helpers.ss`'s `find-source-pathname` preserves the selected pathname text;
  the external-module table keys it with the module name, not `realpath`.
- Includes expand in their include-file directory, but later import resolution uses
  the active compilation-unit directory. An external module establishes its resolved
  file directory; an exported local module uses its first importing context. Cached
  instances retain their original resolutions after later imports/definitions.

The source checkout is ahead of the release. Acceptance/rejection, getter identity,
path-spelling, include-context and symlink tests verify the qualified executable
separately. These observations must not be generalized to other compiler releases.

## Owned model

`Sources.read` still caches immutable syntax once per canonical physical file and
keeps accurate physical source spans. `Sources.locate` separately preserves the
selected pathname. Expansion carries an include base without rewriting locations.

Each semantic scope has its complete names, source-order-visible names, exported
bindings and active import directory. Linking uses the visible environment; later
circuit-body binding sees the completed lexical scope. Exported bindings are kept
separate rather than manufacturing new local declarations or copying callable
lookup-context wrappers into canonical symbol tables.

The instance cache is per module declaration and compares generic arguments by
semantic type equality or numeric natural equality. It reuses one instantiated scope
across a diamond dependency. A nested exported module retains the declaration
identity of its enclosing specialization. New instance IDs include expansion order;
two imports from a repeatedly included physical span cannot collide when they resolve
different declarations. Cache lookup remains bounded by existing
module/type budgets; unsupported or cyclic composition cannot become a clean scan.

That regression uses a compiler-valid empty import selection. The owned grammar
overlay now accepts this construct (ADR 0003); it instantiates and validates the
module without introducing any exported names, rather than acting as an import-all.

The previous blanket transitive-state-sharing diagnostic is removed. This does not
change data-flow transfers: read/write sets, private flows and guard invalidation
automatically use the corrected canonical ledger/function identities.

## Qualification and limits

`tests/module-composition.test.ts` checks direct/diamond sharing, equivalent and
distinct generic types, nested exported modules, source-order lookup, native-name
shadowing, external file shape, physical/path identities, includes and symlinks.
It compares cached/uncached facts and instruction/reference semantic paths, including
shared-predicate guard invalidation and preimage detector evidence. Where exported
state aliases are available, compiler getter indices independently establish whether
the two aliases address the same storage. Negative cases require incomplete reports.

`module-composition.compact` adds a composed compiler-valid application root.
These tests are implementation evidence, not security labels or an audit of
an existing third-party application. Full type legality, broader search-path/platform
and compiler-version qualification, generic circuit specialization equivalence and
general correlated stateful joins remain separate work.
