# ADR 0003: Pinned, generated Compact grammar overlay

Status: accepted for the engineering preview, 2026-09-25.

## Evidence and decision

The official development grammar at
`22de6ee9dbf4b92fe4e2fe3602e53f1e352b79fd` omits two-element expression sequences:
its `expr_seq` alternative requires a first expression, one or more comma-expression
pairs, and another final expression. Compiler 0.34.0 / language 0.26.0 accepts two
expressions. Its `doc/compact-grammar.mdx`, expression-sequence production, specifies
one or more expressions without a trailing comma. The upstream main revision
`6693aff01384a8cf1d928d830f67978c441a2506` retains the defect and lacks several other
modern productions we already support; changing to main would regress compatibility.

Keep the pinned upstream grammar as a development dependency. Extend it through the
tree-sitter grammar-inheritance API in `src/parser/native/grammar.cjs`, replacing
`expr_seq` with one expression followed by zero or more comma-expression pairs.
Do not rewrite user source, accept recovery nodes, modify installed upstream files,
or patch generated parse tables. This is an explicitly maintained local grammar
correction, not an upstream release or an OpenZeppelin fork.

The `sequences-and-imports-v2` overlay additionally permits an empty
`import_selection`: `import {} from Library;`. The pinned grammar incorrectly uses
a nonempty list, while the official parser's `SEP*` production and compiler 0.34.0
accept zero selections. Empty is distinct from absent: it instantiates the module
but introduces none of its exports. The correction preserves nonempty selections
and optional trailing commas, and rejects leading/repeated commas. The repeated-include
identity regression in ADR 0009 exposed this gap; no source-rewriting workaround is used.

The `sequences-imports-strings-v3` overlay retains those fixes and admits
escaped string/file line continuations. ADR 0013 qualifies Compact decoding and
the compiler-equivalent line-ending parser view, with a map back to untouched
original source bytes. This is input transcoding, not a syntax-rewriting workaround.

ADRs 0014 and 0017 extend this to the current v5 overlay: generic cast targets retain
nongeneric comparison parsing; omitted tuple pattern slots and empty struct patterns
match compiler-accepted destructuring syntax. Earlier v3/v4 measurements remain
historical evidence rather than identity claims for the new generated parser.

## Build and distribution

- Pin tree-sitter-cli 0.25.10 and generate language ABI 15; use runtime 0.25.1.
- Verify the upstream grammar SHA-256 before generation. Build identity includes
  the overlay, binding, generator configuration, build script and native build file.
- Generate C, node metadata, source grammar, headers, provenance and license notices
  under ignored `dist/parser`; never commit generated tables or binaries.
- Use a small owned N-API C binding. Embed the build identity into the binding and
  compare it with the manifest at load time; stale native code cannot masquerade as
  the new grammar. Report both upstream `grammarRevision` and `grammarBuild`.
- Hash-check generated files before reuse. `node scripts/build-parser.mjs --verify`
  performs verification without regeneration. These checks detect stale/local
  artifact mismatch; they are not a signature or remote supply-chain attestation.
- Packed artifacts include generated C/metadata, binding/overlay/build sources,
  preserved upstream grammar/notices, Apache-2.0 text and tree-sitter MIT text.
  They include the builder target's N-API 8 parser and exclude the generator.
  Production installation verifies the generated sources and native identity;
  a missing matching grammar binary fails explicitly without compilation.
- Checkout development uses `npm ci` and `npm run build`; a production-only install
  directly from an unbuilt source checkout is not supported. Source builds need
  Python, a C/C++ toolchain and Node headers. Matching packed installs use prebuilds.
- Builds/installation may need network access; ordinary scans remain offline and
  never execute Compact source or the parser generator.

## Qualification

`parser-sequences.test.ts` compiler-checks singleton, pair and longer sequences,
left-to-right writes and abort-before-second-effect behavior; it also checks invalid
separators, CRLF/Unicode byte/column mapping and artifact identity. Existing owned
AST/semantic tests exercise the new native parser. The original sequence correction
left node-types JSON unchanged; the empty-selection correction makes selection children
optional. The owned adapter already distinguishes `[]` selections from absent selections.
`parser-imports.test.ts` qualifies that distinction, generic instantiation, visibility,
malformed lists and Unicode source spans against the release compiler.

The supported compiler-feature suite compares instruction/reference semantic path
facts, including source/sink locations, private-source identities, field values,
guards and write order. Path enumeration order, descriptive branch labels and
provenance-trace wording differ between engines and are normalized for this check;
dedicated source-map/IR tests check traces separately. Differential agreement is not
independent proof: the engines share transfer functions.

An opt-in `compiler-upstream.test.ts` additionally checks seven unmodified language
examples from the pinned official compiler checkout. Five compare complete analysis
facts across engines. Two compiler-accepted examples explicitly document existing
limits: `multiconst` has a 998-iteration loop, beyond the 256-iteration cap; `types`
now passes nominal types (ADR 0006) but stops at the unsupported coin insertion
operation. These two are coverage-gap regressions, not analyzed coverage.
No detectors run on these examples; they provide language conformance evidence, not
independently labeled security findings. Set `COMPACT_SOURCE_TEST` with `COMPACTC_TEST`
to run them; without those inputs they are reported as skipped, not passed.

Clean installation, packed production installation, CLI/API/type-consumer tests,
Linux Node 22/24 runs and remote macOS qualification remain required after changes.
The overlay can be removed only after an upstream revision passes this same suite.
The grammar overlay is distributed under Apache-2.0. Third-party components
retain their own licenses and notices, listed in [THIRD_PARTY.md](../../THIRD_PARTY.md).

`npm pack` includes the builder target's parser in `prebuilds/`, which stays
ignored in Git. The pinned Tree-sitter runtime supplies its own prebuilds.
A target-specific package is not cross-platform
qualification; other OS/architecture/libc targets and hosted CI remain separate gates.
