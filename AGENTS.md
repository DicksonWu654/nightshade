# Nightshade repository context

- `src/parser` is the only layer that may import tree-sitter or inspect concrete
  grammar node kinds. Other layers consume the owned model in `src/model.ts`.
- Detectors consume `AnalysisFacts`; put reusable transfer/constraint logic in
  `src/dataflow`, and scope/call identity logic in `src/semantic`.
- Data-flow defaults to `Program.instructionCFG`; the statement CFG also defines
  source-work estimates. Preserve instruction/reference and cached/uncached tests.
- Higher-order callbacks reuse ordinary call transfers; preserve sequence evaluation
  order and zero-iteration behavior. Arithmetic coercion is not evidence of subtyping.
- Return legality follows syntactic continuations, not constant-path pruning.
  Join branch result types before widening to a declared result (ADR 0015).
- Sequence type inference distinguishes literal/safe-cast indices from later constants.
  Final compiler indexing requires constant reduction after inlining (ADR 0017).
- Vector/Bytes spreads retain element types even when empty. Parameter patterns bind
  in a separate prologue after ordinary parameters; empty patterns need not read values.
- Abort during condition evaluation affects enclosing control, not that condition's
  own branch scope. Keep statement/reference and instruction abort models aligned.
- Compiler 0.34.0 Uint limits are 248 bits, not Field bit width. Use exact exclusive
  result bounds; keep source type legality separate from analysis resource budgets.
- Resolve callable groups nearest-to-outer; non-callable bindings stop lookup.
  Keep lookup context separate from canonical symbols; inner ambiguity cannot fall through.
- Native types retain canonical identities after import; resolve fields in their defining
  scope. ADT defaults/locals can be legal even though signatures/aggregate elements cannot.
- Validate native input restrictions after overload selection, including zero-iteration
  callbacks. Traverse represented fields, not phantom type arguments (ADR 0018).
- Export schemas use free parameters, not concrete sample instantiations. Keep erased
  schema dimensions out of concrete field/nominal/call caches; ADR 0014 defines the boundary.
- Module instances use declaration identity plus semantic generic equality, not type text.
  Physical source caching must not collapse compiler pathname/module identities.
  Imports use the active compilation-unit directory; include source spans are not import bases.
- Ledger locals/parameters are value snapshots. A retained abstract region alone
  does not authorize live storage projection; use resolved expression provenance.
- Collection predicates refine only their ledger revision. Unknown entry storage is
  not empty; missing Map lookup is not a default value. Keep collection transfers,
  definite failures and budget diagnostics shared across engines and summary replay.
- Wildcard storage regions denote may-alias sets, not equal values. Never derive
  must-equality of dynamic reads or collection queries from a shared wildcard path.
- Stateful summaries cache transfer operands/order, not storage or guard snapshots.
  Replay shared mutation transfers; preserve cached/uncached paths and depth/budgets.
- Guard-cover mode is opt-in: subsume only compatible histories with pointwise weaker
  current/write guards. Keep incomparable witnesses; never union exclusive effects.
  Identity normalization must distinguish analysis metadata from user struct fields.
- CLI scans use supervised workers. Keep timeout/failure diagnostics distinct from
  clean scans, and never describe the V8 heap setting as an RSS cap or OS sandbox.
- Preserve byte offsets as UTF-8 and display/SARIF columns as UTF-16 code units.
  Keep non-ASCII source-map regression coverage.
- Decode Compact strings only in the parser. Keep the LF parser view mapped to original
  bytes; raw CR/NEL/LS normalize before lexing, while escaped characters remain data.
- Unsupported syntax, unresolved symbols and exhausted budgets must produce
  diagnostics. Never return a clean scan after dropping unmodeled effects.
- `npm test` builds TypeScript and runs the Node test suite. `dist` and `node_modules`
  are generated and ignored. Pin grammar changes and test native ABI compatibility.
- Grammar corrections belong in `src/parser/native/grammar.cjs`; regenerate through
  `npm run build:parser`. Do not patch dependencies, tables or user source. Keep
  generated/native artifacts ignored; verify packed installs and grammar identity.
- Corpus expectations live in `tests/corpus/manifest.json` and
  `tests/corpus/synthetic-regressions.json`. New detectors need
  compiler-valid positive/corrected pairs and negative lookalikes. Labels are specific
  to a detector, not claims that an entire contract is secure.
- Benchmark through the existing separate-process harness. Record compiler version,
  baseline artifact identity, crashes and coverage gaps; don't substitute upstream
  grammars or conflate release-binary results with current-source results.
- Normal scans are offline. Research clones, baseline binaries, compiled contracts
  and proof artifacts belong outside the repository.
