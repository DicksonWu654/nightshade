# ADR 0001: TypeScript core and an upstream syntax frontend

Status: accepted for the first vertical slice, 2026-09-24.

| Candidate | Strengths | Costs |
| --- | --- | --- |
| TypeScript | Midnight application ecosystem; discriminated IR unions; npm CLI/plugins; native tree-sitter binding; straightforward future worker/JSON integrations | Native parser distribution requires platform builds; immutable facts need discipline; less predictable memory than Rust |
| Rust | Compact grammar binding, compact graph storage, predictable throughput, native distribution | Slower iteration on abstract domains; dynamic plugin ABI and JS integrations need explicit boundaries |
| Python | Mature analysis/graph ecosystem, fast prototyping | Upstream grammar Python packaging lacks an extension build configuration in the inspected revisions; extra distribution boundary to Midnight tooling; no performance advantage over TS here |

Use TypeScript for the semantic model, CFG, abstract values, detector API, and CLI.
Performance is an empirical question: profile project loading, graph construction,
and transfer functions before moving any hot path into Rust. Graph and provenance
identities must be serializable; future fuzzing/symbolic tools can consume a versioned
representation without executing detector plugins.

Use the Apache-2.0 official tree-sitter grammar, pinned to development revision
`22de6ee9dbf4b92fe4e2fe3602e53f1e352b79fd`. Its main branch still uses legacy
assertion syntax; this development revision supports modern `assert(expr, message)`,
block comments, and selective imports. This is an explicit compatibility risk,
not a claim to implement every feature of compiler 0.34.0. Reject parse recovery
nodes and unsupported semantic constructs, with locations. Never silently claim
complete coverage for a partially modeled program.

ADR 0003 adds a pinned generated overlay for expression sequences and supersedes
the original direct-upstream-native-binding distribution described here. The grammar
is now a development dependency; packed artifacts include generated C and notices.

The pinned dependency uses a public HTTPS source archive with lockfile integrity,
avoiding npm's GitHub Git-to-SSH URL normalization and an unnecessary SSH setup.
The grammar's native ABI is 15 but its npm peer range still names tree-sitter 0.21.
The project installs tree-sitter 0.25.1 under the npm alias `tree-sitter-runtime`.
The grammar exports a native language object and does not require the old runtime;
using the alias avoids activating its stale optional peer constraint. A tiny owned
declaration bridges the upstream ambient TypeScript module name. Clean `npm ci`
and packed production installation work without `legacy-peer-deps`. Pin both
packages and test the binding. Source installations may need a C/C++ toolchain,
Python and network access; scans themselves are offline.

Keep tree-sitter nodes inside the parser adapter only. Normalize syntax into our
own source-mapped AST, then resolve symbols before lowering into analysis IR.
No OZ or Slither implementation code is incorporated. Their root licenses are
AGPL-3.0; OZ workspace manifests misleadingly say MIT. Study them as references
and run them as separate baseline tools, without linking their libraries.

The compiler has richer typed internal Nanopass IR, but no documented stable typed
AST interchange. JS, source maps, contract-info JSON, and ZKIR are useful secondary
evidence; none preserves all source-level privacy intent. In particular the compiler
removes `disclose` after its witness analysis. Start source-first, validate corpus
programs with the official compiler, and design a compiler adapter for later
cross-checking types, exports, and ledger layouts.
