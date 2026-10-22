# Nightshade limitations

Nightshade is a bounded, experimental source analyzer. A **complete** result means
the supported analysis finished for the selected rules; it does not establish
compiler validity, transaction feasibility or whole-contract security. Review
`status`, diagnostics, `coverage.baselineStatus` and `coverage.rules` before using
findings or a zero-finding result. Rules can be structurally absent, complete or
unavailable independently of the baseline engine.

## Compiler profiles

| Compiler | Language | Qualified analysis profile |
|---|---|---|
| 0.28.0 | 0.20.0 | Bounded ZKIR2 subset |
| 0.29.0 | 0.21.0 | Bounded ZKIR2 subset |
| 0.30.0 | 0.22.0 | ZKIR2 subset |
| 0.31.1 | 0.23.0 | Main qualified subset; ZKIR2 |
| 0.33.0-rc.2 | 0.25.0 | Pinned prerelease ZKIR2 subset |
| 0.34.0 | 0.26.0 | Main qualified subset; ZKIR2 or explicitly selected ZKIR3 |
| 0.35.0-rc.1 / 0.35.0 | 0.27.0 | Pinned ZKIR2 subset |

These are exact profiles, not support for every patch or intermediate release.
Compiler **0.26.0**, stable **0.33.0**, other unlisted versions and **0.35 ZKIR3**
are unsupported. The 0.33 RC2 binary reports unstamped 0.33.0; optional executable
validation authenticates the pinned Linux-musl RC2 binary. Other RC2 platforms are
unqualified. Rule-specific profiles may be narrower than engine profiles.

Offline selection retains 0.34.0 if the root pragmas allow it, otherwise prefers
the newest compatible stable profile; exact 0.25/0.33 pragmas select RC2. No pragmas
defaults to 0.34.0. Pin `--compiler-version` to the actual build, especially with
open-ended pragmas. Imported pragmas must agree. A profile is an analysis assumption,
not attestation of the project’s build or deployed runtime. A trusted compiler may
be invoked explicitly with `--compiler`; ordinary scans do not run it.
See [ADR 0016](adr/0016-casts-and-semantic-profile.md).

## Soundness boundaries and gaps

- Abstract paths and range envelopes can overapproximate reachable executions.
  Findings may describe intentional rejection, disclosure or protocol behavior.
  Arithmetic interval evidence is not proof of joint feasibility or impact.
- Entry analysis does not establish arbitrary cross-transaction histories,
  node acceptance, witness implementation behavior, cryptographic security or
  deployed runtime compatibility. Ledger parameters/locals are value snapshots.
- Full compiler legality, nominal/subtype/inference boundaries, constant reduction,
  wider import/search-path semantics and every primitive/ADT combination are not
  implemented. Normal scans assume compiler-valid sources; compiler validation
  is separate.
- General correlated stateful joins, whole-program/memory SSA and symbolic solving
  are absent. Branch-heavy effects can exhaust the default 40,000-step/256-path/
  50,000-value budgets. Summary reuse is restricted to supported transfers.
- Collection reasoning is conservative for unknown keys, wildcard may-alias paths,
  richer Map/Set relationships, List ordering/empty-pop and Counter overflow.
  Tree, coin and Kernel APIs have restricted coverage. In the 0.35 profiles,
  `kernel.caller()` is modeled as an opaque kernel read and dynamic
  cross-contract calls are explicit re-entry/abort boundaries: caller writes
  are retained, while post-call reads stay unknown until an overlapping write
  re-establishes the region. Entries that reach such a dynamic call remain
  incomplete and carry a `dynamic-contract-call` diagnostic.
- Legacy 0.28/0.29 curve natives (`ecAdd`, `ecMul`, `ecMulGenerator` and
  `hashToCurve`) return the compiler's struct-backed `NativePoint` and produce
  `unsupported-profile-native`; Opaque persistent hashing/commitments remain
  unsupported. Their invocation-directory-dependent file include/import lookup
  produces `unsupported-profile-search-order`; in-source modules and bundled
  `CompactStandardLibrary` imports remain supported.
- Policy rules need explicit, validated application intent. Name heuristics used
  by some prioritization rules do not establish authorization or privilege.
  See each rule’s false positives and evidence contract.

Unsupported syntax/effects, unresolved symbols and exhausted budgets produce
explicit diagnostics. Partial findings remain useful, but an incomplete scan is
never equivalent to a clean scan. Thresholds, baselines and suppressions cannot
turn diagnostics into success. A declaration-only root has `no entrypoints`
coverage, not execution coverage. [Detailed boundaries](coverage.md).

## Operational and evidence limits

The CLI supervises workers for timeouts, output bounds and native crashes. Its
V8 heap limit is **not an RSS cap or OS sandbox**. Hosted hostile-input scanning
needs external CPU/RSS/disk/filesystem containment. Trusted custom detectors and
`--compiler` execute host code only when explicitly selected.

Linux x86-64/glibc with Node 22/24 is locally qualified. Packed runtime prebuilds
also need libstdc++ providing `GLIBCXX_3.4.31` (Ubuntu 24.04 / Debian 13); on
older runtimes the tree-sitter dependency needs a compiler-toolchain fallback. Other targets need their
own parser build and platform validation. Hosted workflows remain manual-only;
private GitHub SARIF access and hosted uploads have not been established by local
schema checks. Dependency installation needs network access; scans are offline.

Rule examples have selection bias. Public documentation does not claim broad
precision or ecosystem-wide recall. See [evaluation](evaluation.md) for the scope
of published evidence.
