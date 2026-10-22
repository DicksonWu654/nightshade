# Compiler onboarding

Nightshade selects a pinned semantic profile; ordinary scans neither run a compiler
nor download imports. Pin the profile used to build the application, then check
compiler acceptance and analyzer completeness separately. A successful compiler
check does not establish detector coverage or contract security.

## Supported profiles

The current matrix comes from `src/semantic/profile.ts`. Each row describes a
bounded analysis subset, not every feature of that compiler.

| `--compiler-version` | Language version | Matching Compact runtime | ZKIR |
|---|---|---|---|
| `0.28.0` | `0.20.0` | `0.14.0` | 2 |
| `0.29.0` | `0.21.0` | `0.14.0` | 2 |
| `0.30.0` | `0.22.0` | `0.15.0` | 2 |
| `0.31.1` | `0.23.0` | `0.16.0` | 2 |
| `0.33.0-rc.2` | `0.25.0` | `0.18.0-rc.1` | 2 |
| `0.34.0` | `0.26.0` | `0.19.0` | 2; explicitly selected 3 |
| `0.35.0-rc.1` | `0.27.0` | `0.20.0` | 2 |
| `0.35.0` | `0.27.0` | `0.20.0` | 2 |

Runtime versions identify matching build inputs; static scanning does not require
the runtime package. Versions not listed, including compiler 0.26.0 and stable
0.33.0, are unsupported. RC2 executable validation accepts only the pinned
Linux-musl artifact, which reports `0.33.0` without its prerelease suffix. Both
0.35 profiles require a matching source commit/date stamp in `--version` output.
Unstamped or mismatched development builds are rejected.

Without a pin, compatible root pragmas retain 0.34.0; otherwise selection prefers
the newest compatible stable profile. Exact 0.25/0.33 pragmas select RC2. Sources
without pragmas default to 0.34.0. Imported pragmas must agree. Open-ended pragmas
therefore make an explicit pin especially useful. See [limitations](limitations.md#compiler-profiles)
for incomplete primitives and profile-specific gaps.

## Onboard an application using a supported compiler

1. Retain the trusted compiler executable, its release/source identity and the
   application's exact dependency revisions outside this repository. Check its
   `--version` and `--language-version` against the table. Normal analysis needs
   neither a compiler install nor network access; explicit validation executes the
   selected executable on the host.
2. Make imports available locally. Pass dependency directories with
   `--compact-path`; use the platform path delimiter for multiple directories
   (`:` on Unix, `;` on Windows). `COMPACT_PATH` is also supported. Resolution uses
   the active compilation-unit directory; an include's source location is not a
   new import base. Preserve the application's module paths and aliases.
3. Run the scan with the exact profile, optionally adding explicit compiler
   validation. From a source checkout, use `node dist/src/cli.js` in place of
   `nightshade` after `npm run build`:

   ```sh
   node dist/src/cli.js examples/review/contract.compact --compiler-version 0.34.0 --json
   ```

   The shipped positive exits 1 with one medium finding. For your application,
   replace the example path and add local dependency directories with
   `--compact-path`. Optional external validation adds `--compiler` with a
   trusted executable path. It executes that host binary; it is not needed for
   static scanning.

4. Inspect `status`, diagnostics, `compilerValidated`, `semanticProfile`, baseline
   coverage and per-rule coverage. Exit 1 denotes findings meeting the threshold;
   exit 2 denotes invalid or incomplete analysis. A zero-finding result with
   incomplete coverage needs investigation. Library-only roots may have no
   entrypoints; use an application root exporting the relevant circuits.
5. If the actual build uses qualified 0.34.0 ZKIR3, add `--zkir-version 3` to both
   analysis and validation. ZKIR3 is not qualified with other profiles. Record any
   remaining import, primitive or budget diagnostics rather than changing the
   profile to obtain a clean result.

The compiler validation helper uses `--skip-zk`, a temporary output directory,
and a 30-second compiler timeout during a scan. It checks executable/profile
agreement and compiler acceptance; it does not generate or verify proofs. For
0.28/0.29 it uses `COMPACT_PATH` from an empty temporary working directory because
those compilers predate `--compact-path`. File include/import lookup produces
`unsupported-profile-search-order`; in-source modules and bundled standard-library
imports remain supported. Their four struct-backed `NativePoint` curve natives
produce `unsupported-profile-native`. In 0.35, `kernel.caller()` is an opaque
read; dynamic calls preserve caller writes and invalidate later storage reads
until re-established, with an explicit `dynamic-contract-call` incompleteness
diagnostic. See [the exact bounds](limitations.md#soundness-boundaries-and-gaps). The bundled profile-specific `CompactStandardLibrary` supports
offline analysis; unrelated project imports still need local sources.

## Qualify a new compiler profile

Adding a version string is insufficient. The contributor must establish these
independent gates before advertising support:

- Pin release binaries and source commits, the language/runtime pair, standard
  library and ZKIR behavior. Add identity checks in `src/compiler/index.ts` and a
  profile in `src/semantic/profile.ts`; preserve explicit rejection of unknown
  builds. Carry the new identity through config, CLI, workers, report schemas and
  packaging. Compare the default/pragma-selection behavior with existing profiles.
- Build compiler-accepted owned fixtures and compiler-rejected controls for changed
  syntax, type legality, imports, native identities, storage and witness ABI.
  Extend the nearest profile tests, not just a parser acceptance test. Native
  input restrictions apply after overload selection and traverse represented
  fields; phantom parameters do not supply runtime fields. See
  [ADR 0018](adr/0018-native-input-qualification.md).
- Compare instruction and reference dataflow engines, cached and uncached paths,
  effects, abort behavior and explicit unsupported/budget diagnostics. Reusable
  feature fixtures live in `tests/fixtures/features`; profile-specific examples
  are in `tests/compiler-*.test.ts`. New security rules also need compiler-valid
  positive/corrected pairs and negative lookalikes that distinguish the behavior
  from benign cases.
- If syntax changes, edit `src/parser/native/grammar.cjs` and regenerate using
  `npm run build:parser`. Keep the upstream revision/hash and generator pinned in
  `src/parser/native/config.json`. Never patch generated parser tables or
  dependencies. Only the parser layer reads grammar nodes. The current native
  parser uses tree-sitter ABI 15; verify the loaded grammar identity and packed
  native addon on each supported Node/platform combination.
- Run the relevant compiler-backed tests, `npm test` and `npm run test:package`.
  Record skipped compiler/runtime checks and platform gaps explicitly. Runtime
  compatibility requires its own compiled-evaluation qualification; source
  acceptance alone does not establish it. See the
  [runtime fixtures](runtime-qualification.md).

For existing profiles, set the relevant executable variables before testing:
`COMPACTC_TEST` (0.34), `COMPACTC_028_TEST`, `COMPACTC_029_TEST`,
`COMPACTC_030_TEST`, `COMPACTC_031_TEST`, `COMPACTC_033_RC2_TEST`,
`COMPACTC_035_RC1_TEST`, and `COMPACTC_035_TEST`. The focused contributor
example runs after building:

```sh
node --test dist/tests/compiler-features.test.js dist/tests/compiler-stable.test.js
```

Set `COMPACTC_TEST` to a trusted 0.34.0 compiler executable and
`COMPACTC_035_TEST` to the pinned 0.35.0 executable for their acceptance checks.
Missing external tools produce skips; these focused tests do not replace full
release qualification. See [contributor checks](../CONTRIBUTING.md) for the
correctness and packed-install gates.

The upstream conformance suite additionally requires `COMPACT_SOURCE_TEST` at its
separately pinned revision, currently `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`.
Use its pristine sources; do not substitute the current compiler release tree or
rewrite rejected fixtures. Compiler-related tests can skip or omit executable
validation when inputs are absent, so a passing unconfigured suite is not evidence
of compiler qualification. Package installation may need network access; scans
against already installed tools and local imports remain offline.

## Experimental contributor helper

The built source checkout includes `scripts/onboard-compiler.mjs`. Its networked
developer modes are separate from ordinary offline scans. Inspect the helper's arguments without fetching a compiler:

```sh
node scripts/onboard-compiler.mjs --help
```

Its explicit `--watch` mode reads upstream release metadata. Onboarding accepts a
version or archive URL, `--previous VERSION`, `--corpus DIRECTORY_OR_REPORT` and
`--output NEW_DIRECTORY`. These networked developer operations require trusted
external inputs and are not part of the static-analysis quickstart.

The watcher reads upstream release metadata. Onboarding fetches/extracts a compiler,
records archive/binary hashes, rebuilds the checkout, runs a limited profile-test
selection, compiles corpus roots and records analyzer diagnostics and rule gaps.
Use a new external output directory and independently verify the release identity;
recorded hashes alone do not authenticate a download. Run it outside frozen
measurements because it rebuilds `dist`.

Pass an existing compatibility **report** with `rows`, `compilerRejected` and
`sourcePins`, or a directory of Compact sources. A missing or empty corpus can
produce zero rows, so inspect totals. The helper does not restore dependency
search paths for its compiler/analyzer probes. Its `--previous VERSION` compares
profile metadata rather than running a historical analyzer build, and it does not
provide a semantic standard-library diff. Only the 0.35 executable is wired into
its test environment automatically; configure other compiler variables explicitly.
Inspect JSON probe/suite/corpus failures even when the command exits successfully.
These reports assist the manual qualification gates above; they do not register,
qualify or promote a compiler profile automatically.
