# Contributing to Nightshade

Use Linux x86-64/glibc, Node 22 or 24, npm, Git, Python 3, `make` and a C/C++
compiler. Start in a source checkout. Installation downloads pinned dependencies,
the tree-sitter generator and Node headers when needed:

```sh
npm ci
npm run build
npm run demo
node scripts/build-parser.mjs --verify
node --test dist/tests/workflows.test.js dist/tests/project-workflow.test.js
```

The demo checks the shipped positive/corrected pair. The final command is a
focused CLI/configuration check. For a change, choose the test files covering
the affected transfer, detector or workflow. External-input tests explicitly
skip when the required compiler, source tree, runtime or schema is unavailable;
report those skips. A passing unconfigured run is not full qualification.

The [package scripts](package.json) and [CI workflow](.github/workflows/ci.yml)
define checks. Pull requests run build, demo and the focused CLI, reporting,
coverage-policy and package-documentation tests. The full matrix remains an
explicit manual run:


| Script | Purpose |
| --- | --- |
| `test` | Build and run the complete correctness suite, with bounded parallelism |
| `test:timing` | Run timing-sensitive checks serially |
| `test:package` | Build/install a tarball and exercise consumer workflows |
| `test:dual` | Correctness on explicitly configured Node 22 and 24 executables |
| `test:generated` | Compiler-validated synthetic campaigns; see [generated testing](docs/generated-testing.md) |

Changes need relevant focused regressions. Releases additionally need the full
correctness suite on both Node versions, packaged installs, Docker, local Action,
SARIF schema and pinned compiler/corpus checks. Do not substitute a demo or a
run with missing external inputs for these gates.

External compiler tests use `COMPACTC_TEST` for 0.34.0 and versioned
`COMPACTC_028_TEST`, `COMPACTC_029_TEST`, `COMPACTC_030_TEST`, `COMPACTC_031_TEST`,
`COMPACTC_033_RC2_TEST`, `COMPACTC_035_RC1_TEST`, `COMPACTC_035_TEST` for other
profiles. `COMPACT_SOURCE_TEST`, `OZ_COMPACT_TEST`, `COMPACT_RUNTIME_TEST` and
`SARIF_SCHEMA` select separate local reference inputs. Retain their pinned
identities outside Git; see [compiler onboarding](docs/compiler-onboarding.md)
and the relevant test's setup instructions. `NIGHTSHADE_DISABLE_FIXTURE_CACHE=1`
requests fresh compiler acceptance. Dual-Node runs use `NIGHTSHADE_NODE22` and
`NIGHTSHADE_NODE24`. Keep reports and compiler outputs outside the repository.

Read [AGENTS.md](AGENTS.md) and [architecture](docs/architecture.md). Parser code
stays in `src/parser`; detectors consume `AnalysisFacts`, reusable transfers
belong in `src/dataflow`, and scope/call identity belongs in `src/semantic`.
Preserve instruction/reference and cached/uncached behavior. New rules need
compiler-valid positive/corrected pairs and negative lookalikes. Unit snippets
may be partial or ill-typed and cannot supply compiler-valid ground truth.
Intent belongs in validated policies; names and disclosure alone do not prove
a security defect.

Grammar corrections belong in `src/parser/native/grammar.cjs`; the build
regenerates and verifies its pinned ABI/identity. Preserve packed-install and
UTF-8/UTF-16 source-map coverage. Generated parser C, `dist`, dependencies,
prebuilds, caches and tarballs stay ignored. Do not patch dependencies or tables.

Preserve upstream licence and attribution notices. Describe what changed and
why, the checks run and their gaps. Keep research clones and proof artifacts
outside Git. Benchmark through the existing separate-process harness and retain
baseline identity, crashes and coverage gaps. Use [SECURITY.md](SECURITY.md) for
security reports; keep sensitive application material out of public issues.
