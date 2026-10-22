# Nightshade

Nightshade is an offline static security analyzer for Compact smart contracts.
The packaged native build targets **Linux x86-64/glibc on Node 22 or 24**.
On macOS, use [Docker](#docker) with the `linux/amd64` platform.
It resolves modules and calls, tracks private data and ledger effects, and reports
source locations, evidence and coverage gaps in text, JSON or SARIF. Ordinary
scans do not execute contracts or require a Compact compiler.

Use it to find suspicious data disclosure, authorization and state-update
patterns, then review the evidence against the application's intended behavior.
An incomplete scan exits with an error. A complete scan means the selected,
supported analysis finished; it does not establish contract security or prove
that a reported path can execute.

## Quickstart from source

Open a source checkout on Linux x86-64/glibc with Node.js 22 or 24, npm, Git,
Python 3, `make` and a C/C++ compiler. Installation downloads pinned dependencies,
the parser generator and, when needed, Node headers. Then run:

```sh
npm ci
npm run build
npm run demo
```

The demo scans two shipped synthetic contracts and ends with
`Demo passed: expected finding and corrected control verified.` It verifies one
medium-severity `ledger-bound-preimage-publication` at line 12 of
`examples/review/contract.compact` and no findings in `corrected.compact`.

```sh
node dist/src/cli.js examples/review/contract.compact
node dist/src/cli.js examples/review/corrected.compact
```

The first command exits **1** because the contract publishes a secret used in an
authorization check; the second exits **0**. The corrected example is a quiet
control for this rule, not a security certification. After installation/build,
these scans usually take seconds.

## Install a release tarball

The npm package is `nightshade-compact`; its CLI is `nightshade`.
Install a local release tarball or build one from source as shown below.

Source and releases: [DicksonWu654/nightshade](https://github.com/DicksonWu654/nightshade).
Report security issues through [GitHub private vulnerability reporting](SECURITY.md).

To create and try a local tarball from this checkout:

```sh
package_dir=$(mktemp -d)
consumer_dir=$(mktemp -d)
npm pack --pack-destination "$package_dir"
npm install --prefix "$consumer_dir" "$package_dir/nightshade-compact-0.1.0.tgz"
"$consumer_dir/node_modules/.bin/nightshade" "$consumer_dir/node_modules/nightshade-compact/examples/review/contract.compact" --fail-on high
```

The final scan prints the medium finding and exits 0 because this example sets a
high failure threshold. For a downloaded release tarball, use its path in the install step. Run the installed `nightshade` executable on your local contract sources.

The packaged target is Linux x86-64/glibc with Node 22/24 and libstdc++ providing
`GLIBCXX_3.4.31` or newer (Ubuntu 24.04 or Debian 13). The grammar prebuild is
specific to its build platform. Older runtime libraries can require a C/C++
toolchain for the tree-sitter dependency; other targets need a separate qualified
build. See [third-party notices](THIRD_PARTY.md).

## Docker

From the source checkout with Docker available:

```sh
docker build --platform linux/amd64 -t nightshade:local .
docker run --platform linux/amd64 --rm --network none -v "$PWD:/project:ro" nightshade:local examples/review/contract.compact
```

The image builds and installs a tarball. The scan runs without network access and
exits 1 for the expected medium finding. Mount the application's local imports
alongside its sources. A container does not make analysis complete; inspect the
same diagnostics and coverage as a native scan.

## Output, configuration and CI

```sh
node dist/src/cli.js examples/review/contract.compact --json
node dist/src/cli.js examples/review/contract.compact --sarif > report.sarif
node dist/src/cli.js --config examples/review/config.json
node dist/src/cli.js detector list
node dist/src/cli.js detector show ledger-bound-preimage-publication
```

The first three commands exit 1 for the sample finding; JSON and SARIF remain
usable on stdout. Exit **2** means incomplete analysis, invalid input/configuration
or worker failure, even when a report also contains findings. Exit **0** means no
unsuppressed new finding meets the selected threshold and analysis completed.

The [unstable API guide](docs/api.md) documents JavaScript exports and trusted detector modules.
The [user guide](docs/user-guide.md) covers thresholds, detector selection,
imports, baselines, suppressions and offline review maps.
The [configuration reference](docs/configuration.md) lists accepted fields.
The [detector catalog](docs/detectors.md) links every rule's intent, activation,
known false-positive patterns and limits. Policy rules require explicit intent.

The composite [GitHub Action](action.yml) builds Nightshade, scans the caller's
workspace, uploads SARIF and preserves the analyzer exit code. The following is
a workflow template using the v0.1.0 release. Pin the Action to a reviewed commit
for an immutable dependency.

```yaml
name: Compact analysis
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  nightshade:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: DicksonWu654/nightshade@v0.1.0
        with:
          path: contracts
          fail-on: medium
          category: compact-contracts
```

Install contract dependencies before scanning. Hosted upload requires GitHub
code-scanning access and appropriate token permissions; local SARIF generation
does not verify that access. See the [local Action example](docs/user-guide.md#github-action).

## Compiler support and limits

Pinned analysis profiles: **0.28.0, 0.29.0, 0.30.0, 0.31.1, 0.33.0-rc.2,
0.34.0, 0.35.0-rc.1 and 0.35.0**. These are supported subsets. ZKIR2 is the
default; ZKIR3 requires explicit selection and is supported only for 0.34.0.
Unknown versions, unsupported syntax, unresolved imports and exhausted budgets
produce diagnostics. Select the profile that built the application; do not
change versions merely to clear a diagnostic. The
[profile matrix](docs/compiler-onboarding.md#supported-profiles) lists language
and runtime versions and how to opt into external compiler validation.

Default rules do not infer a complete authorization policy from cross-circuit
use of ledger values. An unguarded write to a field that another circuit compares
as an authentication credential can go unreported, including by
`inconsistent-access-control`. Declare the required `authorization` policy and
review every credential-changing circuit; a quiet default scan is insufficient.

Analysis has bounded path and value tracking, incomplete support for some native
operations and dynamic calls, and no general cross-transaction or cryptographic
proof. Intentional disclosures and application-specific authorization policies
can resemble defects. Findings require review, including policy-required and
informational rules. See [limitations](docs/limitations.md) and the scoped
[evaluation summary](docs/evaluation.md).

A pre-release build of 0.1.0 completed baseline analysis on 258/300 roots (86%)
and every selected rule on 237/300 (79%), reporting 315 findings and zero worker
failures. These measurements use a private fixed input set that is not
available for reproduction; the denominator includes 27 compiler-rejected roots.
General precision and recall
have not been established; see the evaluation page for sampling caveats.

## Contributing and licensing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and focused checks,
[architecture](docs/architecture.md) for implementation boundaries and
[SECURITY.md](SECURITY.md) for private reporting instructions.

Nightshade is licensed under [Apache-2.0](LICENSE). [NOTICE](NOTICE) and
[THIRD_PARTY.md](THIRD_PARTY.md) describe bundled grammar, runtime and standard
library licences and retained attribution.
