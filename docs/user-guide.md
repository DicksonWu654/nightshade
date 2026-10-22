# Using Nightshade

Start with the [README](../README.md) for source, tarball, Docker and Action
installation. Commands below run from a built source checkout and use shipped
synthetic examples. An installed package exposes the same CLI as `nightshade`;
replace `node dist/src/cli.js` with that executable for your application.
Normal scans use local sources and imports only. They execute neither contracts
nor a compiler unless the external compiler option is explicitly selected.

## Scan and interpret results

```sh
node dist/src/cli.js scan examples/review/contract.compact
node dist/src/cli.js examples/review/corrected.compact --json
node dist/src/cli.js examples/review/contract.compact --sarif > report.sarif
node dist/src/cli.js examples/review/contract.compact --profile hygiene
node dist/src/cli.js --help
```

The positive example has one medium finding and exits 1; the corrected JSON
scan exits 0 with `status: complete` and an empty findings array. Help exits 0.
SARIF 2.1.0 includes locations, fingerprints, traces, suppressions and incomplete
diagnostics. JSON retains the analyzer's full finding, evidence and coverage
schema. Keep npm's script banner out of redirected reports by using the direct
Node command above or the installed executable.

| Exit | Meaning |
| --- | --- |
| 0 | Analysis complete; no unsuppressed new finding meets the failure threshold |
| 1 | Analysis complete; one or more findings meet the threshold |
| 2 | Incomplete/invalid analysis, configuration error or worker failure |

The default failure threshold is `info`. `--fail-on medium` and
`--min-confidence medium` change CI failure criteria while keeping findings
visible. `--min-severity low` filters displayed findings. Diagnostics remain
visible and cannot be suppressed. `--fail-on none` still exits 2 for incomplete
analysis. Never interpret exit 2 or a rule marked unavailable as a clean check.

To allow a CI run to continue when only selected-rule coverage is incomplete,
set `--rule-incomplete warn` or `"ruleIncomplete": "warn"` in config. The default
is `error`. Findings still determine exit 0/1 under your thresholds; baseline,
input/configuration and worker failures still exit 2. Reports retain
`status: incomplete`, per-rule coverage and every diagnostic. Text labels the
rule gaps as warnings and SARIF uses warning notifications while retaining
`executionSuccessful: false`. This option does not make an unavailable rule a
clean check and does not permit writing a baseline from incomplete analysis.

A directory scan discovers application roots and omits standalone library
templates while analyzing their imported code. Dependency, generated and cache
directories are skipped. A directory with only libraries is incomplete.
`--exclude PATTERN` filters discovered roots; imported effects remain analyzed.
For a multi-root application, configured roots make the selection explicit.

## Configuration and imports

The default filename is `nightshade.json`; it is discovered in the
selected root directory. An explicit config avoids dependence on the working
directory. Try the shipped example:

```sh
node dist/src/cli.js --config examples/review/config.json --json
```

It selects `contract.compact`, compiler profile 0.34.0/ZKIR2 and a medium failure
threshold; expect the medium finding and exit 1. Inspect
[the config](../examples/review/config.json), whose paths are relative to that
file. Use configured roots or a positional file; a positional project directory
can select its configuration's roots. Unknown keys and malformed values fail.

Set `searchPaths` to dependency directories or pass `--compact-path` using the
platform path delimiter (`:` on Linux). `COMPACT_PATH` is also supported.
Dependencies must already exist locally; Nightshade does not fetch imports.
Resolution uses the active compilation-unit directory, not an include's source
location. See [compiler onboarding](compiler-onboarding.md) for the eight pinned
profiles, pragma selection, native restrictions and optional compiler validation.

Budgets constrain work rather than prove coverage. Defaults include 40,000 steps
per entry, 256 paths and 50,000 retained abstract values. Scan workers use a
60-second timeout, 512 MiB V8 heap setting and bounded output by default.
The heap setting is not an RSS cap or OS sandbox. See
[configuration](configuration.md) for all fields and [limitations](limitations.md)
for the supported analysis boundaries.

## Select rules and declare intent

```sh
node dist/src/cli.js detector list
node dist/src/cli.js detector show impossible-assertion
node dist/src/cli.js examples/review/contract.compact --detectors ledger-bound-preimage-publication
node dist/src/cli.js --config examples/review/secret-policy.json --json
```

The catalog commands exit 0. The explicit-rule scan exits 1 for the medium
finding. The policy scan reports the raw publication of `ownerSecret` under the
configured `declared-secret-publication` rule and exits 1.

There are 99 registered IDs. The default `audit` selection excludes high-volume
hygiene observations; `--profile hygiene` restores them. `--detectors ID,ID` or
config `detectors` replaces defaults with an exact nonempty list. Policy-dependent
rules need declared intent even when selected. The shipped
[secret policy](../examples/review/secret-policy.json) allows tracked hash and
commitment forms, but not a raw secret. These forms are analysis labels, not
cryptographic guarantees. Built-in library policies require explicit
`policies.builtins` selection and authenticated library identities.

The [catalog](detectors.md) explains every rule's availability and false-positive
patterns. Inactive experimental IDs emit no findings and provide no completed
check. Host code can be loaded only through explicit trusted CLI/API options;
JSON configuration cannot load plugins or compiler executables.

## Baselines and suppressions

These commands create a new external baseline and replay it with the same
source-root, profile and detector settings:

```sh
baseline_dir=$(mktemp -d)
node dist/src/cli.js examples/review/contract.compact --write-baseline "$baseline_dir/baseline.json" --json
node dist/src/cli.js examples/review/contract.compact --baseline "$baseline_dir/baseline.json" --sarif
```

Creation exits 1 for the current finding and refuses overwrite or incomplete
analysis. Replay exits 0: matching fingerprints stay visible as unchanged and do
not fail CI. Source-location changes can invalidate fingerprints; a baseline is
not semantic equivalence. Config-root and positional scans can use different
source roots, so preserve scan settings across both runs.

Inline directives use the `nightshade-disable-next-line` and
`nightshade-disable-line` prefixes. The shipped
[intentional-reveal example](../examples/review/intentional-reveal.compact) uses:

```compact
// nightshade-disable-next-line ledger-bound-preimage-publication -- Intentional reveal after retiring this authority
published = disclose(secret);
```

```sh
node dist/src/cli.js examples/review/intentional-reveal.compact --json
```

This exits 0 and retains the suppressed finding and reason in JSON.
`nightshade-disable-line` applies to the same line. Exact comma-separated rule
IDs and a reason of at least eight characters are required. Strings and block
comments do not count. Malformed or unmatched directives for selected rules in
the application root make the scan incomplete.

Configuration can instead suppress an exact finding fingerprint with a reason.
Obtain that fingerprint using the same config and scan settings without the
suppression, then add it under `suppressions`. An unused configured suppression
is an error. JSON and SARIF retain suppressed findings; SARIF records accepted
in-source or external suppressions. Configured reasons take precedence.

## Review maps and printers

```sh
review_parent=$(mktemp -d)
node dist/src/cli.js review examples/review/contract.compact --out "$review_parent/brief" --compiler-version 0.34.0
node dist/src/cli.js print human-summary examples/review/contract.compact
node dist/src/cli.js print ledger-access examples/review/contract.compact --json
node dist/src/cli.js print disclosure-map examples/review/contract.compact --json
node dist/src/cli.js print data-dependency examples/review/contract.compact --json
node dist/src/cli.js print inventory examples/review/contract.compact
```

These commands exit 0 for the sample. Review writes a manifest and JSON/Markdown
briefs into a new directory. Its status covers mapping completeness, independent
of findings; questions need human review and do not trigger exit 1. Review does
not inherit ordinary scan configuration or custom detector selection. Inspect
each layer's coverage. Printers expose source structure and retained histories;
they do not prove authorization or transaction feasibility. See
[review mode](review.md) for budgets and optional historical attachments.

[Runtime exploration](explore.md) is a separate experimental source-checkout
workflow that executes a trusted compiler and generated code. It is excluded
from the tarball and is unnecessary for static scanning.

## GitHub Action

The [Action](../action.yml) builds the analyzer on Node 24.20.0, scans the caller
workspace, uploads SARIF even on incomplete results, then preserves the recorded
scan exit status. The [README workflow template](../README.md#output-configuration-and-ci)
uses `DicksonWu654/nightshade@v0.1.1`. Install the
application's local source dependencies separately. Inputs are `path`, `config`,
`compiler-version`, `fail-on` and `category`; outputs are `exit-code` and `sarif`.
Use a distinct category per application. The `config` input selects a JSON
configuration, including `ruleIncomplete`: set it to `warn` to allow rule-only
coverage gaps as CI warnings. Baseline incompleteness still fails.

To exercise the same scan script locally from a built source checkout:

```sh
action_temp=$(mktemp -d)
GITHUB_WORKSPACE="$PWD" RUNNER_TEMP="$action_temp" GITHUB_OUTPUT="$action_temp/outputs" \
NIGHTSHADE_ACTION_PATH="$PWD" NIGHTSHADE_INPUT_PATH=examples/review/contract.compact \
NIGHTSHADE_CONFIG= NIGHTSHADE_COMPILER_VERSION=0.34.0 NIGHTSHADE_FAIL_ON=medium \
bash scripts/action-scan.sh
cat "$action_temp/outputs"
```

The script exits 0 so that the composite Action can upload first. Its outputs
record `exit-code=1` and the SARIF path; the final Action step then exits 1.
Hosted upload additionally requires code-scanning availability and token
permissions. Local generation does not verify GitHub access or hosted behavior.

## SARIF rule documentation

SARIF includes full rule descriptions, offline Markdown help, default levels and
severity/confidence/maturity metadata. `security-severity` maps each rule's lowest
documented priority to GitHub's display scale so a shared rule descriptor does
not inflate lower-priority variants. It is not a calculated CVSS score.
Finding-level severity and evidence remain authoritative, including higher-priority
variants of the same rule. Custom rules supply their own descriptions.

SARIF links point to the [Nightshade repository](https://github.com/DicksonWu654/nightshade)
and its rule documentation. Embedded rule help also works offline.

For JavaScript integrations and explicit trusted `--detector-module` execution,
see the [unstable API guide](api.md).

### Action build and cache behavior

The composite Action builds the reviewed source checkout on each clean runner,
including a native parser build when no matching build is present. It uses the
setup-node npm download cache, keyed by its own lockfile. Compiled native objects
are not reused across workflows: a reusable native cache would need separate
OS, architecture, Node ABI and grammar-identity qualification. This source-build
choice is deliberate; allow build time in the job budget and install a C/C++
toolchain. Repeated builds in one checkout reuse a parser only after its source
and loaded native identities match.

For a workflow that avoids source/native builds, install a separately qualified
release tarball on its supported platform as described in the README and invoke
its installed CLI to generate SARIF. Do not copy an arbitrary native addon from
a different platform or version. The Action preserves the scan's actual exit
status after upload. Its `fail-on` accepts `critical`; a config can opt into
rule-only warnings while baseline failures still return 2.
