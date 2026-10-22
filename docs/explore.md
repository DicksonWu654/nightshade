# Experimental runtime exploration

Exploration is available only through `node scripts/explore.mjs` in a trusted,
built source checkout. The installed CLI has no exploration command. Ordinary
scans and [review](review.md) do not execute contracts. Never run a script taken
from a contract repository you do not trust.

## Run from a built source checkout

The script takes one positional Compact root and environment variables. Run it
from this checkout, whose built `dist` it uses. It invokes
a trusted compiler with `--skip-zk`, then executes generated JavaScript with a
matching local `@midnight-ntwrk/compact-runtime` package. These are explicit host
code executions. Restore the compiler, runtime and local imports separately; the
script does not install them. Choose an external output path: the script can
overwrite an existing report, and its default is beside the input source.

For a small run on the shipped example, first set `COMPACTC_TEST` in your shell
to a trusted Compact 0.34.0 compiler executable. The following restores the pinned
test runtime into a temporary directory; installation needs network access.
The subsequent local exploration uses a five-second search horizon:

```sh
: "${COMPACTC_TEST:?Set a trusted Compact 0.34.0 compiler executable}"
runtime_dir=$(mktemp -d)
cp tests/runtime-fixtures/qualification-inputs/package*.json "$runtime_dir/"
npm ci --prefix "$runtime_dir" --ignore-scripts --omit=dev --no-audit --no-fund
explore_dir=$(mktemp -d)
COMPACTC="$COMPACTC_TEST" \
COMPACT_RUNTIME="$runtime_dir/node_modules/@midnight-ntwrk/compact-runtime/dist/index.js" \
NIGHTSHADE_COMPILER=0.34.0 NIGHTSHADE_EXPLORE_MS=5000 \
NIGHTSHADE_EXPLORE_OUTPUT="$explore_dir/explore.json" \
node scripts/explore.mjs examples/review/contract.compact
```

The command writes `nightshade-explore-2` JSON. Inspect compiler and runtime
setup status, attempted calls, replay errors and explicit misses; an exit-zero
script alone does not establish a successful runtime observation. Use this small
run to check setup, not to infer application security or explorer coverage.

| Input | Meaning |
|---|---|
| positional `ROOT` | One existing contract source |
| `COMPACTC` | Trusted compiler executable; set it explicitly |
| `NIGHTSHADE_COMPILER` | Analysis/compiler profile; script default `0.31.1` |
| `COMPACT_RUNTIME` | Local runtime `dist/index.js`; must match generated metadata |
| `COMPACT_PATH` | Local compiler import search path |
| `NIGHTSHADE_EXPLORE_MS` | Exploration bound and subprocess timeout input; default `180000` ms |
| `NIGHTSHADE_EXPLORE_OUTPUT` | JSON report destination; parent must exist |
| `NIGHTSHADE_ENABLE_EXPERIMENTAL_ORACLES=1` | Re-enable six low-precision oracles for a focused experiment |

These are script inputs, not options accepted by `nightshade scan` or `review`.
The compiler defaults to `compactc` on PATH; runtime lookup also checks local
test/dependency installs. Explicit paths make a run more reproducible. It does not provide the scan worker's `--heap-mib` option
or an OS sandbox. Its time input bounds parts of the workflow, not a guaranteed
whole-process wall-time or resource cap. Use external process/resource supervision
when required. Generated artifacts are retained under a temporary directory;
record their paths and keep research outputs outside the repository.

## What the bounded run observes

Circuit and witness types come from generated `contract-info.json`; constructor
metadata may fall back to the owned source model. Typed boundary values, synthetic
witnesses, caller changes and short call sequences try to reach runtime state
transitions. Name and type heuristics guide generation and oracle interpretation.
Synthetic witnesses need not represent a deployed witness implementation, and a
reached compiled evaluation need not be a feasible submitted transaction.

The experimental runtime explorer and static detectors have separate selection
and evidence contracts. Runtime observations describe attempted local executions;
they do not establish general security properties, application intent, or
deployed behavior.

The JSON schema tag is `nightshade-explore-2`. Inspect compiler status, runtime
availability/setup errors, attempt/replay errors, executed calls, transitions,
oracle detections, disabled markers and explicit misses together. Reports include
replay IDs, arguments, witness samples and before/after ledger observations;
these may contain sensitive material. Preserve source, compiler, runtime and
script identities alongside the report. A replay ID or report hash identifies
recorded evidence; it does not verify its outcome on another build.

A compiler/runtime setup failure, zero reachable calls, an omitted branch or an
exhausted bound is a coverage gap. Empty false-alarm arrays do not measure
precision without independent labels. An alarm-free run establishes neither safety nor
liveness. Compiled evaluation is distinct from proof generation,
proof verification and ledger transaction acceptance. Use static diagnostics and
manual protocol review alongside the run.

## Attach references to a review brief

The shipped review command can attach an existing report for the same physical
root without executing it:

```sh
node dist/src/cli.js review examples/review/contract.compact --out "$explore_dir/brief" \
  --compiler-version 0.34.0 --explorer-report "$explore_dir/explore.json"
```

The output directory must be new. The attachment is limited to 8 MiB and 10,000
replay references. Review copies circuit/status/transition/replay-ID references
and the artifact hash, omitting arguments, witnesses and state snapshots. It marks
the attachment `attached-source-unverified`: source history, compiler/runtime
identity and outcomes have not been reverified. Without an attachment, explorer
status is `not-run`. See [review mode](review.md) for the source map's own limits
and [compiler onboarding](compiler-onboarding.md) for the supported static matrix.
