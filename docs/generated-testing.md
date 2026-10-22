# Generated analyzer correctness testing

`npm run test:generated` checks a bounded grammar of owned synthetic Compact
programs. It does not accept contract targets. It is development infrastructure,
not a contract fuzzer, an exploit generator, or an estimate of security detection
accuracy. The associated core-technology work remains tracked in
the documented analyzer constraints.

## Qualified campaigns

Set `COMPACTC_TEST` to a trusted Compact 0.34.0 compiler executable. Run from a
built source checkout on Node 22 or 24. This small example uses four cases and a
new temporary output directory:

```sh
: "${COMPACTC_TEST:?Set a trusted Compact 0.34.0 compiler executable}"
generated_dir=$(mktemp -d)
npm run test:generated -- \
  --compiler "$COMPACTC_TEST" \
  --output "$generated_dir/campaign" --seed 1 --cases 4 --steps 8
```

Compiler validation is mandatory. The command builds first. It supports at most
256 cases and 32 operations per case; a uint32 seed and a versioned generator
determine the input. Each case runs in a fresh supervised process, with a default
60-second wall limit, 512 MiB V8 heap setting and 4 MiB output bound. Heap settings
are not RSS limits or OS containment. Compiler subprocesses inherit the worker's
process group and scratch directory on POSIX systems.

The first grammar includes initialized Field storage and Set membership/size,
scalar snapshots, unrelated writes, repeated nested read helpers, and conditional
mutations correlated through one Boolean input. Numeric inputs and keys have
explicit finite bounds. This deliberately small grammar does not establish
arbitrary Compact semantics, general branching scale, or cross-transaction behavior.

Each qualified case compares four modes: instruction/reference execution with
summaries on/off, with mutation summaries explicitly enabled in both cached modes.
Full within-engine paths compare traces, ordered public sinks, caller paths and
write guards. Cross-engine comparisons normalize engine-specific trace details.
Cached checks must exercise actual read-summary hits. A separate bigint/Set model
checks concrete checkpoint values for both Boolean inputs. The model does not
import analyzer transfers. Independent provenance/guard oracles remain further
work; cross-engine agreement alone can share a semantic mistake.

The companion opt-in tests in `tests/runtime-fixtures` use the matching Compact
runtime 0.19.0. See their README for exact dependency pins and the boundary between
compiled evaluation, proof checking and transaction application.
A separate harness validates
actual generated-runtime observations and retains a bounded corpus of measured
transition categories. It does not label these categories as execution-edge coverage.

## Evidence and replay

Every case writes its bounded model, exact generated source, source digest,
compiler result, budgets, worker limits and per-mode metrics to an artifact. The
identity records analyzer source/build inputs, harness source, built JavaScript,
loaded native parser/runtime artifacts and parser metadata, compiler launcher and
distribution binaries, semantic profile, Node version, platform and architecture.
Historical output directories are never overwritten. A summary records completed
cases, statuses and generated-operation counts; these counts are not executed-edge
coverage or a coverage-guided mutation campaign.

Replay regenerates source from the validated model and checks the stored source
and digest. Embedded arbitrary source is never executed. By default all recorded
identities must match; `--compare-build` explicitly records a comparison with a
different build/runtime rather than calling it an identical replay.

```sh
node dist/tests/generative/campaign.js \
  --compiler "$COMPACTC_TEST" \
  --replay "$generated_dir/campaign/0000-1.json" \
  --output "$generated_dir/replay"
```

Artifact/campaign schema 2 records all three effective analysis budgets explicitly
(20,000 steps, 256 paths, 50,000 values by default), independently of future
analyzer defaults. Schema 1 development artifacts remain historical evidence;
the schema 2 replay validator rejects them rather than guessing missing defaults.
Passing records require all four distinct engine/cache modes, exact compiler and
language versions, complete per-mode metrics, completed entries, no diagnostics
and actual cache exercise. This validates evidence shape and consistency; it does
not authenticate an artifact or independently attest that its recorded work ran.

Replay preserves recorded budgets and execution limits. Missing evidence,
compiler failures, analyzer budget exhaustion and worker failures cannot become
passing checks. Compiler-validation failure is not automatically classified as a
source-language rejection: the compiler adapter also reports process failures.

Failed, compiler-accepted semantic/differential checks can undergo bounded typed
reduction. Candidates delete operation chunks or simplify operands; each candidate
is compiled and checked again. Only the same recorded failure signature can be
retained; incomplete or unqualified outcomes cannot substitute for it. Reduction
records executed checks, its check budget, exhaustion and interruption. It does not claim
a globally minimal program or prove a common root cause. `--reduce-checks 0` disables
reduction. Every original artifact is retained alongside the reduced case.

Exit 0 means every requested case passed its implemented checks. Exit 1 means a
semantic/differential failure. Exit 2 means incomplete/unqualified work, input
failure or interruption. A partially written campaign without a summary is not
qualified as complete. Individual artifacts survive interruption.
