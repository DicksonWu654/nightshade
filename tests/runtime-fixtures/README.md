# Fixed compiled-evaluation qualification

These three owned synthetic fixtures qualify selected behavior using Compact
0.34.0 / language 0.26.0, default ZKIR2, and **exact runtime 0.19.0**. The test
adapter accepts only the fixed fixture names. It provides no arbitrary-contract
execution, campaign generation, proof generation, or transaction submission API.

Use a built source checkout on Node 22 or 24. Set `COMPACTC_TEST` to a trusted
Compact 0.34.0 compiler executable. Restore the external runtime and run the
focused opt-in suite:

```sh
: "${COMPACTC_TEST:?Set a trusted Compact 0.34.0 compiler executable}"
NIGHTSHADE_RUNTIME_INPUTS=$(mktemp -d)
cp tests/runtime-fixtures/qualification-inputs/package*.json "$NIGHTSHADE_RUNTIME_INPUTS/"
npm ci --prefix "$NIGHTSHADE_RUNTIME_INPUTS" --ignore-scripts --omit=dev --no-audit --no-fund
export COMPACT_RUNTIME_TEST="$NIGHTSHADE_RUNTIME_INPUTS"
npm run build
node --test dist/tests/runtime-qualified.test.js
```

Repeat these tests under each supported Node major during release qualification.
No Node version manager is required by the harness.

`COMPACT_RUNTIME_TEST` names a directory containing `node_modules`, installed
outside the repository. Without it these three tests explicitly skip. Providing
it without the pinned compiler fails; runtime/compiler mismatches also fail.
The test worker is supervised for 60 seconds with a 256 MiB V8 heap setting and
one MiB output bound. Its compiler subprocess has a 30-second limit. These are
process controls, not an OS sandbox or an RSS limit.

Restore `@midnight-ntwrk/compact-runtime@0.19.0` using the production dependency
entries from the release source's `runtime/package-lock.json`; do not resolve
its semver ranges afresh. The exact input set is:

| Package | Version |
| --- | --- |
| `@midnight-ntwrk/compact-runtime` | 0.19.0 |
| `@midnightntwrk/onchain-runtime-v4` | 4.0.0-rc.3 |
| `@noble/curves` | 2.3.0 |
| `@noble/hashes` | 2.3.0 |
| `@types/object-inspect` | 1.13.0 |
| `object-inspect` | 1.13.4 |

Retain the external `package-lock.json` and verified dependency identities with
your results. The runtime registry integrity is
`sha512-0q1ZOlyPdCCEasAxlHxagO6Sb+Db5GM6qYPQ+c+cp71NRxQgiY0Wd0/LIoshQTs+OBISb4XTjiNQ1lxcKR79qQ==`;
the onchain runtime integrity is
`sha512-LAf4g3vgwtPqActbi5RAoZcfYduqnFqtsHN+i1s/Mcb5vi2yMbPmpSOJ0YCCIGb2S/qY7G5tQARHVD0PJyHSNA==`.

Release source is `compactc-v0.34.0`, commit
`1f671fc27818df2b2676b3a97f85b2b821756243` in LFDT-Minokawa/compact.
`runtime/src/{constructor-context,circuit-context,witness}.ts` defines the
positional context API and immutable witness-result convention;
`compiler/midnight-ledger.ss` defines Counter updates and List head/tail lowering.
Its ledger source pin is `4823b5351b17cc49e30f19760dbd30a73cf95e22` in
midnightntwrk/midnight-ledger. The existing research checkout `b3a90d…` is newer:
runtime 0.19.104 changed the context API. It is not the runtime source for this test.

The npm Compact runtime declares Apache-2.0. The onchain runtime archive omits
a license field and LICENSE file, while the pinned source repository contains
Apache-2.0 LICENSE and workspace metadata. This is provenance evidence, not legal
approval or completion of the project's dependency review.

Qualified observations are deliberately narrow:

- List defaults, head/length/iteration, push-front order, pop of a nonempty list,
  reset, and retained constructor snapshots agree with the fixed expectations.
  On the pinned runtime an empty pop evaluates successfully; the subsequent
  inspect rejects with an invalid-index-operation error. Reset then restores
  the empty representation. An empty pop is therefore neither silently modeled
  as a no-op nor asserted to fail immediately by this qualification.
- Counter small updates, comparisons, reset and underflow are observed. Underflow
  raises `CompactError` with the runtime message `Error: arithmetic overflow`;
  accepted state stays unchanged. Fixed injected representation cases additionally
  qualify checked Uint64 increment overflow, exact-boundary success, Uint16 maximum
  updates and typed zero controls. These are not reachable-transaction claims.
- The immutable deterministic witness yields 7, 8, 8 for success/rejection/success.
  The rejected call's witness and ledger updates do not advance accepted state.
  Witness-side JavaScript effects outside returned private state are not rolled back.

Every call starts with a fresh context, fixed time/address/key and the previously
accepted public/private snapshot. Constructor serialization roundtrips and retained
input snapshots are checked. Successful calls record exactly one local transcript;
the private-state fixture also records the witness output count. The test checks
compiled evaluation only. Recorded proof data is not proof verification, and the
resulting snapshots are not applied ledger transactions. No findings, independent
audit labels, generalized List model, or transaction-reachability claims follow.

## Counter representation boundaries

The Counter adapter first verifies the compiled fixture's constructor layout:
one root array slot containing an eight-byte-aligned zero cell, independently
read as zero by the generated ledger accessor. It then constructs only a fixed
table of in-range Uint64 representations using the pinned runtime's public
`StateValue`, `ChargedState` and unsigned type descriptor APIs. It checks descriptor
and contract-state serialization roundtrips and the generated ledger accessor
before invoking any update. Source and compiled-JavaScript SHA-256 hashes identify
the fixed artifacts. Requests cannot supply source text, state or boundary values.

Cases include `2^64-2 + 1`, `2^64-1 + 0`, rejected `2^64-1 + 1`, maximum Uint16
increments immediately below/above the overflow boundary, maximum Uint16
decrements, zero updates and underflow. Each case starts from a separate injected
snapshot; inspect/update/inspect/reset/inspect observations are checked. Both
successful and rejected evaluations preserve retained input snapshots, and reset
restores zero. The injected state construction establishes representation validity
for this fixed test, not deployment reachability, proof verification, transaction
acceptance or transaction atomicity.

Source evidence uses release `1f671fc27818df2b2676b3a97f85b2b821756243`,
`compiler/midnight-ledger.ss:587-620`: Counter initializes/reset to an eight-byte
zero cell, reads Uint64, accepts Uint16 updates, and lowers them to `addi`/`subi`.
At ledger pin `4823b5351b17cc49e30f19760dbd30a73cf95e22`, the VM's `add`/`sub`
decode unsigned 64-bit operands and use `checked_add`/`checked_sub`, returning
`ArithmeticOverflow` on overflow/underflow; the `Addi`/`Subi` dispatch uses those
helpers. The reviewed VM source has SHA-256
`4a948f28e51fd6af05c097e55d749107dd741220691cafcd7f3ed66da38bed4e`.

`tests/counter-boundary.test.ts` separately compiler-validates equality-guarded
entry-state assumptions and compares both analysis engines with caches on/off.
It checks methods, compound updates, replay after a prior successful boundary
update, snapshots and unknown operands. Known arithmetic rejection removes the
successful path without inventing an assertion failure. Unknown operands remain
conservative, and general Uint arithmetic is unchanged.

`runtime-generated.test.ts` additionally compares four fixed owned cases with
the independent concrete oracle in `tests/generative/model.ts`: three fixed
seeds and an explicit correlated-branch/snapshot composition. Its worker accepts
only the validated bounded model (at most 32 operations, no embedded source),
renders that model, compiles it, and evaluates `entry(false)` and `entry(true)`
from distinct constructor snapshots. Exact nested result shapes, scalar kinds,
values and input association are compared. Source and generated-JavaScript hashes
identify the executed artifacts. This checks the model independently of analyzer
transfer functions, within the same compiled-evaluation-only boundary.

Both workers reject input exceeding one MiB. Run the generated runtime suite with
the same external inputs and runtimes:

```sh
node --test dist/tests/runtime-generated.test.js
```

For restoration on another machine, the versioned [runtime-inputs.json](runtime-inputs.json)
contains all six registry URLs, exact versions, archive SHA-512 integrities,
SHA-256 hashes, byte lengths, release-source pins and verification provenance.
The small [qualification package](qualification-inputs/package.json) and
[lockfile](qualification-inputs/package-lock.json) preserve the exact inputs used
on this server. The package is private and test-only. Copy these files outside
the repository before installing; no machine-local lockfile is needed:

The restoration block at the top of this page copies these pinned inputs to a
new temporary directory and exports `COMPACT_RUNTIME_TEST` for the test commands.

The two copied files' SHA-256 hashes appear under `restoration` in the manifest.
`npm ci` verifies downloaded archive SHA-512 integrities against the lockfile;
the manifest's SHA-256 values additionally identify manually retained archives.
An integrity mismatch is a failed restoration, not a reason to refresh the pins.
Restore `COMPACTC_TEST` separately from a trusted compiler distribution; see
[compiler onboarding](../../docs/compiler-onboarding.md). The manifest records this server's Linux x86-64 archive; it does
not attest compiler artifacts on other platforms. No source or binary is vendored
here, and these records do not clear legal, independent-review or release gates.
