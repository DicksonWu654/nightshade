# Reviewer briefs

`nightshade review` is an opt-in, offline source map for human review.
It calls no model and executes no contract. It produces a JSON brief and a Markdown
brief for each contract plus a batch manifest. Findings do not change its exit code:
0 means all requested map layers completed; 2 means an incomplete map or input error.
Completion does not mean the contract is secure. Local file paths and selected source
excerpts are retained; review the artifacts before sharing them.

```sh
review_dir=$(mktemp -d)
node dist/src/cli.js review examples/review/contract.compact --out "$review_dir/main" --compiler-version 0.34.0
node dist/src/cli.js review examples/review --out "$review_dir/project"
```

The output directory must be new and its parent must already exist. Existing
artifacts are never overwritten. Directory inputs use project discovery and record
omitted library templates in `manifest.json`. Re-exported circuits appear in their
application's table with locations in the defining file. Each contract uses a
supervised worker. Compiler/ZKIR profiles, import paths, `--max-steps`, `--max-paths`,
`--max-values`, `--timeout-ms`, and `--heap-mib` are explicit options. Automatic scan
configuration and custom detectors are not loaded; findings always
use the audit profile. No compiler executable or network service is invoked.
Selecting `--compiler-version` chooses analysis assumptions; it does not validate the source with that compiler.
See [compiler onboarding](compiler-onboarding.md) for an explicit validation workflow.

The JSON format is `nightshade-review-1`. It contains source hashes and analysis
budgets, baseline/detector/inventory/history coverage, exported circuit arguments,
transitive witness calls, conservative ledger reads/writes, assertion sites,
disclosures, time usage, canonical value operations, public sinks and audit findings.
JSON retains per-history constraints and write/operation positions; Markdown gives
source excerpts, a circuit table, a field-to-reader/writer sketch and prioritized
questions. Questions carry an evidence score, rank, and signals. Only fact-triggered
questions are generated; the Markdown view shows the top ten and collapses the rest,
while JSON retains the complete ranked list and its collapsed count. Source excerpts
are limited to 400 characters per site; exact spans and source hashes identify the
full source. Extraction is bounded and reports gaps.

Authorization strength describes observed evidence. An assertion, helper call,
public-key equality or private-preimage check does not prove the intended caller
is authorized. Histories remain separate; a check on one branch is not assumed on
another. Marker candidates come from field names and assignments, not a proof of
terminality or one-time behavior. Incomplete source/path facts remain explicit.
Questions are review prompts about value authorization, time binding, disclosure,
state lifecycle, competing marker transitions, coverage gaps and audit findings.
Ranking reflects observed evidence: missing authorization around value movement,
caller-time comparison gates, witness-derived disclosures, and unguarded marker
writes rank above weaker observations. The top of each Markdown brief summarizes
status, counts, diagnostic groups, and five questions. Repeated diagnostics are
grouped with counts and locations. Paths in emitted briefs are repository-relative.
They are not additional detector verdicts.

Trusted source checkouts can run `node scripts/explore.mjs` with explicit local
compiler/runtime inputs. The installed CLI does not dispatch exploration. A report from
the [runtime explorer](explore.md) can be attached to a single-root brief through
the explicit `--explorer-report FILE` option. Use the same physical root recorded
in that report and a new output directory.

The attachment must be a bounded `nightshade-explore-2` report with the same physical
root (at most 8 MiB and 10,000 replay references). Only circuit/status/transition/
replay-ID references and an artifact hash are copied. Arguments, witness values and state snapshots are omitted. It is labeled
`attached-source-unverified`: historical source, compiler/runtime identity and
outcomes have not been reverified. The command does not run or verify a replay.
Without an attachment the explorer section explicitly says `not-run`.

Review outputs are navigation aids. Verify each question against the source and
its surrounding control flow; attached historical evidence is unverified and
does not establish runtime behavior.


The commands above use a built source checkout; an installed tarball exposes
the same review command as `nightshade review`. A review's audit findings and questions are separate from a
normal scan's CI threshold: review exits 0 after complete mapping even when it
contains findings. Inspect the manifest and each brief's layer coverage before
using the result. Worker timeouts, extraction gaps and unsupported source facts
remain incomplete; increasing budgets does not establish security coverage. The
V8 heap limit is not an RSS cap or OS sandbox.

## Unsupported signature inventory

`review` needs a signature-layout inventory in addition to ordinary scan coverage.
Opaque signature values, including `Opaque<"string">` used by the bulletin-board
tutorial, are outside that inventory schema. Their review command exits 2 with
`inventory-unsupported-type` and keeps the partial briefs plus diagnostic locations.
This is an explicit mapping limitation, not a finding or a clean review. Use an
ordinary scan for detector results and inspect unsupported signatures and circuit
behavior manually. Raising scan budgets or `--rule-incomplete warn` cannot make
this review inventory complete; the warning option belongs to normal scan CI.
