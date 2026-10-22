# Evaluation

A pre-release build of 0.1.0 was measured on a fixed input set of 300 roots
from 144 public repositories. The assembled input set and per-source results
are private and unavailable for reproduction. Only aggregate counts are
published; project identities and findings are omitted. The shipped examples
are reproducible checks of defined behavior, not population accuracy.

## Completion and comparator scope

The input compiler versions were 0.28.0, 0.29.0, 0.30.0, 0.31.1, 0.33.0-rc.2,
0.34.0 and 0.35.0. All 300 roots remain in the denominator. Compiler validation
accepted 273; the other 27 were not scanned by Nightshade. Analysis used the
ordinary audit selection and recorded per-root profiles and budgets.

| Outcome | Count |
| --- | ---: |
| Total roots | 300 |
| Compiler accepted / rejected | 273 / 27 |
| Nightshade baseline analysis complete | 258 / 300 (86.0%) |
| Nightshade all selected rules complete | 237 / 300 (79.0%) |
| Nightshade findings | 315 |
| Nightshade worker/process failures | 0 |
| OpenZeppelin scanner successful / nonzero exits | 157 / 143 |

The 15 scanned roots without complete baseline coverage and the additional 21
with incomplete selected-rule coverage remain gaps. Compiler rejection, missing
dependencies, unsupported syntax and exhausted budgets are not clean results.
Completion means the supported static analysis finished; it does not prove
contract safety, reachability of a reported path or general language coverage.

The comparator was the unmodified OpenZeppelin scanner 0.0.3 release asset,
whose embedded version reports 0.0.2. Its binary SHA-256 was
`7e076e23968e30495a61c264b04cb24727b208b915bcf33bd8395737e744f4b8`.
Both advertised built-in checks were selected. It attempted all 300 roots,
including the 27 compiler-rejected inputs, emitted two findings, and had no
timeouts or signals. The 143 nonzero exits used code 101.

The tools implement different checks and have different error/coverage models.
A comparator zero exit is a process outcome, not Nightshade's semantic
completion measure. Neither finding counts nor these completion counts establish
relative vulnerability-detection accuracy. Comparator precision was not measured.

## Precision and recall limits

There is no independently established release-wide precision or recall estimate.
A previous model-assisted source-review exercise labeled 30 findings in two
selected strata: 18 actionable observations, 10 benign observations and two false
reports. This selected sample is not independent human ground truth, and a benign
static observation is not necessarily a detector error. Weighting those strata
does not estimate precision for all rules, applications or findings. No general
accuracy percentage is claimed from it.

Synthetic positive/corrected/lookalike tests check defined rule behavior and
regressions. They do not measure unknown vulnerabilities, unseen application
patterns or ecosystem-wide recall. A quiet result after correcting one rule
does not establish that the contract is secure.

Use [limitations](limitations.md) to interpret incomplete analyses and
[the detector catalog](detectors.md) for each rule's scope and benign matches.
The shipped examples provide a small reproducible check of installation and
expected detector behavior.
