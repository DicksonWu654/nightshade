# circuit-cost

Availability: **default-on**; no policy required.
Severity **info**, confidence **high** for the source estimate.
Use `--min-severity low` to hide informational findings, or
`--detectors circuit-cost` to select only this rule.

Reports analyzed program entries whose expanded source-operation upper bound
exceeds **10,000 units**. Static loops and callees contribute repeated work;
both branch alternatives are counted conservatively.

## Example and review scenario

The compiler-0.34.0-qualified owned [Counter fixture](#example-1)
nests ranges `0..40` and `0..64`, repeating the increment 2,560 times. Its
[correction](#example-2)
performs one increment. Review accidental repeated work or an unexpectedly large
expanded circuit before deciding whether optimization is needed.

Recommendation: inspect loop sizes and repeated callees, then measure actual
compiler/prover cost. Use [circuit-work-budget](circuit-work-budget.md) for
project-specific policy thresholds.

## False positives and limitations

Large circuits can be intentional; the fixed threshold is an informational review
aid. Units are not proof rows, optimized compiler cost, memory usage, runtime
or prover time. A match is not a denial-of-service finding. An unavailable finite
estimate or exhausted visit allowance emits an incomplete diagnostic.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Counter fixture (source: `tests/corpus/informational/circuit-cost-positive.compact`).

```compact
// This file is part of midnightntwrk/example-counter.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pragma language_version >= 0.20;

import CompactStandardLibrary;

// public state
export ledger round: Counter;

// Nightshade owned informational regression; adapted from example-counter.
export circuit increment(): [] {
  for (const i of 0..40) { for (const j of 0..64) { round.increment(1); } }
}
```

### Example 2

Correction (source: `tests/corpus/informational/circuit-cost-corrected.compact`).

```compact
// This file is part of midnightntwrk/example-counter.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pragma language_version >= 0.20;

import CompactStandardLibrary;

// public state
export ledger round: Counter;

// Nightshade owned informational regression; adapted from example-counter.
export circuit increment(): [] {
  round.increment(1);
}
```
