# time-dependence

Availability: **default-on**; no policy required.
Severity **info**, confidence **high** for a canonical block-time observation.
Use `--min-severity low` to hide informational findings, or
`--detectors time-dependence` to select only this rule.

Reports a canonical block-time kernel read on a successful history of a completely
analyzed entry. Called libraries are included, with the application's call site
used when available. User-defined namesakes do not establish a kernel read.

## Example and review scenario

The compiler-0.34.0-qualified owned [Counter fixture](#example-1)
adds `assert(blockTimeGt(0), "started")`. Its
[correction](#example-2)
restores a clock-independent increment. For an actual deadline or timelock,
the time dependency is expected; review the boundary instead of removing it.

Recommendation: check inclusivity, expiration behavior, liveness near the
boundary and permitted clock variation. Protocol time is not a randomness source.

## False positives and limitations

Normal deadlines and timelocks intentionally match. The observation does not
prove unsafe timing, randomness quality, cross-transaction feasibility or
exploitability. It covers modeled canonical `blockTimeLessThan` and
`blockTimeGreaterThan` operations, not every custom notion of time. Incomplete
entries and exhausted observation budgets remain incomplete.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Counter fixture (source: `tests/corpus/informational/time-dependence-positive.compact`).

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
  assert(blockTimeGt(0), "started");
  round.increment(1);
}
```

### Example 2

Correction (source: `tests/corpus/informational/time-dependence-corrected.compact`).

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
