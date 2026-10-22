# constant-condition

Availability: **default-on**; no policy required.
Severity **info**, confidence **high** for the typed source-constant observation.
Use `--min-severity low` to hide informational findings, or
`--detectors constant-condition` to select only this rule.

Reports a root-file branch condition reducing to the same typed scalar constant
across its instantiated copies. This identifies a fixed branch choice for review.

## Example and review scenario

The compiler-0.34.0-qualified owned [Counter fixture](#example-1)
uses `if (1 < 2)` to select an increment. Its
[correction](#example-2)
keeps the selected `round.increment(1)` directly. Review accidental fixed operands
when a branch was intended to depend on configuration or an input.

Recommendation: verify the operands and intended configuration, then correct an
unintended constant or simplify an intentional branch.

## False positives and limitations

Compile-time configuration and generic specialization can intentionally fix a
branch. The source model does not infer arbitrary call results or aggregate
projections as constants; it is not a solver for all invariant conditions. Only
root-file observations are reported. Budget exhaustion remains incomplete.
[Dead-code](dead-code.md) can separately report an excluded branch.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Counter fixture (source: `tests/corpus/informational/constant-condition-positive.compact`).

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
  if (1 < 2) { round.increment(1); } else { round.increment(2); }
}
```

### Example 2

Correction (source: `tests/corpus/informational/constant-condition-corrected.compact`).

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
