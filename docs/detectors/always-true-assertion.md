# always-true-assertion

Availability: **default-on**; no policy required.
Severity **info**, confidence **high** for modeled pre-assertion truth.
Use `--min-severity low` to hide informational findings, or
`--detectors always-true-assertion` to select only this rule.

Reports a root-file assertion already true on every modeled reach before that
assertion adds a constraint. All reaching entries and potential callers must have
complete analysis; unknown or uncovered reaches prevent a universal claim.

## Example and review scenario

The compiler-0.34.0-qualified owned [Counter fixture](#example-1)
uses self-equality for an intended counter-started check. Its
[correction](#example-2)
expresses that intended precondition:

```compact
assert(round > 0, "counter started");
```

Recommendation: check for a missing or mistaken operand, then restore the actual
condition. Review earlier guards before removing a repeated assertion.

## False positives and limitations

Defensive helper checks can be intentionally redundant after caller guards, and
fixed inputs can make an assertion trivially true. High confidence describes
the modeled observation, not a security defect or advice to delete the check.
Assertions outside the root file are not reported. Unknown facts, incomplete
callers and exhausted budgets cannot establish universal truth.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Counter fixture (source: `tests/corpus/informational/always-true-assertion-positive.compact`).

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
  assert(round == round, "counter started");
  round.increment(1);
}
```

### Example 2

Correction (source: `tests/corpus/informational/always-true-assertion-corrected.compact`).

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
  assert(round > 0, "counter started");
  round.increment(1);
}
```
