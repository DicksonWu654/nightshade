# dead-code

Availability: **default-on**; no policy required.
Severity **info**, confidence **high** for the source-control-flow observation.
Use `--min-severity low` to hide informational findings, or
`--detectors dead-code` to select only this rule.

Reports root-file statements after unconditional termination, branches excluded
by typed scalar constants, and empty static loops. This is a bounded source
observation rather than a general path-feasibility proof.

## Example and review scenario

The compiler-0.34.0-qualified owned [Counter fixture](#example-1)
places the update in `for (const i of 0..0)`, so it never executes. Its
[correction](#example-2) performs
`round.increment(1)` directly. Review the rule when expected work disappears
after changing a range, a return, or a compile-time condition.

Recommendation: correct the bound or control flow to restore intended execution,
or remove intentional dead code after reviewing configuration variants.

## False positives and limitations

Empty generic specializations and disabled configuration branches can be
intentional. Arbitrary call results, aggregate projections and general relational
infeasibility are outside the source constant model. Root-file scope does not
certify imported code. Source traversal budget exhaustion remains incomplete.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Counter fixture (source: `tests/corpus/informational/dead-code-positive.compact`).

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
  for (const i of 0..0) { round.increment(1); }
}
```

### Example 2

Correction (source: `tests/corpus/informational/dead-code-corrected.compact`).

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
