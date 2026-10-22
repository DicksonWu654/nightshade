# unnecessary-disclose

Availability: **default-on**; no policy required.
Severity **info**, confidence **high** for the source-publicness observation.
Use `--min-severity low` to hide informational findings, or
`--detectors unnecessary-disclose` to select only this rule.

Reports root-file `disclose` operands already known public from literals or direct
ledger data in a public source control context. This is a readability review of
redundant permission annotations.

## Example and review scenario

The compiler-0.34.0-qualified owned [Counter fixture](#example-1)
uses `round.increment(disclose(1))`. Its
[correction](#example-2)
uses `round.increment(1)`. Review excessive annotations that obscure the places
where private values actually cross a disclosure boundary.

Recommendation: remove a redundant annotation only after confirming that the
compiler accepts the intended privacy boundary.

## False positives and limitations

A uniform explicit-disclosure style is harmless and may be intentional. The rule
is a conservative source observation, not a compiler privacy proof or a secret
leak detector. Calls and uncertain source/control contexts do not acquire assumed
publicness. Only root-file observations are reported; exhausted source traversal
is incomplete. See [declared-secret-publication](declared-secret-publication.md)
for policy-based private dependencies.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Counter fixture (source: `tests/corpus/informational/unnecessary-disclose-positive.compact`).

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
  round.increment(disclose(1));
}
```

### Example 2

Correction (source: `tests/corpus/informational/unnecessary-disclose-corrected.compact`).

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
